"""Bind a GCC/ELF executable and installed bytes to a pinned runtime export.

This records link provenance under compiler/platform trust. The symbolic root
and its assumptions remain the scope of verification, even when main is one
of the analyzed translation units. No process attestation is implied.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
from uuid import uuid4

from tools.verification.backend import save_json
from tools.verification.runtime import check_runtime, native_flags
from tools.verification.source import sha256
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.toolchain import Toolchain


SOURCE = Path(__file__).resolve()
SOURCE_FILES = (SOURCE, SOURCE.with_name('captured_link.py'))
def binding_digest():
    return sha256(b''.join(path.read_bytes() for path in SOURCE_FILES))
IMPORTED_SHA256 = binding_digest()
ERRORS = (SpecificationError, OSError, ValueError, KeyError, TypeError)

# Read files on the execution host, including paths outside Windows mounts.
# Preserve both the spelling used by ld and the fully resolved symlink target.
INVENTORY = '''import hashlib,json,os,stat,sys
result={}
for name in json.loads(sys.argv[1]):
    resolved=os.path.realpath(name,strict=True)
    with open(resolved,"rb") as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("link input is not a regular file: "+name)
        if stream.read(8)==b"!<thin>\\n":
            raise RuntimeError("thin-archive member provenance is unsupported: "+name)
        stream.seek(0)
        checksum=hashlib.file_digest(stream,"sha256").hexdigest()
        after=os.fstat(stream.fileno())
    fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if fields(before)!=fields(after) or fields(after)!=fields(os.stat(name)):
        raise RuntimeError("link input changed while reading: "+name)
    result[name]={"resolved":resolved,"sha256":checksum,"size":after.st_size}
print(json.dumps(result,sort_keys=True))
'''


def require(toolchain, executable, args, directory, timeout=60):
    process = toolchain.run_external(executable, args, timeout, cwd=directory)
    if process.returncode != 0 or process.timed_out:
        raise SpecificationError(f'link provenance command failed: {executable}: {process.stderr[-2000:]}')
    return process


def inventory(toolchain, names, directory):
    names = list(dict.fromkeys(names))
    if not names or any(not isinstance(p, str) or not p.startswith('/') or '\n' in p or '\r' in p for p in names):
        raise SpecificationError('link inputs must have unambiguous absolute POSIX paths')
    return json.loads(require(toolchain, 'python3', ['-c', INVENTORY, json.dumps(names)], directory).stdout)


def pinned_json(path, pin, kind):
    raw = Path(path).read_bytes()
    if not isinstance(pin, str) or not re.fullmatch('[a-f0-9]{64}', pin) or sha256(raw) != pin:
        raise SpecificationError(f'{kind} manifest does not match the caller-pinned SHA-256')
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('kind') != kind:
        raise SpecificationError(f'unsupported {kind} manifest')
    return value


def asset_path(root, name):
    if not isinstance(name, str) or PurePosixPath(name).is_absolute() or '\\' in name:
        raise SpecificationError('invalid bundle asset path')
    path = (root / name).resolve()
    if not path.is_relative_to(root) or path == root:
        raise SpecificationError('asset escapes its bundle directory')
    return path


def check_assets(root, assets):
    if not isinstance(assets, dict):
        raise SpecificationError('bundle assets must be a path-to-hash mapping')
    for name, checksum in assets.items():
        if sha256(asset_path(root, name).read_bytes()) != checksum:
            raise SpecificationError('application link artifact changed: ' + name)


def selected_objects(task, policies, runtime, root, sources):
    selected = [Path(p).resolve() for p in sources]
    if not selected or len(selected) != len(set(selected)):
        raise SpecificationError('select a nonempty list of distinct application translation units')
    known = set(task.sources)
    if not set(selected) <= known:
        raise SpecificationError('application translation unit was not in the verified task')
    if not {p.translation_unit for p in policies} <= set(selected):
        raise SpecificationError('application selection omits a policy translation unit')
    rows = runtime['objects']
    application = rows[:len(task.sources)]
    if [Path(r['source']).resolve() for r in application] != list(task.sources):
        raise SpecificationError('runtime source/object mapping is ambiguous')
    helpers = rows[len(task.sources):]
    if len(helpers) != 3 or [Path(r['source']).name for r in helpers] != ['vm.c', 'bridge.c', 'failure.c']:
        raise SpecificationError('unsupported runtime helper object mapping')
    mapping = {Path(row['source']).resolve(): row for row in application}
    chosen = [mapping[p] for p in selected] + helpers
    names = [row['object'] for row in chosen]
    if len(names) != len(set(names)) or any(n not in runtime['assets'] for n in names):
        raise SpecificationError('selected object is missing or duplicated in pinned runtime assets')
    objects = [asset_path(root, name) for name in names]
    check_assets(root, {name: runtime['assets'][name] for name in names})
    return selected, objects, chosen


def trace_paths(stdout):
    paths = stdout.splitlines()
    # The supported command links explicit .o inputs, with no user archives,
    # plugins, scripts or additional libraries. GNU ld --trace prints paths.
    if not paths or any(not p.startswith('/') or '\x00' in p or p != p.strip() for p in paths):
        raise SpecificationError('unresolved or ambiguous GNU linker trace')
    return paths


def tool_identity(toolchain, compiler, directory):
    identity = toolchain.native_compiler(compiler, directory)
    if 'gcc' not in Path(identity['executable']).name:
        raise SpecificationError('application binding currently requires GCC and GNU ELF tools')
    programs = {'gcc': identity}
    for name in ('collect2', 'ld'):
        found = require(toolchain, compiler, ['-print-prog-name=' + name], directory).stdout.strip()
        programs[name] = toolchain.native_compiler(found, directory)
    programs['readelf'] = toolchain.native_compiler('readelf', directory)
    if 'GNU ld' not in programs['ld']['version'] or 'GNU readelf' not in programs['readelf']['version']:
        raise SpecificationError('application binding requires GNU ld and readelf')
    specs = require(toolchain, compiler, ['-dumpspecs'], directory).stdout
    environment = json.loads(require(toolchain, 'python3', ['-c',
        'import os,json; print(json.dumps({k:v for k,v in os.environ.items() if k in '
        '("GCC_EXEC_PREFIX","COMPILER_PATH","LIBRARY_PATH","LD_PRELOAD","LD_LIBRARY_PATH",'
        '"LD_AUDIT","COLLECT_GCC","COLLECT_LTO_WRAPPER","GNUTARGET","LDEMULATION")}))'], directory).stdout)
    if any(environment.values()):
        raise SpecificationError('link environment overrides are unsupported: ' + ', '.join(sorted(environment)))
    return {'programs': programs, 'gcc_specs_sha256': sha256(specs.encode()), 'environment': environment}


def elf_metadata(toolchain, readelf, executable, directory):
    result = {}
    for name, flag in (('header', '-hW'), ('program_headers', '-lW'), ('dynamic', '-dW'), ('notes', '-nW')):
        result[name] = require(toolchain, readelf, [flag, executable], directory).stdout
    if 'ELF64' not in result['header'] or 'Advanced Micro Devices X86-64' not in result['header']:
        raise SpecificationError('application binding currently qualifies ELF x86-64 only')
    return result


def default_script(toolchain, identity, link_mode, directory):
    return require(toolchain, identity['programs']['ld']['executable'],
                   [*(['-pie'] if link_mode == 'pie' else []), '--verbose'], directory).stdout


def ensure_current_source():
    if binding_digest() != IMPORTED_SHA256:
        raise SpecificationError('application binding implementation changed after import')


def checked_runtime(task, toolchain, policies, path, pin, output):
    result = check_runtime(task, toolchain, policies, path, pin, output)
    if result['runtime_status'] != 'CURRENT_FOR_HARNESS':
        raise SpecificationError('runtime evidence is stale or invalid: ' + '; '.join(result['reasons']))
    return pinned_json(path, pin, 'vulgate-runtime-archive')


def prepare_output(output, bundles):
    output = Path(output).resolve()
    if any(output.is_relative_to(Path(p).resolve().parent) for p in bundles):
        raise SpecificationError('application checks/builds must write outside pinned bundles')
    run = output / 'runs' / uuid4().hex
    run.mkdir(parents=True)
    save_json(output / 'status.json', {'status': 'STARTED', 'run': str(run)})
    return output, run


def finish(output, run, report):
    save_json(run / 'report.json', report)
    save_json(output / 'report.json', report)
    save_json(output / 'status.json', {'status': 'COMPLETE', 'run': str(run)})
    return report


def build_application(task, toolchain, policies, runtime_path, runtime_pin, sources,
                      output, application_id, version, link_mode='pie', *, capture=None,
                      capture_pin=None, captured_output=None):
    output, run = prepare_output(output, [runtime_path])
    report = {'schema': 1, 'status': 'UNKNOWN', 'application_status': 'UNKNOWN',
              'deployment_ready': False, 'reasons': [], 'run': str(run)}
    try:
        ensure_current_source()
        if link_mode not in ('pie', 'exec'):
            raise SpecificationError('supported link modes are pie and exec')
        if any(not isinstance(v, str) or not v.strip() or len(v) > 128 or not v.isprintable()
               for v in (application_id, version)):
            raise SpecificationError('application identity and version must be nonempty printable labels (max 128 characters)')
        runtime_path = Path(runtime_path).resolve()
        runtime = checked_runtime(task, toolchain, policies, runtime_path, runtime_pin, run / 'runtime-before')
        selected, objects, rows = selected_objects(task, policies, runtime, runtime_path.parent, sources)
        recipes = runtime['dependencies']['preprocessed']
        build = recipes[0]['build']
        if any(r['build']['compiler'] != build['compiler'] or r['build']['abi'] != build['abi'] for r in recipes):
            raise SpecificationError('application link requires one compiler and ABI across translation units')
        compiler = build['compiler']['executable']
        identity = tool_identity(toolchain, compiler, run)
        if identity['programs']['gcc'] != build['compiler']:
            raise SpecificationError('native compiler differs from pinned runtime compiler')
        executable, link_map = run / 'application', run / 'application.map'
        capture_evidence = None
        inputs = objects
        if any(value is not None for value in (capture, capture_pin, captured_output)):
            if not all(value is not None for value in (capture, capture_pin, captured_output)):
                raise SpecificationError('captured linking requires manifest, pin and original executable output')
            from tools.captured_link import captured_recipe
            inputs, capture_evidence = captured_recipe(capture, capture_pin, captured_output, runtime,
                                                       selected, objects, compiler, link_mode)
        # Use -Xlinker pairs so a comma/space in a directory remains a path.
        args = [*native_flags(build), '-pie' if link_mode == 'pie' else '-no-pie', *inputs,
                '-Xlinker', '--trace', '-Xlinker', '--build-id=sha1', '-Xlinker', '-Map',
                '-Xlinker', link_map, '-o', executable]
        preliminary = require(toolchain, compiler, args, run, task.timeout)
        paths = trace_paths(preliminary.stdout)
        if not {toolchain.path(p) for p in objects} <= set(paths):
            raise SpecificationError('selected objects are missing from the actual link trace')
        pins = inventory(toolchain, paths, run)
        # The actual linker script includes the GNU ld built-in default script.
        script = default_script(toolchain, identity, link_mode, run)
        if tool_identity(toolchain, compiler, run) != identity:
            raise SpecificationError('link tools changed during preliminary link')
        final = require(toolchain, compiler, args, run, task.timeout)
        if trace_paths(final.stdout) != paths or inventory(toolchain, paths, run) != pins:
            raise SpecificationError('link inputs or trace changed during final link')
        checksum = sha256(executable.read_bytes())
        metadata = elf_metadata(toolchain, identity['programs']['readelf']['executable'], executable, run)
        script_after = default_script(toolchain, identity, link_mode, run)
        if script_after != script or tool_identity(toolchain, compiler, run) != identity:
            raise SpecificationError('link tool or default script changed during final link')
        # Recheck native objects against the upstream pin after ld has read them.
        checked_runtime(task, toolchain, policies, runtime_path, runtime_pin, run / 'runtime-after')
        if capture_evidence is not None:
            if captured_recipe(capture, capture_pin, captured_output, runtime, selected, objects,
                               compiler, link_mode)[1] != capture_evidence:
                raise SpecificationError('captured build changed during final link')
        if inventory(toolchain, paths, run) != pins or sha256(executable.read_bytes()) != checksum:
            raise SpecificationError('application or link inputs changed during qualification')
        ensure_current_source()
        save_json(run / 'link.json', {'preliminary': preliminary.to_dict(), 'final': final.to_dict()})
        (run / 'link.trace').write_text(final.stdout, encoding='utf-8')
        (run / 'linker-default.txt').write_text(script, encoding='utf-8')
        save_json(run / 'elf.json', metadata)
        assets = {p.relative_to(run).as_posix(): sha256(p.read_bytes()) for p in run.rglob('*')
                  if p.is_file() and p != executable}
        manifest = {'schema': 1, 'kind': 'vulgate-application', 'application_id': application_id,
                    'version': version, 'binding_sha256': IMPORTED_SHA256, 'link_mode': link_mode,
                    'runtime_manifest': str(runtime_path), 'runtime_sha256': runtime_pin,
                    'selected_sources': [str(p) for p in selected], 'objects': rows,
                    'link_tools': identity, 'link_inputs': pins, 'trace': paths,
                    'default_linker_script_sha256': sha256(script.encode()),
                    'executable': {'path': 'application', 'sha256': checksum, 'elf': metadata},
                    'assets': assets,
                    'captured_build': capture_evidence,
                    'scope': {'entry': task.entry, 'targets': list(task.targets),
                              'qualification': 'LINKED_WITH_HARNESS_EVIDENCE',
                              'all_main_executions_proved': False, 'running_process_attested': False,
                              'machine_code_correctness': 'compiler and platform trusted'}}
        manifest_path = run / 'manifest.json'
        save_json(manifest_path, manifest)
        report.update(application_status='LINKED_WITH_HARNESS_EVIDENCE', manifest=str(manifest_path),
                      manifest_sha256=sha256(manifest_path.read_bytes()), executable=str(executable),
                      executable_sha256=checksum, application_id=application_id, version=version,
                      scope=manifest['scope'])
    except ERRORS as exc:
        report['reasons'].append(str(exc))
    return finish(output, run, report)


def check_application(task, toolchain, policies, manifest_path, pin, output, installed=None):
    # Check every output boundary before creating even the status directory.
    initial = pinned_json(manifest_path, pin, 'vulgate-application')
    output, run = prepare_output(output, [manifest_path, initial['runtime_manifest']])
    report = {'schema': 1, 'status': 'UNKNOWN', 'application_status': 'STALE_OR_INVALID',
              'deployment_ready': False, 'reasons': [], 'run': str(run)}
    try:
        ensure_current_source()
        path = Path(manifest_path).resolve()
        manifest = pinned_json(path, pin, 'vulgate-application')
        if manifest['binding_sha256'] != IMPORTED_SHA256:
            raise SpecificationError('application binding version differs from the evidence')
        runtime_path = Path(manifest['runtime_manifest']).resolve()
        if output.is_relative_to(runtime_path.parent):
            raise SpecificationError('check output overlaps the runtime bundle')
        runtime = checked_runtime(task, toolchain, policies, runtime_path, manifest['runtime_sha256'], run / 'runtime')
        selected, objects, rows = selected_objects(task, policies, runtime, runtime_path.parent, manifest['selected_sources'])
        if rows != manifest['objects']:
            raise SpecificationError('application object mapping differs from runtime evidence')
        check_assets(path.parent, manifest['assets'])
        compiler = manifest['link_tools']['programs']['gcc']['executable']
        captured = manifest.get('captured_build')
        if captured is not None:
            from tools.captured_link import captured_recipe
            if captured_recipe(captured['manifest'], captured['manifest_sha256'], captured['captured_output'],
                               runtime, selected, objects, compiler, manifest['link_mode'])[1] != captured:
                raise SpecificationError('captured build differs from application evidence')
        if tool_identity(toolchain, compiler, run) != manifest['link_tools']:
            raise SpecificationError('current link tools differ from application evidence')
        if inventory(toolchain, list(manifest['link_inputs']), run) != manifest['link_inputs']:
            raise SpecificationError('current link input differs from application evidence')
        script = default_script(toolchain, manifest['link_tools'], manifest['link_mode'], run)
        if sha256(script.encode()) != manifest['default_linker_script_sha256']:
            raise SpecificationError('default linker script differs from application evidence')
        binary = Path(installed).resolve() if installed is not None else asset_path(path.parent, manifest['executable']['path'])
        checksum = sha256(binary.read_bytes())
        if checksum != manifest['executable']['sha256']:
            raise SpecificationError('installed/executable bytes differ from application evidence')
        # Installed bytes are checked against the external pin, never against a
        # possibly replaced build copy. The build executable may be absent.
        check_assets(path.parent, manifest['assets'])
        if sha256(binary.read_bytes()) != checksum or inventory(toolchain, list(manifest['link_inputs']), run) != manifest['link_inputs']:
            raise SpecificationError('application or link inputs changed during checking')
        if tool_identity(toolchain, compiler, run) != manifest['link_tools']:
            raise SpecificationError('link tools changed during checking')
        checked_runtime(task, toolchain, policies, runtime_path, manifest['runtime_sha256'], run / 'runtime-after')
        if sha256(binary.read_bytes()) != checksum:
            raise SpecificationError('application bytes changed during final freshness check')
        pinned_json(path, pin, 'vulgate-application')
        ensure_current_source()
        report.update(application_status='CURRENT_INSTALLED_BYTES' if installed is not None else 'CURRENT_LINKED_BYTES',
                      checked_file=str(binary), executable_sha256=checksum, application_id=manifest['application_id'],
                      version=manifest['version'], manifest_sha256=pin, scope=manifest['scope'])
    except ERRORS as exc:
        report['reasons'].append(str(exc))
    return finish(output, run, report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('task', type=Path)
    parser.add_argument('--policies', type=Path, required=True)
    parser.add_argument('--toolchain', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--runtime', type=Path, help='pinned runtime manifest to link')
    mode.add_argument('--check', type=Path, help='pinned application manifest to check')
    parser.add_argument('--sha256', required=True, help='caller-retained SHA-256 of the selected manifest')
    parser.add_argument('--source', action='append', type=Path, help='application translation unit (repeatable)')
    parser.add_argument('--application-id')
    parser.add_argument('--version')
    parser.add_argument('--link-mode', choices=('pie', 'exec'), default='pie')
    parser.add_argument('--capture', type=Path, help='completed build-capture manifest for the original link')
    parser.add_argument('--capture-sha256', help='caller-retained build-capture manifest pin')
    parser.add_argument('--captured-output', type=Path, help='original executable output selecting the captured link')
    parser.add_argument('--installed', type=Path, help='check these installed bytes independently of the build copy')
    args = parser.parse_args(argv)
    try:
        task, policies, toolchain = Task.load(args.task), Policy.load_many(args.policies), Toolchain.load(args.toolchain)
        if args.runtime:
            if args.installed or not args.source or not args.application_id or not args.version:
                raise SpecificationError('link mode requires --source, --application-id and --version; --installed requires --check')
            report = build_application(task, toolchain, policies, args.runtime, args.sha256, args.source,
                                       args.output, args.application_id, args.version, args.link_mode,
                                       capture=args.capture, capture_pin=args.capture_sha256, captured_output=args.captured_output)
        else:
            if args.source or args.application_id or args.version or args.link_mode != 'pie' or any(
                    value is not None for value in (args.capture, args.capture_sha256, args.captured_output)):
                raise SpecificationError('check mode uses the pinned manifest selection and labels')
            report = check_application(task, toolchain, policies, args.check, args.sha256, args.output, args.installed)
        print(json.dumps(report, ensure_ascii=False))
        return 0 if report['application_status'] in ('LINKED_WITH_HARNESS_EVIDENCE', 'CURRENT_LINKED_BYTES', 'CURRENT_INSTALLED_BYTES') else 2
    except ERRORS as exc:
        print(json.dumps({'status': 'UNKNOWN', 'error': str(exc)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
