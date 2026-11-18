"""Bind a verified Linux runtime to a staged Kbuild image (native Linux only).

Kbuild owns objtool, archive construction, modpost and final image linking.
This tool preserves the supplied-root proof scope and records image provenance;
guest execution is a separate step. It does not install or boot a host kernel.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from tools.application_binding import asset_path, check_assets, pinned_json
from tools.verification.runtime import check_runtime
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.toolchain import Toolchain

SOURCE = Path(__file__).resolve()
REPOSITORY = SOURCE.parents[1]


def checksum(path):
    with Path(path).open('rb') as stream:
        state = sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            state.update(block)
        return state.hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')


def configuration(path):
    config = dict(re.findall(r'^(CONFIG_\w+)=(.*)$', path.read_text(), re.M))
    if config.get('CONFIG_X86_64') != 'y' or config.get('CONFIG_LTO_NONE') != 'y':
        raise SpecificationError('kernel image binding currently requires x86-64 without LTO')
    # These need additional correspondence qualification across object merging.
    unsupported = ('CONFIG_MODVERSIONS', 'CONFIG_CFI_CLANG', 'CONFIG_LIVEPATCH',
                   'CONFIG_FUNCTION_TRACER', 'CONFIG_GCC_PLUGIN_RANDSTRUCT')
    active = [key for key in unsupported if config.get(key) == 'y']
    if active:
        raise SpecificationError('unsupported kernel binding configuration: ' + ', '.join(active))
    return config


def archive_inputs(command_file):
    """Read the original vmlinux archive inputs without executing command text."""
    text = command_file.read_text().splitlines()[0]
    prefix = 'savedcmd_vmlinux.a := '
    if not text.startswith(prefix):
        raise SpecificationError('unsupported vmlinux archive command')
    parts = text[len(prefix):].split(';')
    if len(parts) != 3 or shlex.split(parts[0]) != ['rm', '-f', 'vmlinux.a']:
        raise SpecificationError('unsupported vmlinux archive construction')
    args = shlex.split(parts[1])
    if args[:3] != ['ar', 'cDPrST', 'vmlinux.a'] or not args[3:]:
        raise SpecificationError('unsupported Kbuild archive input list')
    if args[3] != './built-in.a' or any(not re.fullmatch(r'[A-Za-z0-9_./-]+\.a', a) or
                                      Path(a).is_absolute() or '..' in Path(a).parts for a in args[3:]):
        raise SpecificationError('ambiguous Kbuild archive input path')
    return args[3:]


def objtool_options(command_file):
    text = command_file.read_text().splitlines()[0]
    parts = text.split(';')
    if len(parts) != 2:
        raise SpecificationError('kernel helper processing requires one recorded per-object objtool pass')
    args = shlex.split(parts[1])
    if len(args) < 2 or args[0] != './tools/objtool/objtool' or not args[-1].endswith('.o'):
        raise SpecificationError('unsupported Kbuild object postprocessor')
    if any(not re.fullmatch(r'--[a-z_-]+(?:=[a-z_,-]+)?', a) for a in args[1:-1]):
        raise SpecificationError('ambiguous objtool flags')
    return args[1:-1]


def archive_members(build):
    # GNU ar prepends the archive directory when it is passed an absolute
    # filename. Use a relative name and resolve members against the build.
    names = run(['ar', 't', 'vmlinux.a'], cwd=build).stdout.decode().splitlines()
    result = []
    for name in names:
        path = (build / name).resolve()
        if not path.is_relative_to(build) or not path.is_file() or (build / name).is_symlink():
            raise SpecificationError('thin kernel archive member escapes the staged build')
        result.append(path.relative_to(build).as_posix())
    return result


def select_runtime_objects(task, policies, manifest, root, sources, source_tree):
    selected = [Path(p).resolve() for p in sources]
    if not selected or len(set(selected)) != len(selected) or not set(selected) <= set(task.sources):
        raise SpecificationError('select distinct verified kernel translation units')
    if not {p.translation_unit for p in policies} <= set(selected):
        raise SpecificationError('selection omits a policy translation unit')
    if any(not p.is_relative_to(source_tree) or p.suffix != '.c' for p in selected):
        raise SpecificationError('selected kernel sources must belong to the supplied source tree')
    rows = manifest['objects']
    if [Path(r['source']) for r in rows[:len(task.sources)]] != list(task.sources):
        raise SpecificationError('ambiguous runtime translation-unit mapping')
    helpers = rows[len(task.sources):]
    if [Path(r['source']).name for r in helpers] != ['vm.c', 'bridge.c', 'failure.c']:
        raise SpecificationError('unexpected runtime helper mapping')
    selftest = manifest['native_selftest']
    if selftest['status'] != 'PENDING_KERNEL_GUEST' or selftest['symbol'] != 'vulgate_runtime_selftest':
        raise SpecificationError('kernel runtime must include its callable self-test')
    mapping = {Path(r['source']): asset_path(root, r['object']) for r in rows[:len(task.sources)]}
    extras = [asset_path(root, r['object']) for r in helpers] + [asset_path(root, selftest['object'])]
    names = [p.relative_to(root).as_posix() for p in [*[mapping[p] for p in selected], *extras]]
    if len(set(names)) != len(names) or any(n not in manifest['assets'] for n in names):
        raise SpecificationError('missing or duplicated runtime object asset')
    return selected, mapping, extras


def run(command, *, cwd=None, timeout=180, log=None):
    if log is not None:
        result = subprocess.run([str(a) for a in command], cwd=cwd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    else:
        result = subprocess.run([str(a) for a in command], cwd=cwd, capture_output=True, timeout=timeout)
    if result.returncode:
        details = '' if log is not None else result.stderr.decode(errors='replace')[-2000:]
        raise SpecificationError(f'kernel binding command failed ({result.returncode}): {command[0]} {details}')
    return result


def boot_glue(runtime_pin, has_probe):
    return ('#include <linux/init.h>\n#include <linux/printk.h>\n'
            'extern int vulgate_runtime_selftest(void);\n' +
            ('extern int vulgate_kernel_policy_probe(void);\n' if has_probe else '') +
            'static int __init vulgate_kernel_boot_check(void) {\n'
            ' int result = vulgate_runtime_selftest();\n'
            ' pr_info("VULGATE_KERNEL_VM_SELFTEST:%s\\n", result ? "FAIL" : "PASS");\n' +
            (' if (!result) result = vulgate_kernel_policy_probe();\n'
             ' pr_info("VULGATE_KERNEL_POLICY_PROBE:%s\\n", result ? "FAIL" : "PASS");\n' if has_probe else '') +
            f' pr_info("VULGATE_KERNEL_RUNTIME:{runtime_pin}\\n");\n'
            ' return result;\n}\nlate_initcall(vulgate_kernel_boot_check);\n')


def build_kernel(task, toolchain, policies, runtime_path, runtime_pin, sources,
                 source_tree, baseline, output, *, probe=None, jobs=2, timeout=1800):
    output = Path(output).resolve()
    if os.name != 'posix' or toolchain.wsl_distribution:
        raise SpecificationError('run kernel binding on the native Linux build host')
    source_tree, baseline = Path(source_tree).resolve(), Path(baseline).resolve()
    runtime_path = Path(runtime_path).resolve()
    if any(output.is_relative_to(p) or p.is_relative_to(output)
           for p in (source_tree, baseline, runtime_path.parent)):
        raise SpecificationError('kernel staging must be disjoint from source, baseline and runtime bundle')
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'kernel_status': 'UNKNOWN', 'deployment_ready': False, 'reasons': []}
    try:
        implementation = {str(p): checksum(p) for p in (SOURCE, SOURCE.with_name('kernel_cc.py'))}
        runtime = pinned_json(runtime_path, runtime_pin, 'vulgate-runtime-archive')
        if runtime.get('runtime_environment') != 'linux-kernel':
            raise SpecificationError('kernel image binding requires a Linux kernel runtime')
        fresh = check_runtime(task, toolchain, policies, runtime_path, runtime_pin, output / 'runtime-check')
        if fresh['runtime_status'] != 'CURRENT_FOR_GUEST_VALIDATION':
            raise SpecificationError('runtime is not current: ' + '; '.join(fresh['reasons']))
        config = configuration(baseline / '.config')
        selected, mapping, extras = select_runtime_objects(task, policies, runtime, runtime_path.parent, sources, source_tree)
        snapshots = {Path(r['source']): r for r in runtime['dependencies']['preprocessed']}
        compiler_set = {snapshots[p]['build']['compiler']['executable'] for p in selected}
        if len(compiler_set) != 1 or any(Path(snapshots[p]['build']['directory']) != baseline for p in selected):
            raise SpecificationError('selected kernel units require one compiler and the supplied baseline build')
        compiler = compiler_set.pop()
        compiler_argv0 = snapshots[selected[0]]['build']['provenance']['arguments'][0]
        if Path(shutil.which(compiler_argv0)).resolve() != Path(compiler):
            raise SpecificationError('captured compiler invocation no longer resolves to the verified compiler')
        original_archives = archive_inputs(baseline / '.vmlinux.a.cmd')
        baseline_pins = {str(baseline / name): checksum(baseline / name) for name in
                         ('.config', 'vmlinux', 'arch/x86/boot/bzImage')}
        inputs = output / 'inputs'
        inputs.mkdir()
        for path in [*[mapping[p] for p in selected], *extras]:
            target = inputs / path.name
            if target.exists():
                raise SpecificationError('runtime objects have colliding basenames')
            shutil.copyfile(path, target)
            if checksum(target) != checksum(path):
                raise SpecificationError('runtime object copy differs from its source')
        frozen_mapping = {p: inputs / mapping[p].name for p in selected}
        extras = [inputs / p.name for p in extras]
        build = output / 'build'
        # A new directory and reflink/copy preserve baseline contents and avoid
        # hard links. Existing Kbuild depfiles remain available for inspection.
        run(['cp', '-a', '--reflink=auto', str(baseline), str(build)], timeout=300)
        events = output / 'events'
        events.mkdir()
        recipe = snapshots[selected[0]]['build']
        glue = inputs / 'boot-check.c'
        glue.write_text(boot_glue(runtime_pin, probe is not None))
        generated = [glue]
        if probe is not None:
            probe_copy = inputs / 'policy-probe.c'
            shutil.copyfile(Path(probe).resolve(), probe_copy)
            generated.append(probe_copy)
        compile_commands = []
        for path in generated:
            obj = path.with_suffix('.o')
            command = [compiler, *recipe['preprocess_flags'], '-c', str(path), '-o', str(obj)]
            run(command, cwd=baseline)
            compile_commands.append(command)
            extras.append(obj)
        # Keep each helper as an independent object. Kbuild's ordinary objtool
        # mode expects one compilation unit; premature ld -r merging changes
        # that mode and its cross-function reachability analysis.
        helper_dir = build / 'vulgate'
        helper_dir.mkdir(exist_ok=False)
        anchor = selected[0].relative_to(source_tree).with_suffix('.o')
        postprocess_flags = objtool_options(baseline / anchor.parent / ('.' + anchor.name + '.cmd'))
        processed_helpers = []
        postprocessing = []
        for path in extras:
            target = helper_dir / path.name
            shutil.copyfile(path, target)
            before = checksum(target)
            post_command = [str(build / 'tools/objtool/objtool'), *postprocess_flags, str(target)]
            processed = run(post_command, cwd=build)
            if processed.stderr.strip() or processed.stdout.strip():
                raise SpecificationError('objtool helper diagnostics: ' +
                                         (processed.stdout + processed.stderr).decode(errors='replace')[-2000:])
            postprocessing.append({'command': post_command, 'input_sha256': before,
                                   'output_sha256': checksum(target), 'source_object': str(path)})
            processed_helpers.append(target.relative_to(build).as_posix())
        ld = str(Path(shutil.which('ld')).resolve())
        wrapper_config = {'repository': str(REPOSITORY), 'compiler': compiler,
                          'compiler_argv0': compiler_argv0,
                          'goto_cc': toolchain.executable('goto-cc'), 'ld': ld,
                          'build': str(build), 'events': str(events), 'replacements': {}}
        for p in selected:
            objects = [frozen_mapping[p]]
            wrapper_config['replacements'][str(p)] = {
                'snapshot': snapshots[p], 'inputs': {str(o): checksum(o) for o in objects}}
        config_path = output / 'compiler-config.json'
        save(config_path, wrapper_config)
        interposer = output / 'kernel-cc.py'
        shutil.copyfile(SOURCE.with_name('kernel_cc.py'), interposer)
        wrapper = output / 'cc'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join([sys.executable, str(interposer), str(config_path)]) + ' "$@"\n')
        wrapper.chmod(0o755)
        immutable = {str(p): checksum(p) for p in [config_path, interposer, wrapper, *inputs.iterdir()]}
        command = ['make', '-C', str(source_tree), 'O=' + str(build), 'CC=' + str(wrapper),
                   'ARCH=x86_64', 'KBUILD_VMLINUX_OBJS=' + ' '.join([*original_archives, *processed_helpers]),
                   '-j' + str(jobs), 'V=1', 'bzImage']
        print('Staged Kbuild starting: ' + str(build), flush=True)
        with (output / 'kbuild.log').open('wb') as log:
            run(command, timeout=timeout, log=log)
        print('Staged Kbuild finished; checking replacement and image provenance', flush=True)
        if any(checksum(p) != h for p, h in {**implementation, **immutable}.items()):
            raise SpecificationError('binding implementation or frozen inputs changed during Kbuild')
        build_log = (output / 'kbuild.log').read_text(errors='replace')
        if re.search(r'(?:error|warning): objtool:', build_log):
            raise SpecificationError('Kbuild emitted objtool diagnostics; inspect kbuild.log')
        members = archive_members(build)
        if any(members.count(name) != 1 for name in processed_helpers):
            raise SpecificationError('vmlinux archive does not contain each helper exactly once')
        event_rows = [json.loads(p.read_text()) for p in sorted(events.glob('*.json'))]
        if len(event_rows) != len(selected) or {r['source'] for r in event_rows} != set(map(str, selected)):
            raise SpecificationError('Kbuild did not compile every selected replacement')
        for row in event_rows:
            obj = Path(row['object'])
            if members.count(obj.relative_to(build).as_posix()) != 1:
                raise SpecificationError('selected object is not included once in the final kernel archive')
            cmd_path = obj.with_name('.' + obj.name + '.cmd')
            text = cmd_path.read_text()
            if str(wrapper) not in text:
                raise SpecificationError('Kbuild command no longer records the interposer')
            # The current backend supports ordinary per-object objtool. Delayed
            # whole-vmlinux objtool needs a separate provenance implementation.
            if config.get('CONFIG_OBJTOOL') == 'y' and './tools/objtool/objtool ' not in text.splitlines()[0]:
                raise SpecificationError('selected object has no recorded Kbuild objtool pass')
            row['after_kbuild_postprocessing_sha256'] = checksum(obj)
            row['kbuild_command_file'] = str(cmd_path)
        system_map = (build / 'System.map').read_text()
        required_symbols = ['vulgate_runtime_selftest', 'vulgate_kernel_boot_check',
                            *['vulgate_runtime_' + p.name for p in policies]]
        if probe is not None:
            required_symbols.append('vulgate_kernel_policy_probe')
        if any(not re.search(r'\b' + re.escape(s) + r'$', system_map, re.M) for s in required_symbols):
            raise SpecificationError('final kernel is missing a required runtime symbol')
        if any(checksum(p) != h for p, h in baseline_pins.items()):
            raise SpecificationError('baseline build changed during staging')
        fresh = check_runtime(task, toolchain, policies, runtime_path, runtime_pin, output / 'final-runtime-check')
        if fresh['runtime_status'] != 'CURRENT_FOR_GUEST_VALIDATION':
            raise SpecificationError('runtime context changed during Kbuild')
        if checksum(build / '.config') != baseline_pins[str(baseline / '.config')]:
            raise SpecificationError('Kbuild changed the selected kernel configuration')
        assets = {}
        for path in sorted(output.rglob('*')):
            if path.is_file() and not path.is_symlink() and (not path.is_relative_to(build) or
                    path.suffix in ('.o', '.a', '.cmd') or path.name in
                    ('vmlinux', 'bzImage', 'System.map', '.config', 'vmlinux.lds', 'objtool', 'fixdep', 'modpost')):
                assets[path.relative_to(output).as_posix()] = checksum(path)
        tools = {}
        for executable in [compiler, ld, shutil.which('ar'), shutil.which('make'),
                           run([compiler, '-print-prog-name=cc1']).stdout.decode().strip(), shutil.which('as')]:
            path = Path(executable).resolve()
            tools[str(path)] = checksum(path)
        manifest = {'schema': 1, 'kind': 'vulgate-kernel-image', 'runtime_manifest': str(runtime_path),
                    'runtime_sha256': runtime_pin, 'source_tree': str(source_tree), 'baseline': baseline_pins,
                    'command': command, 'compile_boot_checks': compile_commands, 'replacements': event_rows,
                    'helper_postprocessing': postprocessing, 'original_archive_inputs': original_archives,
                    'archive_members': members,
                    'selected_sources': list(map(str, selected)), 'tools': tools, 'assets': assets,
                    'image': 'build/arch/x86/boot/bzImage', 'symbols': required_symbols,
                    'probe_included': probe is not None, 'guest_status': 'PENDING',
                    'implementation': implementation,
                    'proof_scope': runtime['input_task'],
                    'trust': 'Native compiler, linker and Kbuild; supplied-root proof does not cover all kernel callers.'}
        save(output / 'manifest.json', manifest)
        report.update(kernel_status='LINKED_FOR_GUEST_VALIDATION', manifest=str(output / 'manifest.json'),
                      manifest_sha256=checksum(output / 'manifest.json'), image=str(build / 'arch/x86/boot/bzImage'))
    except (SpecificationError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        report['reasons'].append(str(exc))
    save(output / 'report.json', report)
    return report


def check_kernel(manifest_path, expected_pin):
    path = Path(manifest_path).resolve()
    manifest = pinned_json(path, expected_pin, 'vulgate-kernel-image')
    check_assets(path.parent, manifest['assets'])
    for group in ('tools', 'implementation', 'baseline'):
        for name, pin in manifest[group].items():
            if checksum(name) != pin:
                raise SpecificationError('kernel binding dependency changed: ' + name)
    if checksum(manifest['runtime_manifest']) != manifest['runtime_sha256']:
        raise SpecificationError('runtime manifest changed')
    runtime = json.loads(Path(manifest['runtime_manifest']).read_text())
    check_assets(Path(manifest['runtime_manifest']).parent, runtime['assets'])
    return {'kernel_status': 'CURRENT_LINKED_BYTES', 'manifest_sha256': expected_pin,
            'image': str(asset_path(path.parent, manifest['image'])), 'deployment_ready': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    build = sub.add_parser('build')
    for name in ('task', 'policies', 'toolchain', 'runtime', 'source-tree', 'baseline', 'output'):
        build.add_argument('--' + name, type=Path, required=True)
    build.add_argument('--runtime-sha256', required=True)
    build.add_argument('--source', type=Path, action='append', required=True)
    build.add_argument('--probe', type=Path)
    build.add_argument('--jobs', type=int, default=2)
    build.add_argument('--timeout', type=int, default=1800)
    check = sub.add_parser('check')
    check.add_argument('--manifest', type=Path, required=True)
    check.add_argument('--sha256', required=True)
    args = parser.parse_args()
    if args.mode == 'check':
        report = check_kernel(args.manifest, args.sha256)
    else:
        report = build_kernel(Task.load(args.task), Toolchain.load(args.toolchain), Policy.load_many(args.policies),
            args.runtime, args.runtime_sha256, args.source, args.source_tree, args.baseline, args.output,
            probe=args.probe, jobs=args.jobs, timeout=args.timeout)
    print(json.dumps(report, indent=2))
    return 0 if report['kernel_status'] in ('CURRENT_LINKED_BYTES', 'LINKED_FOR_GUEST_VALIDATION') else 2


if __name__ == '__main__':
    raise SystemExit(main())
