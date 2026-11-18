"""Build typed entry adapters backed by the existing policy compiler and VM.

C evaluates observations using the same expressions as verification. The VM
receives a small unsigned region number, never an untyped application pointer
or signed parameter. Each return action has a Boolean VM monitor.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import re
import struct
from uuid import uuid4

from tools.policy.dsl import validate_dsl
from tools.policy.lowering import compile_monitor
from tools.rulegen.ebpf_asm import assemble_text

from .backend import BackendError, CBMC, save_json
from .engine import analyze, dependency_manifest, digest
from .expression import compile_expression
from .source import instrument, sha256, table_selection
from .spec import FamilyPolicy, SpecificationError, TablePolicy, Task


REPOSITORY = Path(__file__).resolve().parents[2]


def runtime_dependencies():
    files = [REPOSITORY / 'runtime/vm.c', REPOSITORY / 'runtime/autoshield.h',
             REPOSITORY / 'tools/rulegen/__init__.py', REPOSITORY / 'tools/rulegen/ebpf_asm.py']
    files.extend((REPOSITORY / 'tools/policy').glob('*.py'))
    files.extend((REPOSITORY / 'tools/frontier').glob('*.py'))
    return {p.relative_to(REPOSITORY).as_posix(): sha256(p.read_bytes()) for p in files}


_IMPORTED_RUNTIME = runtime_dependencies()


def deterministic_tables(policies):
    result = []
    for policy in policies:
        if isinstance(policy, FamilyPolicy):
            raise SpecificationError('runtime export requires a concrete policy; select and verify a table from the family')
        result.append(policy if isinstance(policy, TablePolicy) else TablePolicy(
            policy.name, policy.translation_unit, policy.function, (policy.guard,), policy.return_actions, (0, 1)))
    if not result:
        raise SpecificationError('runtime export requires at least one policy')
    return result


def configured_task(task):
    # Native artifacts always get explicit native/GOTO ABI qualification.
    if task.units or task.compilation_database is not None:
        return task
    return replace(task, units=tuple({'source': str(source), 'flags': []} for source in task.sources))


def qualifies(report):
    protected = report.get('protected', {})
    if report.get('conditional_on_environment') or protected.get('conditional_on_environment'):
        return False
    return (all(protected.get(key) == 'PROVED_FOR_HARNESS'
                for key in ('target', 'contracts_and_runtime_checks', 'initialization'))
            and protected.get('completeness') == 'COMPLETE_FOR_HARNESS'
            and report.get('pass_preservation', {}).get('status') == 'PROVED_FOR_HARNESS'
            and report.get('nonvacuity', {}).get('status') == 'ESTABLISHED_FOR_HARNESS')


def compile_monitors(policy):
    monitors = []
    for action in range(1, len(policy.return_actions) + 1):
        def branch(start, end, depth):
            prefix = '    ' * depth
            bits = [choice == action for choice in policy.decisions[start:end]]
            if len(set(bits)) == 1:
                return [prefix + f'ctx.set(status="{"unsafe" if bits[0] else "safe"}")']
            middle = (start + end) // 2
            return [prefix + f'if region < {middle}:', *branch(start, middle, depth + 1),
                    prefix + 'else:', *branch(middle, end, depth + 1)]
        lines = [f'@monitor("{policy.function}", phase="enter")',
                 'def monitor(ctx, region):', *branch(0, len(policy.decisions), 1)]
        dsl = '\n'.join(lines) + '\n'
        checked = validate_dsl(dsl, policy.function)
        if not checked.accepted:
            raise SpecificationError('generated observation monitor failed DSL validation: ' + str(checked.errors))
        assembly, model, limitations = compile_monitor(checked.functions)
        if limitations or model == 'legacy_unknown_stub':
            raise SpecificationError('observation monitor lowering is incomplete: ' + str(limitations))
        bytecode = assemble_text(assembly)
        monitors.append({'action': action, 'dsl': dsl, 'assembly': assembly,
                         'bytecode': bytecode, 'instructions': list(struct.iter_unpack('<BBhi', bytecode))})
    return monitors


def bridge_source(tables, monitors, *, kernel=False):
    lines = ['#include "autoshield.h"', '#include <linux/limits.h>' if kernel else '#include <limits.h>']
    if kernel:
        lines += ['#ifndef __KERNEL__', '#error kernel runtime requires the captured __KERNEL__ build environment', '#endif']
    for policy in tables:
        for monitor in monitors[policy.name]:
            name = f'vulgate_vm_{policy.name}_{monitor["action"]}'
            values = ',\n'.join('    {%d, %d, %d, %d}' % values for values in monitor['instructions'])
            lines += [f'static const ebpf_insn {name}_insns[] = {{\n{values}\n}};',
                      f'static const shadow_program {name} = '
                      f'{{{name}_insns, sizeof({name}_insns)/sizeof(ebpf_insn), 0, 0}};']
        lines += [f'unsigned vulgate_runtime_{policy.name}(unsigned region) {{',
                  f'    if (region >= {len(policy.decisions)}u) return UINT_MAX;',
                  '    shadow_ctx ctx = {0};', '    ctx.args[0] = region;']
        for monitor in monitors[policy.name]:
            name = f'vulgate_vm_{policy.name}_{monitor["action"]}'
            lines += ['    {',
                      f'        const shadow_policy config = {{{len(monitor["instructions"]) + 1}u, SHADOW_UNKNOWN_BLOCK, 0}};',
                      f'        shadow_decision decision = run_ebpf_vm(&ctx, &{name}, &config, 0);',
                      f'        if (decision == SHADOW_BLOCK) return {monitor["action"]}u;',
                      '        if (decision != SHADOW_PASS) return UINT_MAX;', '    }']
        lines += ['    return 0u;', '}']
    # This adapter only uses get_arg. Do not link signal-based memory probing.
    lines += ['int safe_read(void *dst, const void *src, size_t len) {',
              '    (void)dst; (void)src; (void)len; return -1;', '}']
    return '\n'.join(lines) + '\n'


def native_instrument(source, policies, entry):
    """Reuse verified expression emission; replace only the total table lookup."""
    if b'vulgate_runtime_' in source:
        raise SpecificationError('source uses the reserved runtime adapter namespace')
    tables = deterministic_tables(policies) if policies else []
    emitted, _, _ = instrument(source, tables, entry, False)
    declarations = []
    for policy in tables:
        name = f'vulgate_runtime_{policy.name}'
        region = f'__vulgate_region_{policy.name}'
        old = f'unsigned __vulgate_decision_{policy.name} = {table_selection(policy.decisions, region)};'
        new = f'unsigned __vulgate_decision_{policy.name} = {name}({region});'
        if emitted.count(old.encode()) != 1:
            raise SpecificationError('ambiguous runtime decision replacement')
        emitted = emitted.replace(old.encode(), new.encode())
        # Invalid VM decisions must never silently become PASS. The complete
        # runtime query proves this branch unreachable for generated programs.
        check = (f'\nif (__vulgate_decision_{policy.name} > {len(policy.return_actions)}u) '
                 '{ vulgate_runtime_failure(); }')
        emitted = emitted.replace(new.encode(), (new + check).encode())
        declarations.append(f'extern unsigned {name}(unsigned);')
    # Keep a statement when a marker was the body of an if. A void expression
    # preserves that control flow without triggering native -Wempty-body.
    emitted = re.sub(rb'__CPROVER_assert\(0, "__VG_REACH_[^"\n]+"\);', b'(void)0;', emitted)
    emitted = emitted.replace(b'__vulgate_blocked = 1; ', b'')
    declarations.append('extern void vulgate_runtime_failure(void);')
    return ('\n'.join(declarations) + '\n').encode() + emitted


def native_flags(build):
    # Classification happens while parsing the original argv, so an include
    # path or macro operand that resembles an option is never replayed as one.
    return list(build['native_flags'])


def pin_files(files):
    return {str(path): sha256(path.read_bytes()) for path in files}


def require_files(expected):
    if any(not Path(path).is_file() or sha256(Path(path).read_bytes()) != checksum for path, checksum in expected.items()):
        raise SpecificationError('runtime input or generated artifact changed during qualification')


def write_bound(path, data, pins):
    data = data.encode('utf-8') if isinstance(data, str) else data
    path.write_bytes(data)
    pins[str(path)] = sha256(data)


def export_runtime(task, toolchain, policies, output, *, runtime_environment='userspace'):
    if runtime_environment not in ('userspace', 'linux-kernel'):
        raise SpecificationError('unsupported runtime environment')
    kernel = runtime_environment == 'linux-kernel'
    task, policies = deepcopy((task, policies))
    output = Path(output).resolve()
    run = output / 'runs' / uuid4().hex
    run.mkdir(parents=True)
    save_json(output / 'status.json', {'status': 'STARTED', 'run': str(run)})
    report = {'schema': 1, 'status': 'UNKNOWN', 'runtime_status': 'UNKNOWN', 'deployment_ready': False,
              'runtime_environment': runtime_environment,
              'conditional_on_environment': bool(task.environment),
              'run': str(run), 'reasons': [], 'pending': ['application installation and executable link binding',
              'lifecycle/external-state scope beyond the supplied root', 'machine-code correctness beyond compiler trust']}

    def finish():
        save_json(run / 'report.json', report)
        save_json(output / 'report.json', report)
        save_json(output / 'status.json', {'status': 'COMPLETE', 'report_sha256': digest(report)})
        return report

    try:
        if task.environment:
            report['runtime_status'] = 'REFUSED'
            report['environment'] = [item.to_dict() for item in task.environment]
            report['reasons'].append('environment summaries require separate native correspondence qualification; no runtime artifacts exported')
            return finish()
        tables = deterministic_tables(policies)
        configured = configured_task(task)
        if runtime_dependencies() != _IMPORTED_RUNTIME:
            raise SpecificationError('runtime/compiler sources changed after import; restart export')
        checked = analyze(configured, toolchain, policies, run / 'verification')
        report['verification'] = str(run / 'verification/report.json')
        if not qualifies(checked):
            report['runtime_status'] = 'REFUSED'
            report['reasons'].append('supplied policy has incomplete or refuted harness obligations')
            return finish()
        expected = json.loads((run / 'verification/dependencies.json').read_text(encoding='utf-8'))
        compiler = CBMC(toolchain, configured, run / 'fresh')
        snapshots = compiler.preprocess()
        if digest(dependency_manifest(configured, toolchain.versions(), snapshots)) != digest(expected):
            raise SpecificationError('program/build/toolchain changed after policy verification')
        inputs = run / 'inputs'
        inputs.mkdir()
        generated_pins = {}
        for name in ('vm.c', 'autoshield.h'):
            data = (REPOSITORY / 'runtime' / name).read_bytes()
            if sha256(data) != _IMPORTED_RUNTIME['runtime/' + name]:
                raise SpecificationError('runtime source changed before snapshot')
            write_bound(inputs / name, data, generated_pins)
        monitors = {policy.name: compile_monitors(policy) for policy in tables}
        for name, items in monitors.items():
            for item in items:
                stem = inputs / f'{name}-{item["action"]}'
                write_bound(stem.with_suffix('.dsl'), item['dsl'], generated_pins)
                write_bound(stem.with_suffix('.asm'), item['assembly'], generated_pins)
                write_bound(stem.with_suffix('.bin'), item['bytecode'], generated_pins)
        bridge = inputs / 'bridge.c'
        write_bound(bridge, bridge_source(tables, monitors, kernel=kernel), generated_pins)
        failure = inputs / 'failure.c'
        # Native callers use the same Boolean assertion ABI as the emitted C.
        # The symbolic query keeps CBMC's intrinsic assertions (including their
        # labels); this native-only body terminates if an assertion is false.
        # It lives with the failure adapter, which the query replaces below.
        stop = '__builtin_trap()' if kernel else 'abort()'
        write_bound(failure, ('' if kernel else '#include <stdlib.h>\n') +
                    f'void vulgate_runtime_failure(void) {{ {stop}; }}\n'
                    'void __CPROVER_assert(_Bool condition, const char *description) {\n'
                    f'    (void)description; if (!condition) {stop};\n}}\n', generated_pins)
        test = inputs / 'selftest.c'
        lines = ['#include <linux/limits.h>' if kernel else '#include <limits.h>',
                 'int vulgate_runtime_selftest(void) {' if kernel else 'int main(void) {']
        for policy in tables:
            lines += [f'extern unsigned vulgate_runtime_{policy.name}(unsigned);']
            for region, choice in enumerate(policy.decisions):
                lines += [f'if (vulgate_runtime_{policy.name}({region}u) != {choice}u) return 1;']
            lines += [f'if (vulgate_runtime_{policy.name}(UINT_MAX) != UINT_MAX) return 2;']
        write_bound(test, '\n'.join([*lines, 'return 0;', '}']) + '\n', generated_pins)
        build = snapshots[0]['build']
        helper_flags = build['preprocess_flags'] if kernel else native_flags(build)
        helper_sources = (inputs / 'vm.c', bridge, failure)
        helpers = Task(inputs / 'task.json', helper_sources, configured.entry, configured.targets,
                       unwind=configured.unwind, timeout=configured.timeout,
                       units=tuple({'source': str(p), 'compiler': build['compiler']['executable'],
                                    'directory': build['directory'],
                                    'flags': helper_flags} for p in helper_sources))
        require_files(generated_pins)
        helper_backend = CBMC(toolchain, helpers, run / 'helper-preprocessed')
        helper_snapshots = helper_backend.preprocess()
        if any(s['build']['abi'] != build['abi'] for s in helper_snapshots):
            raise SpecificationError('runtime adapter ABI differs from the application ABI')
        all_snapshots = snapshots + helper_snapshots
        generated = run / 'generated'
        generated.mkdir()
        native = []
        for index, snapshot in enumerate(snapshots):
            data = snapshot['path'].read_bytes()
            if sha256(data) != snapshot['sha256']:
                raise SpecificationError('source snapshot changed before runtime generation')
            selected = [p for p in policies if p.translation_unit == snapshot['source']]
            path = generated / f'native-{index:03}.i'
            write_bound(path, native_instrument(data, selected, configured.entry), generated_pins)
            native.append(path)
        native += [s['path'] for s in helper_snapshots]
        # The query compiles exactly the native application/VM source bytes.
        # The failure adapter is strengthened to an assertion: proving it is
        # never called justifies the native abort on an impossible decision.
        failure_check = generated / 'failure-check.i'
        write_bound(failure_check, 'extern void __CPROVER_assert(_Bool, const char *);\n'
                    'void vulgate_runtime_failure(void) { __CPROVER_assert(0, "vulgate.runtime.valid_decision"); }\n', generated_pins)
        verification = [*native[:-1], failure_check]
        state = run / 'verification/protected/verification-state.c'
        frozen = {**pin_files([*native, *verification, state]), **generated_pins}
        require_files(frozen)
        # Verify actual caller continuations through the real VM, not a Python
        # interpreter or a replacement C decision function.
        max_insns = max(len(m['instructions']) for items in monitors.values() for m in items)
        runtime_task = replace(configured, unwind=max(configured.unwind, max_insns + 2, 16),
                               object_bits=max(configured.object_bits, 12))
        report['runtime_query_configuration'] = {'unwind': runtime_task.unwind, 'object_bits': runtime_task.object_bits}
        backend = CBMC(toolchain, runtime_task, run / 'runtime-verification')
        binary = backend.compile([*verification, state], units=all_snapshots)
        runtime_query = backend.check(binary)
        report['runtime_verification'] = runtime_query
        if runtime_query['status'] != 'PROVED_FOR_HARNESS':
            report['reasons'].append('the instrumented program with the actual VM did not discharge all harness obligations')
            return finish()
        # Compile the exact frozen native translation units with their own ABI
        # flags. The archive is linkable; it is not an installed application.
        objects = []
        for index, (path, snapshot) in enumerate(zip(native, all_snapshots)):
            obj = generated / f'unit-{index:03}.o'
            recipe = snapshot['build']
            require_files(frozen)
            compiler.require(recipe['compiler']['executable'], [*native_flags(recipe), '-c', path, '-o', obj],
                             cwd=Path(recipe['directory']), external=True)
            objects.append(obj)
        regions = sum(len(p.decisions) for p in tables)
        if kernel:
            native_test = generated / 'runtime-selftest.o'
            compiler.require(build['compiler']['executable'], [*helper_flags, '-c', test, '-o', native_test],
                             cwd=Path(build['directory']), external=True)
            selftest = {'status': 'PENDING_KERNEL_GUEST', 'regions': regions,
                        'symbol': 'vulgate_runtime_selftest', 'source': test.relative_to(run).as_posix(),
                        'object': native_test.relative_to(run).as_posix()}
        else:
            native_test = generated / 'runtime-selftest'
            compiler.require(build['compiler']['executable'], [*native_flags(build), test, *objects[len(snapshots):], '-o', native_test], external=True)
            executed = compiler.require(toolchain.path(native_test), [], external=True)
            selftest = {'status': 'PASSED_ALL_REGIONS', 'regions': regions, 'command': executed.to_dict()}
        archive = generated / 'libvulgate_verified.a'
        archiver = toolchain.native_compiler('ar', inputs)
        compiler.require(archiver['executable'], ['rcs', archive, *objects, *([native_test] if kernel else [])], external=True)
        require_files(frozen)
        if runtime_dependencies() != _IMPORTED_RUNTIME:
            raise SpecificationError('runtime/compiler dependencies changed during export')
        fresh = CBMC(toolchain, configured, run / 'final-freshness').preprocess()
        if digest(dependency_manifest(configured, toolchain.versions(), fresh)) != digest(expected):
            raise SpecificationError('program/build/toolchain changed during runtime export')
        assets = [p for p in run.rglob('*') if p.is_file()]
        manifest = {'schema': 1, 'kind': 'vulgate-runtime-archive',
                    'runtime_environment': runtime_environment,
                    'input_task': task.semantic_spec(), 'policies': [p.to_dict() for p in policies],
                    'dependencies': expected, 'runtime_dependencies': _IMPORTED_RUNTIME,
                    'archiver': archiver, 'archive': archive.relative_to(run).as_posix(),
                    'objects': [{'source': str(s['source']), 'object': p.relative_to(run).as_posix()}
                                for s, p in zip(all_snapshots, objects)],
                    'native_selftest': selftest,
                    'runtime_query': runtime_query['status'],
                    'assertion_adapter': {'symbolic': 'CBMC intrinsic with original labels',
                                          'native': 'return on true; trap on false' if kernel else 'return on true; abort on false',
                                          'scope': 'assertion conditions proved for the supplied root'},
                    'assets': {p.relative_to(run).as_posix(): sha256(p.read_bytes()) for p in assets}}
        manifest_path = run / 'manifest.json'
        save_json(manifest_path, manifest)
        report.update(runtime_status='BUILT_FOR_GUEST_VALIDATION' if kernel else 'BUILT_FOR_HARNESS', manifest=str(manifest_path),
                      manifest_sha256=sha256(manifest_path.read_bytes()), archive=str(archive),
                      native_selftest=manifest['native_selftest'])
        return finish()
    except (BackendError, SpecificationError, OSError, ValueError) as exc:
        report['reasons'].append(str(exc))
        return finish()


def check_runtime(task, toolchain, policies, manifest_path, expected_sha256, output):
    """Recheck a caller-pinned artifact and its current source/build context."""
    output = Path(output).resolve()
    if output.is_relative_to(Path(manifest_path).resolve().parent):
        raise SpecificationError('runtime checks must write outside the pinned bundle')
    output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 1, 'status': 'UNKNOWN', 'runtime_status': 'STALE_OR_INVALID',
              'deployment_ready': False, 'reasons': [], 'conditional_on_environment': bool(task.environment)}
    try:
        if task.environment:
            raise SpecificationError('environment summaries require separate native correspondence qualification')
        path = Path(manifest_path).resolve()
        raw = path.read_bytes()
        if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256) or sha256(raw) != expected_sha256:
            raise SpecificationError('runtime manifest does not match the caller-pinned SHA-256')
        manifest = json.loads(raw)
        if manifest.get('schema') != 1 or manifest.get('kind') != 'vulgate-runtime-archive':
            raise SpecificationError('unsupported runtime manifest')
        environment = manifest.get('runtime_environment')
        if environment not in ('userspace', 'linux-kernel'):
            raise SpecificationError('unsupported runtime environment in manifest')
        if digest(manifest['input_task']) != digest(task.semantic_spec()) or manifest['policies'] != [p.to_dict() for p in policies]:
            raise SpecificationError('task or policy differs from the runtime evidence')
        if manifest['runtime_dependencies'] != runtime_dependencies() or runtime_dependencies() != _IMPORTED_RUNTIME:
            raise SpecificationError('runtime/compiler source version differs from the evidence')
        pins = {}
        for name, checksum in manifest['assets'].items():
            asset = (path.parent / name).resolve()
            if not asset.is_relative_to(path.parent) or asset == path:
                raise SpecificationError('runtime asset escapes its bundle directory')
            pins[str(asset)] = checksum
        require_files(pins)
        configured = configured_task(task)
        snapshots = CBMC(toolchain, configured, output / 'current').preprocess()
        current = dependency_manifest(configured, toolchain.versions(), snapshots)
        if digest(current) != digest(manifest['dependencies']):
            raise SpecificationError('current program/build/toolchain differs from runtime evidence')
        if toolchain.native_compiler('ar', path.parent) != manifest['archiver']:
            raise SpecificationError('archiver identity differs from runtime evidence')
        require_files(pins)
        if path.read_bytes() != raw:
            raise SpecificationError('runtime manifest changed during checking')
        report.update(runtime_status='CURRENT_FOR_GUEST_VALIDATION' if environment == 'linux-kernel' else 'CURRENT_FOR_HARNESS',
                      runtime_environment=environment, manifest=str(path), manifest_sha256=expected_sha256,
                      archive=str(path.parent / manifest['archive']))
    except (BackendError, SpecificationError, OSError, ValueError, KeyError, TypeError) as exc:
        report['reasons'].append(str(exc))
    save_json(output / 'report.json', report)
    return report
