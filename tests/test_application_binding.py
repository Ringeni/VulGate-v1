import json
import os
from pathlib import Path
import shutil

import pytest

from tools.application_binding import (asset_path, build_application, check_application, inventory,
                                       pinned_json, selected_objects, trace_paths)
from tools.verification.runtime import export_runtime
from tools.verification.source import functions, instrument, sha256
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.toolchain import Toolchain


CASE = Path(__file__).parent / 'verification_cases/runtime_contract'


def test_preprocessed_macro_line_markers_preserve_instrumentation_offsets(tmp_path):
    source = (b'int before(void) { return 1; }\r\n'
              b'int operation(unsigned n) {\r\n if (n >\r\n'
              b'# 4 "some path/limits.h" 3 4\r\n (0x7fffffff * 2U + 1U)\r\n'
              b'# 8 "application.c"\r\n ) return -2; return 0; }\r\n')
    names = functions(source)
    assert [f.name for f in names] == ['before', 'operation']
    assert source[names[1].body_start - 1:names[1].body_start] == b'{'
    policy = Policy('p', tmp_path / 'a.c', 'operation', -1, {'const': True})
    emitted, _, _ = instrument(source, [policy], 'absent', False)
    assert source[:names[1].body_start] in emitted
    assert source[names[1].body_start:] in emitted
    assert b'# 4 "some path/limits.h" 3 4' in emitted


def test_line_marker_support_does_not_mask_malformed_code_or_check_pragmas(tmp_path):
    with pytest.raises(SpecificationError, match='syntax'):
        functions(b'int f(void) { return ( ; }')
    with pytest.raises(SpecificationError, match='disables'):
        instrument(b'#pragma CPROVER check disable "pointer-check"\nint f(void) { return 0; }', [], 'f', True)


@pytest.mark.parametrize('trace', ['', 'relative.o\n', '/tmp/a.o\nwarning: unknown\n', ' /tmp/a.o\n'])
def test_ambiguous_trace_is_rejected(trace):
    with pytest.raises(SpecificationError, match='trace'):
        trace_paths(trace)


@pytest.mark.parametrize('name', ['../outside', '/absolute', 'nested/../../outside', '..\\outside'])
def test_application_asset_cannot_escape_bundle(tmp_path, name):
    with pytest.raises(SpecificationError):
        asset_path(tmp_path, name)


def test_manifest_requires_external_pin(tmp_path):
    path = tmp_path / 'manifest.json'
    path.write_text('{"schema":1,"kind":"vulgate-application"}', encoding='utf-8')
    with pytest.raises(SpecificationError, match='caller-pinned'):
        pinned_json(path, '0' * 64, 'vulgate-application')
    assert pinned_json(path, sha256(path.read_bytes()), 'vulgate-application')['schema'] == 1


@pytest.mark.parametrize('selection,message', [([], 'nonempty'), (['native.c'], 'omits'),
    (['program.c', 'new-main.c'], 'not in'), (['program.c', 'program.c'], 'distinct')])
def test_selection_enforces_verified_source_set_and_all_policy_units(selection, message):
    task = Task.load(CASE / 'application-task.json')
    policies = Policy.load_many(CASE / 'policies.json')
    with pytest.raises(SpecificationError, match=message):
        selected_objects(task, policies, {}, CASE.resolve(), [CASE / n for n in selection])


@pytest.fixture(scope='module')
def application(tmp_path_factory):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for real GCC/CBMC application binding')
    toolchain = Toolchain.load(config)
    task, policies = Task.load(CASE / 'application-task.json'), Policy.load_many(CASE / 'policies.json')
    output = tmp_path_factory.mktemp('application')
    report_path = os.environ.get('VULGATE_APPLICATION_RUNTIME_REPORT')
    runtime = (json.loads(Path(report_path).read_text(encoding='utf-8')) if report_path else
               export_runtime(task, toolchain, policies, output / 'runtime'))
    assert runtime['runtime_status'] == 'BUILT_FOR_HARNESS', runtime
    report = build_application(task, toolchain, policies, Path(runtime['manifest']), runtime['manifest_sha256'],
                               [CASE / 'program.c', CASE / 'native.c'], output / 'linked', 'contract-application', '1.0')
    assert report['application_status'] == 'LINKED_WITH_HARNESS_EVIDENCE', report
    return task, policies, toolchain, output, runtime, report


def test_real_application_links_exact_objects_and_runs(application):
    task, policies, toolchain, output, runtime, report = application
    manifest = json.loads(Path(report['manifest']).read_text(encoding='utf-8'))
    assert not any(Path(row['source']).name == 'harness.c' for row in manifest['objects'])
    assert [Path(s).name for s in manifest['selected_sources']] == ['program.c', 'native.c']
    process = toolchain.run_external(toolchain.path(Path(report['executable'])), [], 30)
    assert process.returncode == 0 and not process.timed_out, process
    assert report['status'] == 'UNKNOWN' and report['deployment_ready'] is False
    assert manifest['scope']['all_main_executions_proved'] is False
    checked = check_application(task, toolchain, policies, report['manifest'], report['manifest_sha256'], output / 'current')
    assert checked['application_status'] == 'CURRENT_LINKED_BYTES', checked


def test_real_installed_file_uses_pin_without_build_executable(application):
    task, policies, toolchain, output, runtime, report = application
    binary = Path(report['executable'])
    installed = output / 'installed application'
    shutil.copyfile(binary, installed)
    saved = binary.read_bytes()
    try:
        binary.unlink()
        checked = check_application(task, toolchain, policies, report['manifest'], report['manifest_sha256'],
                                    output / 'installed-check', installed)
        assert checked['application_status'] == 'CURRENT_INSTALLED_BYTES', checked
        assert checked['version'] == '1.0' and checked['checked_file'] == str(installed)
    finally:
        binary.write_bytes(saved)


def test_real_changed_installed_bytes_are_rejected(application):
    task, policies, toolchain, output, runtime, report = application
    installed = output / 'changed-installed'
    installed.write_bytes(Path(report['executable']).read_bytes() + b'changed')
    checked = check_application(task, toolchain, policies, report['manifest'], report['manifest_sha256'],
                                output / 'changed-check', installed)
    assert checked['application_status'] == 'STALE_OR_INVALID', checked
    assert 'bytes differ' in checked['reasons'][0]


def test_real_changed_selected_object_is_rejected(application):
    task, policies, toolchain, output, runtime, report = application
    manifest_path = Path(runtime['manifest'])
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    obj = manifest_path.parent / manifest['objects'][0]['object']
    saved = obj.read_bytes()
    try:
        obj.write_bytes(saved + b'changed')
        checked = check_application(task, toolchain, policies, report['manifest'], report['manifest_sha256'], output / 'object-changed')
        assert checked['application_status'] == 'STALE_OR_INVALID', checked
        assert 'runtime evidence' in checked['reasons'][0]
    finally:
        obj.write_bytes(saved)


def test_real_wrong_pin_and_output_overlap_do_not_write(application):
    task, policies, toolchain, output, runtime, report = application
    with pytest.raises(SpecificationError, match='caller-pinned'):
        check_application(task, toolchain, policies, report['manifest'], '0' * 64, output / 'wrong-pin')
    unsafe = Path(runtime['manifest']).parent / 'must-not-create'
    with pytest.raises(SpecificationError, match='outside'):
        check_application(task, toolchain, policies, report['manifest'], report['manifest_sha256'], unsafe)
    assert not unsafe.exists()


def test_real_inventory_detects_changed_host_input_and_symlink_target(application):
    _, _, toolchain, output, _, _ = application
    a, b = output / 'input A', output / 'input B'
    a.write_bytes(b'first')
    b.write_bytes(b'second')
    link = output / 'input-link'
    names = [toolchain.path(link)]
    assert toolchain.run_external('ln', ['-s', a, link]).returncode == 0
    original = inventory(toolchain, names, output)
    a.write_bytes(b'changed')
    assert inventory(toolchain, names, output) != original
    assert toolchain.run_external('ln', ['-sf', b, link]).returncode == 0
    assert inventory(toolchain, names, output)[names[0]]['resolved'] == toolchain.path(b)


def test_real_thin_archive_requires_member_binding(application):
    _, _, toolchain, output, _, _ = application
    thin = output / 'thin.a'
    thin.write_bytes(b'!<thin>\n')
    with pytest.raises(SpecificationError, match='thin-archive'):
        inventory(toolchain, [toolchain.path(thin)], output)


def test_real_non_pie_application_mode(application):
    task, policies, toolchain, output, runtime, _ = application
    report = build_application(task, toolchain, policies, runtime['manifest'], runtime['manifest_sha256'],
                               [CASE / 'program.c', CASE / 'native.c'], output / 'linked-exec',
                               'contract-application', '1.0-exec', 'exec')
    assert report['application_status'] == 'LINKED_WITH_HARNESS_EVIDENCE', report
    manifest = json.loads(Path(report['manifest']).read_text(encoding='utf-8'))
    assert 'EXEC (Executable file)' in manifest['executable']['elf']['header']
    process = toolchain.run_external(toolchain.path(Path(report['executable'])), [], 30)
    assert process.returncode == 0 and not process.timed_out, process


def test_real_native_assertion_adapter_preserves_true_and_false(application):
    _, _, toolchain, output, runtime, _ = application
    manifest_path = Path(runtime['manifest'])
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    adapter = manifest_path.parent / manifest['objects'][-1]['object']
    driver, binary = output / 'assertion-driver.c', output / 'assertion-driver'
    driver.write_text('extern void __CPROVER_assert(_Bool, const char *);\n'
                      'int main(int argc, char **argv) {\n'
                      ' (void)argv; __CPROVER_assert(argc == 1, "native.check"); return 0; }\n', encoding='utf-8')
    compiler = manifest['dependencies']['preprocessed'][0]['build']['compiler']['executable']
    linked = toolchain.run_external(compiler, [driver, adapter, '-o', binary])
    assert linked.returncode == 0 and not linked.timed_out, linked.stderr
    passed = toolchain.run_external(toolchain.path(binary), [])
    assert passed.returncode == 0 and not passed.timed_out
    # Exercise ordinary assertion failure without leaving a core dump.
    rejected = toolchain.run_external('python3', ['-c',
        'import json,resource,subprocess,sys; resource.setrlimit(resource.RLIMIT_CORE,(0,0)); '
        'result=subprocess.run(sys.argv[1:],capture_output=True); '
        'print(json.dumps({"returncode":result.returncode}))', binary, 'fail'])
    # Inspect the signal on Linux itself; WSL translates a signaled process's
    # outer exit status differently across launch modes and Windows versions.
    assert rejected.returncode == 0 and not rejected.timed_out, rejected
    assert json.loads(rejected.stdout)['returncode'] == -6


def test_real_changed_input_during_final_link_is_rejected(application, monkeypatch):
    task, policies, toolchain, output, runtime, _ = application
    manifest_path = Path(runtime['manifest'])
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    obj = manifest_path.parent / manifest['objects'][0]['object']
    original = obj.read_bytes()
    invoke = toolchain.run_external
    links = 0

    def mutate_after_final(executable, args, *extra, **options):
        nonlocal links
        result = invoke(executable, args, *extra, **options)
        if '--trace' in args:
            links += 1
            if links == 2:
                obj.write_bytes(original + b'changed-during-link')
        return result

    try:
        with monkeypatch.context() as context:
            context.setattr(toolchain, 'run_external', mutate_after_final)
            report = build_application(task, toolchain, policies, runtime['manifest'], runtime['manifest_sha256'],
                                       [CASE / 'program.c', CASE / 'native.c'], output / 'raced-link',
                                       'contract-application', 'race-test')
        assert links == 2 and report['application_status'] == 'UNKNOWN', report
        assert 'changed during final link' in report['reasons'][0]
        assert 'manifest' not in report
    finally:
        obj.write_bytes(original)
