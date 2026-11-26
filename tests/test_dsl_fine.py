import ctypes
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.dsl import parser, vm  # noqa: E402
from runtime.dsl import vm_run  # noqa: E402
from runtime.frida.build import build  # noqa: E402


PASS, BLOCK = 0, 1
FINE_PATCHES = ROOT / 'runtime' / 'dsl' / 'patches_fine'


@pytest.fixture(scope='module')
def native_bridge(tmp_path_factory):
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        pytest.skip('fine patch fixtures use 64-bit pointers')
    compiler = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc')
    if not compiler:
        pytest.skip('native Shadow VM requires a C compiler')

    directory = tmp_path_factory.mktemp('fine-guard-vm')
    if sys.platform == 'win32':
        library = directory / 'vulgate_frida.dll'
        # MinGW ignores the bridge's MSVC TLS attribute. This fixture runs one
        # invocation at a time and does not exercise read tracing or replay.
        subprocess.run([
            compiler, '-std=c11', '-shared', '-Wno-attributes', '-Iruntime',
            'runtime/frida/bridge.c', 'runtime/frida/state.c', 'runtime/vm.c',
            '-o', str(library),
        ], cwd=ROOT, check=True)
    else:
        library = Path(build(directory, cc=compiler)['bridge'])
    return library


@pytest.fixture(scope='module')
def run_guard(native_bridge):
    bridge = ctypes.CDLL(str(native_bridge))
    bridge.vg_program_create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    bridge.vg_program_create.restype = ctypes.c_void_p
    bridge.vg_program_destroy.argtypes = (ctypes.c_void_p,)
    bridge.vg_program_destroy.restype = None
    uint64_pointer = ctypes.POINTER(ctypes.c_uint64)
    bridge.vg_run.argtypes = (ctypes.c_void_p, uint64_pointer, uint64_pointer,
                             ctypes.c_uint, uint64_pointer)
    bridge.vg_run.restype = ctypes.c_int

    def run(case: str, *arguments: int, global_addresses=None, mount_index: int = 0) -> int:
        patch = parser.load(FINE_PATCHES / f'CVE-2026-{case}.vg')
        mount = vm.compile_patch(patch, global_addresses).mounts[mount_index]
        assert len(arguments) == len(mount.args)
        handle = bridge.vg_program_create(mount.code, len(mount.code))
        assert handle
        try:
            args = (ctypes.c_uint64 * 6)(*arguments)
            observations = (ctypes.c_uint64 * 16)()
            stats = (ctypes.c_uint64 * 3)()
            return bridge.vg_run(handle, args, observations, 4096, stats)
        finally:
            bridge.vg_program_destroy(handle)

    return run


@pytest.mark.parametrize(('variable', 'decision'), [
    (b'', PASS),
    (b'LA-', PASS),
    (b'HTTP:Accept', PASS),
    (b'LA-U:REQUEST_URI', PASS),
    (b'LA-U:HTTP:', PASS),
    (b'LA-U:HTTP:Host', PASS),
    (b'la-f:hTtP:hOsT', PASS),
    (b'LA-F:HTTP_HOST', PASS),
    (b'LA-U:HTTP:Accept', BLOCK),
    (b'la-f:hTtP:Accept', BLOCK),
    (b'LA-U:HTTP:Host-Name', BLOCK),
    (b'LA-U:HTTP_USER_AGENT', BLOCK),
])
def test_rewrite_preserves_unrelated_lookups(run_guard, variable, decision):
    name = ctypes.create_string_buffer(variable)
    assert run_guard('56154', ctypes.addressof(name), 0) == decision


@pytest.mark.parametrize(('extended', 'length', 'text', 'decision'), [
    (0, 0, b'', BLOCK),
    (0, 0, b'old contents', BLOCK),
    (0, 0xffffffffffffffff, b'', BLOCK),
    (0, 0xffffffffffffffff, b'text', PASS),
    (0, 4, b'text', PASS),
    (1, 0, b'', PASS),
    (1, 4, b'text', PASS),
])
def test_proxy_html_preserves_buffered_content(run_guard, extended, length, text, decision):
    buffer = ctypes.create_string_buffer(text)
    config = ctypes.create_string_buffer(60)
    ctypes.c_uint32.from_buffer(config, 56).value = extended
    context = ctypes.create_string_buffer(56)
    ctypes.c_void_p.from_buffer(context, 8).value = ctypes.addressof(config)
    ctypes.c_void_p.from_buffer(context, 32).value = ctypes.addressof(buffer)
    ctypes.c_uint64.from_buffer(context, 48).value = length

    assert run_guard('56449', ctypes.addressof(context)) == decision


@pytest.mark.parametrize(('count', 'namespace_id', 'decision'), [
    (3, 0, PASS),
    (3, 2, PASS),
    (3, 3, BLOCK),
    (3, -1, BLOCK),
    (0, 0, BLOCK),
    (-1, 0, BLOCK),
    (32767, 32766, PASS),
    (32767, 32767, BLOCK),
])
def test_dav_namespace_lookup_checks_index(run_guard, count, namespace_id, decision):
    database = ctypes.create_string_buffer(56)
    ctypes.c_int16.from_buffer(database, 48).value = count
    # The hook receives a C int, whose upper register bits are not part of the ID.
    argument = ctypes.c_uint32(namespace_id).value | 0xa5a5a5a500000000

    assert run_guard('93546', ctypes.addressof(database), argument) == decision


@pytest.mark.parametrize(('core_index', 'alias_length', 'raw_length', 'decision'), [
    (0, 12, 11, BLOCK),
    (0, 12, 12, PASS),
    (0, 12, 13, PASS),
    (0, 0, 11, PASS),
    (0, 0x7fffffffffffffff, 11, PASS),
    (1, 12, 11, PASS),
    (0, 12, None, PASS),
])
def test_nginx_dav_checks_an_upper_bound_for_destination_length(
        run_guard, core_index, alias_length, raw_length, decision):
    module = ctypes.c_uint64(core_index)
    core_loc_conf = ctypes.create_string_buffer(104)
    ctypes.c_uint64.from_buffer(core_loc_conf, 96).value = alias_length
    loc_conf = ctypes.c_void_p(ctypes.addressof(core_loc_conf))
    destination = ctypes.create_string_buffer(32)
    request = ctypes.create_string_buffer(376)
    ctypes.c_void_p.from_buffer(request, 40).value = ctypes.addressof(loc_conf)
    if raw_length is not None:
        ctypes.c_uint64.from_buffer(destination, 24).value = raw_length
        ctypes.c_void_p.from_buffer(request, 368).value = ctypes.addressof(destination)

    globals_ = {'ngx_http_core_module': ctypes.addressof(module)}
    assert run_guard('27654', ctypes.addressof(request), global_addresses=globals_) == decision


@pytest.mark.parametrize(('activated', 'chained_callback', 'decision'), [
    (0, 0, PASS),
    (0, 1, PASS),
    (1, 0, BLOCK),
    (1, 1, PASS),
])
def test_php_preserves_startup_progress_and_chained_callbacks(
        run_guard, activated, chained_callback, decision):
    core = ctypes.create_string_buffer(489)
    core[488] = activated
    callback = ctypes.c_uint64(chained_callback)
    globals_ = {
        'core_globals': ctypes.addressof(core),
        'php_session_rfc1867_orig_callback': ctypes.addressof(callback),
    }

    assert run_guard('109619', 0, 0, 0, global_addresses=globals_) == decision


@pytest.mark.parametrize(('converter', 'decision'), [(0, BLOCK), (1, PASS)])
def test_xml2enc_only_rejects_a_missing_converter(run_guard, converter, decision):
    assert run_guard('63686', converter, 0, 0, 0, 0) == decision


@pytest.mark.parametrize(('saved', 'available', 'decision'), [
    (2, 1, PASS),
    (2, 6, PASS),
    (2, 7, BLOCK),
    (7, 1, PASS),
    (7, 2, BLOCK),
    (8, 1, BLOCK),
    (2, 0xffffffffffffffff, BLOCK),
])
def test_charset_bounds_partial_character_appends(run_guard, saved, available, decision):
    context = ctypes.create_string_buffer(40)
    ctypes.c_uint64.from_buffer(context, 32).value = saved
    bucket = ctypes.c_uint64(available)

    assert run_guard('56153', ctypes.addressof(context), 0,
                     ctypes.addressof(bucket), 0, 0) == decision


@pytest.mark.parametrize(('state', 'decision'), [
    ('empty', PASS),
    ('occupied', BLOCK),
    ('no_brigade', PASS),
    ('no_session', PASS),
])
def test_http2_checks_the_temporary_brigade_before_send(run_guard, state, decision):
    session = ctypes.create_string_buffer(424)
    brigade = ctypes.create_string_buffer(24)
    bucket = ctypes.create_string_buffer(24)
    if state in ('empty', 'occupied'):
        ctypes.c_void_p.from_buffer(session, 416).value = ctypes.addressof(brigade)
        first = (ctypes.addressof(brigade) + 8 if state == 'empty'
                 else ctypes.addressof(bucket))
        ctypes.c_void_p.from_buffer(brigade, 8).value = first
    session_argument = 0 if state == 'no_session' else ctypes.addressof(session)

    assert run_guard('57941', 0, 0, 0, 0, 0, session_argument) == decision


HTTP2_FIELD_LIMIT = 2097278


@pytest.mark.parametrize(('method', 'method_length', 'flags', 'raw', 'uri', 'args', 'decision'), [
    (1, HTTP2_FIELD_LIMIT, 16, 1, 0, 0, PASS),
    (1, HTTP2_FIELD_LIMIT + 1, 16, 1, 0, 0, BLOCK),
    (2, HTTP2_FIELD_LIMIT + 1, 16, 1, 0, 0, PASS),
    (8, HTTP2_FIELD_LIMIT + 1, 16, 1, 0, 0, PASS),
    (2, 0, 16, HTTP2_FIELD_LIMIT, 0, 0, PASS),
    (2, 0, 16, HTTP2_FIELD_LIMIT + 1, 0, 0, BLOCK),
    (2, 0, 16, 10, HTTP2_FIELD_LIMIT, 0, PASS),
    (2, 0, 0, 10, HTTP2_FIELD_LIMIT - 2, 1, PASS),
    (2, 0, 0, 10, HTTP2_FIELD_LIMIT - 2, 2, BLOCK),
])
def test_grpc_checks_the_selected_method_and_uri_lengths(
        run_guard, method, method_length, flags, raw, uri, args, decision):
    request = ctypes.create_string_buffer(1208)
    for offset, value in [(872, method), (904, uri), (920, args),
                          (952, raw), (968, method_length)]:
        ctypes.c_uint64.from_buffer(request, offset).value = value
    request[1207] = flags

    assert run_guard('42055', ctypes.addressof(request), mount_index=1) == decision


@pytest.mark.parametrize(('fields', 'decision'), [
    ({}, PASS),
    ({'upstream_method': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'upstream_method': 1, 'request_method': HTTP2_FIELD_LIMIT + 1}, PASS),
    ({'request_method': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'request_method': HTTP2_FIELD_LIMIT + 1, 'configured_method': 1}, PASS),
    ({'raw_uri': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'raw_uri': HTTP2_FIELD_LIMIT + 1, 'flags': 0}, PASS),
    ({'raw_uri': HTTP2_FIELD_LIMIT + 1, 'dynamic': 1}, PASS),
    ({'host': HTTP2_FIELD_LIMIT}, PASS),
    ({'host': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'host': HTTP2_FIELD_LIMIT + 1, 'host_overridden': 1}, PASS),
    ({'proxy_uri': HTTP2_FIELD_LIMIT + 1, 'flags': 8}, BLOCK),
    ({'proxy_uri': 1, 'uri': HTTP2_FIELD_LIMIT, 'flags': 8}, PASS),
    ({'proxy_uri': 1, 'uri': HTTP2_FIELD_LIMIT, 'flags': 0}, BLOCK),
    ({'proxy_uri': 1, 'args': HTTP2_FIELD_LIMIT, 'flags': 8}, BLOCK),
])
def test_proxy_v2_checks_visible_fields_without_guessing_dynamic_values(run_guard, fields, decision):
    request = ctypes.create_string_buffer(1208)
    upstream = ctypes.create_string_buffer(1008)
    config = ctypes.create_string_buffer(920)
    ctypes.c_void_p.from_buffer(request, 72).value = ctypes.addressof(upstream)
    ctypes.c_void_p.from_buffer(upstream, 352).value = ctypes.addressof(config)
    request[1207] = fields.get('flags', 16)
    for name, buffer, offset in [
        ('uri', request, 904), ('args', request, 920), ('raw_uri', request, 952),
        ('request_method', request, 968), ('upstream_method', upstream, 1000),
        ('host_overridden', config, 704), ('dynamic', config, 712),
        ('configured_method', config, 760), ('host', config, 880), ('proxy_uri', config, 912),
    ]:
        ctypes.c_uint64.from_buffer(buffer, offset).value = fields.get(name, 0)

    assert run_guard('42055', ctypes.addressof(request)) == decision


@pytest.mark.parametrize(('regex_count', 'saved_count', 'vector', 'flags', 'decision'), [
    (1, 2, 1, 8, BLOCK),
    (0, 2, 1, 8, PASS),
    (1, 0, 1, 8, PASS),
    (1, 2, 0, 8, PASS),
    (1, 2, 1, 16, PASS),
])
def test_regex_reallocation_guard_preserves_unrelated_calls(
        run_guard, regex_count, saved_count, vector, flags, decision):
    request = ctypes.create_string_buffer(1211)
    regex = ctypes.create_string_buffer(16)
    ctypes.c_uint64.from_buffer(regex, 8).value = regex_count
    ctypes.c_uint64.from_buffer(request, 1096).value = saved_count
    ctypes.c_void_p.from_buffer(request, 1104).value = vector
    request[1210] = flags

    assert run_guard('42533', ctypes.addressof(request), ctypes.addressof(regex), 0) == decision


REWRITE_REPAIR = FINE_PATCHES / 'CVE-2026-42945.vg'
REWRITE_LENGTH_REPAIR = FINE_PATCHES / 'CVE-2026-9256.vg'


@pytest.mark.parametrize(('source', 'replacement', 'error'), [
    ('args=[pointer]', 'args=[uint64]', 'declared pointer'),
    ('arg0, 64', 'arg1, 64', 'declared pointer'),
    ('0x08', '0', 'mask 1..255'),
    ('arg0, 64', 'arg0, 4096', 'offset must be'),
    ('0x08);', '0x08); clear_arg_u8(arg0, 8, 1);', 'exactly one'),
    ('24ffa74c6144d36f19d953cfa960ff2e7df0fdb2', 'aabb', 'hexadecimal build_id'),
    ('nature: repair_point', 'nature: read_point', 'repair_point only'),
    ('location: symbol=', 'location: module="other", symbol=', 'main executable'),
])
def test_repair_point_rejects_unsupported_operations(source, replacement, error):
    text = REWRITE_REPAIR.read_text(encoding='utf-8').replace(source, replacement)
    with pytest.raises(parser.DSLParseError, match=error):
        parser.parse(text)


def test_repair_point_requires_the_matching_build_id(tmp_path, monkeypatch):
    mount, = parser.load(REWRITE_REPAIR).mounts
    target = tmp_path / 'nginx'
    target.touch()
    monkeypatch.setattr(vm_run.dsl_resolve.frida_symbols, 'build_id', lambda _path: 'a' * 40)
    with pytest.raises(ValueError, match='expected Build ID'):
        vm_run._target_address(None, mount, target)

    monkeypatch.setattr(vm_run.dsl_resolve.frida_symbols, 'build_id', lambda _path: mount.build_id)
    assert vm_run._target_address(None, mount, target) == (0x9b4b0, 'nginx')


def test_repair_point_clears_only_the_expected_bit_and_runs_original(request, tmp_path):
    frida = pytest.importorskip('frida')
    native_bridge = request.getfixturevalue('native_bridge')
    compiler = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc')
    source = tmp_path / 'fixture.c'
    source.write_text('''
#ifdef _WIN32
__declspec(dllexport)
#endif
void rewrite_end(unsigned char *engine)
{
    if (engine) {
        engine[64] &= ~4;
        engine[0] += 1;
    }
}
''', encoding='utf-8')
    library = tmp_path / ('fixture' + native_bridge.suffix)
    mode = '-dynamiclib' if sys.platform == 'darwin' else '-shared'
    args = [compiler, '-std=c11', '-O0', mode, source.name, '-o', library.name]
    if sys.platform != 'win32':
        args.append('-fPIC')
    subprocess.run(args, cwd=tmp_path, check=True)
    original = ctypes.CDLL(str(library)).rewrite_end
    original.argtypes = (ctypes.c_void_p,)
    original.restype = None
    address = ctypes.cast(original, ctypes.c_void_p).value
    patch = parser.load(REWRITE_REPAIR)
    mount, = patch.mounts
    compiled = vm.compile_patch(patch)

    session = frida.attach(os.getpid())
    try:
        script = session.create_script(vm_run._script(
            patch, compiled, [(address, None)], native_bridge))
        script.load()
        script.exports_sync.install()
        for flags, expected, status in [(0xff, 0xf3, 'repaired'),
                                        (0xa7, 0xa3, 'repair-unneeded')]:
            engine = (ctypes.c_uint8 * 66)()
            engine[63], engine[64], engine[65] = 0x51, flags, 0x52
            original(engine)
            assert engine[0] == 1
            assert list(engine[63:66]) == [0x51, expected, 0x52]
            assert script.exports_sync.status()['run'][mount.id] == status
        original(None)
        status = script.exports_sync.status()
        assert status['run'][mount.id] == 'repair-skipped-null'
        assert status['hits'][mount.id] == 3
    finally:
        session.detach()


@pytest.mark.parametrize(('source', 'replacement', 'error'), [
    ('offset=0xdd73c', '', 'explicit address'),
    ('rsp, 0xb0', 'rax, 0xb0', 'supported x86-64 registers'),
    ('rbp, 64', 'rbp, 4096', 'offset must be'),
    ('requires_spawn: true', 'requires_spawn: yes', 'true or false'),
])
def test_repair_point_validates_instruction_metadata(source, replacement, error):
    text = REWRITE_LENGTH_REPAIR.read_text(encoding='utf-8').replace(source, replacement)
    with pytest.raises(parser.DSLParseError, match=error):
        parser.parse(text)


def test_rewrite_length_repair_requires_spawn(tmp_path):
    with pytest.raises(ValueError, match='requires --spawn'):
        vm_run.install(REWRITE_LENGTH_REPAIR, 123, None, tmp_path)


def test_rewrite_spawn_preserves_arguments_and_cleans_failed_install(tmp_path, monkeypatch):
    events = []
    device = SimpleNamespace(spawn=lambda argv: events.append(argv) or 123,
                             kill=lambda pid: events.append(pid))
    monkeypatch.setitem(sys.modules, 'frida', SimpleNamespace(get_local_device=lambda: device))
    monkeypatch.setattr(vm_run.dsl_resolve, 'resolve_patch', lambda *args, **kwargs: None)

    def reject_target(*_args):
        raise ValueError('Build ID mismatch')

    monkeypatch.setattr(vm_run, '_target_address', reject_target)
    executable = tmp_path / 'nginx'
    with pytest.raises(ValueError, match='Build ID mismatch'):
        vm_run.install(REWRITE_LENGTH_REPAIR, None, executable, tmp_path, spawn=True,
                       spawn_args=['-c', '/tmp/nginx.conf'])
    assert events == [[str(executable.resolve()), '-c', '/tmp/nginx.conf'], 123]


def test_9256_repairs_compiler_and_live_script_state(request, tmp_path):
    frida = pytest.importorskip('frida')
    if sys.platform not in ('linux', 'win32') or platform.machine().lower() not in ('x86_64', 'amd64'):
        pytest.skip('instruction fixture uses Linux or Windows x86-64 assembly')
    native_bridge = request.getfixturevalue('native_bridge')
    compiler = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc')
    source = ROOT / 'tests' / 'workloads' / 'dsl' / 'rewrite_repair_fixture.S'
    library = tmp_path / ('repair_fixture' + native_bridge.suffix)
    flags = ['-Wl,--export-all-symbols'] if sys.platform == 'win32' else ['-fPIC']
    subprocess.run([compiler, '-shared', *flags, str(source), '-o', str(library)], check=True)
    fixture = ctypes.CDLL(str(library))
    fixture.repair_config.argtypes = (ctypes.c_int,)
    fixture.repair_regex.argtypes = (ctypes.c_void_p, ctypes.c_int)
    fixture.repair_complex.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    sites = ('repair_config_site', 'repair_regex_site', 'repair_complex_site')
    targets = [(ctypes.cast(getattr(fixture, site), ctypes.c_void_p).value, None) for site in sites]
    patch = parser.load(REWRITE_LENGTH_REPAIR)
    compiled = vm.compile_patch(patch)

    # Control calls use only ordinary flags and never execute nginx code.
    assert fixture.repair_config(0) == 0xa9
    session = frida.attach(os.getpid())
    try:
        script = session.create_script(vm_run._script(patch, compiled, targets, native_bridge))
        script.load()
        script.exports_sync.install()
        assert fixture.repair_config(1) == -1
        assert fixture.repair_config(0) == 0xe9

        engine = (ctypes.c_uint8 * 66)()
        engine[63], engine[64], engine[65] = 0x51, 0xff, 0x52
        assert fixture.repair_regex(engine, 1) == -1
        assert engine[64] == 0xff
        assert fixture.repair_regex(engine, 0) == 0xf3
        assert list(engine[63:66]) == [0x51, 0xf3, 0x52]

        local = (ctypes.c_uint8 * 66)()
        engine[32:48] = bytes(range(16))
        local[63], local[65] = 0x51, 0x52
        for flags, expected in [(0x08, 0xab), (0x04, 0xa7)]:
            engine[64] = flags
            assert fixture.repair_complex(engine, local) == expected
            assert engine[64] == flags
            assert list(local[63:66]) == [0x51, expected, 0x52]
            assert bytes(local[32:48]) == bytes(range(16))

        status = script.exports_sync.status()
        assert [status['hits'][mount.id] for mount in patch.mounts] == [1, 1, 2]
    finally:
        session.detach()
