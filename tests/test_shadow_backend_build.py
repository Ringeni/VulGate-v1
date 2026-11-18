from contextlib import nullcontext
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from types import SimpleNamespace

import pytest

from tools import build_shadow_backend as backend
from tools.build_shadow_backend import (ORIGINAL_FILE_SHA256, PATCH, PATCH_SHA256, PATCHED_FILE_SHA256,
                                        SOURCE_SHA256, build, checksum, require_pin,
                                        JSON_PATCH, JSON_PATCH_SHA256, JSON_ORIGINAL_SHA256,
                                        JSON_PATCHED_SHA256,
                                        TYPED_EXPORT_PATCH, TYPED_EXPORT_PATCH_SHA256, TYPED_EXPORT_FILES,
                                        FRONTEND_PATCH, FRONTEND_PATCH_SHA256, FRONTEND_ORIGINAL_SHA256,
                                        FRONTEND_PATCHED_SHA256, GENERIC_PATCH, GENERIC_PATCH_SHA256,
                                        GENERIC_PATCHED_SHA256, DECAY_PATCH, DECAY_PATCH_SHA256, DECAY_PATCHED_SHA256,
                                        POINTER_DIFFERENCE_PATCH, POINTER_DIFFERENCE_PATCH_SHA256,
                                        POINTER_DIFFERENCE_FILES)


def test_bad_archive_is_rejected_before_creating_private_prefix(tmp_path):
    if os.name != 'posix':
        pytest.skip('native Linux builder')
    archive = tmp_path / 'invalid.tar.gz'
    archive.write_bytes(b'not the pinned source archive')
    prefix = tmp_path / 'backend'
    with pytest.raises(ValueError, match='pinned bytes'):
        build(prefix, archive, archive, tmp_path / 'unused-config.json')
    assert not prefix.exists()


@pytest.mark.parametrize('patch,pin,relative,before,after', [
    (PATCH, PATCH_SHA256, 'src/goto-symex/shadow_memory_util.cpp', ORIGINAL_FILE_SHA256, PATCHED_FILE_SHA256),
    (JSON_PATCH, JSON_PATCH_SHA256, 'src/util/json.cpp', JSON_ORIGINAL_SHA256, JSON_PATCHED_SHA256),
    (FRONTEND_PATCH, FRONTEND_PATCH_SHA256, 'src/ansi-c/c_typecheck_expr.cpp',
     FRONTEND_ORIGINAL_SHA256, FRONTEND_PATCHED_SHA256),
])
def test_source_patch_applies_exactly_to_official_release(tmp_path, patch, pin, relative, before, after):
    source = os.environ.get('VULGATE_CBMC_SOURCE_ARCHIVE')
    if not source or not shutil.which('patch'):
        pytest.skip('set VULGATE_CBMC_SOURCE_ARCHIVE to audit the pinned source patch')
    require_pin(source, SOURCE_SHA256)
    require_pin(patch, pin)
    with tarfile.open(source) as archive:
        content = archive.extractfile('cbmc-cbmc-6.11.0/' + relative).read()
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    assert checksum(path) == before
    subprocess.run(['patch', '--batch', '--forward', '-p1', '-i', str(patch.resolve())],
                   cwd=tmp_path, check=True, capture_output=True, timeout=30)
    assert checksum(path) == after


def test_frontend_patch_sequence_applies_to_pinned_release(tmp_path):
    source = os.environ.get('VULGATE_CBMC_SOURCE_ARCHIVE')
    if not source or not shutil.which('patch'):
        pytest.skip('set VULGATE_CBMC_SOURCE_ARCHIVE to audit the pinned source patch')
    require_pin(source, SOURCE_SHA256)
    relative = 'src/ansi-c/c_typecheck_expr.cpp'
    with tarfile.open(source) as archive:
        content = archive.extractfile('cbmc-cbmc-6.11.0/'+relative).read()
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    for patch, pin, expected in ((FRONTEND_PATCH, FRONTEND_PATCH_SHA256, FRONTEND_PATCHED_SHA256),
                                  (GENERIC_PATCH, GENERIC_PATCH_SHA256, GENERIC_PATCHED_SHA256),
                                  (DECAY_PATCH, DECAY_PATCH_SHA256, DECAY_PATCHED_SHA256)):
        require_pin(patch, pin)
        subprocess.run(['patch', '--batch', '--forward', '-p1', '-i', str(patch.resolve())],
                       cwd=tmp_path, check=True, capture_output=True, timeout=30)
        require_pin(target, expected)


def test_full_typed_export_patch_applies_exactly_to_official_release(tmp_path):
    source = os.environ.get('VULGATE_CBMC_SOURCE_ARCHIVE')
    if not source or not shutil.which('patch'):
        pytest.skip('set VULGATE_CBMC_SOURCE_ARCHIVE to audit the pinned source patch')
    require_pin(source, SOURCE_SHA256)
    require_pin(TYPED_EXPORT_PATCH, TYPED_EXPORT_PATCH_SHA256)
    with tarfile.open(source) as archive:
        for relative, before, _ in TYPED_EXPORT_FILES:
            path = tmp_path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile('cbmc-cbmc-6.11.0/' + relative).read())
            require_pin(path, before)
    subprocess.run(['patch', '--batch', '--forward', '-p1', '-i', str(TYPED_EXPORT_PATCH.resolve())],
                   cwd=tmp_path, check=True, capture_output=True, timeout=30)
    for relative, _, after in TYPED_EXPORT_FILES:
        require_pin(tmp_path / relative, after)


@pytest.mark.parametrize('with_shadow,c_frontend', [(False, False), (True, False), (True, True)])
def test_pointer_difference_patch_and_combinations_apply_to_pinned_release(tmp_path, with_shadow, c_frontend):
    source = os.environ.get('VULGATE_CBMC_SOURCE_ARCHIVE')
    if not source or not shutil.which('patch'):
        pytest.skip('set VULGATE_CBMC_SOURCE_ARCHIVE to audit the pinned source patch')
    require_pin(source, SOURCE_SHA256)
    originals = {relative: before for relative, before, _ in POINTER_DIFFERENCE_FILES if before is not None}
    if with_shadow:
        originals['src/goto-symex/shadow_memory_util.cpp'] = ORIGINAL_FILE_SHA256
    if c_frontend:
        originals['src/ansi-c/c_typecheck_expr.cpp'] = FRONTEND_ORIGINAL_SHA256
    with tarfile.open(source) as archive:
        for relative, before in originals.items():
            path = tmp_path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile('cbmc-cbmc-6.11.0/' + relative).read())
            require_pin(path, before)
    for relative, before, _ in POINTER_DIFFERENCE_FILES:
        if before is None:
            assert not (tmp_path / relative).exists()
    sequence = []
    if with_shadow:
        sequence.append((PATCH, PATCH_SHA256, 'src/goto-symex/shadow_memory_util.cpp', PATCHED_FILE_SHA256))
    if c_frontend:
        relative = 'src/ansi-c/c_typecheck_expr.cpp'
        sequence.extend((patch, pin, relative, after) for patch, pin, after in (
            (FRONTEND_PATCH, FRONTEND_PATCH_SHA256, FRONTEND_PATCHED_SHA256),
            (GENERIC_PATCH, GENERIC_PATCH_SHA256, GENERIC_PATCHED_SHA256),
            (DECAY_PATCH, DECAY_PATCH_SHA256, DECAY_PATCHED_SHA256)))
    for patch, pin, relative, after in sequence:
        require_pin(patch, pin)
        subprocess.run(['patch', '--batch', '--forward', '-p1', '-i', str(patch.resolve())],
                       cwd=tmp_path, check=True, capture_output=True, timeout=30)
        require_pin(tmp_path / relative, after)
    require_pin(POINTER_DIFFERENCE_PATCH, POINTER_DIFFERENCE_PATCH_SHA256)
    subprocess.run(['patch', '--batch', '--forward', '-p1', '-i', str(POINTER_DIFFERENCE_PATCH.resolve())],
                   cwd=tmp_path, check=True, capture_output=True, timeout=30)
    for relative, _, after in POINTER_DIFFERENCE_FILES:
        require_pin(tmp_path / relative, after)
    if with_shadow:
        require_pin(tmp_path / 'src/goto-symex/shadow_memory_util.cpp', PATCHED_FILE_SHA256)
    if c_frontend:
        require_pin(tmp_path / 'src/ansi-c/c_typecheck_expr.cpp', DECAY_PATCHED_SHA256)


@pytest.mark.parametrize('patch_name,options', [
    ('JSON_PATCH', {}),
    ('TYPED_EXPORT_PATCH', {}),
    ('POINTER_DIFFERENCE_PATCH', {'pointer_difference_overflow': True}),
])
def test_bad_patch_is_rejected_before_prefix_or_toolchain(tmp_path, monkeypatch, patch_name, options):
    if os.name != 'posix':
        pytest.skip('native Linux builder')
    archive = tmp_path / 'archive'
    archive.write_bytes(b'pinned fixture archive')
    monkeypatch.setattr(backend, 'SOURCE_SHA256', checksum(archive))
    monkeypatch.setattr(backend, 'SOLVER_SHA256', checksum(archive))
    bad_patch = tmp_path / 'bad.patch'
    bad_patch.write_bytes(b'changed patch bytes')
    monkeypatch.setattr(backend, patch_name, bad_patch)
    monkeypatch.setattr(backend.Toolchain, 'load', lambda *_: pytest.fail('toolchain queried before patch validation'))
    prefix = tmp_path / 'backend'
    with pytest.raises(ValueError, match='pinned bytes'):
        build(prefix, archive, archive, tmp_path / 'unused-config.json', **options)
    assert not prefix.exists()


@pytest.mark.parametrize('c_frontend,pointer_difference,expected', [
    (False, False, ['cbmc', 'goto-cc', 'goto-instrument', 'symtab2gb']),
    (True, False, ['cbmc', 'goto-cc', 'goto-instrument', 'symtab2gb']),
    (False, True, ['cbmc', 'goto-cc', 'goto-instrument', 'symtab2gb']),
    (True, True, ['cbmc', 'goto-cc', 'goto-instrument', 'symtab2gb']),
])
def test_build_always_requests_all_tools_and_fixed_export_patches(tmp_path, monkeypatch,
                                                                c_frontend, pointer_difference, expected):
    if os.name != 'posix':
        pytest.skip('native Linux builder')
    archive = tmp_path / 'archive'
    archive.write_bytes(b'archive fixture; extraction is stubbed')
    pins, commands = [], []
    monkeypatch.setattr(backend, 'require_pin', lambda path, expected: pins.append(Path(path)))
    monkeypatch.setattr(backend.tarfile, 'open', lambda *_: nullcontext(
        SimpleNamespace(extractall=lambda *args, **kwargs: None)))
    monkeypatch.setattr(backend.Toolchain, 'load', lambda *_: SimpleNamespace(
        wsl_distribution=None, versions=lambda: {'cbmc': {'version': '6.11.0 fixture'}}))
    if not pointer_difference:
        monkeypatch.setattr(backend, 'POINTER_DIFFERENCE_PATCH', tmp_path / 'unselected-missing.patch')

    def capture_run(command, log, cwd=None, timeout=3600):
        commands.append(command)
        if command[:2] == ['cmake', '--build']:
            raise RuntimeError('captured build command')
        log.write_text('process boundary stub\n')

    monkeypatch.setattr(backend, 'run', capture_run)
    options = {'c_frontend': c_frontend}
    if pointer_difference:
        options['pointer_difference_overflow'] = True
    with pytest.raises(RuntimeError, match='captured build command'):
        build(tmp_path / 'backend', archive, archive, tmp_path / 'unused-config.json', **options)
    command = commands[-1]
    assert command[command.index('--target') + 1:-1] == expected
    assert backend.JSON_PATCH in pins
    assert backend.TYPED_EXPORT_PATCH in pins
    assert (backend.POINTER_DIFFERENCE_PATCH in pins) == pointer_difference
    patch_names = [Path(command[-1]).name for command in commands if command[0] == 'patch']
    expected_patches = [PATCH.name, JSON_PATCH.name, TYPED_EXPORT_PATCH.name]
    if c_frontend:
        expected_patches.extend([FRONTEND_PATCH.name, GENERIC_PATCH.name, DECAY_PATCH.name])
    if pointer_difference:
        expected_patches.append(POINTER_DIFFERENCE_PATCH.name)
    assert patch_names == expected_patches


@pytest.mark.parametrize('tamper_source,tamper_stage', [
    (None, None),
    ('src/util/json.cpp', 'after-build'),
    *[(relative, stage) for relative, _, _ in TYPED_EXPORT_FILES
      for stage in ('before-patch', 'after-build')],
])
def test_default_build_pins_export_sources_and_all_rebuilt_tools(tmp_path, monkeypatch,
                                                               tamper_source, tamper_stage):
    if os.name != 'posix':
        pytest.skip('native Linux builder')
    archive = tmp_path / 'archive'
    archive.write_bytes(b'archive fixture; extraction is stubbed')
    monkeypatch.setattr(backend, 'SOURCE_SHA256', checksum(archive))
    monkeypatch.setattr(backend, 'SOLVER_SHA256', checksum(archive))
    prefix = tmp_path / 'backend'
    source = prefix / 'cbmc-cbmc-6.11.0'
    files = {
        PATCH.name: ('src/goto-symex/shadow_memory_util.cpp', 'ORIGINAL_FILE_SHA256', 'PATCHED_FILE_SHA256'),
        JSON_PATCH.name: ('src/util/json.cpp', 'JSON_ORIGINAL_SHA256', 'JSON_PATCHED_SHA256'),
    }
    for relative, before, after in files.values():
        fixture = tmp_path / 'source-fixture'
        fixture.write_text('original ' + relative)
        monkeypatch.setattr(backend, before, checksum(fixture))
        fixture.write_text('patched ' + relative)
        monkeypatch.setattr(backend, after, checksum(fixture))
    export_files = []
    for relative, _, _ in TYPED_EXPORT_FILES:
        fixture = tmp_path / 'export-source-fixture'
        fixture.write_text('original ' + relative)
        before = checksum(fixture)
        fixture.write_text('patched ' + relative)
        export_files.append((relative, before, checksum(fixture)))
    monkeypatch.setattr(backend, 'TYPED_EXPORT_FILES', tuple(export_files))

    def extract(*args, **kwargs):
        for relative, _, _ in [*files.values(), *export_files]:
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('original ' + relative)
        if tamper_stage == 'before-patch':
            (source / tamper_source).write_text('changed before patch')

    monkeypatch.setattr(backend.tarfile, 'open', lambda *_: nullcontext(SimpleNamespace(extractall=extract)))
    names = ('cbmc', 'goto-cc', 'goto-instrument', 'symtab2gb')
    base_config = tmp_path / 'base-toolchain.json'
    base_versions = {name: {'version': '6.11.0 fixture', 'sha256': 'base-' + name} for name in names}

    def toolchain(config):
        if Path(config) == base_config:
            return SimpleNamespace(wsl_distribution=None, versions=lambda: base_versions)
        bin_dir = Path(json.loads(Path(config).read_text())['bin_dir'])
        return SimpleNamespace(versions=lambda: {
            name: {'version': '6.11.0 fixture', 'sha256': checksum(bin_dir / name)} for name in names})

    monkeypatch.setattr(backend.Toolchain, 'load', toolchain)
    commands = []

    def run_fixture(command, log, cwd=None, timeout=3600):
        commands.append(command)
        log.write_text('process boundary fixture\n')
        if command[0] == 'patch':
            name = Path(command[-1]).name
            affected = export_files if name == TYPED_EXPORT_PATCH.name else [files[name]]
            for relative, _, _ in affected:
                (source / relative).write_text('patched ' + relative)
        elif command[:2] == ['cmake', '--build']:
            assert command[command.index('--target') + 1:-1] == list(names)
            bin_dir = prefix / 'build/bin'
            bin_dir.mkdir(parents=True)
            for name in names:
                (bin_dir / name).write_text('rebuilt ' + name)
            if tamper_stage == 'after-build':
                (source / tamper_source).write_text('changed during build')

    monkeypatch.setattr(backend, 'run', run_fixture)
    if tamper_source:
        with pytest.raises(ValueError, match='pinned bytes'):
            build(prefix, archive, archive, base_config)
        assert not (prefix / 'backend-manifest.json').exists()
        if tamper_stage == 'before-patch':
            assert all(command[-1] != str(prefix / 'archives' / TYPED_EXPORT_PATCH.name)
                       for command in commands)
            assert not any(command[0] == 'cmake' for command in commands)
        else:
            assert any(command[:2] == ['cmake', '--build'] for command in commands)
        return
    result = build(prefix, archive, archive, base_config)
    manifest = json.loads(Path(result['manifest']).read_text())
    assert manifest['json_control_escaping_correction'] is True
    assert manifest['typed_export_capabilities'] == {
        'functions': {'irepCommentsIncluded': True, 'sourceLocationIrepIncluded': True},
        'symbolTableWrapper': {'irepCommentsIncluded': True, 'symbolLocationIrepIncluded': True}}
    assert manifest['typed_transport_capabilities'] == {
        'raw_functions_option': '--show-goto-functions-raw',
        'raw_symbols_option': '--show-symbol-table-raw',
        'preserved_instruction_code': ['SKIP', 'SET_RETURN_VALUE']}
    assert manifest['base_tools'] == base_versions
    assert set(manifest['tools']) == set(names)
    for name in names:
        executable = prefix / 'toolchain-bin' / name
        assert executable.read_text() == 'rebuilt ' + name
        assert manifest['tools'][name]['sha256'] == checksum(executable)
        assert manifest['assets']['toolchain-bin/' + name] == checksum(executable)
    assert manifest['assets']['archives/' + JSON_PATCH.name] == JSON_PATCH_SHA256
    assert manifest['assets']['cbmc-cbmc-6.11.0/src/util/json.cpp'] == backend.JSON_PATCHED_SHA256
    assert manifest['assets']['json-patch.log'] == checksum(prefix / 'json-patch.log')
    assert manifest['assets']['archives/' + TYPED_EXPORT_PATCH.name] == TYPED_EXPORT_PATCH_SHA256
    for relative, _, after in export_files:
        assert manifest['assets']['cbmc-cbmc-6.11.0/' + relative] == after
    assert manifest['assets']['typed-export-patch.log'] == checksum(prefix / 'typed-export-patch.log')
    assert 'typed transport adapter and actual-model roundtrip' in manifest['scope']
    assert backend.check(prefix, result['manifest_sha256'])['status'] == 'CURRENT_BACKEND_BYTES'


@pytest.mark.parametrize('enabled', [False, True])
def test_pointer_difference_cli_is_opt_in(tmp_path, monkeypatch, capsys, enabled):
    calls = []
    monkeypatch.setattr(backend, 'build', lambda *args, **kwargs: calls.append(kwargs) or {'status': 'captured'})
    argv = ['build_shadow_backend', '--prefix', str(tmp_path / 'output'), '--cbmc-archive', 'cbmc.tar.gz',
            '--minisat-archive', 'minisat.tar.gz', '--base-toolchain', 'toolchain.json']
    if enabled:
        argv.append('--pointer-difference-overflow')
    monkeypatch.setattr('sys.argv', argv)
    backend.main()
    assert calls == [{'c_frontend': False, 'pointer_difference_overflow': enabled}]
    assert json.loads(capsys.readouterr().out) == {'status': 'captured'}
