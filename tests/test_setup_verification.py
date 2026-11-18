from pathlib import Path

import pytest

from tools.setup_verification import (ARCHIVE_SHA256, LOCK, check_setup, checksum,
                                      install, managed_assets, obtain_archive, parse_release)


def test_minimal_python_bootstrap_targets_private_interpreter(tmp_path, monkeypatch):
    from tools import setup_verification as setup
    calls = []
    monkeypatch.setattr(setup.importlib.util, 'find_spec', lambda name: None if name == 'ensurepip' else object())
    def command(argv):
        calls.append(argv)
        return '--python PYTHON' if '--help' in argv else ''
    monkeypatch.setattr(setup, 'local_command', command)
    result = setup.create_python(tmp_path)
    assert '--without-pip' in calls[-1]
    assert result[-2:] == ['--python', setup.python_executable(tmp_path)]


def test_missing_python_bootstrap_dependency_has_actionable_error(tmp_path, monkeypatch):
    from tools import setup_verification as setup
    monkeypatch.setattr(setup.importlib.util, 'find_spec', lambda name: None)
    with pytest.raises(ValueError, match='ensurepip or host pip'):
        setup.create_python(tmp_path)


@pytest.mark.parametrize('release', ['ID=debian\nVERSION_ID="24.04"', 'ID=ubuntu\nVERSION_ID="22.04"', ''])
def test_setup_refuses_incompatible_os(release):
    with pytest.raises(ValueError, match='Ubuntu 24.04'):
        parse_release(release)


def test_setup_accepts_the_pinned_os_release():
    assert parse_release('ID=ubuntu\nVERSION_ID="24.04"\nNAME="Ubuntu"')['VERSION_ID'] == '24.04'


def test_offline_archive_is_checked_before_copy_or_extraction(tmp_path):
    source = tmp_path / 'wrong.deb'
    source.write_bytes(b'unrelated bytes')
    destination = tmp_path / 'cbmc.deb'
    with pytest.raises(ValueError, match='pinned SHA-256'):
        obtain_archive(destination, source)
    assert not destination.exists()
    assert checksum(source) != ARCHIVE_SHA256


def test_existing_prefix_is_never_overwritten(tmp_path):
    marker = tmp_path / 'keep.txt'
    marker.write_text('keep', encoding='utf-8')
    import os
    with pytest.raises(ValueError, match='already exists'):
        install(tmp_path, 'Ubuntu-24.04' if os.name == 'nt' else None)
    assert marker.read_text(encoding='utf-8') == 'keep'


def test_setup_check_requires_an_external_manifest_pin(tmp_path):
    (tmp_path / 'setup-manifest.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='caller-retained'):
        check_setup(tmp_path, None)


def test_managed_inventory_detects_added_and_changed_sources(tmp_path):
    script = tmp_path / 'module.py'
    script.write_text('value = 1', encoding='utf-8')
    before = managed_assets(tmp_path)
    script.write_text('value = 2', encoding='utf-8')
    assert before != managed_assets(tmp_path)
    before = managed_assets(tmp_path)
    (tmp_path / 'extra.pth').write_text('extra', encoding='utf-8')
    assert before != managed_assets(tmp_path)


def test_dependency_lock_pins_every_requirement_and_accepts_wheels_only():
    lines = LOCK.read_text(encoding='utf-8').splitlines()
    requirements = [line for line in lines if line and not line.startswith(('#', ' '))]
    assert len(requirements) == 8
    assert all('==' in line and line.endswith('\\') for line in requirements)
    assert sum('--hash=sha256:' in line for line in lines) >= len(requirements)


def test_real_backend_inventory_tracks_linux_symlinks(tmp_path):
    import os
    from tools.verification.toolchain import Toolchain
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN to check native-backend symlinks')
    tc = Toolchain.load(config)
    folder = tmp_path / 'cbmc/usr/bin'
    folder.mkdir(parents=True)
    (folder / 'tool').write_bytes(b'tool bytes')
    link = folder / 'alias'
    result = tc.run_external('ln', ['-s', 'tool', link])
    assert result.returncode == 0, result.stderr
    inventory = managed_assets(tmp_path, tc)
    assert inventory['files']['cbmc/usr/bin/tool'] == checksum(folder / 'tool')
    assert inventory['symlinks'] == {'cbmc/usr/bin/alias': 'tool'}
