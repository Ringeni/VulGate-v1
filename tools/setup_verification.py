"""Install a pinned verification environment without modifying system packages.

Run as ``python -m tools.setup_verification --prefix PATH [--wsl DISTRO]``.
The host supplies Ubuntu 24.04 x86-64, GCC, dpkg-deb and CPython >= 3.11.
"""
from __future__ import annotations

import argparse
import importlib.util
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

from tools.verification.toolchain import Toolchain


VERSION = '6.11.0'
ARCHIVE_URL = 'https://github.com/diffblue/cbmc/releases/download/cbmc-6.11.0/ubuntu-24.04-cbmc-6.11.0-Linux.deb'
ARCHIVE_SHA256 = 'b3721aa541038384d7801ea3aeabbcddc3e8845ac8f1cbff637cf8dec7481ac8'
REPO = Path(__file__).resolve().parents[1]
LOCK = REPO / 'requirements-verification.lock'
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024


def checksum(path):
    with Path(path).open('rb') as stream:
        value = sha256()
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()


def setup_sources():
    return {str(p.relative_to(REPO)): checksum(p) for p in (
        Path(__file__).resolve(), LOCK, REPO / 'tools/verification/toolchain.py',
        REPO / 'tools/verification/spec.py', REPO / 'tools/verification/__init__.py')}


def require(result):
    if result.returncode != 0 or result.timed_out:
        raise ValueError(f'command failed: {result.argv!r}\n{result.stdout[-1500:]}\n{result.stderr[-1500:]}')
    return result.stdout.strip()


def local_command(argv, timeout=600):
    result = subprocess.run([str(a) for a in argv], capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise ValueError(f'command failed: {argv!r}\n{result.stdout.decode("utf-8", errors="replace")[-1000:]}\n{result.stderr.decode("utf-8", errors="replace")[-2000:]}')
    return result.stdout.decode('utf-8').strip()


def parse_release(text):
    result = {}
    for line in text.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            result[key] = value.strip('"')
    if result.get('ID') != 'ubuntu' or result.get('VERSION_ID') != '24.04':
        raise ValueError('the pinned CBMC package requires Ubuntu 24.04')
    return result


def validate_host(toolchain, directory):
    release = parse_release(require(toolchain.run_external('cat', ['/etc/os-release'], 15)))
    architecture = require(toolchain.run_external('uname', ['-m'], 15))
    if architecture != 'x86_64':
        raise ValueError('the pinned CBMC package requires x86-64')
    require(toolchain.run_external('dpkg-deb', ['--version'], 15))
    gcc = toolchain.native_compiler('gcc', directory)
    return {'release': release, 'architecture': architecture, 'gcc': gcc}


def obtain_archive(destination, source=None):
    if source is not None:
        source = Path(source).resolve()
        if not source.is_file() or checksum(source) != ARCHIVE_SHA256:
            raise ValueError('offline CBMC archive does not match the pinned SHA-256')
        shutil.copyfile(source, destination)
    else:
        request = urllib.request.Request(ARCHIVE_URL, headers={'User-Agent': 'VulGate-verification-setup'})
        size = 0
        with urllib.request.urlopen(request, timeout=60) as response, destination.open('xb') as output:
            if not response.geturl().startswith('https://'):
                raise ValueError('CBMC download redirected to a non-HTTPS URL')
            while data := response.read(1024 * 1024):
                size += len(data)
                if size > MAX_ARCHIVE_BYTES:
                    raise ValueError('CBMC download exceeded the package size limit')
                output.write(data)
    if checksum(destination) != ARCHIVE_SHA256:
        raise ValueError('downloaded CBMC archive does not match the pinned SHA-256')


def python_executable(prefix):
    return prefix / 'python' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def python_packages(executable):
    script = ('import importlib.metadata,json,sys; '
              'print(json.dumps({"version":sys.version,"packages":'
              '{d.metadata["Name"].lower():d.version for d in importlib.metadata.distributions()}}))')
    return json.loads(local_command([executable, '-I', '-B', '-c', script], 60))


def create_python(prefix):
    """Bootstrap a private venv, including minimal Ubuntu Python installations."""
    interpreter = python_executable(prefix)
    if importlib.util.find_spec('ensurepip') is not None:
        local_command([sys.executable, '-m', 'venv', prefix / 'python'])
        return [interpreter, '-I', '-m', 'pip']
    # Debian/Ubuntu can ship venv without ensurepip. The host pip's --python
    # mode installs into the new environment; it does not change host packages.
    if importlib.util.find_spec('pip') is None:
        raise ValueError('Python needs ensurepip or host pip with --python support to create a private environment')
    help_text = local_command([sys.executable, '-I', '-m', 'pip', '--help'])
    if '--python' not in help_text:
        raise ValueError('host pip lacks --python support; install the Python venv prerequisite')
    local_command([sys.executable, '-m', 'venv', '--without-pip', prefix / 'python'])
    return [sys.executable, '-I', '-m', 'pip', '--python', interpreter]


def managed_assets(prefix, toolchain=None):
    # Python may create bytecode caches during ordinary use. Source and extension
    # modules, scripts, wheel metadata and tool binaries are checked separately.
    files = {}
    for top in prefix.iterdir():
        if top == prefix / 'setup-manifest.json' or top == prefix / 'cbmc' and toolchain is not None:
            continue
        for path in top.rglob('*') if top.is_dir() else [top]:
            if path.is_file() and '__pycache__' not in path.parts:
                files[path.relative_to(prefix).as_posix()] = checksum(path)
    links = {}
    if toolchain is not None:
        root = toolchain.path(prefix / 'cbmc')
        # Linux symlinks stored on a Windows drive cannot reliably be opened by
        # Win32. Inspect that tree on its owning host without following links.
        output = require(toolchain.run_external('find', [root, '-type', 'f', '-exec', 'sha256sum', '--zero', '--', '{}', '+'], 120))
        for item in output.split('\0'):
            if not item:
                continue
            digest, path = item.split('  ', 1)
            if len(digest) != 64 or not path.startswith(root + '/'):
                raise ValueError('unrecognized backend file inventory')
            files['cbmc/' + path[len(root) + 1:]] = digest
        output = require(toolchain.run_external('find', [root, '-type', 'l', '-printf', r'%P\0%l\0'], 30))
        items = output.split('\0')
        if items[-1] == '':
            items.pop()
        if len(items) % 2:
            raise ValueError('unrecognized backend symlink inventory')
        links = {'cbmc/' + items[n]: items[n+1] for n in range(0, len(items), 2)}
    return {'files': files, 'symlinks': links}


def check_setup(prefix, expected_sha256):
    prefix = Path(prefix).resolve()
    manifest = prefix / 'setup-manifest.json'
    if not expected_sha256 or checksum(manifest) != expected_sha256:
        raise ValueError('setup manifest does not match the caller-retained SHA-256')
    data = json.loads(manifest.read_text(encoding='utf-8'))
    if data.get('schema') != 1 or data.get('kind') != 'vulgate-verification-setup':
        raise ValueError('unsupported setup manifest')
    if data['prefix'] != str(prefix):
        raise ValueError('Python virtual environments cannot be relocated; install in the final directory')
    if data['setup_sources'] != setup_sources():
        raise ValueError('setup implementation or dependency lock changed')
    tc = Toolchain(**data['configuration'])
    if data['assets'] != managed_assets(prefix, tc):
        raise ValueError('managed setup files changed')
    config = prefix / 'toolchain.json'
    if data['host'] != validate_host(tc, prefix):
        raise ValueError('host release or native compiler changed')
    if data['tools'] != tc.versions() or data['python'] != python_packages(python_executable(prefix)):
        raise ValueError('installed tool or Python dependency versions changed')
    if checksum(manifest) != expected_sha256 or data['assets'] != managed_assets(prefix, tc):
        raise ValueError('setup changed during checking')
    return {'status': 'CURRENT', 'manifest': str(manifest), 'manifest_sha256': expected_sha256,
            'toolchain': str(config), 'python': str(python_executable(prefix))}


def install(prefix, distribution=None, archive=None, wheelhouse=None):
    if sys.version_info < (3, 11):
        raise ValueError('CPython 3.11 or newer is required')
    if os.name == 'nt' and not distribution:
        raise ValueError('Windows installation requires --wsl with an existing Ubuntu-24.04 distribution')
    if os.name != 'nt' and distribution:
        raise ValueError('--wsl is only supported from Windows')
    prefix = Path(prefix).resolve()
    if prefix.exists():
        raise ValueError('prefix already exists; use --check with its manifest pin or choose a new directory')
    if not prefix.parent.is_dir():
        raise ValueError('prefix parent directory must already exist')
    if wheelhouse is not None and not Path(wheelhouse).is_dir():
        raise ValueError('offline wheelhouse does not exist')
    original = setup_sources()
    host_toolchain = Toolchain(wsl_distribution=distribution)
    host = validate_host(host_toolchain, prefix.parent)
    prefix.mkdir()
    package = prefix / 'cbmc.deb'
    obtain_archive(package, archive)
    require(host_toolchain.run_external('dpkg-deb', ['--extract', package, prefix / 'cbmc'], 120))
    # Extracting data never runs Debian package maintainer scripts or needs root.
    tc = Toolchain(bin_dir=host_toolchain.path(prefix / 'cbmc/usr/bin'), wsl_distribution=distribution)
    tools = tc.versions()
    if any(VERSION not in tool['version'] for tool in tools.values()):
        raise ValueError('extracted CBMC tools have unexpected versions')
    config = prefix / 'toolchain.json'
    configuration = {'bin_dir': tc.bin_dir, 'wsl_distribution': distribution}
    config.write_text(json.dumps(configuration, indent=2), encoding='utf-8')
    lock = prefix / 'requirements-verification.lock'
    shutil.copyfile(LOCK, lock)
    pip_command = create_python(prefix)
    interpreter = python_executable(prefix)
    args = [*pip_command, '--disable-pip-version-check', 'install', '--no-compile',
            '--require-hashes', '--only-binary=:all:', '-r', lock]
    if wheelhouse is not None:
        args += ['--no-index', '--find-links', Path(wheelhouse).resolve()]
    local_command(args)
    python = python_packages(interpreter)
    # Exercise the parser's native extension in the new virtual environment.
    local_command([interpreter, '-I', '-B', '-c',
                   'from tree_sitter import Language,Parser; import tree_sitter_c; '
                   'assert not Parser(Language(tree_sitter_c.language())).parse(b"int x;").root_node.has_error'])
    if original != setup_sources():
        raise ValueError('setup sources changed during installation')
    if host != validate_host(tc, prefix) or tools != tc.versions():
        raise ValueError('host or toolchain changed during installation')
    manifest = prefix / 'setup-manifest.json'
    data = {'schema': 1, 'kind': 'vulgate-verification-setup', 'prefix': str(prefix),
            'archive': {'url': ARCHIVE_URL, 'sha256': ARCHIVE_SHA256},
            'host': host, 'tools': tools, 'python': python, 'setup_sources': original,
            'configuration': configuration, 'assets': managed_assets(prefix, tc),
            'scope': 'Pinned CBMC and Python dependencies; host OS and GCC are prerequisites recorded in this manifest.'}
    manifest.write_text(json.dumps(data, indent=2), encoding='utf-8')
    return {'status': 'INSTALLED', 'manifest': str(manifest), 'manifest_sha256': checksum(manifest),
            'toolchain': str(config), 'python': str(interpreter)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--wsl', metavar='DISTRIBUTION')
    parser.add_argument('--archive', type=Path, help='offline official CBMC Debian package')
    parser.add_argument('--wheelhouse', type=Path, help='offline directory of locked Python wheels')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--manifest-sha256', help='caller-retained setup manifest hash for --check')
    args = parser.parse_args(argv)
    try:
        if args.check and any((args.wsl, args.archive, args.wheelhouse)):
            raise ValueError('--check reads its configuration from the pinned installation')
        if not args.check and args.manifest_sha256:
            raise ValueError('--manifest-sha256 requires --check')
        report = (check_setup(args.prefix, args.manifest_sha256) if args.check else
                  install(args.prefix, args.wsl, args.archive, args.wheelhouse))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'INCOMPLETE_OR_INVALID', 'reason': str(exc)}))
        return 2
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
