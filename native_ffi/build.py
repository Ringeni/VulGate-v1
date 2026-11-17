"""Build the standalone libffi/funchook bridge.

This is the release-build entry point for the FFI backend. It does not touch the
Frida JS backend.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str], cwd: Path | None = None) -> None:
    print('+', ' '.join(str(a) for a in args), flush=True)
    subprocess.run([str(a) for a in args], cwd=cwd, check=True)


def build_funchook(source: Path, build_dir: Path) -> Path:
    lib = build_dir / 'libfunchook.so'
    if not lib.exists():
        run(['cmake', '-S', str(source), '-B', str(build_dir),
             '-DCMAKE_BUILD_TYPE=Release', '-DFUNCHOOK_BUILD_TESTS=OFF'])
        run(['cmake', '--build', str(build_dir), '-j4'])
    if not lib.exists():
        raise RuntimeError('libfunchook.so was not produced')
    return lib


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--funchook-dir', type=Path,
                        default=Path(os.environ.get('FUNCHOOK_DIR', str(ROOT / 'native_ffi' / 'third_party' / 'funchook'))))
    parser.add_argument('--output', type=Path, default=ROOT / 'build' / 'ffi')
    parser.add_argument('--cc', default=os.environ.get('CC', 'gcc'))
    args = parser.parse_args()

    if platform.machine() not in ('x86_64', 'AMD64'):
        raise SystemExit('FFI bridge currently supports x86-64 only')
    source = args.funchook_dir.resolve()
    if not (source / 'CMakeLists.txt').exists():
        raise SystemExit(f'funchook source not found: {source}')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    funchook_build = output / 'funchook-build'
    funchook = build_funchook(source, funchook_build)
    target = output / 'libfunchook.so.2'
    shutil.copy2(funchook, target)
    link = output / 'libfunchook.so'
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target.name)
    bridge = output / 'libvg_ffi.so'
    run([args.cc, '-shared', '-fPIC', '-O2', '-g',
         '-I', str(ROOT), '-I', str(ROOT / 'runtime'),
         '-I', str(source / 'include'),
         str(ROOT / 'native_ffi' / 'ffi_bridge.c'),
         str(ROOT / 'runtime' / 'vm.c'),
         str(ROOT / 'runtime' / 'user' / 'safe_mem.c'),
         '-L', str(output), '-lfunchook', '-lffi', '-ldl', '-lpthread',
         '-Wl,-rpath,$ORIGIN', '-o', str(bridge)])
    print('built:', bridge)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

