"""Build the standalone INT3/SIGTRAP Shadow-VM bridge."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str]) -> None:
    print('+', ' '.join(str(a) for a in args), flush=True)
    subprocess.run([str(a) for a in args], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build' / 'ffi')
    parser.add_argument('--cc', default=os.environ.get('CC', 'gcc'))
    args = parser.parse_args()
    if platform.machine() not in ('x86_64', 'AMD64'):
        raise SystemExit('FFI bridge currently supports x86-64 only')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    bridge = output / 'libvg_ffi.so'
    run([args.cc, '-shared', '-fPIC', '-O2', '-g',
         '-I', str(ROOT), '-I', str(ROOT / 'runtime'),
         str(ROOT / 'native_ffi' / 'ffi_bridge.c'),
         str(ROOT / 'runtime' / 'vm.c'),
         str(ROOT / 'runtime' / 'user' / 'safe_mem.c'),
         '-ldl', '-lpthread', '-Wl,-rpath,$ORIGIN', '-o', str(bridge)])
    print('built:', bridge)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
