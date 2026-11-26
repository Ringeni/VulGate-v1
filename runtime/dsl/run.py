"""Compile/install a DSL patch into a running (or spawned) process."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dsl', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=False)
    target.add_argument('--pid', type=int)
    target.add_argument('--spawn', type=Path)
    parser.add_argument('--spawn-arg', action='append', default=[])
    parser.add_argument('--duration', type=float, default=5.0)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--summary', type=Path)
    parser.add_argument('--bridge-dir', type=Path, default=ROOT / 'build' / 'frida-vm')
    args = parser.parse_args()
    if not args.check and args.pid is None and args.spawn is None:
        parser.error('one of --pid/--spawn is required unless --check is used')

    from runtime.dsl import vm_run
    patch = dsl_parser.load(args.dsl)
    if args.check:
        print(json.dumps({'dsl': str(args.dsl), 'backend': 'vm',
                          'mounts': [asdict(mount) for mount in patch.mounts],
                          'actions': {name: action.__dict__
                                      for name, action in patch.actions.items()}},
                         ensure_ascii=False))
        return 0
    result = vm_run.install(args.dsl, args.pid, args.spawn, args.bridge_dir,
                            args.duration, spawn=args.spawn is not None, spawn_args=args.spawn_arg)
    if args.summary:
        args.summary.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
