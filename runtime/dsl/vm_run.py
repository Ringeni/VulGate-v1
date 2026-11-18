"""Install a DSL patch through the VulGate Shadow VM (runtime/vm.c) instead of JS guards."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser  # noqa: E402
from runtime.dsl import resolve as dsl_resolve  # noqa: E402
from runtime.dsl import vm as dsl_vm  # noqa: E402


def _bridge(output: Path) -> Path:
    bridge = output / 'vulgate_frida.so'
    if not bridge.is_file():
        subprocess.run([sys.executable, '-m', 'runtime.frida.build',
                        '--output', str(output)], check=True)
    return bridge


def _global_names(patch: dsl_parser.PatchSpec) -> list[str]:
    names = []
    for mount in patch.mounts:
        for name in re.findall(r'global\("([^"]+)"\)', mount.body):
            if name not in names:
                names.append(name)
    return names


def _target_address(pid: int | None, mount: dsl_parser.MountSpec,
                    executable: Path | None) -> tuple[int, str | None]:
    info = dsl_resolve.module_base(pid, mount.module, executable)
    if info is None:
        raise ValueError('cannot find module for mount ' + mount.id)
    module, base, path = info
    if mount.offset is None:
        offsets = dsl_resolve.frida_symbols.symbol_offsets(path, [mount.symbol])
        if mount.symbol not in offsets:
            raise ValueError('symbol not found in ' + str(path) + ': ' + mount.symbol)
        mount.offset = offsets[mount.symbol]
    return (base + mount.offset, module)


def _action_value(action: dsl_parser.ActionSpec) -> str:
    if action.return_type == 'void':
        return 'undefined'
    if action.return_type == 'pointer':
        return 'ptr(0)' if action.value is None else 'ptr(' + str(int(action.value)) + ')'
    if action.return_type == 'string':
        return 'null' if action.value is None else 'Memory.allocUtf8String(%s)' % json.dumps(str(action.value))
    return str(int(action.value))


def _script(patch: dsl_parser.PatchSpec, compiled: dsl_vm.VMPatch,
            targets: list[tuple[int, str | None]], bridge: Path) -> str:
    entries = []
    for mount, target in zip(compiled.mounts, targets):
        if mount.action_id is None:
            action_expr = 'undefined'
        else:
            action_expr = _action_value(patch.actions[mount.action_id])
        entries.append(
            '{id: %s, args: %s, return_type: %s, target: %s, code: %s, '
            'action: %s, nature: %s, locals: %s}' % (
                json.dumps(mount.id), json.dumps(mount.args),
                json.dumps(mount.return_type), json.dumps(hex(target[0])),
                json.dumps(list(mount.code)), action_expr,
                json.dumps(mount.nature), json.dumps(mount.locals)))
    mounts_literal = '[' + ', '.join(entries) + ']'
    capacities = [int(item['capacity']) for item in compiled.maps]
    map_literal = json.dumps({'count': len(capacities),
                              'capacity': max(capacities) if capacities else 0})
    return r'''
'use strict';
const bridge = Module.load(%s);
const create = new NativeFunction(bridge.getExportByName('vg_program_create'), 'pointer', ['pointer', 'uint']);
const run = new NativeFunction(bridge.getExportByName('vg_run_with_maps'), 'int',
    ['pointer', 'pointer', 'pointer', 'uint', 'pointer', 'uint', 'pointer']);
const mapCreate = new NativeFunction(bridge.getExportByName('vg_map_pool_create'), 'pointer', ['uint', 'uint']);
const mapGet = new NativeFunction(bridge.getExportByName('vg_map_pool_get'), 'int', ['pointer', 'uint', 'uint64', 'pointer']);
const VG_MAP_INFO = %s;
const VG_MAP_POOL = VG_MAP_INFO.count ? mapCreate(VG_MAP_INFO.count, VG_MAP_INFO.capacity) : ptr(0);
const VG_MOUNTS = %s;
const VG_STATE = [];
const VG_HITS = {};
const VG_RUN = {};

function vg_fill(target, values, count) {
  const length = count === undefined ? values.length : count;
  for (let index = 0; index < length; index++) {
    const value = values[index];
    if (value instanceof NativePointer) target.add(index * 8).writePointer(value);
    else target.add(index * 8).writeU64(value);
  }
}

function vg_read_mem(address, size) {
  if (size === 1) return address.readU8();
  if (size === 2) return address.readU16();
  if (size === 4) return address.readU32();
  return address.readU64();
}

function vg_local(recipe, context) {
  if (recipe.kind === 'constant') return recipe.value;
  if (recipe.kind === 'register') {
    return context[recipe.reg];
  }
  if (recipe.kind !== 'memory') {
    throw new Error('unknown local recipe: ' + recipe.kind);
  }
  let base = context[recipe.base];
  if (base === undefined || base === null) {
    throw new Error('missing register for local: ' + recipe.base);
  }
  let address = ptr(base).add(recipe.offset);
  for (let index = 0; index < (recipe.deref || 0); index++) {
    address = address.readPointer();
  }
  return vg_read_mem(address, recipe.size || 8);
}

function vg_store_local(target, slot, value) {
  if (value instanceof NativePointer) target.add(slot * 8).writePointer(value);
  else target.add(slot * 8).writeU64(value);
}

function vg_install() {
  for (const spec of VG_MOUNTS) {
    const code = Memory.alloc(spec.code.length);
    code.writeByteArray(spec.code);
    const handle = create(code, spec.code.length);
    if (handle.isNull()) throw new Error('vg_program_create failed: ' + spec.id);
    const args = Memory.alloc(6 * 8);
    const regs = Memory.alloc(16 * 8);
    const stats = Memory.alloc(64);
    if (spec.nature === 'read_point') {
      Interceptor.attach(ptr(spec.target), {
        onEnter: function(callArgs) {
          VG_HITS[spec.id] = (VG_HITS[spec.id] || 0) + 1;
          try {
            for (const localSpec of (spec.locals || [])) {
              vg_store_local(regs, localSpec.slot,
                             vg_local(localSpec.recipe, this.context));
            }
            vg_fill(args, callArgs, spec.args.length);
          } catch (error) {
            VG_RUN[spec.id] = 'fill-error: ' + (error && error.stack ? error.stack : error);
            return;
          }
          try {
            VG_RUN[spec.id] = run(handle, args, regs, 4096, VG_MAP_POOL, VG_MAP_INFO.count, stats);
          } catch (error) {
            VG_RUN[spec.id] = 'run-error: ' + error;
          }
        },
      });
      VG_STATE.push({id: spec.id, target: String(spec.target), handle: handle,
                     nature: spec.nature, program: code});
      continue;
    }
    const original = new NativeFunction(ptr(spec.target), spec.return_type, spec.args);
    const callback = new NativeCallback(function() {
      VG_HITS[spec.id] = (VG_HITS[spec.id] || 0) + 1;
      const values = Array.prototype.slice.call(arguments);
      vg_fill(args, values);
      const decision = run(handle, args, regs, 4096, VG_MAP_POOL, VG_MAP_INFO.count, stats);
      VG_RUN[spec.id] = decision;
      if (decision === 1) return spec.action;
      return original.apply(null, values);
    }, spec.return_type, spec.args);
    Interceptor.replace(ptr(spec.target), callback);
    VG_STATE.push({id: spec.id, target: String(spec.target), handle: handle,
                   callback: callback, nature: spec.nature, program: code});
  }
  Interceptor.flush();
}

rpc.exports = {
  mapInfo: () => ({pool: String(VG_MAP_POOL), count: VG_MAP_INFO.count, capacity: VG_MAP_INFO.capacity, capacity_field: VG_MAP_POOL.readU32(), used: VG_MAP_POOL.add(4).readU32()}),
  mapGet: (index, key) => {
    const out = Memory.alloc(8);
    const rc = mapGet(VG_MAP_POOL, index, key, out);
    return {rc: rc, value: out.readU64().toString()};
  },
  install: () => { vg_install(); return {installed: VG_STATE.map((s) => ({id: s.id, target: s.target, nature: s.nature})), hits: VG_HITS}; },
  status: () => ({installed: VG_STATE.map((s) => ({id: s.id, target: s.target, nature: s.nature})), hits: VG_HITS, run: VG_RUN}),
};
''' % (json.dumps(str(bridge)), map_literal, mounts_literal)


def install(patch_path: Path, pid: int | None, executable: Path | None,
            bridge_dir: Path, duration: float = 5.0, spawn=False) -> dict:
    patch = dsl_parser.load(patch_path)
    import frida
    device = frida.get_local_device()
    if spawn:
        pid = device.spawn([str(executable.resolve())])
    assert pid is not None
    dsl_resolve.resolve_patch(patch, pid=pid, executable=executable)
    globals_ = {}
    for name in _global_names(patch):
        module, address = dsl_resolve.resolve_global(
            name, pid, None, executable)
        globals_[name] = address
    compiled = dsl_vm.compile_patch(patch, globals_)
    targets = []
    for mount in patch.mounts:
        targets.append(_target_address(pid, mount, executable))
    bridge = _bridge(bridge_dir)
    session = None
    try:
        session = device.attach(pid)
        script = session.create_script(_script(patch, compiled, targets, bridge))
        if os.environ.get('VG_DEBUG'):
            script.on('message', lambda message, data: print('VG_SCRIPT', message, flush=True))
        script.load()
        result = script.exports_sync.install()
        if spawn:
            device.resume(pid)
        time.sleep(max(0.0, duration))
        result['final'] = script.exports_sync.status()
        return result
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if spawn:
            try:
                device.kill(pid)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dsl', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid', type=int)
    target.add_argument('--spawn', type=Path)
    parser.add_argument('--duration', type=float, default=5.0)
    parser.add_argument('--bridge-dir', type=Path, default=ROOT / 'build' / 'frida-vm')
    args = parser.parse_args()
    result = install(args.dsl, args.pid, args.spawn, args.bridge_dir,
                     args.duration, spawn=args.spawn is not None)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())





