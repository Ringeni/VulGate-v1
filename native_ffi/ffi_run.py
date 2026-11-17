"""Run a DSL patch through the standalone libffi/funchook bridge.

Frida is used only to attach to the target and load libvg_ffi.so. All per-hit
execution is C. Callsite/local currently uses the Frida context fallback.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser
from runtime.dsl import resolve as dsl_resolve
from runtime.dsl import vm as dsl_vm
from runtime.dsl import vm_run

TYPE_CODES = {
    'pointer': 0, 'int': 1, 'uint': 2, 'int64': 3, 'uint64': 4, 'void': 5,
}
SUPPORTED_TYPES = set(TYPE_CODES)


def _action_value(action) -> int:
    if action is None or action.value is None:
        return 0
    if isinstance(action.value, (int, float)):
        return int(action.value)
    return 0


def _mount_records(patch, compiled, targets) -> list[dict]:
    records = []
    for mount, target in zip(patch.mounts, targets):
        if mount.location_kind == 'callsite':
            raise RuntimeError('callsite observer requires the Frida fallback')
        locals_payload = []
        for item in (next(item for item in compiled.mounts if item.id == mount.id).locals or []):
            recipe = item.get('recipe') or {}
            if recipe.get('base') != 'rbp' or recipe.get('deref', 0):
                raise RuntimeError('unsupported local recipe: ' + json.dumps(recipe))
            locals_payload.append({
                'slot': int(item['slot']),
                'offset': int(recipe.get('offset', 0)),
                'size': int(recipe.get('size', 8)),
            })
        for kind in mount.args:
            if kind not in SUPPORTED_TYPES:
                raise RuntimeError('unsupported ABI argument type: ' + kind)
        if mount.return_type not in SUPPORTED_TYPES:
            raise RuntimeError('unsupported ABI return type: ' + mount.return_type)
        compiled_mount = next(item for item in compiled.mounts if item.id == mount.id)
        nature = compiled_mount.nature
        records.append({
            'id': mount.id,
            'target': hex(target),
            'code': list(compiled_mount.code),
            'arg_codes': [TYPE_CODES[kind] for kind in mount.args],
            'return_code': TYPE_CODES[mount.return_type],
            'action': 0 if nature == 'read_point' else _action_value(
                patch.actions.get(compiled_mount.action_id)),
            'action_kind': 1 if (nature != 'read_point' and
                                 patch.actions.get(compiled_mount.action_id) is not None and
                                 patch.actions[compiled_mount.action_id].return_type == 'string') else 0,
            'nature': 1 if nature == 'read_point' else 0,
            'locals': locals_payload,
        })
    return records


def _translate_callsite(patch) -> None:
    """Approximate a read-only callsite observer at the callee entry.

    The callee entry sees the same arguments; caller locals are resolved through
    the caller/callee DWARF location. This is how the FFI backend covers the
    111497 callsite observer without a second instruction-level hook.
    """
    for mount in patch.mounts:
        if mount.location_kind != 'callsite' or mount.nature != '读取点':
            continue
        reference = next(
            (item for item in patch.mounts
             if item.location_kind == 'symbol' and item.symbol == mount.callee),
            None)
        if reference is None:
            raise RuntimeError('callsite observer has no callee signature reference')
        mount.location_kind = 'symbol'
        mount.symbol = mount.callee
        mount.args = list(reference.args)
        mount.return_type = reference.return_type


FRIDA_FALLBACK_SYMBOLS = {
    # funchook cannot relocate this function's prologue reliably; Frida's
    # Interceptor is used only for this mount.
    'ngx_http_map_uri_to_path',
}


def install(dsl_path: Path, pid: int, bridge: Path, duration: float, target_skip: int = 0) -> dict:
    import frida
    patch = dsl_parser.load(dsl_path)
    if any(mount.symbol in FRIDA_FALLBACK_SYMBOLS for mount in patch.mounts):
        print('FFI: target uses the Frida fallback', flush=True)
        return vm_run.install(dsl_path, pid, None, ROOT / 'build' / 'frida-vm',
                              duration, spawn=False)
    try:
        _translate_callsite(patch)
    except RuntimeError:
        print('FFI: callsite/local uses the Frida fallback', flush=True)
        return vm_run.install(dsl_path, pid, None, ROOT / 'build' / 'frida-vm',
                              duration, spawn=False)
    if any(mount.location_kind == 'callsite' for mount in patch.mounts):
        print('FFI: callsite/local uses the Frida fallback', flush=True)
        return vm_run.install(dsl_path, pid, None, ROOT / 'build' / 'frida-vm',
                              duration, spawn=False)

    dsl_resolve.resolve_patch(patch, pid=pid, executable=None)
    globals_ = {}
    for name in vm_run._global_names(patch):
        _, address = dsl_resolve.resolve_global(name, pid, None, None)
        globals_[name] = address
    compiled = dsl_vm.compile_patch(patch, globals_)
    capacities = [int(item['capacity']) for item in compiled.maps]
    targets = [vm_run._target_address(pid, mount, None)[0] + target_skip for mount in patch.mounts]
    mounts = _mount_records(patch, compiled, targets)

    session = frida.get_local_device().attach(pid)
    script = None
    loaded = False
    destroyed = False
    try:
        script = session.create_script(f'''
const lib = Module.load({json.dumps(str(bridge))});
const patchCreate = new NativeFunction(lib.getExportByName('vg_ffi_patch_create'),
    'long', ['uint', 'pointer']);
const patchInstall = new NativeFunction(lib.getExportByName('vg_ffi_patch_install'),
    'long', ['long','pointer','pointer','ulong','uint','pointer','int','int64','int','int',
             'uint','pointer','pointer','pointer']);
const patchDestroy = new NativeFunction(lib.getExportByName('vg_ffi_patch_destroy'),
    'int', ['long']);
const capacities = Memory.alloc({max(1, len(capacities)) * 4});
{''.join(f"capacities.add({i*4}).writeU32({value});" for i, value in enumerate(capacities))}
const patch = patchCreate({len(capacities)}, capacities);
if (patch < 0) throw new Error('vg_ffi_patch_create failed: ' + patch);
const mounts = {json.dumps(mounts)};
const handles = [];
for (let mountIndex = 0; mountIndex < mounts.length; mountIndex++) {{
  const mount = mounts[mountIndex];
  const code = Memory.alloc(mount.code.length);
  code.writeByteArray(mount.code);
  const args = Memory.alloc(Math.max(1, mount.arg_codes.length) * 4);
  for (let i = 0; i < mount.arg_codes.length; i++) args.add(i * 4).writeS32(mount.arg_codes[i]);
  const localSlots = Memory.alloc(Math.max(1, mount.locals.length) * 4);
  const localOffsets = Memory.alloc(Math.max(1, mount.locals.length) * 8);
  const localSizes = Memory.alloc(Math.max(1, mount.locals.length));
  for (let i = 0; i < mount.locals.length; i++) {{
    localSlots.add(i * 4).writeU32(mount.locals[i].slot);
    localOffsets.add(i * 8).writeS64(mount.locals[i].offset);
    localSizes.add(i).writeU8(mount.locals[i].size);
  }}
  const handle = patchInstall(patch, ptr(mount.target), code, mount.code.length,
                              mount.arg_codes.length, args, mount.return_code,
                              mount.action, mount.nature, mount.action_kind, mount.locals.length,
                              localSlots, localOffsets, localSizes);
  if (handle < 0) throw new Error('vg_ffi_patch_install failed: ' + mount.id + ': ' + handle);
  handles.push({{id: mount.id, target: mount.target, handle: String(handle),
                 nature: mount.nature === 1 ? 'read_point' : 'intercept'}});
}}
send({{patch_handle: String(patch), hooks: handles}});
rpc.exports = {{ destroy: () => patchDestroy(patch) }};
''')
        script.load()
        loaded = True
        receipt = {'dsl': str(dsl_path), 'pid': pid, 'hooks': mounts}
        time.sleep(max(0.0, duration))
        try:
            script.exports_sync.destroy()
        except (frida.InvalidOperationError, frida.TransportError):
            receipt['target_gone'] = True
        destroyed = True
        return receipt
    finally:
        if loaded and not destroyed and script is not None:
            try:
                script.exports_sync.destroy()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def main() -> int:
    import threading
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dsl', type=Path, required=True)
    parser.add_argument('--pid', type=int, action='append', required=True)
    parser.add_argument('--duration', type=float, default=5.0)
    parser.add_argument('--bridge', type=Path, default=Path('/tmp/libvg_ffi.so'))
    parser.add_argument('--target-skip', type=int, default=0)
    args = parser.parse_args()
    results = []
    errors = []
    threads = []

    def run_one(pid: int) -> None:
        try:
            results.append(install(args.dsl, pid, args.bridge, args.duration, args.target_skip))
        except Exception as error:
            errors.append({'pid': pid, 'error': repr(error)})

    for pid in args.pid:
        thread = threading.Thread(target=run_one, args=(pid,))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    print(json.dumps({'results': results, 'errors': errors}, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
