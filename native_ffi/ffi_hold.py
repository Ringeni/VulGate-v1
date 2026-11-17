"""Install a libffi/funchook hook and hold it for a benchmark window."""
import sys, time
sys.path.insert(0, '/kyz/VulGate-v1')
import frida
from runtime.dsl import parser, vm
from runtime.dsl import vm_run

pid = int(sys.argv[1])
dsl = sys.argv[2]
hold = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0
patch = parser.load(dsl)
mount = patch.mounts[0]
compiled = vm.compile_patch(patch, {})
action = patch.actions.get(compiled.mounts[0].action_id)
action_value = 0 if action is None else int(action.value or 0)
target = vm_run._target_address(pid, mount, None)[0]
code = compiled.mounts[0].code
arg_codes = [{'pointer': 0, 'int': 1, 'uint': 2, 'int64': 3, 'uint64': 4, 'void': 5}.get(kind, 4) for kind in mount.args]
ret_code = {'pointer': 0, 'int': 1, 'uint': 2, 'int64': 3, 'uint64': 4, 'void': 5}.get(mount.return_type, 4)
js = f'''
const lib = Module.load('/tmp/libvg_ffi.so');
const install = new NativeFunction(lib.getExportByName('vg_ffi_install'), 'long',
    ['pointer','pointer','ulong','uint','pointer','int','uint64']);
const uninstall = new NativeFunction(lib.getExportByName('vg_ffi_uninstall'), 'int', ['long']);
const code = Memory.alloc({len(code)});
code.writeByteArray([{','.join(str(b) for b in code)}]);
const args = Memory.alloc({max(1,len(arg_codes))*4});
{''.join(f"args.add({i*4}).writeS32({v});" for i, v in enumerate(arg_codes))}
const h = install(ptr({hex(target)}), code, {len(code)}, {len(arg_codes)}, args, {ret_code}, {action_value});
send({{handle: String(h)}});
rpc.exports.hold = () => {{ return true; }};
rpc.exports.uninstall = () => {{ return uninstall(h); }};
'''
session = frida.get_local_device().attach(pid)
script = session.create_script(js)
script.on('message', lambda m, d: print(m, flush=True))
script.load()
time.sleep(hold)
try:
    script.exports_sync.uninstall()
finally:
    session.detach()
