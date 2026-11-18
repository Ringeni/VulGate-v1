# native_ffi: independent INT3 Shadow-VM bridge

Frida is used only to attach and `Module.load`. The hook engine is an
independent INT3/SIGTRAP implementation in `ffi_bridge.c`; no funchook,
libffi closure, or Frida Gum hook is used.

## Build

```sh
python native_ffi/build.py --output build/ffi
```

Output:

```text
build/ffi/libvg_ffi.so
```

No third-party hook library is linked.

## Usage

```sh
python native_ffi/ffi_run.py \
  --dsl runtime/dsl/patches/CVE-2026-27654.vg \
  --pid 1234 \
  --duration 5 \
  --bridge build/ffi/libvg_ffi.so
```

Multi-process:

```sh
python native_ffi/ffi_run.py \
  --dsl patch.vg --pid 1234 --pid 1235 --duration 5
```

## Hook mechanism

```text
target entry byte -> 0xCC
SIGTRAP handler -> run VM from ucontext
BLOCK -> set RAX, pop return address, continue caller
PASS/observer -> restore first byte, single-step, reinsert 0xCC
```

This avoids prologue relocation entirely. It works on
`ngx_http_map_uri_to_path` and `ngx_http_copy_filter`, where funchook,
Subhook, and Dobby failed to execute their replacement.

## Verified

- guard PASS/BLOCK;
- observer;
- map set/get/present/take;
- dynamic u64 key;
- caller local;
- callsite read_point equivalent;
- multiple hooks on the same target (processed in install order);
- uninstall;
- multi-process;
- invalid ABI error;
- target exit;
- bounded `for`;
- release build.

## Multi-hook targets

Multiple hooks may share one entry. The SIGTRAP handler runs them in install
order, so an observer can populate a map before a guard on the same function
reads it. The original 111497 observer+guard pair now runs unchanged.

## Replacements

```text
CVE-2026-93479 -> runtime/dsl/patches_alt/CVE-2026-93479-rewrite.vg
```

The 93479 fine-grained action still hangs; the replacement is a safe coarse
return at `ngx_http_rewrite_handler`.

## Local preload verification

`int3_driver.c` loads the bridge and installs an unconditional BLOCK hook at
`ngx_http_map_uri_to_path` before nginx starts; no Frida is involved.

Real nginx 1.31.6 result:

```text
/files/file.txt -> 500
/plain          -> 200
```

This confirms the INT3 engine handles the entry that funchook, Subhook, and
Dobby could not replace.

## Performance

nginx 1.31.6, BLOCK 42945, 32 threads:

| mode | run 1 RPS | run 2 RPS |
|---|---:|---:|
| baseline | 1005.6 | 950.9 |
| INT3 | 886.0 | 863.4 |
| Frida | 837.1 | 883.3 |

INT3 is in the same range as Frida; the third load window expired and is not
used.

## Hot-patch behavior

Writing `0xCC` does not suspend the process. Threads already inside the
function continue; only a thread that fetches the patched entry traps into the
SIGTRAP handler. The handler runs the VM and either returns the action or
single-steps the original instruction.

The install order is: install SIGTRAP handler, publish hook, write `0xCC`,
serialize. Uninstall sets the hook inactive, restores the original byte, and
removes the target reference.

This is not a stop-the-world patcher. Patching/unpatching while another thread
is entering the target is inherently racy; a production deployment that
requires strict atomicity should quiesce threads around install/uninstall or
use a dedicated patching agent.

## Current limits

- x86-64 Linux only;
- SIGTRAP hook adds per-hit signal overhead;
- 42533 / 60005 / 97205 execute BLOCK but the target function does not map it
  to a standard HTTP 500/503;
- 20/20 patches install through INT3; the behavior matrix is in
  `native_ffi/MATRIX.md`.
