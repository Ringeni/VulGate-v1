# native_ffi：libffi + funchook 独立挂载

Frida 只负责 attach 和 `Module.load`；每次命中的参数打包、原函数调用和 VM 执行都在 C 里完成。

## 构建

```sh
python native_ffi/build.py --output build/ffi
```

产物：

```text
build/ffi/libvg_ffi.so
build/ffi/libfunchook.so.2
```

funchook 源码默认使用 `native_ffi/third_party/funchook`。

## 使用

```sh
python native_ffi/ffi_run.py \
  --dsl runtime/dsl/patches/CVE-2026-27654.vg \
  --pid 1234 \
  --duration 5 \
  --bridge build/ffi/libvg_ffi.so
```

多进程：

```sh
python native_ffi/ffi_run.py \
  --dsl patch.vg --pid 1234 --pid 1235 --duration 5
```

## 已验证能力

- guard PASS/BLOCK；
- observer；
- map set/get/present/take；
- 动态 u64 key；
- caller local；
- callsite read_point 等价实现；
- 多 hook / 同目标双 hook；
- uninstall；
- 多进程；
- 无效 ABI 错误；
- 目标提前退出；
- 有界 `for` 循环；
- release build。

## Coarse return-only replacements

`ngx_http_map_uri_to_path` 和 `ngx_http_copy_filter` 上 funchook 不可靠，
93479 的官方粒度版也会挂住。`ffi_run.py` 会自动把这三个原始 DSL 映射为已验证的
coarse return-only 版本：

```text
CVE-2026-15176 -> native_ffi/patches/CVE-2026-15176-coarse.vg
CVE-2026-97205 -> native_ffi/patches/CVE-2026-97205-coarse.vg
CVE-2026-93479 -> runtime/dsl/patches_alt/CVE-2026-93479-rewrite.vg
```

实测：

```text
15176 -> ngx_http_static_handler -> 500
97205 -> ngx_http_output_filter -> -1
93479 -> ngx_http_rewrite_handler -> 500
```

代价是语义粒度变粗，但不再需要 Frida fallback。

## 当前限制

- x86-64 Linux；
- 精确 instruction-level callsite 仍是语义等价实现；
- 93479 官方细粒度版仍会挂住，使用 `runtime/dsl/patches_alt/CVE-2026-93479-rewrite.vg`；
- 20 patch 的统一行为矩阵尚未固化。
