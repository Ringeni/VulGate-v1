# VulGate-v1

VulGate-v1 的主链是：

```text
DSL 补丁
  ↓ parser.py
PatchSpec / MountSpec / ActionSpec
  ↓ vm.py
Shadow VM 字节码
  ↓ resolve.py + x86.py + dwarf_local.py
绝对地址 / callsite / caller local
  ↓ vm_run.py
Frida bridge（vulgate_frida.so）
  ↓ Interceptor.attach / Interceptor.replace
运行中的用户态进程
```

目标是：

> 输入一个 DSL 补丁，编译成 VM 字节码，自动解析符号和位置，安装到真实进程，并由 VM 返回 PASS/BLOCK。

独立 `libffi + funchook` 原型在当前仓库的 `ffi-backend` 分支，尚未合入 `main`。

---

## 1. DSL → VM 主链实现

### 1.1 解析

`runtime/dsl/parser.py`

把 DSL 解析成：

```text
PatchSpec
  actions: dict[str, ActionSpec]
  maps:    dict[str, MapSpec]
  mounts:  list[MountSpec]
```

每个 mount 包含：

```text
location / args / return_type
nature: intercept | read_point
body
local_recipes
```

### 1.2 编译

`runtime/dsl/vm.py`

每个 mount 编译成一个 VM 程序。

值表达式编译到寄存器/helper：

```text
argN                 → GET_ARG
global("sym")        → 安装期解析成绝对地址常量
vg_read_u8/u16/u32/u64/pointer
                     → SAFE_READ_* helper
算术 / 位运算         → ALU 指令
map[...]             → MAP_SET / MAP_GET
map_present(...)     → MAP_PRESENT
map_take(...)        → MAP_GET + consume
local("x")           → 从 caller frame 读取
```

条件编译成跳转：

```text
if / == / != / < / <= / > / >= / && / || / !
  ↓
条件分支 + block/pass 标签

block("ACTION") → r0 = BLOCK, exit
不返回          → r0 = PASS, exit
```

VM 的返回值：

```text
SHADOW_PASS     0
SHADOW_BLOCK    1
SHADOW_UNKNOWN  2
SHADOW_VM_ERROR 3
```

### 1.3 位置解析

`runtime/dsl/resolve.py`

负责：

1. 从 `/proc/<pid>/maps` 找到 module 路径与 load base；
2. 用 `nm` 解析符号；
3. 把 module-relative offset 转成绝对地址；
4. 解析 `global("...")`；
5. 对 `callsite` / `line` 位置调用 `x86.py`；
6. 对 `local()` 调用 `dwarf_local.py`。

`runtime/dsl/x86.py` 当前只支持 x86-64：

```text
nm -S + objdump call 扫描 + addr2line
DWARF decoded line
```

支持的位置写法：

```text
location: symbol="fn", args=[pointer], return=int64

location: offset=0x1234

location: callsite(
    module="libpd_brotli.so",
    caller="BrotliDecoderDecompressStream",
    callee="WriteRingBuffer",
    line=2426
)

location: line(file="decode.c", line=2426)

location: address(module="libpd_brotli.so", offset=0x1234)
```

`runtime/dsl/dwarf_local.py` 读取：

```text
DW_TAG_variable
DW_TAG_formal_parameter
DW_AT_location
  DW_OP_fbreg / DW_OP_reg / DW_OP_breg / DW_OP_const / deref
```

当前支持 exprloc；loclist 还没有实现。

### 1.4 安装

`runtime/dsl/vm_run.py`

先构建 Frida bridge：

```sh
python -m runtime.frida.build
```

产物：

```text
build/frida-vm/vulgate_frida.so
```

安装流程：

1. 编译 bridge（包含 `runtime/vm.c`）；
2. 对每个 mount：
   - `vg_program_create(bytecode)`；
   - observer：`Interceptor.attach`；
   - guard：`Interceptor.replace`；
   - 用 `NativeFunction` 调用 `vg_run_with_maps`；
   - BLOCK：返回 action；
   - PASS：调用原函数；
3. 输出 target / hits / run。

安装器使用 `NativeFunction` 和显式 `int64`，不依赖 `SystemFunction` 的 `{value, errno}` 包装。

### 1.5 VM 与 map

`runtime/vm.c`

Shadow VM 是 eBPF 子集解释器：

```text
shadow_ctx {
  args[6];
  regs[16];
  maps / map_count;
}

run_ebpf_vm(ctx, program, policy, stats)
```

helper：

```text
GET_ARG
SAFE_READ_U8/U16/U32/U64
GET_REG
SCRATCH_LOAD / SCRATCH_STORE
MAP_SET
MAP_GET
MAP_PRESENT
MAP_DELETE
```

map 是程序级对象：

```text
vg_map_pool_create
vg_run_with_maps
```

observer 和 guard 共享同一个 map pool。

---

## 2. 用法

### 2.1 构建 bridge

```sh
python -m runtime.frida.build
```

### 2.2 检查 DSL

```sh
python -m runtime.dsl.run \
    --dsl runtime/dsl/patches/CVE-2026-42945.vg \
    --check
```

### 2.3 安装到运行中进程

```sh
python -m runtime.dsl.run \
    --dsl runtime/dsl/patches/CVE-2026-42945.vg \
    --pid 1234 \
    --duration 30
```

### 2.4 spawn 并安装

```sh
python -m runtime.dsl.run \
    --dsl runtime/dsl/patches/CVE-2026-15176.vg \
    --spawn ./nginx \
    --duration 30
```

### 2.5 显式指定 bridge

```sh
python -m runtime.dsl.run \
    --dsl patch.vg \
    --pid 1234 \
    --bridge-dir build/frida-vm
```

注意：

- 让 `--duration` 自然到期，不要用 `pkill` 强行结束；
- 强行中断 Frida detach 可能破坏目标进程；
- 当前没有常驻 daemon / uninstall 子命令。

---

## 3. DSL 功能与格式

### 3.1 action

```text
action REJECT:
{
    return_type: int64
    return: -1
}
```

支持字段：

```text
return_type
return
errno（可选）
```

`return_type` 支持：

```text
pointer / int / uint / int64 / uint64 / void / string
```

当前 VM 只读，不支持 action writes。

### 3.2 mount

```text
mount CVE-2026-27654/ngx_http_dav_copy_move_handler:
{
    location: symbol="ngx_http_dav_copy_move_handler",
              args=[pointer],
              return=int64
    nature: intercept
    behavior:
    {
        if (true) {
            return block("NGX_HTTP_405_RETURN");
        }
    }
}
```

字段：

| 字段 | 说明 |
|---|---|
| `location` | `symbol` / `offset` / `callsite` / `line` / `address` |
| `args` | 目标函数参数类型 |
| `return` | 目标函数返回类型 |
| `nature` | `intercept` 或 `read_point` |
| `behavior` | VM 行为程序 |

### 3.3 行为语句

```text
value["x"] = <expr>;
map["name"][key] = <expr>;
map_take("name", key);
map_present("name", key);
return block("ACTION");
```

表达式支持：

```text
argN
global("symbol")
vg_read_u8 / u16 / u32 / u64 / pointer / s32
local("name")
算术 + - * / %
位运算 & | ^ << >>
比较 == != < <= > >=
逻辑 && || !
```

### 3.4 有界 for 循环

支持固定上界的计数循环：

```text
for (i = 0; i < 4; i++) {
    map["seen"][i] = 1;
}
```

约束：

- 上界必须是编译期常量；
- `0 < 迭代次数 <= 256`；
- 目前只支持 `i++`、从 0 开始；
- 不支持嵌套循环；
- 循环变量可用于 map key/表达式；
- 循环体内目前支持 map 赋值，不支持任意局部变量/action writes。

VM 侧不是简单展开，而是生成官方 eBPF 风格的有界后向跳转：

```text
<set loop var>
MOV  r10, count
L:  <body>
    <increment loop var>
    SUB  r10, 1
    JGT  r10, 0, L
```

`runtime/vm.c` 的 `validate_bounded_backedge()` 会检查：

- 初始化必须是合法常量；
- 循环末尾必须是 `SUB 1` + `JGT 0`；
- 循环体不能修改计数寄存器；
- 只允许这一种受控后向跳转。

VM 还有 `SHADOW_DEFAULT_STEP_LIMIT` 指令预算，作为第二层死循环保护。

验证：

```sh
python -m runtime.dsl.vm_loop_validate
```

### 3.5 map / observer / caller local

map 声明：

```text
map current_input:
{
    capacity: 64
}
```

observer 只写 map，不阻断：

```text
mount observe:
{
    location: symbol="fn",
              args=[pointer],
              return=void
    nature: read_point
    behavior:
    {
        map["state"][arg0] = arg1;
    }
}
```

guard 读取同一 map：

```text
value["seen"] = map_present("state", arg0);
value["v"]    = map_take("state", arg0);
```

`map_take` 是读取后删除；`map_present` 只判断存在。

caller local：

```text
map["current_input"][arg0] = local("available_in");
```

### 3.5 代表性的 observer patch：CVE-2026-111497

```text
map current_input:
{
    capacity: 64
}

action BROTLI_REFILL_FATAL:
{
    return_type: int
    return: -9
}

mount before_refill:
{
    location: callsite(
        module="libpd_brotli.so",
        caller="BrotliDecoderDecompressStream",
        callee="WriteRingBuffer"
    )
    nature: read_point
    behavior:
    {
        map["current_input"][arg0] = local("available_in");
    }
}

mount refill_capacity:
{
    location: module="libpd_brotli.so",
              symbol="WriteRingBuffer",
              args=[pointer, pointer, pointer, pointer, int],
              return=int
    nature: intercept
    behavior:
    {
        value["remaining"]  = vg_read_s32(arg0 + 132);
        value["occupied"]   = vg_read_u64(arg0 + 80);
        value["capacity"]   = 8;
        value["next_in"]    = vg_read_pointer(arg0 + 24);
        value["last_in"]    = vg_read_pointer(arg0 + 40);
        value["sample_present"] = map_present("current_input", arg0);
        value["available_in"]   = map_take("current_input", arg0);

        if (value["remaining"] <= 2147483647 &&
            (value["sample_present"] == 0 ||
             value["occupied"] > value["capacity"] ||
             value["last_in"] < value["next_in"] ||
             (value["occupied"] == 0 &&
              value["last_in"] - value["next_in"] > value["capacity"]) ||
             (value["occupied"] > 0 &&
              value["occupied"] == value["capacity"] &&
              value["last_in"] > value["next_in"] &&
              value["available_in"] > 0))) {
            return block("BROTLI_REFILL_FATAL");
        }
    }
}
```

这个例子覆盖：

- callsite observer；
- caller local `available_in`；
- 动态 u64 key `arg0`；
- 程序级 map；
- `map_present` / `map_take`；
- guard 返回 int。

真实 brotli worker 上已验证：

```text
baseline: result=1, error=1, produced=352
patched:  result=0, error=-9, produced=0
```

---

## 4. 选用的 20 个漏洞补丁

当前 `runtime/dsl/patches/` 中选了以下 20 个 CVE：

| # | 漏洞 | 应用 | 挂载函数 | 当前验证状态 |
|---:|---|---|---|---|
| 1 | CVE-2026-15176 | nginx | `ngx_http_map_uri_to_path` | 已验证：`/files/file.txt` 200 → 500 |
| 2 | CVE-2026-27654 | nginx | `ngx_http_dav_copy_move_handler` | 已验证：DAV COPY 204 → 405 |
| 3 | CVE-2026-42055 | nginx | `ngx_http_proxy_v2_create_request` / `ngx_http_grpc_create_request` | 已验证：`/h2proxy`、`/grpc` 502 → 500 |
| 4 | CVE-2026-42533 | nginx | `ngx_http_map_variable` | 已命中且 BLOCK 执行；HTTP 仍为 200（该返回 -1 未改变状态） |
| 5 | CVE-2026-42945 | nginx | `ngx_http_rewrite_handler` | 已验证：BLOCK 500；PASS 变体 302 |
| 6 | CVE-2026-47360 | httpd | `proxy_handler` | 已验证触发：internal redirect run=1（HTTP 404 由 ErrorDocument 决定） |
| 7 | CVE-2026-56153 | httpd | `xlate_out_filter` | 已验证：charset 请求 200 → 500 |
| 8 | CVE-2026-56154 | httpd | `lookup_variable` | 已验证：`Location: ...?x=` |
| 9 | CVE-2026-56449 | httpd | `pcomment` | 已验证：条件注释被删除 |
| 10 | CVE-2026-57941 | httpd | `h2_c1_setup` | 已验证：HTTP/2 连接失败 |
| 11 | CVE-2026-60005 | nginx | `ngx_http_regex_exec` | 已触发 run=1（SSI set subrequest）；HTTP 层仍 200 |
| 12 | CVE-2026-63292 | httpd | `mva_translate` | 已验证：vhost 请求 200 → 414 |
| 13 | CVE-2026-63686 | httpd | `xml2enc_ffunc` | 已验证：xml 请求 200 → 500 |
| 14 | CVE-2026-9256 | nginx | `ngx_http_rewrite_handler` | 已验证：500 |
| 15 | CVE-2026-93479 | nginx | `ngx_http_script_check_length` | **未通过**：真实 nginx 下请求挂住 |
| 16 | CVE-2026-93546 | httpd | `dav_method_proppatch` | 已验证：PROPPATCH 207 → 503 |
| 17 | CVE-2026-97205 | nginx | `ngx_http_copy_filter` | 已验证触发：SSI + proxy_store + aio_write，run=1；HTTP 000（action -1 断流） |
| 18 | CVE-2026-109618 | PHP | `rfc1867_post_handler` | 已验证：multipart 解析被阻断 |
| 19 | CVE-2026-109619 | PHP | `php_session_rfc1867_callback` | 已验证：fresh session 下 files 正常、progress=false |
| 20 | CVE-2026-111497 | brotli | callsite → `WriteRingBuffer` | 已验证：error=-9 |

说明：

- 20 个 patch 都已经完成过安装；
- 上表“已验证”只表示在当前真实应用路径上观察到了预期效果；
- `93479` 仍未通过；
- `109619` 在 fresh session 下已验证通过；
- `93479` 的 coarse 替代版本在 `runtime/dsl/patches_alt/CVE-2026-93479-rewrite.vg`：
  hook `ngx_http_rewrite_handler`，返回 500，不需要 action writes；已验证真实 nginx 500，但粒度比官方 check_length 条件粗；
- 验证 109619 时必须使用新的 `PHPSESSID`（或开启 `session.upload_progress.cleanup`），否则会读到同一 session 上一次请求遗留的 progress，误判为未生效；
- `60005` 已用 SSI set subrequest 触发 run=1，但 action -1 没有在 HTTP 层体现；
- `97205` 已用 SSI + proxy_store + aio_write 触发 run=1，HTTP 000 是 action -1 断流；
- `42533` 的 guard 已执行 BLOCK，但该函数的返回 -1 没有改变 HTTP 200 结果，不能算 HTTP 层已验证阻断。

### 4.1 写依赖补丁的 return-only 降级

VM 只读，不支持 action writes，因此 3 个写依赖补丁改成 return-only：

```text
CVE-2026-93479:
  ngx_http_script_check_length + length != 0
  return -1
  另有 patches_fine/CVE-2026-93479.vg（end - pos < len）

CVE-2026-42945 / CVE-2026-9256:
  ngx_http_rewrite_handler
  return 500
```

这是有意的语义降级，不等于原始字段写补丁。

---

## 5. DSL → VM → Frida 性能

测试环境：

```text
nginx: 1.31.6, master_process off
injector: Frida 17.26.2 / Python 3.12
请求: GET /rewrite/ordinary
补丁: CVE-2026-42945
负载: 32 线程，5 s 采样
```

方法：

- baseline / VM 各跑 5 次；
- 取中位数，并给 min–max；
- 每次前 warm-up；
- VM 安装后等待 2 s；
- patch 自然结束，不强制 pkill。

结果：

| 模式 | RPS 中位数 | RPS min–max | p95 中位数 | p99 中位数 | HTTP |
|---|---:|---:|---:|---:|---|
| baseline | 974.34 | 900.77–1045.92 | 70.82 ms | 98.76 ms | 302 |
| DSL→VM→Frida | 864.97 | 853.58–975.07 | 78.43 ms | 103.13 ms | 500 |

结论：

```text
RPS:  -11.2%
p95:  70.82 ms → 78.43 ms
p99:  98.76 ms → 103.13 ms
```

注意：

- baseline 自身波动约 ±7%；
- 该补丁把 302 改成 500，业务路径不同，RPS 差异不完全等于纯 hook 开销；
- 但 VM 相对 baseline 的方向在 5 次运行中稳定；
- 当前未做 CPU 绑核。

更完整结果见 [`PERFORMANCE.md`](PERFORMANCE.md)。

### 5.1 补丁安装耗时

同一 nginx 进程、已有 `build/frida-vm/vulgate_frida.so`、`CVE-2026-42945`：

```text
resolve + compile（5 次）:
  median 27.75 ms
  min    26.05 ms
  max    48.70 ms

CLI 端到端安装（5 次）:
  0.50–0.52 s
  median 0.51 s
```

说明：

- `resolve + compile` 是纯 Python 的 DSL 解析、符号/地址解析和字节码编译；
- CLI 端到端还包括 Python 启动、Frida attach、bridge 加载和 detach；
- 测试使用 `--duration 0.1`，不是长驻安装。

安装耗时命令：

```sh
/usr/bin/time -f '%e' \
  python -m runtime.dsl.run \
  --pid <pid> \
  --dsl runtime/dsl/patches/CVE-2026-42945.vg \
  --duration 0.1
```

---

## 6. 当前限制

- VM 只读，不支持 action writes；
- `for` 只支持固定常量上界、从 0 开始、`i++`，不支持嵌套循环/while/任意局部变量；
- callsite 目前只解析直接 `call`，PLT/内联调用有限；
- 位置解析只适配 x86-64 Linux；
- `local()` 只支持 DWARF exprloc，loclist 未实现；
- map 是程序级全局，没有 thread-scoped 分片；
- Frida 回调仍主要适合单线程路径；
- 没有常驻 daemon / uninstall 子命令；
- 安装失败没有完整事务回滚；
- 真实应用行为覆盖仍不完整：
  - nginx：部分 patch；
  - httpd：部分 patch；
  - PHP：109618 通过，109619 在 fresh session 下通过；
  - brotli：111497 通过；
- 93479 当前仍未通过；
- 60005 已触发 run=1，但 HTTP 层没有体现 action 效果；
- 97205 已触发 run=1，HTTP 000 是 action -1 断流；
- 42533 的 BLOCK 已执行，但 HTTP 层没有观察到阻断效果。

---

## 7. 仓库结构

```text
runtime/dsl/
  parser.py          DSL 解析
  vm.py              DSL → VM 字节码
  resolve.py         符号/地址/global 解析
  x86.py             x86-64 callsite/line 解析
  dwarf_local.py     caller local 解析
  vm_run.py          Frida 安装器
  patches/           20 个 CVE DSL

runtime/vm.c         Shadow VM
runtime/frida/       Frida bridge/build/symbols
tests/               DSL/VM 测试
tools/               性能与同步工具
```
