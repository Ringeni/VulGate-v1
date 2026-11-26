# Patch DSL → VulGate Shadow VM

`runtime/dsl/` 将补丁 DSL 编译成 `runtime/vm.c` 可执行的 eBPF 子集字节码，
通过 Frida bridge 安装到用户态进程；执行引擎固定为 VulGate Shadow VM。

## 文件

| 文件 | 作用 |
|---|---|
| `parser.py` | DSL → `PatchSpec` |
| `vm.py` | behavior/selector/表达式 → VM 字节码 |
| `resolve.py` | 自动补 `offset`、解析 `global("...")` 绝对地址 |
| `vm_run.py` | Frida bridge + `vg_program_create` / `vg_run` / `Interceptor.replace` |
| `run.py` | 统一 CLI（Shadow VM） |
| `patches/*.vg` | 20 个 CVE 补丁 |
| `vm_validate.py` | 合成 fixture 的 VM 验证 |

## 用法

```sh
# 解析/显示挂载点
python -m runtime.dsl.run --dsl patch.vg --check

# 安装到运行中进程（默认 VM）
python -m runtime.dsl.run --dsl patch.vg --pid 1234 --duration 30

# spawn 并安装
python -m runtime.dsl.run --dsl patch.vg --spawn ./target --duration 30
```

## VM 编译

- 每个 mount 生成 `r0=0`（PASS）或 `r0=1`（BLOCK）的 VM 程序；
- `argN` → `get_arg` helper；
- `vg_read_u8/u16/u32/u64/pointer` → `safe_read_*` helper；
- `global("x")` → 安装期解析成绝对地址常量；
- 比较/逻辑/算术 → 条件跳转/ALU；
- BLOCK 后由安装器执行 action 返回值，PASS 调原函数。

## 标志位修复

`repair_point` 用于上游修复只需更新函数参数里的标志位、随后继续原函数的场景。

```text
mount example:
{
    location: symbol="script_step", args=[pointer], return=void
    nature: repair_point
    build_id: "0123456789abcdef0123456789abcdef01234567"
    behavior:
    {
        clear_arg_u8(arg0, 64, 0x08);
    }
}
```

安装器先比对主程序 ELF Build ID，再用 Frida 更新一个字节中掩码指定的位。其他位与相邻字段保留，原程序照常执行。每个修复点执行一次操作，字节偏移范围为 `0..4095`，掩码范围为 `1..255`。

- 函数入口支持 `clear_arg_u8(argN, offset, mask)`，参数须声明为 `pointer`。已核对的模块相对入口偏移可以写在 `location.offset`，支持对应的 stripped 构建。
- x86-64 指令位置使用 `address(symbol="...", offset=...)`。支持 `set_reg_u8(reg, offset, mask)`、`clear_reg_u8(reg, offset, mask)` 和 `copy_reg_u8(dst, dst_offset, src, src_offset, mask)`。寄存器名限于 `rbx`、`rbp`、`rsp`、`r12` 到 `r15`。寄存器提供内存基址，指令照常执行。
- 配置编译所需的修复点声明 `requires_spawn: true`。此类补丁用 `--spawn` 在恢复目标进程前挂载。需要传程序参数时逐个使用 `--spawn-arg=<参数>`。

修复动作由安装器执行。Shadow VM 的拦截判定仍只读。运行结果在 `run` 中报告 `repaired`、`repair-unneeded`、`repair-skipped-null` 或 `repair-error`。构建不匹配时安装在挂载前失败。

## 程序级 map / observer

```text
map limits:
{
    capacity: 16
}

mount observe_limit:
{
    location: symbol="observe_limit", args=[uint64, uint64], return=void
    nature: read_point
    behavior:
    {
        map["limits"]["max_upload"] = arg1;
    }
}
```

- `read_point` 用 `Interceptor.attach` 安装，只写 map，继续原函数；
- 拦截点用 `map["limits"]["key"]` 读取，值进入 guard 条件；
- map 由 `vg_map_pool_create` 创建，observer/guard 共享；
- 字符串 key 在编译期映射为 per-map 的 `u64` key id；
- VM helper：`MAP_SET(9)` / `MAP_GET(10)` / `MAP_PRESENT(11)` / `MAP_DELETE(12)`；
- 动态 u64 key：`map["limits"][arg0]`；
- `map_present("limits", arg0)`：只判断存在；
- `map_take("limits", arg0)`：读取后删除（consume）；
- `local("available_in")`：按 DWARF location 读取 caller 局部变量。

## 位置解析（x86-64）

DSL 不需要写 offset：

```text
location: callsite(caller="caller", callee="callee", line=18)
location: line(file="fixture.c", line=18)
location: address(module="libfoo.so", offset=0x1234)
```

`runtime/dsl/x86.py`：

1. `nm -S` 取 caller/callee 符号地址和函数范围；
2. `objdump -d` 找 caller 内的 `call callee`；
3. `addr2line` 按源码行过滤；
4. `objdump --dwarf=decodedline` 支持 `line(file,line)`；
5. 返回 module-relative offset，安装时加 `module.base`。

callsite observer 用户态验证：

```sh
python -m runtime.dsl.vm_callsite_validate
```

结果：callsite offset `0x11fb`、target `0x4011fb`，observer 写 map，
callee guard BLOCK，fixture `body_calls=0`。

## 验证

```sh
python -m runtime.dsl.vm_validate
python -m runtime.dsl.vm_map_validate
python -m runtime.dsl.vm_callsite_validate
python -m runtime.dsl.vm_brotli_validate
python -m runtime.dsl.vm_php_validate
python -m runtime.dsl.vm_93479_validate
```

服务器最近结果：

- `vm_validate`：**24/24**（111497 / 93479 单独验证）；
- `vm_map_validate`：动态 key + consume，第一次 BLOCK、第二次 PASS，
  `body_calls=1`；
- `vm_callsite_validate`：callsite + `local("available_in")`，`body_calls=0`；
- `vm_brotli_validate`：原始 111497 DSL（callsite + local + 动态 key +
  present/take），`body_calls=0`；
- `vm_php_validate`：PHP 109618 原 DSL 的全局 selector 真实读取，`body_calls=0`；
- `vm_93479_validate`：官方粒度 `check_length + length != 0` 和细粒度 `end - pos < len` 两个版本。

真实 nginx 1.31.6：

- CVE-2026-27654 DAV COPY：204 → 405；
- CVE-2026-93479 dynamic script：200 → 500；
- CVE-2026-42945 rewrite：302 → 500。

## 限制

- VM 只读，安装器的状态修复限于 `repair_point` 的单字节掩码操作；
- DSL→VM 目前支持 20 例子集：无循环；callsite 仅解析直接 call；
- 位置解析只适配 x86-64 Linux；
- map 支持字面量/动态 u64 key；运行时字符串 key 未支持；
- map 仍是程序级全局，没有 thread-scoped；
- caller local 仅支持 DWARF exprloc（reg/breg/fbreg/const/deref）；loclist 未实现；
- Frida 回调仍只适合单线程；
- 自动 offset 依赖可读 ELF + `nm`。
