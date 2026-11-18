# Linux 用户态部署后验证：实现与 Brotli 实验

日期：2026-11-12。代码入口：`python -m tools.postdeploy`。

当前实现将 Frida 安装、差分符号分析、正常功能输入生成、三方重放、Monitor 和覆盖分析接成一个命令行实验。实例使用会话中标记为 CVE-2026-111497 的 Brotli 修复案例，代码身份由下面两个上游提交固定。实验直接运行上游 Brotli C 库；Node.js 自带的压缩模块尚未作为运行目标接入。

- 原版：`34f020fa9daba975747b29885314c2545b7aa040`。
- 官方修复版：[0ed4268a4401abcb4472096340477cf4af7d1a2b](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)。
- 官方修复版编码器产生全部压缩输入；输入变异发生在原文、压缩质量和流式调用安排上。

## 1. 实际运行顺序

1. 启动等待请求的应用 worker，安装真实 Frida observer/guard，保存安装回执。
2. 读取安装字节码，生成真实 VM 与表达式摘要的等价性查询。对全部 64 位标量快照求解；只有等价性和附加检查全部成功，才允许使用摘要。
3. 将 gate 插入经 C 编译器预处理的真实函数入口，生成原版与补丁版共享输入、独立局部对象的成对执行。
4. 从编译器调用图核对声明的验证根和应用根与挂点的关系。相关根和调用祖先写入 `plan.json`。
5. 根据输出规格生成差分关系，运行可达、存在差异、存在相等三类查询。根据求解见证和 guard 谓词细分区域。
6. 重放应用回归用例和结构化随机变异；再根据实际快照与差分见证的距离、覆盖增量选择父用例，生成进一步的正常功能变异。
7. 每个输入分别在原版、真实 Frida 补丁版、官方修复版运行。Monitor 比较功能结果并重放观察表和真实 VM。
8. 比较原版与补丁版相同 ELF 的精确执行序列和覆盖边，保存总报告及每个 episode 的证据。

整个流程由 `tools/postdeploy/runner.py` 驱动。应用适配器负责输入编码、worker 协议、输出规格和类型化初始状态。验证器中没有按 CVE 或软件名称分支的逻辑。

## 2. 补丁如何实际执行

`experiments/postdeploy/brotli/configure.py` 生成 `policy.bin`、`patch.json`、`actions.json`、`guard.json`。受限标量表达式经 `tools/postdeploy/expressions.py` 编译为现有 VM 接受的 eBPF 指令；实际判定由 `runtime/vm.c` 执行。

挂载安排：

- observer：指定调用点之前的寄存器参数准备区间，读取当时的 `*available_in`。
- guard：真实 `WriteRingBuffer` 入口，以调用后的返回 PC 限定为选中的调用点。
- 私有 map：以线程和 state 地址为键记录样本；guard 消费一次后删除。
- BLOCK：执行动作目录中的固定整数返回动作。

ELF 符号、源位置和 DWARF 用于解析地址、栈槽和类型布局。当前定位器面向 Linux x86-64、保留符号和帧指针的研究构建。它验证了调用前存在足够长度的寄存器准备区间，以免改写 CALL 本身而改变返回 PC。没有把这个定位器推广为任意优化二进制的变量恢复器。

只有显式 observer 更新样本。读取失败会删除可确定键上的旧样本；键本身不能恢复时，对应 scope 保持失效并在 guard 处执行 BLOCK。诊断单独记录，补丁的动作只有 PASS/BLOCK。内部 VM 保留现有诊断枚举，Frida 将非 PASS 的诊断结果映射到 BLOCK。

## 3. 差分符号分析的实现

`tools/postdeploy/product.py` 从实际预处理源码定位函数，按安装 manifest 生成参数读取、观察表读取及固定返回动作。Brotli 字段使用带 `offsetof` 和字段宽度静态断言的类型化访问，避免字节偏移别名使求解式膨胀。运行版和符号版使用相同布局。

`tools/postdeploy/symbolic.py` 使用 CBMC。首先对真实 VM 建立过程摘要证明：

```text
任意 scalar snapshot：
  VM(安装字节码, snapshot) ∈ {PASS, BLOCK}
  VM(安装字节码, snapshot) == 摘要(snapshot)
```

该查询运行真实 `runtime/vm.c`，保留内存、指针、展开、移位和有符号溢出等检查。通过后，成对程序使用已证明的摘要，减少解释器路径与应用路径相乘造成的开销。证明未通过时不启用摘要。摘要不是预先给出的功能影响范围。

成对执行保留原函数正文及适配器中返回后的结果提取。比较器按输出字段逐项生成，避免直接比较指针地址或结构体 padding。对于区域 R，执行以下查询：

| 查询 | 寻找的条件 | 无解时的解释 |
|---|---|---|
| reach | R 中存在完整执行 | 当前边界下不可达 |
| diff | R 中存在可观察输出差异 | 当前区域输出不变 |
| equal | R 中存在输出相等 | 已知非空区域中的输出全部改变 |

同时存在相等和差异时，尝试使用完整 guard 或其中的比较谓词切分。切分预算耗尽则保留 mixed；超时、展开不完整或附加检查失败则保留 unresolved。这些区域继续属于潜在影响范围。

源码产品、编译命令、GOTO 文件、CBMC 原始 JSON、查询见证和分类结果均保留在 `symbolic/`。

## 4. Brotli 符号结论的范围

本实验的符号根是 `symbolic_adapter.c` 中的类型化入口状态适配器，调用真实 `WriteRingBuffer`。源码包含真实上游 `decode.c`，没有重写一份输出函数模型。

输入范围：

| 字段 | 范围 |
|---|---|
| 已产生位置 | 0..16 |
| 剩余块长度 | 0..4 |
| 暂存占用 | 0..8 |
| 同一输入对象中的未读长度 | 0..8 |
| 当前输入量 | 0..2 |
| 输出容量 | 0..16 |

ring 和输出各为独立 16 字节对象。输出比较包含返回码、剩余输出容量、累计输出、state 中的输出位置与轮次、输出指针相对位移、16 个输出字节。

这是入口局部状态上的差分结论。该状态域没有证明从完整流式解码入口可达；完整流式接口由后续 native 功能测试执行。报告分别记录这两个范围，`whole_operation_symbolic_proof` 和 `vulnerability_sufficiency_proof` 均为 false。

这次实现验证的是补丁部署后的功能影响。漏洞充分性需要另行建立目标安全契约、完整调用前缀/续体和相应可达性证明，不能从正常语料全部通过或入口局部差分结果推导出来。

## 5. 功能 Fuzz、Monitor 和覆盖

初始语料包括空输入、单字节、文本、JSON、中文、全字节数据和重复数据，组合不同压缩质量和输入/输出分块；还包括首轮零输出容量后继续解压的调用安排。

新增变异始终重新调用官方修复版编码器。引导调度优先选择实际状态接近差分见证、同时提供覆盖增量的正常用例，变异其分块与输出安排。这个距离是调度启发式，不是入口状态到压缩输入的逆映射。没有命中的影响类记录为 `unvisited_impact_regions`。

Monitor 分三层：

- 功能：原文与输出一致、输入消耗量、输出长度、返回/错误码；同一用例与原版、官方修复版比较。
- 状态：观察事件顺序、map set/get/consume、样本到 VM slot 的映射、episode 结束时 map 是否为空。
- 执行：用独立进程中的真实原生 VM 重放快照，比较判定和指令数；检查进展界限与诊断。

覆盖来自真实解码库的 GCC `-fsanitize-coverage=trace-pc`，trace runtime 自身不插桩。记录模块相对 PC、相邻 PC 边和完整顺序，比较相同 ELF 的原版与补丁版。官方修复版代码布局不同，只参加功能结果比较。

统计包括请求级边出现频率、精确 McNemar 和 BH 校正，标记为探索性指标。trace 缓冲溢出的请求明确排除，不计入完整覆盖结论。

## 6. 当前实现边界

| 能力 | 当前状态 |
|---|---|
| 实际 Frida 安装及自动触发验证 | 已实现 |
| 精确字节码、真实 VM、显式观察 map | 已实现 |
| VM 过程摘要的等价性验证 | 已实现 |
| 真实函数的成对符号分析、自动区域分类 | 已实现 |
| 编译器调用图及声明根关联检查 | 已实现 |
| 正常功能测试、差分/覆盖引导变异、Monitor | 已实现 |
| 配对路径覆盖与频率报告 | 已实现 |
| 任意应用初始状态和协议自动推断 | 由应用适配器提供 |
| 任意全局状态和对象图的自动双世界克隆 | 尚未实现；当前要求独立局部对象契约 |
| 完整 Brotli 流式调用前缀的符号可达性 | 尚未证明 |
| 任意多 guard、多表的符号组合 | 当前产品生成器支持一个 guard、一张显式观察表 |
| Node.js 自带 Brotli 的进程内实测 | 尚未执行 |
| 优化二进制、并发状态隔离、内部指令挂点在线卸载 | 当前实验未覆盖 |

这是可运行的科研流水线和明确范围的实例；后续扩展直接沿应用状态建模和验证根范围进行。

## 7. 复现

在 Linux 仓库根目录执行。需要 GCC/binutils、Python、CBMC 6.11.0 的 `cbmc`/`goto-cc`/`goto-instrument`；三个 CBMC 程序位于同一目录。

```bash
python3 -m pip install -r requirements-postdeploy.txt pytest
python3 -m runtime.frida.build --output build/frida-linux --with-fixture
python3 experiments/postdeploy/brotli/fetch.py --output build/postdeploy-sources/brotli
python3 experiments/postdeploy/brotli/build.py \
  --sources build/postdeploy-sources/brotli --output build/postdeploy-brotli
python3 experiments/postdeploy/brotli/configure.py \
  --output build/postdeploy-brotli --bridge build/frida-linux/vulgate_frida.so
python3 experiments/postdeploy/brotli/profile.py --cbmc /absolute/path/to/cbmc
python3 -m tools.postdeploy --profile build/postdeploy-brotli/profile.json \
  --output build/postdeploy-brotli/run-new
python3 experiments/postdeploy/brotli/negative_control.py
```

输出目录必须为新目录，避免覆盖历史实验。`negative-control` 目录也只创建一次；重复负对照可指定另一个已配置的实验构建目录。

本机 WSL 的 Python 依赖目录为 `/tmp/vulgate-frida-deps-20261111`，运行命令使用 `PYTHONPATH` 指向它。该临时目录需要在环境重建后重新安装。

回归测试：

```bash
VULGATE_FRIDA_BUILD="$PWD/build/frida-linux" \
VULGATE_CBMC=/absolute/path/to/cbmc \
python3 -m pytest tests/test_postdeploy.py tests/test_frida_backend.py -q
```

测试包含字节码编译与原生 VM 的边界值一致性、过度拦截、错误输出、观察重放错误、不完整覆盖、求解附加义务失败，以及跳过输出参数初始化的早返回例子。最后一个例子中，返回码相同而输出参数不同，差分分析仍会报告改变。
