# Linux 用户态补丁部署后自动验证：实现方案

日期：2026-11-12。

实现进展：可运行代码及实际范围见 [POSTDEPLOY_IMPLEMENTATION.md](POSTDEPLOY_IMPLEMENTATION.md)。本文件保留完整设计蓝图；当前符号根采用独立局部对象的类型化适配器，尚未完成任意全局对象的双世界克隆。

本文给出下一阶段的实现方案。现有代码已经完成 Frida 用户态安装、原生 VM 执行，以及 CBMC 验证基础设施；本文新增的自动差分计划、应用功能测试和部署后覆盖分析尚待实现。实现以科研实验为目标，使用命令行、进程和文件，无需界面、生产发布系统或运维平台。

## 1. 方法与最终实验形态

一次实验以固定应用构建、固定补丁及应用功能规格为输入，执行：

```text
Frida 安装补丁，获得安装回执
  → 自动构造原程序/补丁程序的成对符号执行
  → 计算可能受影响的输入类、程序位置和可观察结果
  → 生成按类分层的正常功能测试
  → 在实际 Frida 补丁进程中运行测试并执行 Monitor
  → 比较原程序与补丁程序的功能结果、路径覆盖和频率
  → 输出分类结论、可复现功能差异、未覆盖的验证义务
```

研究问题是：对一个已安装的入口拦截补丁，哪些正常功能可能受到影响，哪些影响确实发生，影响能否由其声明的拒绝契约解释。

采用两类证据：

- 验证类：成对符号执行、输入类判定、有限区域穷举和实际执行一致性检查。
- 检测类：功能请求的成对重放、分层 property fuzzing、运行时 Monitor、路径覆盖及分布变化。

验证单位为一次操作或一段有界操作序列，称为 episode。接口身份、初始应用状态、输入序列和环境选择共同定义 episode。不同程序复用同一验证算法；应用适配器提供该程序的操作入口、输入结构和结果提取方式。

第一版选择源码可得的 Linux x86-64 C 程序、顺序 episode，以及现有 Frida 可安装的入口返回动作。编译、插桩和进程重启均可用于实验。多线程程序可以使用已明确的串行请求模式；未建模的并发调度不计入符号结论。

## 2. 实验者提供什么，系统自动做什么

### 应用级输入：每个应用配置一次

`ApplicationProfile` 包含以下信息，不包含某个补丁的影响条件：

| 字段 | 含义 |
|---|---|
| build | 源码、编译命令、ELF 与调试信息 |
| operations | 对外操作名、请求边界及源码处理入口集合 |
| input_schema | 输入结构、字段类型、长度关系、有效协议编码、最大 episode 长度 |
| fixture | 可重建的配置、文件、数据库及启动状态 |
| nominal | 独立定义的正常业务操作类别及允许的成功/错误结果 |
| observations | 对外返回、输出参数、响应、文件或业务状态、资源状态的提取规则 |
| environment | 时间、随机、外部服务等所需的可重复实验环境及符号模型 |
| corpus | 应用回归用例或已知正常的操作序列 |

应用适配器使用统一接口：

```python
class ApplicationAdapter:
    def reset(self, fixture_id): ...
    def encode(self, operation, structured_input): ...
    def execute(self, worker, episode): ...
    def observe(self, worker, episode): ...
    def symbolic_setup(self, schema, fixture, bound): ...
```

函数库使用 typed C driver；命令行程序使用 argv/stdin adapter；HTTP 程序使用结构化请求编码和响应解析 adapter。复杂应用的初始化与协议规格需要一次性接入；更换该应用的补丁时，系统重新生成验证计划，不逐补丁重写 harness 或 Monitor。

### 补丁级输入

使用既有 `manifest + bytecode + action catalog`，补充精确构建绑定、观察点源位置和实际安装回执。完整 DSL 必须先得到可执行字节码。补丁仅选择候选点、观察绑定和拦截策略，BLOCK 动作由目录确定。

漏洞信息用于绑定目标安全属性及解释预期的拒绝行为。本文的功能测试种子来自应用功能规格和正常回归输入。

### 系统自动产生

1. 相关操作根、调用者续体、相关状态与源码位置集合。
2. 两个程序版本及共享输入的符号 driver。
3. 差分判定式、输入区域分类与每类求解结果。
4. 可编码的功能测试种子、测试优先级和路径目标。
5. 依据同一观察规格生成的符号比较器与 native Monitor。
6. 路径覆盖、请求结果及资源变化报告。

这里的“通用”指算法和生成器复用。接口的业务含义来自应用规格，例如一个返回 200 的空响应是否正确，需要由响应契约定义。

## 3. 统一补丁语义，连接现有 Frida 后端

现有 `agent.js` 保留挂点和 ABI 参数传递职责；将观察表的 set/delete/lookup 及固定返回动作选择迁入原生 `runtime/experiment/patch_state.c`。运行版与符号版编译同一份状态转移代码、真实 `runtime/vm.c` 和同一份字节码。

第一版采用固定容量、64 位键和值的简单表，显式占用标记，容量写入实验配置。set、delete 只发生在 manifest 指定的观察点；满表、读取失败和预算耗尽保留运行诊断，并执行绑定的 BLOCK 动作。没有额外的策略动作，也不自动补出生命周期观察。

```c
void vg_observe(unsigned point_id, const uint64_t args[6]);
vg_result vg_evaluate(unsigned hook_id, const uint64_t args[6]);
/* result = decision(PASS/BLOCK), catalog_action_id, diagnostic */
```

符号版在源码绑定点插入上述调用；native 版由 Frida 在真实绑定点调用它们。符号版的 BLOCK 使用目录生成的 C 返回语句，native 版由返回 ABI adapter 执行相同动作。

通过共享代码缩小两版之间的差异；同时逐次记录实际参数、显式观察事件、动作及 VM 结果，进行运行一致性核对。记录使用实验者指定的字段和有界对象序列化，不能把原始指针值当成跨进程对象身份。

Frida 安装接口新增结构化返回值：

```text
InstallationReceipt = {
  build_id, module_hashes, patch_hash, vm_hash, action_catalog_hash,
  hook_bindings, observation_bindings, adapter_version,
  installation_epoch, installed_hook_count
}
```

`run.py` 在安装成功后直接调用 `run_experiment(receipt, profile)`。科研运行器控制待测进程，在安装完成前不发送 episode；无需异步生产灰度发布系统。

## 4. 自动确定验证入口和影响位置

入口由应用操作根和真实补丁挂点共同确定。设 H 为所有拦截点，O 为显式观察点，R 为 profile 声明的操作根。

1. 从编译后的 GOTO IR 生成调用图及函数指针目标集合。
2. 从 H∪O 反向查找调用祖先，与 R 相交，得到相关操作根。
3. 对有状态操作序列，加入能够执行显式观察更新、影响守卫输入或读取补丁改变状态的操作；迭代至固定点。这样设置状态的操作与消费状态的操作都进入同一个 episode。
4. 对每个相关根，从真实初始 fixture 执行到挂点，保留调用前缀和返回后的调用者续体。
5. 对 guard/返回动作的读写位置做 data/control dependence 传播，得到可能受影响的调用、分支、输出字段和资源事件。
6. 对这些观察量做反向切片，用于安排求解优先级。第一版仍执行完整的相关根及其实际续体，切片不直接删除语义。

不能解析的间接调用加入其类型兼容的保守目标集；如果缺少正文或效果模型，相关查询保留待完成状态。未关联到某操作的挂点仍列在覆盖义务中，不以“没有发现调用者”认定无影响。

入口闭包包含在当前构建和别名分析下所有可能相关的已声明操作根。第一版不把这种闭包当作互不干扰证明来删除其余操作：它们仍参加普通功能对照测试。将来若要裁掉某个操作的符号查询，需要另行证明其与挂点及相关持久状态互不影响。

源码绑定使用 `(build, translation_unit, function, instruction)`；native 入口使用调试符号或相应 module offset。对于非导出入口，需要给当前 agent 增加经过构建绑定的 module-offset 安装方式。内部观察点的变量恢复是额外 adapter 能力；首批实验选择入口参数可表达的观察方案。

## 5. 成对符号执行：自动构造差分问题

为每个操作根构造 `P0` 与 `Pπ`：前者是原程序，后者加入完整补丁、观察状态和真实 VM。

生成器在 GOTO IR 中克隆函数及全局符号为两个命名空间。共享一个符号输入对象、初始 fixture 和环境种子，再按 input schema 深复制成两个互不别名的世界。各世界单独运行初始化、内存分配、观察表和实际操作序列。

```c
Input input = generated_symbolic_input();
assume(application_nominal_domain(input));
World a = initialize_original_world(input, fixture, environment_seed);
World b = initialize_patched_world(input, fixture, environment_seed);
Outcome oa = execute_episode_original(&a, input);
Outcome ob = execute_episode_patched(&b, input);
assert(compare_observables(oa, ob));
```

这是生成产物的逻辑结构；实际代码使用类型化对象构造、独立名字空间和字段比较，不能对包含指针的 World 做字节复制或直接 memcmp。

克隆对象是应用函数、应用全局和环境模型状态；CBMC 的语言内建操作与分配语义保留一套。两世界的对象在同一后端中是不同的分配对象。对象图比较从配对的输出根开始建立有界的别名对应，不依赖分配次序相同。资源和终止义务按世界标记，比较完成后释放各自的实验 fixture，避免把 product 自身持有的两个结果当作应用泄漏。第一版不能处理的对象形态必须在 plan 中列明，不通过浅拷贝绕过。

外部环境采用可重复的状态转移模型，每个世界持有一份初始相同的环境状态。时间、随机、文件和服务响应按照各自模型执行。不能让两个世界无条件共享“第 n 次外部调用”的返回值，因为补丁可能增删调用。确定性的环境模型不足时，记录明确的对应关系或报告该项差分尚未确定。

补丁守卫不能成为正常输入域的定义。正常域来自 application profile；被补丁 BLOCK 的正常输入必须继续进入功能比较，否则会漏掉过度拦截。

### 5.1 观察量与差分定义

`Outcome` 根据 profile 自动生成，包括：

- 返回值、errno、输出参数的有效字段。
- 响应状态及经规格允许归一化的响应内容。
- 对外持久状态：指定文件、记录、业务对象字段。
- 完成/错误/超时事件及资源契约结果。

忽略项只来自显式的应用规格，例如响应中的时间戳；不能因为测试遇到差异就自动忽略它。指针结果比较可观察对象图及别名关系，不能比较两个世界的地址或未经初始化的结构体 padding。原程序执行未定义、符号循环没有展开完成、环境效果不完整，都单独列为未完成义务。

对界限 K 下的正常输入和初始状态 z 定义：

```text
Dsem(z)  = Observable(P0,z) != Observable(Pπ,z)
Dctrl(z) = ProjectedControlTrace(P0,z) != ProjectedControlTrace(Pπ,z)
Daux(z)  = 新出现的初始化、内存、资源或结束契约失败
```

三个量分开输出。控制路径变化可能保持功能结果；功能差异也可能体现在同一粗粒度路径上的输出值变化。动作合法性检查复用现有 `actions/` 与 `protected/` 查询；功能差分增加成对观察比较。

### 5.2 自动计算影响区域

避免要求求解器输出任意程序的封闭形式精确差分条件。采用有限谓词划分与增量细化，得到带证据的影响区域上近似。

初始谓词来自输入 grammar 选择、guard 字节码的数据依赖比较、以及调用者中影响输出/错误处理的分支。对只能在执行中计算的谓词，在基线副本记录其执行事件，使用“未访问/假/真”标签；重复访问按 episode 的事件界限保留序列。分类依据固定基线世界，不使用补丁 PASS 条件来排除 BLOCK 输入。

开始只有一个区域 C=true。对每个区域运行三项查询：

```text
Qreach: exists z. Nominal(z) AND C(z)
Qdiff:  exists z. Nominal(z) AND C(z) AND Dsem(z)
Qequal: exists z. Nominal(z) AND C(z) AND NOT Dsem(z)
```

| 求解结果 | 区域结论 |
|---|---|
| Qreach 不可满足 | INFEASIBLE |
| Qreach 可满足，Qdiff 不可满足 | EQUAL：该类功能结果一致 |
| Qreach 可满足，Qequal 不可满足 | DIFFERENT：该类均有功能差异 |
| Qdiff 与 Qequal 均可满足 | MIXED：类内同时存在改变和保持的输入 |
| 任何必要查询未完成 | UNRESOLVED |

MIXED 区域优先用能区分两组见证的候选谓词二分；选择规则固定为“相关比较优先、表达式规模更小优先、源码编号更小优先”。没有可用谓词或达到预算就保留该区域。相应的运行定义性、循环展开和模型完整性义务通过后，才可以使用不可满足结果给出 EQUAL/DIFFERENT 结论。

```python
regions = [True]
while has_budget():
    c = next_unclassified_region(regions)
    r = solve_region(c, paired_program)
    if r.mixed and can_split(r):
        q = choose_predicate(r.diff_witness, r.equal_witness)
        replace(c, [c & q, c & ~q])
    else:
        record(c, r)
```

最终影响上近似是所有 DIFFERENT、MIXED、UNRESOLVED 区域之并；EQUAL 区域保留为对照测试。分裂始终保留两个子区域，预算耗尽不丢弃输入域。

`impact.json` 自动输出：相关根、位置集合、区域谓词、各项查询、差异见证、受影响的观察字段、模型/界限。整个过程不手写 Nginx 专用 delta。

## 6. 从影响区域自动生成等价类式功能测试

区域是测试分组；只有得到 EQUAL 证明的区域才称为已证明行为保持的类。谓词组合相同本身不意味着所有路径或所有输出等价。

每个可达区域至少保留一个满足域约束的具体种子。抽取符号输入模型后，由同一 input schema 编码成函数参数、argv/stdin 或协议请求。先在 native 基线重放，检查它是否到达预计的区域；不匹配则归入 `MODEL_REPLAY_MISMATCH`，不能当成已覆盖。

初始测试池包括应用正常回归语料、各区域见证，以及等值/相邻值/长度边界的有效变体。生成器的变异对象是结构化字段；每次变异都重新维护长度、字段依赖和协议语法，并满足独立的正常业务前置条件。

默认预算分配可设置为：50% 给可能有差异或尚未确定的区域，25% 给 guard 比较边界，25% 给 EQUAL 区域和未涉及补丁的普通操作。调度依据为：新增正常功能覆盖、未访问区域、未访问 guard 分支、未触发的 Monitor 义务。该比例是实验参数，需在评估中做消融。

符号查询与 Fuzz 通过统一 Case 交换输入：

```text
Case = {case_id, operation_sequence, fixture_id, environment_seed,
        structured_input, expected_nominal_class, region_id, provenance}
```

Fuzz 找到新正常路径后，可以回馈路径涉及的比较，细化尚未确定的区域。它不因单个测试成功把整个类升级为符号等价。

## 7. 在实际 Frida 部署上运行配对实验

准备两个由同一 ELF 启动的 worker：

- B：基线，具有同样的测量设施。
- T：Frida 实际安装待测补丁。

可选第三个官方修复版本 F，仅用于参考功能结果。B 与 T 的基本块身份可直接对应；F 的源码和布局变化后，不直接比较裸路径 ID。

每个 Case 都在相同 fixture、输入及可重复环境下分别运行 B、T。操作序列内部保持状态；不同 episode 之间重建状态，第一版直接重启进程。一个 episode 内，补丁观察表仅由真实显式观察事件推进，不人为注入期望值。

```python
for case in scheduler:
    b = execute_fresh_episode(baseline, case)
    t = execute_fresh_episode(frida_patched, case)
    verdict = monitors.compare(case, b, t)
    coverage.update(case, b.trace, t.trace, verdict)
    scheduler.feedback(case, verdict, coverage)
```

补丁必须在 T 中通过真实应用调用触发。源码中模拟出来的 patched 函数只服务于符号分析，不能代替这个 native 验证对象。

失败结果自动最小化：删除 episode 中不必要的操作、缩小合法字段与长度；每次约简仍验证正常域和可复现性。保存最小功能回归输入、安装回执、状态差异及轨迹。

## 8. Monitor：用什么判断功能是否正确

Monitor 从 `ObservationSpec` 生成两套实现：符号版本产生断言，native 版本提取结果并比较。两者使用相同字段、正常化规则及状态机定义。

| Monitor | 具体检查 |
|---|---|
| M-install | 实际 ELF、规则、动作目录、挂点数量及安装 epoch 与实验计划一致 |
| M-policy | 同一实际观察序列下，原生共享策略核与记录的 PASS/BLOCK/动作一致 |
| M-functional | 正常请求的返回、响应、输出参数与持久结果满足应用契约及配对关系 |
| M-continuation | BLOCK 后调用者完成合法返回、错误响应及清理，不出现额外重复操作 |
| M-progress | episode 在预定实验期限内结束；超时单独记录为可复现的进展异常 |
| M-resource | 指定资源对象的申请、释放和移交符合契约；跨 episode 的保留资源有声明 |
| M-path | 真实操作命中相关入口、区域、返回续体及指定路径事件 |

资源检查第一版使用 adapter 声明的资源以及通用 allocation/fd 事件模板。其对象身份与事件由测量器产生，不作为补丁新增的观察输入；补丁仍只可使用自己声明的显式观察点。框架内部的 buffer、map 等资源与应用资源分别统计。

M-functional 的判定顺序：

1. 检查环境和输入是否属于声明的实验域。
2. 检查独立应用契约及 episode 是否完整结束。
3. 若基线为合法成功而 T 变成拒绝/错误，计为正常功能回归，即使错误码来自合法目录。
4. 若两边均成功但返回内容、状态效果不同，记录具体字段差异。
5. 只有规格预先允许的差异可以被接受；以补丁 guard 自己的判断作为允许条件会形成自证。

对真正需要拒绝的业务类别，由独立规格或官方修复参考给出允许关系。若 F 可用，单独报告 T 对 F 的一致性，以及 T 对 B 的变化。

## 9. 功能路径采集与部署后变化检测

第一版采用编译期插桩，而不是先实现任意二进制的动态路径重建。源码可得的科研对象统一生成测量构建，B 与 T 使用同一份 ELF，补丁仍由 Frida 动态安装。

增加 LLVM `vgtrace` pass：给应用函数中的基本块/CFG 边插入轻量事件，保存 `(module build-id, block-id, source location)` 映射；记录函数入口、正常返回和 profile 定义的请求开始/结束。事件写入预分配的线程缓冲区，保留 errno，不在每个事件处做文件 I/O。框架/Frida/VM 的路径单列，功能覆盖只计算应用路径。

每个 episode 的轨迹按操作边界切分。收集边集合、顺序轨迹、相关调用上下文和循环次数桶。完整轨迹用于复现；压缩签名用于调度和统计，不能凭哈希相同证明轨迹等价。缓冲区溢出或缺少结束事件会把该次覆盖记为不完整。

首版 worker 同时只处理一个 episode，runner 分配 episode/operation ID，profile 指定的开始/结束测量点负责关联事件。异步跨线程请求若需要扩展，必须显式传递关联令牌，不能假设一个线程永远对应一个请求。这套测量关联独立于补丁观察表，不增加补丁能够读取的状态。

符号 GOTO IR 与 native 构建绑定同一源码及 ABI 配置。覆盖插桩是测量代码，符号比较器使用同源的应用逻辑。通过源码映射关联多个优化后的块，并记录匹配歧义。对插桩引入的开销，使用相同测量构建的 B/T 配对，并另测无测量构建的性能开销。

### 9.1 配对重放：第一版的主要检测

对于同一批正常 episode，令 `hitB(i,e)` 与 `hitT(i,e)` 表示第 i 次是否经过边或相关路径 e：

```text
lost(e)   = count(hitB=1 AND hitT=0)
gained(e) = count(hitB=0 AND hitT=1)
functional_regressions = count(基线结果满足正常契约 AND 补丁结果违反对应契约)
```

同时输出覆盖保留比例、丢失的原成功续体、新增错误续体、BLOCK 在正常请求中的比例、成功率与结果差异率。分母包括所有预先选定的正常 episode，不能只保留补丁后仍成功的请求。

路径变化是检测信号，功能契约决定其含义。无输出差异但新出现的错误/重试路径仍保留为待解释变化；全 BLOCK 必须表现为成功续体覆盖下降和功能回归，不能因“有错误返回且没有崩溃”通过。

### 9.2 窗口统计：同一实验里的第二类检测

在固定的接口/正常输入类别比例下产生若干流量窗口，B/T 使用相同 episode 序列。统计单位为独立 episode；有状态操作序列作为一个样本。

第一版可以直接报告各类的 paired loss/gain 和置信区间。需要显著性检测时，对每条预登记的边/路径使用精确 McNemar 检验：只比较 B-only 与 T-only 的 episode 数，进行 BH 多重比较校正，并要求效果量达到预设阈值。

路径特征清单和阈值在基线预热阶段冻结，评估窗口不用于重新选择阈值。对稀有路径追加同类配对重放，区分补丁效应与抽样遗漏。真实在线的非配对流量属于后续扩展；科研第一版通过相同输入与状态控制解释变量。

“正常功能占多数”用于决定正常语料覆盖与检测灵敏度；它本身不把任何一次拒绝判定为正确或错误。

## 10. 调度、文件产物与最终判定

一个命令表达完整实验，下面是拟新增接口：

```sh
python -m tools.postdeploy run \
  --application experiments/arithmetic_service/application.json \
  --patch build/frida/fixture.manifest.json \
  --catalog build/frida/fixture.actions.json \
  --output build/postdeploy/run-001
```

调度状态依次为 `INSTALLED → PLANNED → SYMBOLIC_ANALYZED → REPLAYED → FUZZED → COMPARED → REPORTED`。
符号分析超时时仍保留粗区域并执行功能测试；报告分别保留符号与实测结果。

```text
run-001/
  installation.json       实际安装身份与挂点
  plan.json               操作根、输入/观察规格、界限和比较规则
  impact.json             自动生成的区域及位置影响
  symbolic/               成对程序、查询、完整求解状态和见证
  cases/                  正常语料、符号种子、有效变异和最小回归
  executions/             B/T/F 结果、轨迹、VM 决策、资源事件
  functional.json         功能与续体 Monitor 结果
  coverage.json           类/边/路径覆盖、loss/gain、窗口统计
  report.json             各轴结论与未覆盖义务
```

结果拆成独立字段，而不是一个总 PASS：

```text
symbolic_functional: PROVED_WITHIN_MODEL | DIFFERENCE_FOUND | INCOMPLETE
symbolic_action_safety: PROVED_WITHIN_MODEL | VIOLATION_FOUND | INCOMPLETE
runtime_binding: MATCHED | MISMATCH | INCOMPLETE
functional_tests: NO_REGRESSION_OBSERVED | REGRESSION_FOUND | INCOMPLETE
path_change: NONE_OBSERVED | CHANGE_DETECTED | INCOMPLETE
target_safety: existing verifier result, if requested
```

模型、输入域、边界、观察字段与具体证据随每项结果一起输出。功能 Fuzz 的零违规结果不升级为全输入充分性证明；既有独立目标安全查询继续单独回答目标非法事件是否被消除。

## 11. 新增模块及现有代码复用

| 文件/模块 | 工作 |
|---|---|
| `runtime/frida/run.py` | 安装成功后自动调用实验运行器，返回安装回执 |
| `runtime/frida/agent.js` | 事件关联、原生共享状态核、实际决策记录及精确绑定 |
| `runtime/experiment/patch_state.c` | 显式观察表、诊断与目录动作选择；native/symbolic 共用 |
| `tools/postdeploy/spec.py` | 应用、episode、输入、观察规格 |
| `tools/postdeploy/plan.py` | 调用根及状态依赖闭包，生成计划 |
| `tools/postdeploy/product.py` | GOTO 双副本、独立初始堆、相同输入和观察比较器 |
| `tools/postdeploy/impact.py` | 区域查询、细化与影响上近似 |
| `tools/postdeploy/cases.py` | 求解见证编码、合法变异、区域调度及最小化 |
| `tools/postdeploy/runner.py` | 实际 Frida worker 与基线 worker 的 episode 配对 |
| `tools/postdeploy/monitors.py` | 从共享规格生成符号/native 比较器和契约检查 |
| `runtime/trace/` | LLVM pass、低开销事件 buffer、请求与资源事件 |
| `tools/postdeploy/coverage.py` | 覆盖映射、轨迹特征、配对统计和窗口检验 |
| `tools/postdeploy/report.py` | 组织分项结果和可复现功能差异 |

复用现有 `tools/verification/backend.py`、构建与 typed GOTO 传递、`engine.py` 的动作/完整程序检查、`runtime.py` 的 VM 导出和字节码 lowering。新增 product 查询不能只把 baseline/protected 两次检查的最终状态相减，必须比较同一输入和对应初始状态下的观察结果。

## 12. 分阶段实现及验收

### 第一步：实际部署后的自动配对测试

扩展现有无漏洞 fixture 为有状态整数服务，建立 application profile 和几个操作。Frida install 自动触发 episode runner。先完成结果 Monitor 和实际安装回执。

验收：合法规则保持应保留的正常输出；全 BLOCK 被判为功能回归；错误目录值和缺失观察导致的误拒均被准确归因；卸载后相同输入恢复基线结果。

### 第二步：自动 product 与影响区域

从该 profile 生成两份 GOTO 程序和共享输入，加入真实 VM 与共享 map。加入调用者错误续体、输出参数及两步有状态 episode。差分区域必须自动计算，测试文件不得预置正确 delta。

验收：可识别完全无影响、仅某些输入改变、合法但过宽的 BLOCK、被调用者漏处理的返回值；反向调用链和前序观察操作自动纳入根。求解预算耗尽保留 INCOMPLETE。

### 第三步：功能路径 Fuzz 与测量

实现 vgtrace、区域种子编码、有效变异和 native 重放。并行记录功能结果、区域、原函数体/错误续体、资源及进展事件。

验收：符号见证可以在实际部署进程中重放；等价类式分组引导能增加有效功能路径覆盖；失配报告指向模型、输入编码或绑定层。

### 第四步：跨应用实验及检测

至少接入函数库、命令行程序和 HTTP 服务三种入口形式；同一应用换多个补丁只更换补丁包。完成配对覆盖变化与窗口统计。

验收：全部应用由同一个命令流水线执行；全 BLOCK、阈值过宽、错误返回、遗漏输出初始化、观察陈旧等功能回归变体能被独立 Monitor 或现有安全查询发现。变体在无漏洞 fixture 或正常业务域内构造。

## 13. 论文实验与贡献表述

主要评估问题：

1. 自动选出的根和影响区域能否包含实际功能差异？报告已证明 EQUAL 类的测试结果、差异见证重放率及未确定类比例。
2. 在相同测试时间或 episode 数量下，影响区域引导相比普通正常输入 Fuzz，多发现多少功能回归、多覆盖多少相关路径？
3. Monitor 相比只检查崩溃/返回码，增加发现了哪些输出、状态、清理或进展错误？
4. 路径变化检测相比只统计 BLOCK 比例，何时更早发现某个接口的正常功能退化？
5. 实际 Frida 部署与符号/原生策略核之间有多少绑定或状态传递失配？

比较组：仅普通回归测试、普通 property fuzzing、仅影响区域引导、引导加 Monitor、完整方案。固定输入域、初始 fixture、总时间/样本预算和独立 seed；报告多个 seed 的结果及不确定性。

“影响范围更小”不能单独作为正确性指标：可能是漏建模。应同时报告源码/操作覆盖、模型完整性、符号区域状态以及实际重放结果。新旧版本的全路径等价并非所有补丁的目标；正常功能保持和声明的拒绝行为分别评估。

论文方法可以表述为：**一个以实际动态补丁为验证对象的功能影响分析与测试系统。系统将补丁、显式观察和返回动作编译成成对程序，通过符号差分自动划分功能影响区域，再把这些区域转化为真实部署上的功能测试，并以独立契约和配对路径统计评价补丁的功能影响。**

## 14. 无漏洞例子：系统怎样自动找到一次正常功能回归

采用一个整数计算服务。profile 声明正常操作序列为：

```text
set_limit(key, L)       1 <= L <= 8
calculate(key, n)       0 <= n <= L
期望结果                100 + n
```

`set_limit` 经过显式观察点保存当前 key 对应的 L；`calculate` 调用已有整数计算函数，函数体为返回 `100+n` 并增加一次调用计数。设实验规则计划拒绝 `n > observed_limit`，目录动作是返回 -73。

实验一安装 `n > observed_limit`。生成器自动构造两个调用都存在的 episode，正常域来自 profile。成对求解得到：正常域内不存在功能结果差异；native 测试检查每次结果和函数体调用次数，并验证正常计算续体仍被覆盖。

实验二只把字节码的比较条件改为 `n >= observed_limit`。无需修改 profile、Monitor 或测试程序：

1. 产品程序中的差分查询自动找到 `n=L` 的输入，例如 L=4、n=4。
2. EQUAL 见证可以是 L=4、n=3；区域细化使用已有 guard 比较，并结合正常域，区分 `n<L` 与 `n=L`。
3. 运行器编码 `set_limit(1,4); calculate(1,4)`，在 B 和实际 Frida worker T 中分别运行。
4. B 返回 104，T 返回 -73；M-functional 报告正常功能回归，M-policy 确认字节码确实按其内容执行。
5. M-path 观察到 T 未进入计算函数体，而 B 进入；覆盖报告把此变化关联到同一个 episode 和已求解的区域。
6. 若将规则改成全 BLOCK，所有正常计算结果都失败，系统无法靠“返回值合法”或“进程没有崩溃”通过验收。

这个例子的差异区域由成对查询产生，不在测试中写 `expected_delta=n==L`。前面的具体数值用于展示可能的一次求解结果；实际求解器可以给出满足条件的其他 L、n。

## 15. 完整实现的完成标准

一个版本可以称为论文方法的完整实验实现，需要同时满足：

- 一个命令从真实安装回执出发，自动产生计划、差分查询、测试输入、执行轨迹和结果报告。
- 至少三个结构不同的无漏洞 fixture 通过同一生成器；真实应用接入后，更换补丁不要求重写其业务 profile。
- 差分区域与测试预期由生成器和独立应用规格产生，测试代码没有逐补丁手写答案。
- 功能测试运行的被测对象是实际 Frida 进程，运行轨迹可关联到已安装的规则和目录动作。
- 边界误拒、全 BLOCK、错误返回、输出状态破坏及有状态序列回归有明确的负向验收案例。
- 报告同时保留原程序、符号模型、实际部署三者的覆盖范围与失配，不能用其中一层成功代替另一层。
- 源码/规则/规格变化后重新计算相应结果，既有历史回执保持版本身份，不直接用于新版本结论。
