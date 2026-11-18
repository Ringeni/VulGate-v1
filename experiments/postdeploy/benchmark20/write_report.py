"""Render the consolidated Chinese research report from archived measurements."""
import argparse
import hashlib
import json
from pathlib import Path


def write_report(directory):
    data=json.loads((directory/'results.json').read_text()); totals=data['totals']; cases=data['cases']
    text=['**20 例 Linux 用户态快速拦截实验：部署、功能影响与充分性证据**','',
      '记录日期：2026-11-13。目录名称保留本轮开始日期 20261112。','',
      f'本轮收集20条公开漏洞记录，完成20套实际部署配置，运行{totals["normal_cases"]}个正常功能用例、{totals["world_executions"]}次三方进程执行。全部案例在真实函数处执行了VulGate VM，监测与VM重放没有诊断错误。{totals["cases_with_impact"]}例观察到正常功能变化，共{totals["affected_normal_cases"]}个用例。',
      '充分性结论：20例的已安装字节码均通过表达式等价证明；其中19例另外完成20项非空局部拦截契约证明。Brotli另有真实源函数的有界差分符号执行。整个CVE的全路径拦截充分性，以及每个动作在调用者继续执行中的安全性，尚未形成20例统一的证明闭包。',
      '材料入口：[部署策略、挂点与原函数diff](PATCHES.zh-CN.md)；[官方patch链接](OFFICIAL_LINKS.zh-CN.md)；[机器可读结果](results.json)；[结果CSV](results.csv)。','',
      '**逐例结果**','',
      '“功能变化”统计基线与官方修复版本均满足正常用例契约，而补丁版本改变了关键输出的样本。分母由本实验的功能组及固定变异组成；它描述本次语料，不能解释为真实业务流量误伤概率。CVSS保留版本与来源；表中优先展示v3.1，没有时展示v4.0。','',
      '|CVE|软件/功能|CVSS（版本；来源）|公开日期|正常功能变化|充分性分类|',
      '|---|---|---|---|---:|---|']
    for c in cases:
        text.append(f'|[{c["id"]}]({c["id"]}/README.zh-CN.md)|{c["topic"]}|{c["cvss_score"]}（{c["cvss_version"]}；{c["cvss_provider"]}）|{c["published"]}|{c["affected_normal_cases"]}/{c["normal_cases"]}|{c["sufficiency_grade"]}|')
    text+=['','分类含义：','',
      '- **局部条件**：拦截判定对应官方新增的拒绝条件，已对安装字节码证明该局部条件必定BLOCK；真实字段绑定和调用者行为另列。',
      '- **条件截断**：在列明的部署前提下，入口阻断使受保护函数体不再执行；目前有源代码对应关系、局部VM证明和正常请求实测，尚无完整程序支配关系与继续执行的形式证明。',
      '- **部分覆盖**：已明确发现当前挂点覆盖之外的官方受影响路径，不能将其记为整个漏洞修复成功。',
      '- **联系待证**：现有局部契约与官方修复主线之间的完整关系尚未建立。','',
      '**实际运行的链路**','',
      '人工阅读漏洞记录和官方修复，确定本轮构建的挂点、只读字段与固定动作目录；将PASS/BLOCK表达式编译为eBPF指令；Frida替换固定ELF/模块中的目标函数入口；进入时只读取此刻的字段；runtime/vm.c解释执行.bin；BLOCK请求独立catalog中的返回动作。随后用同一正常请求驱动原版、动态补丁版、官方修复版，记录输出、路径与VM快照并重放。',
      '这些策略来自独立JSON和字节码文件。此次没有接大模型生成策略，没有把逐CVE判断写进通用VM；逐CVE的函数、字段、动作和功能语料由研究适配器提供。当前C++展示文件是阅读视图，执行链路不经过C++/LLVM eBPF C编译器。',
      'Brotli在明确的before_refill指令处记录available_in，在指定WriteRingBuffer调用上下文消费该记录。其余本轮策略直接读取入口字段或全局字段。这里没有自动生命周期观测。动作只包含PASS/BLOCK；PASS以结束拦截代码表示，BLOCK动作来自固定目录。',
      '六套服务器构建为Nginx 1.29.6/1.31.0/1.31.6/1.31.7与httpd 2.4.68/2.4.71；PHP和Brotli使用记录中的基线/官方提交。实验在本地WSL Linux真实进程上运行。Brotli对象是原生库worker，尚未把这条结果扩写成完整Node.js服务实验；PHP对象是NTS内置HTTP server。',
      '参考Nginx/httpd使用包含官方修复的发布版本，发布版可能带其他更新；每个计入正常样本的基线和参考结果都通过输出对照。单独提取的官方修复用于源码审阅，未伪称每个参考二进制只应用了这一CVE的最小diff。','',
      '**验证到什么程度**','',
      '|环节|本轮实现与证据|',
      '|---|---|',
      '|安装字节码与表达式一致|20例，21个guard。CBMC直接执行实际runtime/vm.c，检查所有标量估值及边界/指针/展开断言。|',
      '|局部拦截义务|19例、20项。检查独立给定的 must_block ⇒ BLOCK，同时检查must_block状态域非空；契约与字节码SHA-256一起保存。|',
      '|源函数差分分析影响范围|Brotli有界WriteRingBuffer适配，得到changed/unchanged分区；本轮另19例没有宣称完成真实请求状态的差分符号执行。|',
      '|正常功能回归与变异|329个正常用例。Brotli有符号区域/路径反馈联动；新增HTTP案例是功能路径组加固定正常头部、查询和值变异，未称为全应用覆盖引导fuzz。|',
      '|部署后Monitor|比较响应、业务字段、同构建路径序列；核对观测和逐条VM决策重放。|',
      '|动作安全性|固定catalog的返回类型/写入在现场运行；尚缺逐例调用者清理、输出初始化、并发状态的通用差分安全证明。|',
      '|整个CVE充分性|0/20建立完整形式证明；每例记录已覆盖条件、源码切断前提和已知遗漏路径。|','',
      '局部契约的例子是length > remaining ⇒ BLOCK。长度门控length != 0能满足这一蕴含；remaining是独立抽象输入。这证明长度门控覆盖了该局部义务，但没有同时证明每条危险路径都到达该门，以及remaining与真实对象剩余容量的对应关系。恒BLOCK策略的局部证明更简单，其功能代价需要由回归给出。',
      '代码回归共20项通过，包括真实Frida类型化返回/固定写入、表达式编译、VM重放、差分影响区分以及“遗漏输出初始化”的检测。新增负向契约测试确认过宽放行产生SAT，空条件域不会被接受为成功充分性证明。完整输出见[pytest日志](pytest-final.log)。','',
      '**关键实验发现**','',
      'PHP上传进度策略最能说明为什么不能只看状态码：18个用例均继续返回200，文件内容保持一致，其中6个进度上传用例丢失进度状态。业务Monitor检出了这一差异。更粗的multipart入口策略影响12/18个用例，正常字段或文件数据直接缺失。',
      'HTML注释门控同样可以保留200状态，却改变响应内容。路径统计还能显示没有输出差异的内部执行变化；反过来，少数插桩模块的路径统计不变，也不保证功能输出相同。PHP multipart本例的覆盖探针位于session.c，因此它不是multipart函数体的覆盖测量。',
      'Brotli、Nginx AIO、alias和captures四例在当前正常语料中没有功能变化，且没有正常请求命中BLOCK。它们的零误伤观测应和未命中拒绝分支一起报告。Brotli的影响区域没有被正常语料访问，官方块切换修复与当前容量门控之间的关系仍需补齐。',
      '本轮采用若干明显更粗的入口策略。虚拟主机路径展开、DAV更新、字符集转换、rewrite、HTTP/2代理等功能可以被整体限制，换取简单的函数体切断。先前六例细粒度示意仍保留，当前数字只描述本目录中的实际运行变体。','',
      '**官方补丁筛选与版本修正**','',
      '每例保存原始CVE记录、命名评分来源、官方提交、生产文件diff与hunk分类。额外调试断言、纯注释和独立并发修复被单列为adjacent；保留官方语义hunk内部的格式变化。筛选结果用于审阅；新增筛选未逐一建立可独立构建的最小修复闭包。未入选的48005来源记录单独存放在excluded-research/，不参与20例统计。',
      'PHP两例共享大型安全改造提交。当前依赖保留审阅集是110个文件、716个hunk，其中174个仍标为待归属；不能把它说成两个已经精确分离的最小CVE补丁。旧713-hunk材料保留作历史，默认对照使用dependency-preserving版本，参考程序使用完整官方提交。',
      'CVE-2026-9256已从不在该公告现代受影响范围内的1.29.6改为1.31.0并重新运行。CVE-2026-60005的ncaptures读取已更正为64位，位掩码从构建布局读取；最终报告采用重跑结果。h2_session_process入口候选因持续重试被淘汰，最终采用新建session之前的h2_c1_setup。','',
      '**复查与复跑**','',
      '每个CVE目录含：deployment/中的可安装JSON、固定动作与.bin；policy.bpf.demo.cpp阅读视图；entry-equivalent.diff原函数视图；evidence/中的三方请求与coverage；contracts/中的本地证明；source-binding-review.json字段对应；provenance-check.json记录输入哈希复核。绝对路径的installed-manifest.json保留原安装配置，patch.json使用同目录相对字节码路径。',
      f'归档复核了{totals["recorded_input_hashes_verified"]}项运行记录中的输入哈希；二进制及模块通过artifact_pins另行固定。构建归档位于build-records/，实现快照位于source-snapshots/。大体积二进制保留在VulGate的build/中。',
      '从VulGate仓库目录在Linux执行；下面的输出目录需使用尚不存在的新目录。CBMC路径由suite.py固定，Frida依赖路径是本次安装位置。','',
      '```sh',
      'export PYTHONPATH=/tmp/vulgate-frida-deps-20261111',
      'export VULGATE_CBMC=/mnt/d/Codex/2026-11-03/goal-042fb9fb-01ec-4a00-960b-c95a63665f9e/work/general-implementation/reproducible-toolchain-v3/cbmc/usr/bin/cbmc',
      'python3 experiments/postdeploy/benchmark20/build.py',
      'python3 experiments/postdeploy/benchmark20/suite.py --output build/benchmark20/new-http-run',
      'python3 experiments/postdeploy/benchmark20/php_multipart.py --output build/benchmark20/new-multipart-run',
      'python3 experiments/postdeploy/php_session/run.py --cbmc "$VULGATE_CBMC" --output build/benchmark20/new-session-run',
      'python3 -m tools.postdeploy --profile build/postdeploy-brotli/profile.json --output build/benchmark20/new-brotli-run',
      '```','',
      '归档脚本run_contracts.py和export_results.py的selected_runs()固定了本轮最终证据集合；重新实验后应显式更新其输入目录。返回值、偏移和模块SHA绑定到此构建，不能直接复制到另一个发行版二进制。',
      '当前最值得继续推进的是：为已标出缺口的策略补齐入口集合；对Brotli重新建立官方缺陷与门控的对应；把19例尚未接入的真实应用状态差分分析加入同一验证链，随后缩小有明确功能损失的粗粒度策略。']
    (directory/'REPORT.zh-CN.md').write_text('\n'.join(text)+'\n')
    # The archive index hashes finished files only; it is not a signature.
    hashes={str(path.relative_to(directory)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.rglob('*')) if path.is_file() and path.name!='SHA256SUMS.json'}
    (directory/'SHA256SUMS.json').write_text(json.dumps(hashes,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'files':len(hashes),'totals':totals},ensure_ascii=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('directory',type=Path)
    write_report(parser.parse_args().directory)
