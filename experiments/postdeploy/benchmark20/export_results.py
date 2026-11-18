"""Archive measured evidence and render reviewable patch/result documents."""
import argparse
import csv
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from experiments.postdeploy.benchmark20.run_contracts import selected_runs, policies
from experiments.postdeploy.benchmark20.case_notes import NOTES, SOURCES, FIELD_EXPRESSIONS
from tools.postdeploy.expressions import parse, c_expression, compile_guard


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path): return json.loads(Path(path).read_text())
def write(path, obj): Path(path).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')


def copy_evidence(source,destination):
    destination.mkdir(parents=True,exist_ok=True)
    for path in source.iterdir():
        if path.is_file() and (path.suffix in ['.json','.bin','.gz','.md']):
            shutil.copy2(path,destination/path.name)
        elif path.is_dir() and (path.name.startswith('vm-') or path.name=='symbolic'):
            for item in path.rglob('*'):
                if item.is_file() and item.suffix in ['.json','.c','.log','.md']:
                    target=destination/item.relative_to(source)
                    target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(item,target)
        elif path.is_dir() and path.name in ['baseline','patched','reference','corpus']:
            for item in path.rglob('*'):
                if item.is_file() and item.suffix in ['.conf','.log','.body']:
                    target=destination/item.relative_to(source)
                    target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(item,target)


def source_root(identifier, report):
    if identifier=='CVE-2026-111497': return ROOT/'build/postdeploy-sources/brotli/baseline'
    if identifier in ['CVE-2026-109618','CVE-2026-109619']:
        return Path(read(ROOT/'build/postdeploy-php-session/build.json')['baseline']['source'])
    return Path(read(ROOT/'build/benchmark20'/report['baseline']/'build.json')['source'])


def source_diff(identifier, rules, manifest, actions, source):
    changes={}; bindings=[]
    for index,(rule,guard) in enumerate(zip(rules,manifest['guards'],strict=True)):
        filename,function=SOURCES[guard['id']]
        original=(source/filename).read_text()
        pattern=r'(?m)^[ \t]*(?:[A-Za-z_]\w*[ \t]+|\*[ \t]*)*'+re.escape(function)+r'\s*\([^;{}]*?\)\s*\{'
        if function=='rfc1867_post_handler': pattern=r'SAPI_POST_HANDLER_FUNC\(rfc1867_post_handler\)\s*\{'
        matches=list(re.finditer(pattern,original))
        if len(matches)!=1: raise ValueError('source definition not unique: '+function)
        match=matches[0]; line=original[:match.start()].count('\n')+1
        action=actions['actions'][guard['action_id']]
        statements=[]
        if action.get('writes'):
            statements+=['e->ip = (u_char *) &ngx_http_script_exit_code;', 'e->status = 500;']
        kind=action['kind']
        if kind=='return_void': statements+=['return;']
        elif kind=='return_null': statements+=['return NULL;']
        elif kind=='return_string': statements+=['return VULGATE_INSTALL_TIME_EMPTY_STRING;']
        else: statements += [f'return {action["value"]};']
        names=FIELD_EXPRESSIONS.get(guard['id'],{})
        if set(names)!=set(rule['fields']): raise ValueError('field explanation mismatch '+guard['id'])
        condition=c_expression(parse(rule['expression'],rule['fields']),names)
        preface=''
        if guard.get('return_offsets'):
            condition='VULGATE_BOUND_CALLER() && ('+condition+')'
            preface='\n    /* snapshot is consumed from the explicit before_refill observation. */'
        inserted=preface+'\n    /* Entry-equivalent view: deployed through Frida and the VM. */\n'
        inserted+='    if ('+condition+') {\n'+''.join('        '+s+'\n' for s in statements)+'    }\n'
        changes.setdefault(filename,[]).append((match.end(),inserted))
        bindings.append({'hook_id':guard['id'],'function':function,'file':filename,'definition_line':line,
                         'source_sha256':digest(source/filename),'field_expressions':names})
    diff=[]
    for filename,edits in changes.items():
        original=(source/filename).read_text(); revised=original
        for index,text in sorted(edits,reverse=True): revised=revised[:index]+text+revised[index:]
        diff.extend(difflib.unified_diff(original.splitlines(True),revised.splitlines(True),
                    fromfile='a/'+filename,tofile='b/'+filename,n=3))
    return ''.join(diff),bindings


def demo(rules,manifest):
    lines=['// Readable eBPF-style view; executable source is policy-source.json / guard.json.',
           '// BLOCK requests the trusted catalog action. Normal fallthrough is PASS.',
           '#include <cstdint>', 'extern void BLOCK();','']
    if manifest['observers']:
        lines+=['#include <map>',
          'std::map<std::pair<uint64_t, uintptr_t>, uint64_t> current_input;',
          '// Only at the declared before_refill instruction; values come from its binding.',
          'void observe_before_refill(uint64_t tid, uintptr_t state, uint64_t available_in) {',
          '    current_input[{tid, state}] = available_in;', '}',
          '// At the bound guard: find (tid,state), copy value/presence into slots, erase it.',
          '// The real runtime uses its declared bounded map; no implicit lifecycle observer.','']
    for index,rule in enumerate(rules):
        fields=rule['fields']
        lines+=['struct Snapshot_'+str(index)+' {']
        lines+=['    uint64_t '+name+';' for name in fields]
        lines+=['};',f'void guard_{index}(const Snapshot_{index}& s) {{']
        predicate=c_expression(parse(rule['expression'],fields),{name:'s.'+name for name in fields})
        lines+=['    if ('+predicate+') BLOCK();','}','']
    return '\n'.join(lines)


def normalized(identifier,report):
    if identifier=='CVE-2026-111497':
        count=len(report['cases']); affected=sum(bool(x['failures']) for x in report['cases'])
        vm=report['symbolic_resolved']; controls=report['functional_pass']
    elif identifier=='CVE-2026-109619':
        count=sum(x['cases'] for x in report['groups'].values())
        affected=sum(x['affected'] for x in report['groups'].values())
        vm=report['vm_summary']['status']=='unsat'
        controls=all(not any(f.get('world') in ['baseline','reference'] for f in x['failures']) for x in report['cases'])
    else:
        count=report['normal_cases']; affected=report['affected_normal_cases']
        proofs=report.get('vm_proofs',[report.get('vm_proof')])
        vm=all(x['status']=='unsat' for x in proofs); controls=report['all_normal_controls_pass']
    return count,affected,vm,controls


def export(workspace):
    out=workspace/'outputs/benchmark20-20261112'
    inventory=read(out/'inventory.json'); runs=selected_runs()
    output_rows=[]; official_lines=['**20 例官方修复链接与筛选记录**','']
    patch_lines=['**20 例挂载点、策略与函数入口 diff**','',
      '运行输入是 JSON 标量表达式，编译为 eBPF 指令后交给 runtime/vm.c。下面的 C++ 只用于阅读，未通过 C/eBPF C 编译器；函数 diff 是部署行为的等价视图。',
      'PASS 由正常结束表达；BLOCK 只请求固定 action_id，对象写入和返回值由独立 catalog 提供。Brotli 的调用点过滤、观测快照与固定空字符串在 diff 中保留运行时占位符。','']
    snapshots=out/'source-snapshots'; snapshots.mkdir(exist_ok=True)
    current_files=list((ROOT/'experiments/postdeploy/benchmark20').glob('*'))
    current_files += list((ROOT/'tools/postdeploy').glob('*.py'))
    current_files += [ROOT/p for p in ['runtime/frida/agent.js','runtime/vm.c','runtime/autoshield.h',
                        'tests/test_postdeploy.py','tests/test_frida_backend.py']]
    for path in current_files:
        if path.is_file():
            target=snapshots/path.relative_to(ROOT); target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(path,target)
    shutil.copy2(ROOT/'build/benchmark20/pytest-final.log',out/'pytest-final.log')
    for version in ['nginx-1.29.6','nginx-1.31.0','nginx-1.31.6','nginx-1.31.7','httpd-2.4.68','httpd-2.4.71']:
        target=out/'build-records'/version; target.mkdir(parents=True,exist_ok=True)
        for name in ['build.json','layout.json','configure.log','trace.log','trace-io.log']:
            path=ROOT/'build/benchmark20'/version/name
            if path.exists(): shutil.copy2(path,target/name)
    provenance=[]
    for case in inventory['cases']:
        identifier=case['id']; directory=runs[identifier]; report=read(directory/'report.json')
        print('archiving '+identifier,flush=True)
        folder=out/identifier; evidence=folder/'evidence'; copy_evidence(directory,evidence)
        rules,manifest=policies(identifier,directory)
        manifest_origin=Path(read(directory/'profile.json')['patch']) if identifier=='CVE-2026-111497' else directory/'patch.json'
        catalog_origin=manifest_origin.parent/'actions.json'; actions=read(catalog_origin)
        deployment=folder/'deployment'; deployment.mkdir(exist_ok=True)
        shutil.copy2(manifest_origin,deployment/'installed-manifest.json')
        shutil.copy2(catalog_origin,deployment/'actions.json')
        write(deployment/'policy-source.json',rules)
        for index,guard in enumerate(manifest['guards']):
            origin=Path(guard['rule'])
            if not origin.is_absolute(): origin=manifest_origin.parent/origin
            assert compile_guard(rules[index]['expression'],rules[index]['fields'])==origin.read_bytes()
            shutil.copy2(origin,deployment/f'guard-{index}.bin')
            guard['rule']=f'guard-{index}.bin'
        write(deployment/'patch.json',manifest)
        diff,bindings=source_diff(identifier,rules,manifest,actions,source_root(identifier,report))
        (folder/'entry-equivalent.diff').write_text(diff)
        (folder/'policy.bpf.demo.cpp').write_text(demo(rules,manifest))
        write(folder/'source-binding-review.json',bindings)
        local=[]
        if identifier!='CVE-2026-111497':
            group='contracts-revised-final' if identifier in ['CVE-2026-9256','CVE-2026-109618'] else 'contracts-final'
            contract_source=ROOT/'build/benchmark20'/group/identifier
            for path in contract_source.rglob('*'):
                if path.is_file() and path.suffix in ['.json','.c','.log']:
                    target=folder/'contracts'/path.relative_to(contract_source)
                    target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,target)
            for path in sorted(contract_source.glob('*/contract-result.json')):
                result=read(path); assert result['status']=='unsat' and result['nonvacuity_status']=='sat'
                index=int(path.parent.name)
                assert result['bytecode_sha256']==digest(deployment/f'guard-{index}.bin')
                local.append(result)
        count,affected,vm,controls=normalized(identifier,report)
        assert controls and vm and report['monitor']['diagnostics']==0
        assert report['monitor']['decisions']>0
        title,grade,gate,scope,damage=NOTES[identifier]
        metric=next((m for m in case['qualifying_metrics'] if m['version']=='3.1'),case['qualifying_metrics'][0])
        hashes=report.get('source_hashes',report.get('input_hashes',{}))
        if identifier=='CVE-2026-111497': hashes=read(directory/'input-hashes.json')
        verified=[]
        for name,expected in hashes.items():
            source=Path(name)
            if source.name=='suite.py' and digest(source)!=expected:
                source=directory.parent/'source-snapshot/suite.py'
            if not source.is_file() or digest(source)!=expected: raise ValueError('provenance mismatch '+name)
            target=folder/'recorded-inputs'/source.name
            target.parent.mkdir(exist_ok=True); shutil.copy2(source,target)
            verified.append({'original':name,'sha256':expected,'archive':str(target.relative_to(out))})
        write(folder/'provenance-check.json',{'verified':verified,'verified_count':len(verified)})
        provenance.extend(verified)
        row={'ordinal':case['ordinal'],'id':identifier,'product':case['product'],'topic':title,
             'published':case['published'][:10],'cvss_score':metric['score'],'cvss_version':metric['version'],
             'cvss_provider':metric['source'],'normal_cases':count,'affected_normal_cases':affected,
             'vm_proved':vm,'local_contracts_proved':len(local),'whole_cve_sufficiency_proved':False,
             'sufficiency_grade':grade,'sufficiency_scope':scope,'gate':gate,'functional_damage':damage,
             'monitor':report['monitor'],'coverage':report['coverage'],
             'original_run':str(directory),'baseline':report.get('baseline','commit-pinned build'),
             'reference':report.get('reference','official commit-pinned build'),
             'official_fixes':[x['url'] for x in case['official_fixsets']]}
        write(folder/'result.json',row); output_rows.append(row)
        case['status']={'native_run':'completed','sufficiency':grade,'whole_cve_proved':False,
                        'functional_impact':f'{affected}/{count}','result':'result.json'}
        write(folder/'case.json',case)
        links='；'.join(f'[{f["commit"][:12]}]({f["url"]})' for f in case['official_fixsets'])
        reviewed=read(folder/'official-review.json')
        fixname='dependency-preserving-security.patch' if case['product']=='PHP' else 'official-security.diff'
        text=[f'**{identifier} — {title}**','',
            f'公开日期 {row["published"]}；CVSS {metric["score"]}（v{metric["version"]}，{metric["source"]}）。',
            f'官方提交：{links}。完整来源记录：[CVE JSON](cve.json)。',
            f'官方筛选：[diff]({fixname})；[hunk筛选记录](official-review.json)。','',
            gate,scope,damage,'',f'正常用例 {count}，功能变化 {affected}；VM决策 {report["monitor"]["decisions"]}，BLOCK {report["monitor"]["blocks"]}。',
            f'充分性分类：**{grade}**。标量VM等价证明通过；局部拦截契约 {len(local)} 项通过。整个CVE充分性未建立。',
            '正常功能结果按响应内容、状态、完整性或PHP业务字段比较；路径统计独立记录。','',
            '[真实部署配置](deployment/patch.json) · [字节码来源](deployment/policy-source.json) · [固定动作](deployment/actions.json) · [完整结果](result.json) · [逐请求报告](evidence/report.json)','',
            '拦截代码阅读视图：','```cpp',demo(rules,manifest),'```','',
            '原函数入口等价 diff：','```diff',diff,'```','',
            '运行来源与覆盖限制：',f'- 基线：`{row["baseline"]}`；参考：`{row["reference"]}`。',
            '- 原始运行目录：`'+str(directory)+'`。',
            '- 原函数diff用于审阅；实际安装的是 deployment 中的JSON和.bin。',
            '- 真实返回动作及调用者继续执行的通用差分安全性证明，尚未在这些入口逐例完成。']
        if identifier=='CVE-2026-109618': text+=['- 本例覆盖探针来自 session.c，不能作为 multipart handler 本体的路径覆盖。']
        if case['original_six']: text+=['- 保留先前六例设计；本次除Brotli外，均应按本目录的部署变体解释，不能把粗入口策略当成原精细策略的测量结果。']
        if case['product']=='PHP': text+=['- 官方两例共享716-hunk/110文件的依赖保留审阅集，含174个待归属hunk；未拆成两个已验证的最小修复。参考程序使用完整官方提交。']
        (folder/'README.zh-CN.md').write_text('\n\n'.join(text)+'\n')
        official_lines += [f'**{identifier}**：{links}。筛选记录 [{reviewed.get("included_files",reviewed.get("files"))} 个文件]({identifier}/official-review.json)。','']
        patch_lines += [f'**{identifier} — {title}**','',gate,
                       f'[完整代码、原函数diff与官方对照]({identifier}/README.zh-CN.md)','',
                       f'正常功能变化 {affected}/{count}；充分性：{grade}。{scope}','']
    totals={'cases':len(output_rows),'normal_cases':sum(r['normal_cases'] for r in output_rows),
            'affected_normal_cases':sum(r['affected_normal_cases'] for r in output_rows),
            'world_executions':3*sum(r['normal_cases'] for r in output_rows),
            'cases_with_impact':sum(r['affected_normal_cases']>0 for r in output_rows),
            'vm_decisions':sum(r['monitor']['decisions'] for r in output_rows),
            'vm_blocks':sum(r['monitor']['blocks'] for r in output_rows),
            'local_contract_proofs':sum(r['local_contracts_proved'] for r in output_rows),
            'whole_cve_proofs':0,'recorded_input_hashes_verified':len(provenance)}
    write(out/'results.json',{'as_of':'2026-11-13','totals':totals,'cases':output_rows})
    write(out/'inventory.json',inventory)
    columns=['ordinal','id','product','published','cvss_score','cvss_version','cvss_provider','normal_cases',
             'affected_normal_cases','vm_proved','local_contracts_proved','whole_cve_sufficiency_proved','sufficiency_grade','gate']
    with (out/'results.csv').open('w',encoding='utf-8-sig',newline='') as file:
        writer=csv.DictWriter(file,fieldnames=columns,extrasaction='ignore'); writer.writeheader(); writer.writerows(output_rows)
    (out/'OFFICIAL_LINKS.zh-CN.md').write_text('\n'.join(official_lines))
    (out/'PATCHES.zh-CN.md').write_text('\n'.join(patch_lines))
    print(json.dumps(totals,ensure_ascii=False),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--workspace',type=Path,required=True)
    export(parser.parse_args().workspace)
