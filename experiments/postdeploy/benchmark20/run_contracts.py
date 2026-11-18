"""Check independently declared local obligations against the deployed binaries."""
import argparse
import copy
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from tools.postdeploy.contract import prove_gate_contract
from experiments.postdeploy.benchmark20.contracts import CONTRACTS
from experiments.postdeploy.benchmark20.suite import CASES, CBMC


def selected_runs():
    base=ROOT/'build/benchmark20'
    runs={identifier:base/'final-01'/identifier for identifier in CASES}
    runs['CVE-2026-60005']=base/'captures-final/CVE-2026-60005'
    runs['CVE-2026-9256']=base/'rewrite-version-final/CVE-2026-9256'
    runs['CVE-2026-109618']=base/'php-multipart-final'
    runs['CVE-2026-109619']=base/'php-session-final'
    runs['CVE-2026-111497']=base/'brotli-final'
    return runs


def policies(identifier, directory):
    if identifier == 'CVE-2026-111497':
        profile=json.loads((directory/'profile.json').read_text())
        rule=json.loads(Path(profile['guard']).read_text())
        manifest=json.loads(Path(profile['patch']).read_text())
        return [rule],manifest
    manifest=json.loads((directory/'patch.json').read_text())
    if identifier == 'CVE-2026-109619':
        return [{'expression':'True','fields':{}}],manifest
    if identifier == 'CVE-2026-109618':
        return [json.loads((directory/'guard.json').read_text())],manifest
    return json.loads((directory/'policy-source.json').read_text()),manifest


def contract_for(identifier):
    contract=copy.deepcopy(CONTRACTS[identifier])
    if identifier in ['CVE-2026-60005','CVE-2026-15176','CVE-2026-97205']:
        name=CASES[identifier][0]
        layout_file=ROOT/'build/benchmark20'/name/'layout.json'
        offsets=json.loads(layout_file.read_text())
        key={'CVE-2026-60005':'realloc_captures',
             'CVE-2026-15176':'uri_changed','CVE-2026-97205':'blocked'}[identifier]
        bit=offsets['bit.'+key]
        mask=bit['mask']
        contract['layout_evidence']={'file':str(layout_file),'field':key,**bit}
        if key=='realloc_captures': contract['must_block']=f'captures != 0 and (flags & {mask}) != 0'
        elif key=='uri_changed': contract['must_block']=f'alias != 0 and (flags & {mask}) != 0'
        else: contract['must_block']=f'(counter & {mask}) >= {250*(mask & -mask)}'
    return contract


def run(output, cases=None):
    output.mkdir(parents=True,exist_ok=False)
    reports=[]
    for identifier,directory in selected_runs().items():
        if cases and identifier not in cases: continue
        if identifier not in CONTRACTS: continue
        rules,manifest=policies(identifier,directory)
        results=[]
        for index,(rule,guard) in enumerate(zip(rules,manifest['guards'],strict=True)):
            result=prove_gate_contract(rule,guard['rule'],contract_for(identifier),
                {'cbmc':str(CBMC),'timeout':90,'unwind':10,'step_limit':guard.get('step_limit',4096)},
                output/identifier/str(index))
            results.append(result)
        reports.append({'id':identifier,'run_directory':str(directory),'contracts':results,
                        'all_local_contracts_proved':all(r['status']=='unsat' for r in results)})
        print(json.dumps({'id':identifier,'statuses':[r['status'] for r in results]}),flush=True)
    (output/'report.json').write_text(json.dumps(reports,indent=2)+'\n')
    if not all(r['all_local_contracts_proved'] for r in reports): raise SystemExit(1)


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cases',nargs='*')
    args=parser.parse_args()
    run(args.output.resolve(),args.cases)
