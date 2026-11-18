"""Run the startup multipart gate on ordinary forms and file uploads."""
import argparse
from contextlib import ExitStack
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT))
from experiments.postdeploy.benchmark20.bindings import symbols
from experiments.postdeploy.php_session.run import corpus, binding
from tools.postdeploy.expressions import compile_guard
from tools.postdeploy.http_process import HTTPWorker
from tools.postdeploy.monitors import VMReplay, compare
from tools.postdeploy.coverage import summarize
from tools.postdeploy.symbolic import prove_vm_summary
from experiments.postdeploy.benchmark20.suite import CBMC


def run(output):
    output=output.resolve(); output.mkdir(parents=True,exist_ok=False)
    inputs=[Path(__file__),HERE/'layout_php.c',HERE.parent/'php_session/run.py',
            HERE.parent/'php_session/router.php',ROOT/'tools/postdeploy/http_process.py',
            ROOT/'tools/postdeploy/monitors.py',ROOT/'tools/postdeploy/expressions.py',
            ROOT/'runtime/frida/agent.js',ROOT/'runtime/vm.c']
    input_hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    folder=ROOT/'build/postdeploy-php-session'
    build=json.loads((folder/'build.json').read_text())
    exe=folder/'baseline/php'; sym=symbols(exe)
    source=Path(build['baseline']['source'])
    subprocess.run(['gcc','-O0','-I.','-IZend','-Imain','-ITSRM',str(HERE/'layout_php.c'),
                    '-o',str(source/'vg_multipart_layout')],cwd=source,check=True)
    offsets=json.loads(subprocess.check_output([source/'vg_multipart_layout'],text=True))
    def global_field(name,offset,kind):
        return {'global':{'module':'php','offset':sym[name]},'reads':[{'offset':offset,'type':kind}]}
    expression='activated == 0 and throws == 0 and uploads == 0'
    fields={name:{'source':'arg','index':i} for i,name in enumerate(['activated','throws','uploads'])}
    code=output/'policy.bin'; code.write_bytes(compile_guard(expression,fields))
    guard={'id':'multipart_startup','module':'php','offset':sym['rfc1867_post_handler'],
        'arg_types':['pointer','pointer'],'return_type':'void','rule':str(code),
        'action_id':'PHP_MULTIPART_RETURN_VOID','vm_args':[
            global_field('core_globals',offsets['modules_activated'],'u8'),
            global_field('sapi_globals',offsets['throws'],'u8'),
            global_field('sapi_globals',offsets['uploads'],'pointer')]}
    manifest={'schema':1,'bridge':str(ROOT/'build/frida-linux/vulgate_frida.so'),
              'maps':{},'observers':[],'guards':[guard],'telemetry':True,
              'artifact_pins':{str(exe):build['baseline']['executable_sha256']}}
    patch,catalog=output/'patch.json',output/'actions.json'
    patch.write_text(json.dumps(manifest,indent=2))
    catalog.write_text(json.dumps({'schema':1,'actions':{'PHP_MULTIPART_RETURN_VOID':{'kind':'return_void'}}},indent=2))
    (output/'guard.json').write_text(json.dumps({'expression':expression,'fields':fields},indent=2))
    proof=prove_vm_summary({'expression':expression,'fields':fields},{'rule_path':str(code)},
                           {'cbmc':str(CBMC),'timeout':90,'unwind':10},output/'vm-proof')
    if proof['status']!='unsat': raise RuntimeError('summary unresolved')
    results=[]; pairs=[]; totals={'decisions':0,'blocks':0,'diagnostics':0}
    with ExitStack() as stack:
        workers={}
        for world in ['baseline','patched','reference']:
            mode='reference' if world=='reference' else 'baseline'
            directory=output/world; state=directory/'sessions'; state.mkdir(parents=True)
            command=[str(folder/mode/'php'),'-n','-d','session.save_path='+str(state),
                '-d','session.upload_progress.enabled=1','-d','session.upload_progress.cleanup=0',
                '-d','session.upload_progress.freq=1','-d','session.upload_progress.min_freq=0',
                '-d','display_errors=0','-d','log_errors=1','-S','127.0.0.1:{port}',
                str(HERE.parent/'php_session/router.php')]
            workers[world]=stack.enter_context(HTTPWorker(command,directory,binding(folder/mode/'php',build[mode]['layout']),
                patch=patch if world=='patched' else None,catalog=catalog))
        vm=VMReplay(manifest['bridge'],{guard['id']:{'path':code,'observations':[]}}); stack.callback(vm.close)
        for case in corpus(output/'corpus'):
            executions={world:worker.execute(case['request']) for world,worker in workers.items()}
            outcomes={world:result['outcome'] for world,result in executions.items()}
            replay=vm.check(executions['patched']['events'])
            if replay['violations']: raise AssertionError(replay['violations'])
            for key in totals: totals[key]+=replay[key]
            fields_check=list(case['expected'])+['progress_bytes']
            failures=compare(case,outcomes['baseline'],outcomes['patched'],outcomes['reference'],fields_check)
            if any(f.get('world') in ['baseline','reference'] for f in failures): raise AssertionError('control failed')
            changed=[key for key in fields_check if outcomes['baseline'][key]!=outcomes['patched'][key]]
            pairs.append((case['id'],outcomes['baseline'],outcomes['patched']))
            with gzip.open(output/('case-'+case['id']+'.json.gz'),'wt') as file:
                json.dump({'case':case,'executions':executions,'replay':replay},file)
            results.append({'id':case['id'],'group':case['group'],'changed_fields':changed,
                'blocks':replay['blocks'],'failures':failures,
                'outcomes':{world:{k:v for k,v in o.items() if k!='trace'} for world,o in outcomes.items()}})
            print(json.dumps({'case':case['id'],'group':case['group'],'changed':changed}),flush=True)
    coverage=summarize(pairs)
    report={'id':'CVE-2026-109618','vm_proof':proof,'monitor':totals,'cases':results,
        'normal_cases':len(results),'affected_normal_cases':sum(bool(r['changed_fields']) for r in results),
        'native_hook_exercised':totals['decisions']>0,'all_normal_controls_pass':True,
        'coverage':{k:v for k,v in coverage.items() if k not in ['paths','edge_tests']},
        'variant':'startup-state gate; broader than previous map/caller-specific example',
        'input_hashes':input_hashes,
        'coverage_scope':'PHP build instruments ext/session/session.c; multipart body coverage is not measured',
        'sufficiency':{'whole_vulnerability_proved':False,'vm_predicate_equivalence':True,
            'scope':'selected automatic multipart initialization path; other OOM paths remain outside this gate'}}
    assert input_hashes=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    (output/'coverage.json').write_text(json.dumps(coverage,indent=2))
    (output/'report.json').write_text(json.dumps(report,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args().output)
