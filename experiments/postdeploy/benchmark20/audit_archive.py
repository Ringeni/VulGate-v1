"""Cross-check archived reports against installed bytes and native evidence."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from tools.postdeploy.expressions import compile_guard


def read(path): return json.loads(path.read_text())
def version(text): return tuple(int(n) for n in text.split('.'))


def within(value,entry):
    if entry['status']!='affected': return False
    if value < version(entry['version']): return False
    if 'lessThan' in entry: return value < version(entry['lessThan'])
    if 'lessThanOrEqual' in entry: return value <= version(entry['lessThanOrEqual'])
    return value == version(entry['version'])


def audit(directory):
    data=read(directory/'results.json'); inventory=read(directory/'inventory.json')
    assert len(data['cases'])==20 and len({r['id'] for r in data['cases']})==20
    assert {r['id'] for r in data['cases']}=={r['id'] for r in inventory['cases']}
    metadata={r['id']:r for r in inventory['cases']}
    hashes={}; checks=[]
    for row in data['cases']:
        folder=directory/row['id']; case=metadata[row['id']]
        assert case['state']=='PUBLISHED'
        assert any(m['score']>=7 and '/AV:N/' in m['vector'] for m in case['qualifying_metrics'])
        if row['baseline'].startswith(('nginx-','httpd-')):
            product='NGINX Open Source' if row['product']=='Nginx' else 'Apache HTTP Server'
            record=next(a for a in case['affected'] if a['product']==product)
            assert any(within(version(row['baseline'].split('-')[1]),entry) for entry in record['versions']),row['id']
        deployment=folder/'deployment'; manifest=read(deployment/'patch.json')
        rules=read(deployment/'policy-source.json'); actions=read(deployment/'actions.json')['actions']
        for guard,rule in zip(manifest['guards'],rules,strict=True):
            assert guard['action_id'] in actions
            assert compile_guard(rule['expression'],rule['fields'])==(deployment/guard['rule']).read_bytes()
        for filename,expected in manifest['artifact_pins'].items():
            if filename not in hashes: hashes[filename]=hashlib.sha256(Path(filename).read_bytes()).hexdigest()
            assert hashes[filename]==expected,filename
        episodes=list((folder/'evidence').glob('*.json.gz'))
        assert len(episodes)==row['normal_cases'],row['id']
        monitors={'decisions':0,'blocks':0,'diagnostics':0}
        for path in episodes:
            with gzip.open(path,'rt') as file: episode=json.load(file)
            assert set(episode['executions'])=={'baseline','patched','reference'}
            monitor=episode.get('replay',episode.get('monitor'))
            assert not monitor.get('violations')
            for key in monitors: monitors[key]+=monitor[key]
        assert all(row['monitor'][k]==v for k,v in monitors.items()),row['id']
        contracts=list((folder/'contracts').glob('*/contract-result.json'))
        assert len(contracts)==row['local_contracts_proved']
        for path in contracts:
            result=read(path)
            assert result['status']=='unsat' and result['nonvacuity_status']=='sat'
            assert result['whole_program_sufficiency'] is False
            assert hashlib.sha256((deployment/f'guard-{path.parent.name}.bin').read_bytes()).hexdigest()==result['bytecode_sha256']
        checks.append({'id':row['id'],'episodes':len(episodes),'guards':len(rules),
                       'local_contracts':len(contracts),'artifact_pins':True,'monitor_totals':True})
    result={'status':'passed','cases':checks,'normal_episodes':sum(x['episodes'] for x in checks),
            'world_executions':3*sum(x['episodes'] for x in checks),'unique_pinned_artifacts':len(hashes),
            'note':'Evidence consistency and affected release-range audit; not a new whole-CVE sufficiency proof.'}
    (directory/'archive-audit.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('directory',type=Path)
    audit(parser.parse_args().directory)
