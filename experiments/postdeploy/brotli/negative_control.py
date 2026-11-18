"""Install a deliberately overbroad policy on the same normal round trip."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools.postdeploy.coverage import summarize
from tools.postdeploy.expressions import compile_guard
from tools.postdeploy.monitors import VMReplay, compare
from tools.postdeploy.process import Worker


def run(folder):
    output = folder / 'negative-control'
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((folder / 'patch.json').read_text())
    code = output / 'always-block.bin'
    code.write_bytes(compile_guard('True', {}))
    manifest['guards'][0]['rule'] = str(code)
    patch = output / 'patch.json'
    patch.write_text(json.dumps(manifest, indent=2) + '\n')
    plain, encoded = output / 'normal.txt', output / 'normal.br'
    plain.write_bytes(b'Ordinary functional compression round trip.\n' * 8)
    subprocess.run([folder / 'encoder', plain, encoded, '5'], check=True)
    results = {}
    for mode in ['baseline', 'patched', 'reference']:
        executable = folder / ('reference' if mode == 'reference' else 'baseline') / 'worker'
        with Worker([executable], output / mode, patch=patch if mode == 'patched' else None,
                    catalog=folder / 'actions.json') as worker:
            results[mode] = worker.execute(f'0 {encoded} {plain} 1 7 1')
    monitor = VMReplay(manifest['bridge'], {manifest['guards'][0]['id']: {'path': code}})
    try: replay = monitor.check(results['patched']['events'])
    finally: monitor.close()
    failures = compare({'expected': {'result': 1, 'matches_expected': True}},
        results['baseline']['outcome'], results['patched']['outcome'], results['reference']['outcome'],
        ['result', 'output_hex', 'consumed', 'produced'])
    coverage = summarize([('0', results['baseline']['outcome'], results['patched']['outcome'])])
    report = {'purpose': 'overblocking sensitivity on one ordinary encoder-produced stream',
              'monitor': replay, 'detected_failures': failures, 'coverage': coverage,
              'outcomes': {k: {n: v for n, v in r['outcome'].items() if n != 'trace'} for k, r in results.items()}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert replay['blocks'] > 0 and not replay['violations']
    assert failures and coverage['lost_edge_union'] > 0
    assert results['patched']['outcome']['error'] == -9
    print(json.dumps({'blocks': replay['blocks'], 'detected_failures': len(failures),
                      'lost_edges': coverage['lost_edge_union']}))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, default=ROOT / 'build/postdeploy-brotli')
    run(p.parse_args().output.resolve())
