"""Initial normal round-trip check for the real internal Frida binding."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools.postdeploy.process import Worker

folder = ROOT / 'build/postdeploy-brotli'
plain = folder / 'smoke.txt'
encoded = folder / 'smoke.br'
plain.write_bytes(b'Ordinary functional compression round trip.\n' * 8)
subprocess.run([folder / 'encoder', plain, encoded, '5'], check=True)
receipt = {}
for mode in ('baseline', 'patched', 'reference'):
    worker = folder / ('reference' if mode == 'reference' else 'baseline') / 'worker'
    with Worker([worker], folder / ('smoke-' + mode),
                patch=folder / 'patch.json' if mode == 'patched' else None,
                catalog=folder / 'actions.json') as process:
        result = process.execute(f'1 {encoded} {plain} 1 7 1')
        (folder / ('smoke-' + mode) / 'result.json').write_text(json.dumps(result) + '\n')
        summary = {k: v for k, v in result['outcome'].items() if k not in ('trace', 'output_hex')}
        summary['trace_points'] = len(result['outcome']['trace'])
        summary['events'] = len(result['events'])
        summary['agent_errors'] = [e for e in result['events'] if e.get('type') == 'error']
        decisions = [e['payload'] for e in result['events'] if e.get('payload', {}).get('event') == 'decision']
        summary['blocks'] = sum(d['action'] == 'BLOCK' for d in decisions)
        receipt[mode] = summary
print(json.dumps(receipt, indent=2))
