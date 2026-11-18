import argparse
import json
from pathlib import Path

from .runner import run

parser = argparse.ArgumentParser(description='VulGate post-deployment research experiment')
parser.add_argument('--profile', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
report = run(json.loads(args.profile.read_text()), args.output)
print(json.dumps({k: report[k] for k in ('pipeline_completed', 'functional_pass', 'symbolic_resolved', 'monitor', 'coverage')}, indent=2))
raise SystemExit(0 if report['functional_pass'] and report['symbolic_resolved'] else 1)
