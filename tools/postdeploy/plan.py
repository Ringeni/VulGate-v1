"""Compiler call-graph evidence for declared application and symbolic roots."""
import json
import re
import subprocess


def discover(tool, binary, spec, output):
    result = subprocess.run([str(tool), '--call-graph', str(binary)],
                            capture_output=True, text=True, check=True, timeout=60)
    (output / 'callgraph.txt').write_text(result.stdout)
    edges = sorted(set(re.findall(r'^([\w.$:]+) -> ([\w.$:]+)$', result.stdout, re.M)))
    hook = spec['hook_function']
    ancestors = {hook}
    while True:
        expanded = ancestors | {caller for caller, callee in edges if callee in ancestors}
        if expanded == ancestors: break
        ancestors = expanded
    symbolic_root = spec.get('root', 'pd_application')
    if symbolic_root not in ancestors:
        raise ValueError('declared symbolic root does not reach the installed hook in compiler call graph')
    roots = spec.get('operation_roots', [])
    report = {'hook': hook, 'symbolic_root': symbolic_root,
              'declared_operation_roots': roots,
              'related_operation_roots': sorted(set(roots) & ancestors),
              'unrelated_operation_roots': sorted(set(roots) - ancestors),
              'ancestor_functions': sorted(ancestors),
              'scope': 'compiler-resolved call graph; symbolic execution uses the declared typed adapter root',
              'automatic_world_cloning': False}
    (output / 'plan.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
