"""Bounded relational queries and predicate-guided functional region discovery."""
import ast
import copy
import json
from pathlib import Path
import subprocess
import struct
import time

from .expressions import parse, c_expression, evaluate, predicates, compile_guard
from .product import generate, ROOT
from .plan import discover


def parse_result(messages, exit_code):
    results = [p for m in messages for p in m.get('result', [])]
    queries = [p for p in results if p.get('description') == 'pd.query']
    auxiliary = [p for p in results if p.get('description') != 'pd.query' and p.get('status') != 'SUCCESS']
    errors = [m.get('messageText') for m in messages if m.get('messageType') == 'ERROR']
    status = 'unresolved'
    witness = {}
    if len(queries) == 1 and not auxiliary and not errors and exit_code in (0, 10):
        if queries[0]['status'] == 'SUCCESS': status = 'unsat'
        elif queries[0]['status'] == 'FAILURE':
            status = 'sat'
            for step in queries[0].get('trace', []):
                name = step.get('lhs', '')
                if name.startswith('pd_in_'):
                    value = step.get('value', {})
                    try:
                        witness[name[6:]] = int(value['binary'], 2) if 'binary' in value else int(value['data'])
                    except (ValueError, KeyError): pass
    return {'status': status, 'witness': witness, 'auxiliary_failures': auxiliary,
            'errors': errors, 'checked_properties': len(results)}


def query(template, spec, region, kind, directory, instruction_count):
    directory.mkdir(parents=True, exist_ok=True)
    names = {f['name']: 'pd_in_' + f['name'] for f in spec['inputs']}
    constraint = c_expression(parse(region, names), names)
    # Every query executes both worlds. Auxiliary safety/unwind obligations are
    # checked together with the query, including when a witness is found.
    assertion = {'reach': '0', 'diff': '!pd_diff', 'equal': 'pd_diff'}[kind]
    code = template.replace('/*PD_REGION*/', '__CPROVER_assume(' + constraint + ');')
    code = code.replace('/*PD_QUERY*/', '__CPROVER_assert(' + assertion + ', "pd.query");')
    source = directory / 'query.c'
    # One translation unit keeps recursive VM callback types canonical in CBMC.
    source.write_text(code + '\n#include "' + str(ROOT / 'runtime/vm.c') + '"\n#include "' + str(ROOT / 'runtime/experiment/state.c') + '"\n')
    binary = directory / 'query.goto'
    reduced = directory / 'reduced.goto'
    tool_dir = Path(spec['cbmc']).parent
    stages = [[str(tool_dir / 'goto-cc'), str(source), '-I', str(ROOT / 'runtime'), '-o', str(binary)],
              [str(tool_dir / 'goto-instrument'), '--drop-unused-functions', '--slice-global-inits',
               str(binary), str(reduced)]]
    command = [spec['cbmc'], str(reduced), '--json-ui', '--trace', '--unwind',
               str(max(spec.get('unwind', 70), instruction_count + 1)),
               '--unwinding-assertions', '--bounds-check', '--pointer-check',
               '--div-by-zero-check', '--signed-overflow-check', '--undefined-shift-check',
               '--slice-formula']
    if spec.get('path_strategy', 'lifo'):
        command += ['--paths', spec.get('path_strategy', 'lifo')]
    (directory / 'command.json').write_text(json.dumps(stages + [command], indent=2))
    start = time.monotonic()
    try:
        for index, stage in enumerate(stages):
            with (directory / ('stage%d.log' % index)).open('w') as log:
                subprocess.run(stage, stdout=log, stderr=log, timeout=spec.get('timeout', 120), check=True)
        with (directory / 'stdout.json').open('w') as stdout, (directory / 'stderr.log').open('w') as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=spec.get('timeout', 120))
        messages = json.loads((directory / 'stdout.json').read_text())
        report = parse_result(messages, result.returncode)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        report = {'status': 'unresolved', 'reason': type(error).__name__, 'witness': {}}
    report.update(kind=kind, region=region, seconds=time.monotonic() - start, evidence=str(directory))
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def prove_vm_summary(rule, guard, spec, directory):
    """Discharge a procedure summary against the actual VM for all scalar snapshots."""
    raw = Path(guard['rule_path']).read_bytes()
    if compile_guard(rule['expression'], rule['fields']) != raw:
        raise ValueError('guard description does not compile to installed bytecode')
    rows = list(struct.iter_unpack('<BBhi', raw))
    names = {name: 'pd_in_' + name for name in rule['fields']}
    declarations = '\n'.join('uint64_t ' + name + ';' for name in names.values())
    inputs = '\n'.join(name + ' = nondet_pd_u64();' for name in names.values())
    assignments = []
    bindings = {}
    for name, binding in rule['fields'].items():
        if 'constant' in binding:
            bindings[name] = 'UINT64_C(%d)' % binding['constant']
        else:
            destination = ('args' if binding['source'] == 'arg' else 'regs') + '[%d]' % binding['index']
            if destination in bindings.values(): raise ValueError('summary fields must have distinct bindings')
            bindings[name] = destination
            assignments.append('ctx.' + destination + ' = ' + names[name] + ';')
    expected_names = {name: ('ctx.' + destination if not destination.startswith('UINT64_C') else destination)
                      for name, destination in bindings.items()}
    expression = c_expression(parse(rule['expression'], rule['fields']), expected_names)
    code = '''#include "autoshield.h"
extern uint64_t nondet_pd_u64(void);
int safe_read(void *d, const void *s, size_t n) { (void)d; (void)s; (void)n;
    __CPROVER_assert(0, "pd.summary.memory_helper"); return -1; }
''' + declarations + '\nstatic const ebpf_insn insns[] = {' + ','.join('{%d,%d,%d,%d}' % row for row in rows) + '''};
int main(void) {
''' + inputs + '''
    /*PD_REGION*/
    shadow_ctx ctx = {0};
''' + '\n'.join(assignments) + f'''
    shadow_program program = {{insns, {len(rows)}, 0, 0}};
    shadow_policy policy = {{{guard.get('step_limit',4096)}, SHADOW_UNKNOWN_BLOCK, 0}};
    shadow_stats stats;
    shadow_decision decision = run_ebpf_vm(&ctx, &program, &policy, &stats);
    __CPROVER_assert(decision == SHADOW_PASS || decision == SHADOW_BLOCK, "pd.summary.total_decision");
    int pd_diff = ((decision == SHADOW_BLOCK) != !!({expression}));
    /*PD_QUERY*/
}}
'''
    summary_spec = dict(spec, inputs=[{'name': name} for name in names], path_strategy='lifo')
    result = query(code, summary_spec, 'True', 'diff', directory, len(rows))
    result['scope'] = 'all uint64 scalar snapshots for exact installed bytecode; real runtime/vm.c'
    (directory / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def analyze(profile, manifest, catalog, directory):
    profile = copy.deepcopy(profile)
    spec = profile['symbolic']
    spec.pop('proved_vm_expression', None)
    rule = json.loads(Path(profile['guard']).read_text())
    summary = prove_vm_summary(rule, manifest['guards'][0], spec, directory / 'vm-summary')
    if summary['status'] == 'unsat':
        bindings = {name: ('UINT64_C(%d)' % field['constant'] if 'constant' in field else
                    ('args' if field['source'] == 'arg' else 'slots') + '[%d]' % field['index'])
                    for name, field in rule['fields'].items()}
        spec['proved_vm_expression'] = c_expression(parse(rule['expression'], rule['fields']), bindings)
        spec['path_strategy'] = None
    template, count = generate(profile, manifest, catalog, directory)
    inputs = {x['name'] for x in spec['inputs']}
    # Candidate predicates are obtained from the patch, then translated through
    # the adapter's field-to-input correspondence. There is no hand-written delta.
    correspondence = spec['field_expressions']
    class Substitute(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.parse(correspondence[node.id], mode='eval').body, node)
    candidates = []
    for predicate in [rule['expression'], *predicates(parse(rule['expression'], rule['fields']))]:
        mapped = ast.unparse(Substitute().visit(ast.parse(predicate, mode='eval')).body)
        parse(mapped, inputs)
        if mapped not in candidates: candidates.append(mapped)
    root = spec.get('domain', 'True')
    pending, leaves, queries = [(root, 0, [])], [], []
    budget = spec.get('max_regions', 5)
    def run(region, kind):
        result = query(template, spec, region, kind, directory / ('q%03d-%s' % (len(queries), kind)), count)
        queries.append(result)
        return result
    while pending:
        region, depth, used = pending.pop(0)
        reachable = run(region, 'reach')
        if reachable['status'] == 'unsat':
            leaves.append({'region': region, 'classification': 'unreachable'}); continue
        if reachable['status'] != 'sat':
            leaves.append({'region': region, 'classification': 'unresolved'}); continue
        diff = run(region, 'diff')
        if diff['status'] == 'unsat':
            leaves.append({'region': region, 'classification': 'unchanged'}); continue
        equal = run(region, 'equal') if diff['status'] == 'sat' else None
        if equal and equal['status'] == 'unsat':
            leaves.append({'region': region, 'classification': 'changed', 'witness': diff['witness']}); continue
        split = None
        if equal and equal['status'] == 'sat' and len(leaves) + len(pending) + 2 <= budget:
            for predicate in candidates:
                if predicate in used: continue
                expression = parse(predicate, inputs)
                try:
                    if bool(evaluate(expression, diff['witness'])) != bool(evaluate(expression, equal['witness'])):
                        split = predicate; break
                except KeyError: pass
        if split:
            for condition in [split, 'not (' + split + ')']:
                pending.append(('(' + region + ') and (' + condition + ')', depth + 1, used + [split]))
        else:
            leaves.append({'region': region, 'classification': 'mixed' if equal and equal['status'] == 'sat' else 'unresolved',
                           'witness': diff.get('witness', {})})
    report = {'scope': spec['scope'], 'root': spec.get('root', 'pd_application'),
              'hook': spec['hook_function'], 'inputs': spec['inputs'], 'outputs': spec['outputs'],
              'candidate_predicates': candidates, 'regions': leaves, 'queries': queries,
              'potential_impact': [x for x in leaves if x['classification'] in ('changed', 'mixed', 'unresolved')],
              'whole_operation_reachability': False,
              'vm_summary': summary,
              'all_queries_resolved': summary['status'] == 'unsat' and all(q['status'] != 'unresolved' for q in queries)}
    binary = directory / 'q000-reach/query.goto'
    if binary.exists():
        report['plan'] = discover(Path(spec['cbmc']).parent / 'goto-instrument', binary, spec, directory)
    (directory / 'analysis.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
