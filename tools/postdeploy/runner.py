"""One install -> relational analysis -> functional replay/monitor -> report run."""
from contextlib import ExitStack
import gzip
import hashlib
import importlib
import json
from pathlib import Path
import time

from . import coverage
from .case_compiler import project_snapshot_to_symbols, snapshot_guard_from_bindings
from .expressions import parse, evaluate
from .monitors import VMReplay, compare
from .process import Worker
from .symbolic import analyze
from .product import ROOT


def run(profile, output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'profile.json').write_text(json.dumps(profile, indent=2) + '\n')
    sources = [Path(profile[name]) for name in ['patch', 'catalog', 'guard', 'bridge']]
    sources += [Path(profile['symbolic']['adapter_source']), ROOT / 'runtime/vm.c', ROOT / 'runtime/experiment/state.c']
    sources += list((ROOT / 'tools/postdeploy').glob('*.py'))
    for record in profile.get('build_records', []):
        path = Path(record)
        (output / path.name).write_bytes(path.read_bytes())
        sources.append(path)
    (output / 'input-hashes.json').write_text(json.dumps(
        {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}, indent=2) + '\n')
    manifest = json.loads(Path(profile['patch']).read_text())
    catalog = json.loads(Path(profile['catalog']).read_text())
    for guard in manifest['guards']:
        guard['rule_path'] = str((Path(profile['patch']).parent / guard['rule']).resolve())
    adapter = importlib.import_module(profile['adapter'])
    started = time.monotonic()
    with ExitStack() as stack:
        workers = {}
        # Installation precedes symbolic analysis and every application episode.
        for mode in ['patched', 'baseline', 'reference']:
            if mode not in profile['workers']: continue
            workers[mode] = stack.enter_context(Worker(profile['workers'][mode], output / mode,
                patch=profile['patch'] if mode == 'patched' else None, catalog=profile['catalog']))
        analysis = analyze(profile, manifest, catalog, output / 'symbolic')
        monitor = VMReplay(profile['bridge'], {g['id']: {'path': g['rule_path'], 'step_limit': g.get('step_limit', 4096),
                                                        'observations': g.get('observations', [])}
                                               for g in manifest['guards']})
        stack.callback(monitor.close)
        summaries, pairs, feedback = [], [], []
        observed_edges = set()
        totals = dict(decisions=0, observations=0, blocks=0, diagnostics=0)
        region_counts = {str(i): 0 for i in range(len(analysis['regions']))}
        mapped_events = unmapped_events = 0
        symbolic_spec = profile.get('symbolic') or {}
        symbolic_names = {item['name'] for item in symbolic_spec.get('inputs') or []}
        snapshot_formulas = symbolic_spec.get('snapshot_to_symbolic_exprs') or {}
        guards_by_id = {guard['id']: guard for guard in manifest['guards']}
        for case in adapter.cases(profile, output / 'corpus', analysis, feedback):
            executions = {mode: worker.execute(case['command']) for mode, worker in workers.items()}
            outcomes = {mode: result['outcome'] for mode, result in executions.items()}
            check = monitor.check(executions['patched']['events'])
            failures = compare(case, outcomes['baseline'], outcomes['patched'], outcomes.get('reference'),
                               profile['comparison_fields']) + check['violations']
            for name in profile.get('empty_maps_after_episode', []):
                if executions['patched']['runtime_status']['map_sizes'].get(name) != 0:
                    failures.append({'kind': 'observation_retention', 'map': name})
            for mode, result in outcomes.items():
                for obligation in profile.get('progress', []):
                    value = result.get(obligation['field'])
                    if not isinstance(value, (int, float)) or not obligation['min'] <= value <= obligation['max']:
                        failures.append({'kind': 'progress', 'world': mode, 'field': obligation['field']})
            for key in totals: totals[key] += check[key]
            impact_distance = None
            for message in executions['patched']['events']:
                event = message.get('payload', {})
                if event.get('event') != 'decision' or not event.get('snapshot'): continue
                guard = guards_by_id.get(event.get('hook')) or manifest['guards'][0]
                guard_ir = snapshot_guard_from_bindings(guard, symbolic_spec)
                values = project_snapshot_to_symbols(
                    guard_ir, event['snapshot'], symbolic_names, snapshot_formulas,
                )
                for region in analysis['potential_impact']:
                    witness = region.get('witness', {})
                    common = values.keys() & witness.keys()
                    if common:
                        distance = sum(abs(values[name] - witness[name]) / (1 + abs(witness[name])) for name in common)
                        impact_distance = distance if impact_distance is None else min(impact_distance, distance)
                matched = False
                for i, region in enumerate(analysis['regions']):
                    try:
                        if evaluate(parse(region['region'], {x['name'] for x in profile['symbolic']['inputs']}), values):
                            region_counts[str(i)] += 1; matched = True
                    except KeyError: pass
                if matched: mapped_events += 1
                else: unmapped_events += 1
            pairs.append((case['id'], outcomes['baseline'], outcomes['patched']))
            current_edges = coverage.edges(outcomes['patched']['trace']) if outcomes['patched'].get('trace_complete') else set()
            feedback.append({'case': case, 'new_edges': len(current_edges - observed_edges),
                             'impact_distance': impact_distance})
            observed_edges.update(current_edges)
            with gzip.open(output / ('case-%s.json.gz' % case['id']), 'wt') as file:
                json.dump({'case': case, 'executions': executions, 'monitor': check, 'failures': failures}, file)
            summaries.append({'case_id': case['id'], 'origin': case['origin'], 'input': case['input'],
                              'failures': failures, 'decisions': check['decisions'], 'blocks': check['blocks'],
                              'impact_distance': impact_distance, 'new_edges': feedback[-1]['new_edges'],
                              'elapsed_seconds': {k: v['elapsed_seconds'] for k, v in executions.items()}})
            print(json.dumps({'case': case['id'], 'failures': len(failures), 'decisions': check['decisions']}), flush=True)
        paths = coverage.summarize(pairs)
        (output / 'coverage.json').write_text(json.dumps(paths, indent=2) + '\n')
        report = {'schema': 1, 'name': profile['name'], 'seconds': time.monotonic() - started,
            'pipeline_completed': True, 'functional_pass': all(not c['failures'] for c in summaries),
            'symbolic_resolved': analysis['all_queries_resolved'], 'symbolic_scope': analysis['scope'],
            'whole_operation_symbolic_proof': False, 'vulnerability_sufficiency_proof': False,
            'cases': summaries, 'monitor': totals,
            'coverage': {k: v for k, v in paths.items() if k not in ('paths', 'edge_tests')},
            'regions': analysis['regions'], 'region_predicate_hits': region_counts,
            'region_mapping': {'mapped': mapped_events, 'unmapped': unmapped_events,
                'scope': 'predicate hits only; does not establish membership in complete bounded entry-state domain'},
            'artifacts': {'profile': str(output / 'profile.json'), 'analysis': str(output / 'symbolic/analysis.json'),
                          'coverage': str(output / 'coverage.json')},
            'patch_sha256': hashlib.sha256(Path(profile['patch']).read_bytes()).hexdigest()}
        report['unvisited_impact_regions'] = [i for i, region in enumerate(analysis['regions'])
            if region['classification'] in ('changed', 'mixed', 'unresolved') and region_counts[str(i)] == 0]
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        lines = [f'# {profile["name"]} post-deployment experiment', '',
                 f'Functional cases: {len(summaries)}; passed: {report["functional_pass"]}.',
                 f'Symbolic queries resolved: {report["symbolic_resolved"]}.',
                 'Symbolic scope: ' + analysis['scope'] + '.',
                 f'VM decisions: {totals["decisions"]}; observations: {totals["observations"]}; blocks: {totals["blocks"]}.',
                 f'Complete paired traces: {paths["complete_episodes"]}; lost union edges: {paths["lost_edge_union"]}; changed sequences: {paths["changed_sequences"]}.',
                 '', '## Regions', '']
        lines += [f'- **{r["classification"]}**: `{r["region"]}`' for r in analysis['regions']]
        lines += ['', 'Whole-decoder reachability, unrestricted vulnerability sufficiency, Node.js embedding, concurrency, and live instruction-hook unload are outside this run.']
        (output / 'report.md').write_text('\n'.join(lines) + '\n')
        return report
