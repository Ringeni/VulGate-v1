"""Native-dependent builtin folding must not produce native proof claims."""
import json
import os
import subprocess
from copy import deepcopy

import pytest

from tools.verification.compiler_queries import (BINDING_PREFIX, bind_query_entries, guard_compiler_queries,
                                                remove_query_bindings, source_references)
from tools.verification.backend import classify
from tools.verification.engine import analyze
from tools.verification.spec import SpecificationError, Task
from tools.verification.toolchain import ProcessResult, Toolchain


def test_query_guard_ignores_literal_comment_and_line_marker_contents():
    source = b'''# 4 "__builtin_object_size(x,1)"
int f(void) { /* __builtin_constant_p(x) */ return "__builtin_constant_p(x)"[0]; }
'''
    data, sites = guard_compiler_queries(source)
    assert data == source and sites == []


def test_query_guard_keeps_unevaluated_native_operands_unchanged():
    source = b'int f(void) { int a[4]; return __builtin_object_size(a,1); }'
    data, sites = guard_compiler_queries(source)
    assert b'return __builtin_object_size(a,1);' in data
    assert len(sites) == 1 and sites[0]['function'] == 'f'
    assert sites[0]['marker'].encode() in data


@pytest.mark.parametrize('builtin', ['__builtin_constant_p', '__builtin_object_size', '__builtin_dynamic_object_size'])
def test_query_guard_records_parenthesized_and_noncall_uses(builtin):
    source = f'int inspect(void) {{ (void)({builtin}); return 0; }}'.encode()
    data, sites = guard_compiler_queries(source)
    assert len(sites) == 1 and sites[0]['function'] == 'inspect'
    assert sites[0]['queries'][0]['query'] == builtin
    assert f'(void)({builtin});'.encode() in data


def test_source_reference_graph_keeps_function_addresses_global_initializers_and_duplicate_names():
    sources = [b'int inspect(void){return 1;} static int mid(void){return inspect();} void root(void){(void)&mid;}',
               b'int second(void){return 2;} static int mid(void){return second();}',
               b'int hidden(void){return 3;} int (*selected)(void)=hidden;']
    assert {'root', 'mid', 'inspect', 'second', 'hidden'} <= source_references(sources, 'root')


def test_query_bindings_have_distinct_identity_for_identical_static_sources():
    source = b'static int inspect(int n){return __builtin_constant_p(n);}'
    a, first = guard_compiler_queries(source, 'first.c')
    b, second = guard_compiler_queries(source, 'second.c')
    assert first[0]['marker'] != second[0]['marker']
    assert first[0]['binding_function'] != second[0]['binding_function']
    assert b'__typeof__(&inspect)' in a and b'__typeof__(&inspect)' in b


@pytest.mark.parametrize('statuses', [('FAILURE', 'SUCCESS'), ('SUCCESS', 'FAILURE')])
def test_duplicate_reachability_descriptions_aggregate_every_occurrence(statuses):
    properties = [{'property': 'root.assertion.0', 'description': 'target', 'status': 'SUCCESS'}]
    properties += [{'property': 'f.assertion.' + str(i), 'description': '__VG_REACH_COMPILER_QUERY:same',
                    'status': status} for i, status in enumerate(statuses)]
    process = ProcessResult([], 10, json.dumps([{'result': properties}, {'cProverStatus': 'failure'}]), '')
    report = classify(process, ['target'], {'guarded_unsupported': []})
    assert report['reachability']['__VG_REACH_COMPILER_QUERY:same'] == 'REACHABLE'


def test_restored_entry_guard_preserves_original_branch_destinations():
    reference = {'id': 'symbol', 'namedSub': {'identifier': {'id': 'actual'}}}
    probe = {'name': 'binding', 'instructions': [{'instructionId': 'SET_RETURN_VALUE',
             'code': {'sub': [{'id': 'address_of', 'sub': [reference]}]}}]}
    target = {'name': 'actual', 'instructions': [
        {'instructionId': 'GOTO', 'locationNumber': 10, 'targets': [12]},
        {'instructionId': 'GOTO', 'locationNumber': 11, 'targets': [10]},
        {'instructionId': 'END_FUNCTION', 'locationNumber': 12}]}
    site = {'function': 'redirected', 'binding_function': 'binding', 'marker': '__VG_REACH_COMPILER_QUERY:test'}
    bind_query_entries([probe, target], {'actual': {'type': {'id': 'code'}}}, [site], transport_mode='legacy')
    assert site['compiler_symbol'] == 'actual' and site['entry_marker_restored']
    assert target['instructions'][0]['instructionId'] == 'ASSERT'
    assert target['instructions'][1]['targets'] == [3]
    assert target['instructions'][2]['targets'] == [1]


def test_missing_compiler_binding_does_not_manufacture_an_entry():
    site = {'function': 'missing', 'binding_function': 'absent', 'marker': '__VG_REACH_COMPILER_QUERY:test'}
    functions = []
    assert bind_query_entries(functions, {}, [site]) == []
    assert site['binding_status'] == 'UNRESOLVED'


def test_binding_namespace_reserved_even_without_queries():
    with pytest.raises(SpecificationError, match='reserved'):
        guard_compiler_queries(b'int __vulgate_query_binding_original(void) { return 1; }')


def binding_model():
    name = BINDING_PREFIX + 'test'
    site = {'binding_function': name, 'compiler_symbol': 'query',
            'binding_status': 'BOUND_TO_COMPILED_ENTRY', 'marker': '__VG_REACH_COMPILER_QUERY:test'}
    reference = {'id': 'symbol', 'namedSub': {'identifier': {'id': 'query'}}}
    helper = {'name': name, 'instructions': [
        {'instructionId': 'SET_RETURN_VALUE', 'locationNumber': 0,
         'code': {'sub': [{'id': 'address_of', 'sub': [reference]}]}},
        {'instructionId': 'GOTO', 'locationNumber': 1, 'targets': [2],
         'guard': {'id': 'constant', 'namedSub': {'type': {'id': 'bool'}, 'value': {'id': 'true'}}}},
        {'instructionId': 'END_FUNCTION', 'locationNumber': 2}]}
    target = {'name': 'query', 'instructions': [
        {'instructionId': 'ASSERT', 'sourceLocation': {'comment': site['marker']}}]}
    symbols = {name: {'type': {'id': 'code'}, 'value': {'id': 'compiled'}},
               'query': {'type': {'id': 'code'}, 'value': {'id': 'compiled'}}}
    return [helper, target], symbols, [site]


def test_binding_metadata_removal_preserves_originals_and_entry_obligations():
    functions, symbols, sites = binding_model()
    before = deepcopy((functions, symbols))
    kept_functions, kept_symbols = remove_query_bindings(functions, symbols, sites)
    assert kept_functions == before[0][1:]
    assert kept_symbols == {'query': before[1]['query']}
    assert (functions, symbols) == before
    assert sites[0]['binding_metadata_removed']


@pytest.mark.parametrize('location', ['code', 'guard', 'value'])
def test_binding_metadata_with_retained_references_is_rejected(location):
    functions, symbols, sites = binding_model()
    reference = {'id': 'address_of', 'sub': [
        {'id': 'symbol', 'namedSub': {'identifier': {'id': sites[0]['binding_function']}}}]}
    if location == 'value':
        symbols['global_callback'] = {'value': reference}
    else:
        functions[1]['instructions'].append({location: reference})
    with pytest.raises(SpecificationError, match='retained model references'):
        remove_query_bindings(functions, symbols, sites)
    assert 'binding_metadata_removed' not in sites[0]


@pytest.mark.parametrize('damage', ['unrecorded', 'unresolved', 'effects', 'jump', 'marker', 'value'])
def test_unqualified_binding_metadata_cannot_be_removed(damage):
    functions, symbols, sites = binding_model()
    if damage == 'unrecorded':
        symbols[BINDING_PREFIX + 'unknown'] = {}
    elif damage == 'unresolved':
        sites[0]['binding_status'] = 'UNRESOLVED'
    elif damage == 'effects':
        functions[0]['instructions'].insert(0, {'instructionId': 'ASSIGN'})
    elif damage == 'jump':
        functions[0]['instructions'][1]['targets'] = [0]
    elif damage == 'marker':
        functions[1]['instructions'].clear()
    else:
        symbols[sites[0]['binding_function']]['value'] = {'id': 'side_effect'}
    with pytest.raises(SpecificationError):
        remove_query_bindings(functions, symbols, sites)
    assert 'binding_metadata_removed' not in sites[0]


@pytest.mark.parametrize('reached', [False, True])
@pytest.mark.parametrize('body', [
    'unsigned char a[4]={0}; return (int)__builtin_object_size(a,1);',
    'unsigned char a[4]={0}; return (int)__builtin_dynamic_object_size(a,1);',
    'return __builtin_constant_p(n);',
    'unsigned char a[4]={0}; return (int)(__builtin_object_size)(a,1);',
    'unsigned char a[4]={0}; return (int)(__builtin_dynamic_object_size)(a,1);',
    'return (__builtin_constant_p)(n);',
])
def test_compiler_queries_require_contextual_unreachability(tmp_path, reached, body):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for compiler-query correspondence checks')
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                      'int inspect(int n) { ' + body + ' }\n'
                      'void root(void) { ' + ('(void)inspect(4);' if reached else '') +
                      '__CPROVER_assert(1,"target"); }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60,
                units=({'source': str(source), 'flags': ['-O2']},))
    report = analyze(task, Toolchain.load(config), [], tmp_path / 'result')
    query = report['protected']
    assert query['status'] == ('UNKNOWN' if reached else 'PROVED_FOR_HARNESS'), report
    assert query['build_semantics']['compiler_queries']
    if reached:
        assert query['abstract_model_statuses']['target'] == 'PROVED_FOR_HARNESS'
        assert set(query['reachability'].values()) <= {'UNKNOWN'}
    # Preserve evidence distinguishing this native correspondence gap from a
    # property counterexample in the frontend's abstract program.
    assert json.loads((tmp_path / 'result/protected/program.compiler-queries.json').read_text())


@pytest.mark.parametrize('reached', [False, True])
@pytest.mark.parametrize('kind', ['gnu_inline', 'static_names', 'asm_redirect'])
def test_compiler_bound_entries_across_translation_units(tmp_path, reached, kind):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for compiler-bound entry checks')
    sources = []
    for index in range(2):
        path = tmp_path / f'unit{index}.c'
        declaration = ('extern inline __attribute__((gnu_inline)) ' if kind == 'gnu_inline' else 'static ')
        prefix = ''
        if kind == 'asm_redirect':
            prefix = f'extern int inspect{index}(int) __asm__("actual{index}");\n'
            function = f'inspect{index}'
            declaration = ''
        else:
            function = 'inspect'
        path.write_text(prefix + declaration + f'int {function}(int n) {{ return __builtin_constant_p(n); }}\n'
                        f'int caller{index}(int use) {{ return use ? {function}(4) : 0; }}\n')
        sources.append(path)
    root = tmp_path / 'root.c'
    root.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                    'extern int caller0(int); extern int caller1(int);\n'
                    f'void root(void) {{ caller0(0); caller1({int(reached)}); __CPROVER_assert(1,"target"); }}\n')
    sources.append(root)
    task = Task(tmp_path / 'task.json', tuple(sources), 'root', ('target',), timeout=60,
                units=tuple({'source': str(p), 'flags': ['-O2']} for p in sources))
    report = analyze(task, Toolchain.load(config), [], tmp_path / 'result')
    query = report['protected']
    assert query['status'] == ('UNKNOWN' if reached else 'PROVED_FOR_HARNESS'), query.get('reasons')
    sites = query['build_semantics']['compiler_queries']
    assert len(sites) == 2 and all(s['binding_status'] == 'BOUND_TO_COMPILED_ENTRY' for s in sites)
    assert all(s['binding_metadata_removed'] for s in sites)
    # GNU inline bodies can be retained as separate $linkN functions. Bind
    # each actual compiler identity rather than assuming a name-based merge.
    assert len({s['compiler_symbol'] for s in sites}) == 2
    if kind == 'asm_redirect':
        assert {s['compiler_symbol'] for s in sites} == {'actual0', 'actual1'}
    if reached:
        assert any(s['status'] == 'REACHABLE' for s in sites)
    else:
        assert all(s['status'] == 'UNREACHABLE' for s in sites)


@pytest.mark.parametrize('reached', [False, True])
def test_redirected_inline_definitions_restore_both_entry_obligations(tmp_path, reached):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for compiler-bound entry checks')
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
        'extern int named(int) __asm__("actual");\n'
        'extern inline __attribute__((gnu_inline)) int named(int n) { return __builtin_constant_p(n); }\n'
        'extern inline __attribute__((gnu_inline)) int actual(int n) { return __builtin_constant_p(n+1); }\n'
        'void root(void) { ' + ('named(4);' if reached else '') + '__CPROVER_assert(1,"target"); }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60,
                units=({'source': str(source), 'flags': ['-O2']},))
    query = analyze(task, Toolchain.load(config), [], tmp_path / 'result')['protected']
    assert query['status'] == ('UNKNOWN' if reached else 'PROVED_FOR_HARNESS'), query.get('reasons')
    sites = query['build_semantics']['compiler_queries']
    assert len(sites) == 2 and {s.get('compiler_symbol') for s in sites} == {'actual'}
    assert any(s['entry_marker_restored'] for s in sites)
    assert all(s['status'] == ('REACHABLE' if reached else 'UNREACHABLE') for s in sites)
    assert all(s['binding_metadata_removed'] for s in sites)


@pytest.mark.parametrize('query_callback', [False, True])
def test_callback_targets_exclude_metadata_addresses_but_keep_originals(tmp_path, query_callback):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for callback target checks')
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
        'static int query(int n) { return __builtin_constant_p(n); }\n'
        'static int ordinary(int n) { return n + 1; }\n'
        'struct callback { int (*run)(int); };\n'
        'static int invoke(struct callback *c) { return c->run(2); }\n'
        'void root(void) { struct callback c = { ' + ('query' if query_callback else 'ordinary') +
        ' }; (void)invoke(&c); __CPROVER_assert(1,"target"); }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    query = analyze(task, Toolchain.load(config), [], tmp_path / 'result')['protected']
    assert query['status'] == ('UNKNOWN' if query_callback else 'PROVED_FOR_HARNESS')
    assert all(s['binding_metadata_removed'] for s in query['build_semantics']['compiler_queries'])
    functions = json.loads((tmp_path / 'result/protected/verification.functions.json').read_text())['functions']
    symbols = json.loads((tmp_path / 'result/protected/verification.symbols.json').read_text())['symbolTable']
    assert not any(f['name'].startswith(BINDING_PREFIX) for f in functions)
    assert not any(n.startswith(BINDING_PREFIX) for n in symbols)
    addresses, pending = set(), [functions, symbols]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            if node.get('id') == 'address_of' and node.get('sub', [{}])[0].get('id') == 'symbol':
                addresses.add(node['sub'][0].get('namedSub', {}).get('identifier', {}).get('id'))
            pending.extend(node.values())
    compiled = query['build_semantics']['compiler_queries'][0]['compiler_symbol']
    assert (compiled in addresses) == query_callback


@pytest.mark.parametrize('attribute', ['const', 'pure', 'always_inline'])
@pytest.mark.parametrize('callee', ['__builtin_constant_p', '(__builtin_constant_p)'])
def test_optimized_inline_query_cannot_claim_native_constant_value(tmp_path, attribute, callee):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for compiler-bound entry checks')
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
        f'static inline __attribute__(({attribute})) int inspect(int n) {{ return {callee}(n); }}\n'
        'void root(void) { __CPROVER_assert(inspect(4)==0,"target"); }\n')
    driver = tmp_path / 'driver.c'
    driver.write_text('static int failed; void __CPROVER_assert(_Bool ok,const char *label) '
                      '{ (void)label; failed=!ok; } extern void root(void); '
                      'int main(void) { root(); return failed; }\n')
    native = tmp_path / 'native'
    subprocess.run(['gcc', '-O2', str(source), str(driver), '-o', str(native)], check=True, capture_output=True)
    assert subprocess.run([str(native)], capture_output=True).returncode == 1
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60,
                units=({'source': str(source), 'flags': ['-O2']},))
    query = analyze(task, Toolchain.load(config), [], tmp_path / 'result')['protected']
    assert query['status'] == 'UNKNOWN'
    assert query['abstract_model_statuses']['target'] == 'PROVED_FOR_HARNESS'
    assert query['build_semantics']['compiler_queries'][0]['status'] == 'REACHABLE'
