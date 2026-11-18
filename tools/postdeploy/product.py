"""Generate a paired C harness around an application's typed operation adapter.

The adapter constructs independent local objects for each execution. The gate is
inserted into compiler-preprocessed actual source, not a hand-authored predicate
model. Application-wide reachability and entry-local scopes are reported apart.
"""
import json
from pathlib import Path
import struct
import subprocess

from tools.verification.source import functions

ROOT = Path(__file__).resolve().parents[2]


def selector_c(source, parameters):
    if 'constant' in source: return f'UINT64_C({source["constant"]})'
    if 'arg' not in source: raise ValueError('symbolic entry selector requires an argument')
    value = '(uint64_t)(uintptr_t)(' + parameters[source['arg']] + ')'
    for read in source.get('reads', []):
        typ = {'pointer': 'uintptr_t', 'u64': 'uint64_t', 's64': 'int64_t',
               'u32': 'uint32_t', 's32': 'int32_t', 'u8': 'uint8_t'}[read['type']]
        value = f'(uint64_t)(*({typ} *)((uintptr_t)({value}) + ({read.get("offset", 0)})))'
    return value


def generate(profile, manifest, catalog, output):
    spec = profile['symbolic']
    output.mkdir(parents=True, exist_ok=True)
    guard = manifest['guards'][0]
    if len(manifest['guards']) != 1: raise ValueError('paired adapter currently binds one entry guard')
    if guard['return_type'] != 'int': raise ValueError('paired adapter requires int return')
    if spec.get('state_contract') != 'independent_local_objects':
        raise ValueError('adapter must construct independent world objects from explicit inputs')
    source = Path(spec['adapter_source'])
    command = [spec.get('cc', 'gcc'), '-E', '-std=c11', '-I' + str(ROOT / 'runtime'),
               *spec.get('cppflags', []), str(source)]
    preprocessed = subprocess.check_output(command)
    found = [f for f in functions(preprocessed) if f.name == spec['hook_function']]
    if len(found) != 1: raise ValueError('symbolic hook function is not unique')
    params = spec['hook_parameters']
    if len(params) != len(guard['arg_types']): raise ValueError('ABI parameter count mismatch')
    argument_expressions = []
    layout_checks = []
    for i, selector in enumerate(guard.get('vm_args', [])):
        typed = spec.get('typed_fields', {}).get(str(i))
        if typed:
            reads = selector.get('reads', [])
            if 'arg' not in selector or len(reads) != 1:
                raise ValueError('typed field requires one argument dereference')
            typ, member = typed['type'], typed['member']
            width = {'s32': 4, 'u32': 4, 'pointer': 8, 'u64': 8, 's64': 8, 'u8': 1}[reads[0]['type']]
            layout_checks += [f'_Static_assert(offsetof({typ}, {member}) == {reads[0].get("offset",0)}, "binding offset");',
                              f'_Static_assert(sizeof((({typ} *)0)->{member}) == {width}, "binding width");']
            value = f'(({typ} *){params[selector["arg"]]})->{member}'
            cast = {'s32': '(int64_t)(int32_t)', 's64': '(int64_t)', 'pointer': '(uintptr_t)',
                    'u32': '(uint32_t)', 'u64': '(uint64_t)', 'u8': '(uint8_t)'}[reads[0]['type']]
            argument_expressions.append(f'(uint64_t){cast}({value})')
        else:
            argument_expressions.append(selector_c(selector, params))
    if not argument_expressions:
        argument_expressions = [f'(uint64_t)(uintptr_t)({name})' for name in params]
    argument_expressions += ['0'] * (6 - len(argument_expressions))
    statements = layout_checks + ['if (pd_enabled) {', 'uint64_t pd_args[6] = {' + ','.join(argument_expressions) + '};',
                  'uint64_t pd_slots[16] = {0};']
    for ref in guard.get('observations', []):
        if 'key_arg' not in ref: raise ValueError('symbolic map lookup requires key_arg')
        if len(manifest['maps']) != 1: raise ValueError('paired adapter currently binds one explicit observation table')
        key = params[ref['key_arg']]
        statements += [f'int pd_found = vg_table_get(&pd_observations, 0, (uint64_t)(uintptr_t)({key}), '
                       f'&pd_slots[{ref["slot"]}], {int(bool(ref.get("consume")))});']
        if 'present_slot' in ref: statements += [f'pd_slots[{ref["present_slot"]}] = pd_found;']
        else: statements += [f'if (!pd_found) return {catalog["actions"][guard["action_id"]]["value"]};']
    action = catalog['actions'][guard['action_id']]
    if action['kind'] != 'return_int': raise ValueError('unsupported action in product')
    statements += [f'if (pd_decide(pd_args, pd_slots)) return {action["value"]};', '}']
    at = found[0].body_start
    instrumented = preprocessed[:at] + ('\n' + '\n'.join(statements) + '\n').encode() + preprocessed[at:]
    (output / 'instrumented.i').write_bytes(instrumented)
    code = Path(guard['rule_path']).read_bytes()
    rows = list(struct.iter_unpack('<BBhi', code))
    if any(op == 0x85 and immediate not in (1, 3) for op, _, _, immediate in rows):
        raise ValueError('symbolic snapshots require get_arg/get_reg-only bytecode')
    table = ',\n'.join('{%d,%d,%d,%d}' % row for row in rows)
    capacity = next(iter(manifest.get('maps', {}).values()), {}).get('capacity', 1)
    prefix = f'''
#include <stdint.h>
#include <string.h>
#include "autoshield.h"
#include "experiment/state.h"
static int pd_enabled;
static vg_slot pd_storage[{capacity}];
static vg_table pd_observations = {{{capacity}, 0, pd_storage}};
static void pd_record(uint64_t key, uint64_t value) {{
    int status = vg_table_set(&pd_observations, 0, key, value);
    __CPROVER_assert(status == 0, "pd.observation.capacity");
}}
static const ebpf_insn pd_code[] = {{ {table} }};
static const shadow_program pd_program = {{pd_code, {len(rows)}, 0, 0}};
static int pd_decide(const uint64_t args[6], const uint64_t slots[16]) {{
    {('return !!(' + spec['proved_vm_expression'] + ');') if spec.get('proved_vm_expression') else ''}
    shadow_ctx ctx;
    shadow_stats stats;
    shadow_policy policy = {{{guard.get('step_limit',4096)}, SHADOW_UNKNOWN_BLOCK, 0}};
    memcpy(ctx.args, args, sizeof(ctx.args));
    memcpy(ctx.regs, slots, sizeof(ctx.regs));
    shadow_decision decision = run_ebpf_vm(&ctx, &pd_program, &policy, &stats);
    __CPROVER_assert(decision == SHADOW_PASS || decision == SHADOW_BLOCK, "pd.vm.total_decision");
    return decision != SHADOW_PASS;
}}
int safe_read(void *dst, const void *src, size_t len) {{
    (void)dst; (void)src; (void)len;
    __CPROVER_assert(0, "pd.vm.unexpected_memory_helper");
    return -1;
}}
'''
    inputs = spec['inputs']
    declarations = '\n'.join('uint64_t pd_in_' + item['name'] + ';' for item in inputs)
    assumptions = []
    for item in inputs:
        name = 'pd_in_' + item['name']
        assumptions += [f'{name} = nondet_pd_u64();',
                        f'__CPROVER_assume({name} >= UINT64_C({item["min"]}) && {name} <= UINT64_C({item["max"]}));']
    names = ','.join('pd_in_' + item['name'] for item in inputs)
    tail = f'''
extern uint64_t nondet_pd_u64(void);
{declarations}
int main(void) {{
    {' '.join(assumptions)}
    /*PD_REGION*/
    uint64_t input[{len(inputs)}] = {{{names}}};
    uint64_t before[{len(spec['outputs'])}] = {{0}}, after[{len(spec['outputs'])}] = {{0}};
    memset(pd_storage, 0, sizeof(pd_storage)); pd_observations.count = 0;
    pd_enabled = 0;
    {spec.get('root', 'pd_application')}(input, before);
    memset(pd_storage, 0, sizeof(pd_storage)); pd_observations.count = 0;
    pd_enabled = 1;
    {spec.get('root', 'pd_application')}(input, after);
    int pd_diff = 0;
    for (unsigned i = 0; i < {len(spec['outputs'])}; ++i) pd_diff |= before[i] != after[i];
    /*PD_QUERY*/
    return 0;
}}
'''
    template = prefix + '\n' + instrumented.decode() + '\n' + tail
    (output / 'product.template.c').write_text(template)
    (output / 'generation.json').write_text(json.dumps({'preprocessor_command': command,
        'hook': spec['hook_function'], 'root': spec.get('root', 'pd_application'),
        'scope': spec['scope'], 'bytecode_instructions': len(rows)}, indent=2) + '\n')
    return template, len(rows)
