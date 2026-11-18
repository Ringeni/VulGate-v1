"""Prove an explicit local interception obligation against installed VM bytes.

The obligation is supplied separately from the guard. This establishes a local
implication, not whole-program reachability or automatic CVE interpretation.
"""
import json
import hashlib
from pathlib import Path
import struct
from .expressions import parse, c_expression, compile_guard
from .symbolic import query


def prove_gate_contract(rule, bytecode, contract, spec, directory):
    fields=rule['fields']
    raw=Path(bytecode).read_bytes()
    if compile_guard(rule['expression'], fields) != raw:
        raise ValueError('contract rule does not compile to installed bytecode')
    inputs=list(fields)+contract.get('auxiliary_inputs',[])
    if len(set(inputs))!=len(inputs): raise ValueError('duplicate contract input')
    names={name:'pd_in_'+name for name in inputs}
    declarations='\n'.join('uint64_t '+name+';' for name in names.values())
    initializers='\n'.join(name+' = nondet_pd_u64();' for name in names.values())
    bindings=[]
    destinations=set()
    for name,field in fields.items():
        if 'constant' in field: continue
        destination='args' if field['source']=='arg' else 'regs'
        key=(destination,field['index'])
        if key in destinations: raise ValueError('contract fields must have distinct bindings')
        destinations.add(key)
        bindings.append(f'ctx.{destination}[{field["index"]}] = {names[name]};')
    expected_names=dict(names)
    expected_names.update({name:'UINT64_C(%d)'%field['constant'] for name,field in fields.items() if 'constant' in field})
    obligation=c_expression(parse(contract['must_block'],expected_names),expected_names)
    assumption=c_expression(parse(contract.get('assume','True'),expected_names),expected_names)
    rows=list(struct.iter_unpack('<BBhi',raw))
    source='''#include "autoshield.h"
extern uint64_t nondet_pd_u64(void);
int safe_read(void *d, const void *s, size_t n) {
    (void)d; (void)s; (void)n;
    __CPROVER_assert(0,"contract.memory_helper_not_modeled"); return -1;
}
'''+declarations+'\nstatic const ebpf_insn code[] = {'+','.join('{%d,%d,%d,%d}'%r for r in rows)+'''};
int main(void) {
'''+initializers+'''
    shadow_ctx ctx = {0};
'''+ '\n'.join(bindings)+f'''
    shadow_program program = {{code,{len(rows)},0,0}};
    shadow_policy policy = {{{spec.get('step_limit',4096)},SHADOW_UNKNOWN_BLOCK,0}};
    shadow_stats stats;
    __CPROVER_assume({assumption});
    /*PD_REGION*/
    shadow_decision decision = run_ebpf_vm(&ctx,&program,&policy,&stats);
    __CPROVER_assert(decision == SHADOW_PASS || decision == SHADOW_BLOCK,"contract.total_decision");
    int pd_diff = ({obligation}) && decision != SHADOW_BLOCK;
    /*PD_QUERY*/
}}
'''
    spec=dict(spec,inputs=[{'name':name} for name in inputs])
    result=query(source,spec,'True','diff',directory,len(rows))
    reachable=query(source.replace('/*PD_REGION*/',f'__CPROVER_assume({obligation});\n/*PD_REGION*/'),
                    spec,'True','reach',Path(directory)/'nonvacuity',len(rows))
    result['implication_status']=result['status']
    result['nonvacuity_status']=reachable['status']
    if reachable['status'] != 'sat':
        result['status']='unresolved'
        result['reason']='must-block domain is empty or its reachability was not resolved'
    result.update(contract=contract,scope='all scalar valuations satisfying the declared local contract',
        bytecode_sha256=hashlib.sha256(raw).hexdigest(),
        whole_program_sufficiency=False,
        interpretation='UNSAT means must_block implies BLOCK; coverage and continuation obligations are external')
    (Path(directory)/'contract-result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
