from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from tools.verification.backend import configure_object_encoding
from tools.verification.shadow import BOOL, TRUE, code as irep_code, operation, symbol_name, transform as shadow_transform, typ
from tools.verification.typed_transport import FULL, copy_location, transport_view, validate_model

from .missing_callees import READONLY_READS


def _rewrite_irep_symbols(node: Any, rename_map: dict[str, str]) -> Any:
    if isinstance(node, list):
        return [_rewrite_irep_symbols(item, rename_map) for item in node]
    if not isinstance(node, dict):
        return node
    out = dict(node)
    if out.get('id') == 'symbol':
        ident = out.get('namedSub', {}).get('identifier', {}).get('id')
        if ident in rename_map:
            named = dict(out['namedSub'])
            named['identifier'] = {'id': rename_map[ident]}
            out['namedSub'] = named
    elif out.get('id') == 'parameter':
        ident = out.get('namedSub', {}).get('#identifier', {}).get('id')
        if ident in rename_map:
            named = dict(out['namedSub'])
            named['#identifier'] = {'id': rename_map[ident]}
            out['namedSub'] = named
    if 'sub' in out:
        out['sub'] = [_rewrite_irep_symbols(c, rename_map) for c in out['sub']]
    if 'namedSub' in out:
        out['namedSub'] = {k: _rewrite_irep_symbols(v, rename_map) for k, v in out['namedSub'].items()}
    return out


def shared_readonly_symbol(name: str) -> bool:
    return name.split('::')[-1] in READONLY_READS


VERIBIN_LOOP_UNWIND = 2

_HYBRID_ENGINE_BASES = {
    'ngx_http_script_run',
    'ngx_regex_exec',
    'ngx_http_rewrite_handler',
    'ngx_http_core_content_phase',
    'ngx_http_map_find',
}

_VERIBIN_DRIVER_FILES = {
    'auto_synthesized_driver.c',
    'local_driver.c',
    'driver_region.c',
    'vg_paired_helpers.c',
}


def _base_name(name: str, symbols: dict[str, Any]) -> str:
    base = str(symbols.get(name, {}).get('baseName') or '')
    if base:
        return base
    return name.split('::')[-1]


def _location_file(name: str, symbols: dict[str, Any]) -> str:
    return str((symbols.get(name, {}).get('location') or {}).get('file') or '')


def _veribin_footprint_bases(case_ir: dict[str, Any], plan: dict[str, Any]) -> set[str]:
    bases: set[str] = set()
    footprint = (plan or {}).get('patch_footprint') or {}
    for name in footprint.get('slice_functions') or []:
        text = str(name or '')
        if text:
            bases.add(text.split('::')[-1])
    for guard in (case_ir or {}).get('guards') or []:
        text = str(guard.get('function') or '')
        if text:
            bases.add(text.split('::')[-1])
    anchors = (case_ir or {}).get('defect_anchors') or {}
    for key in ('sink_site', 'root_cause_site'):
        text = str((anchors.get(key) or {}).get('function') or '')
        if text:
            bases.add(text.split('::')[-1])
    return bases


def veribin_keep_names(functions: list[dict[str, Any]],
                       symbols: dict[str, Any],
                       case_ir: dict[str, Any],
                       plan: dict[str, Any]) -> set[str]:
    bases = _veribin_footprint_bases(case_ir, plan)
    keep: set[str] = set()
    for fn in functions:
        name = str(fn.get('name') or '')
        if not name:
            continue
        base = _base_name(name, symbols)
        loc = _location_file(name, symbols).replace('\\', '/')
        leaf = loc.rsplit('/', 1)[-1]
        if (name.startswith(('__CPROVER_', '__vulgate_', '__vg_'))
                or base.startswith(('__CPROVER_', '__vulgate_', '__vg_'))
                or loc.startswith('<builtin-library-')
                or leaf in _VERIBIN_DRIVER_FILES
                or shared_allocator_symbol(name)
                or shared_readonly_symbol(name)
                or base in bases
                or name in bases):
            keep.add(name)
    return keep


def _direct_callees(fn: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for insn in fn.get('instructions') or []:
        if insn.get('instructionId') != 'FUNCTION_CALL':
            continue
        ops = (insn.get('code') or {}).get('sub') or []
        if len(ops) < 2 or ops[1].get('id') != 'symbol':
            continue
        callee = symbol_name(ops[1])
        if callee:
            found.append(callee)
    return found


def veribin_query_subtree(functions: list[dict[str, Any]],
                          keep: set[str]) -> list[str]:
    by_name = {str(fn.get('name') or ''): fn for fn in functions}
    seen: set[str] = set()
    stack: list[str] = []
    for root in ('__vg_run_world_0', '__vg_run_world_1', '__vg_impact_harness', '__vg_verify_obligations'):
        fn = by_name.get(root)
        if fn is not None:
            stack.extend(_direct_callees(fn))
    while stack:
        name = stack.pop()
        if name in seen or name not in keep or name not in by_name:
            continue
        if name.startswith(('__CPROVER_', '__vulgate_', '__vg_verify', '__vg_run_world', '__vg_impact')):
            continue
        seen.add(name)
        stack.extend(_direct_callees(by_name[name]))
    return sorted(seen)


def _collapse_indirect_calls(fn: dict[str, Any]) -> int:
    count = 0
    for insn in fn.get('instructions') or []:
        if insn.get('instructionId') != 'FUNCTION_CALL':
            continue
        ops = (insn.get('code') or {}).get('sub') or []
        if len(ops) < 2 or ops[1].get('id') == 'symbol':
            continue
        lhs = ops[0]
        if not isinstance(lhs, dict) or lhs.get('id') in (None, 'nil'):
            insn['instructionId'] = 'SKIP'
            insn['code'] = {
                'id': 'code',
                'namedSub': {'statement': {'id': 'skip'}, 'type': {'id': 'empty'}},
            }
            insn.pop('targets', None)
            count += 1
            continue
        lhs_type = (lhs.get('namedSub') or {}).get('type') or {
            'id': 'unsignedbv',
            'namedSub': {'width': {'id': '64'}},
        }
        nondet = {
            'id': 'side_effect',
            'namedSub': {
                'statement': {'id': 'nondet'},
                'type': deepcopy(lhs_type),
            },
        }
        insn['instructionId'] = 'ASSIGN'
        insn['code'] = irep_code('assign', [deepcopy(lhs), nondet])
        insn.pop('targets', None)
        count += 1
    return count


def _summarize_function(fn: dict[str, Any]) -> bool:
    if not fn.get('isBodyAvailable'):
        return False
    fn['isBodyAvailable'] = False
    fn['instructions'] = []
    return True


def _constant_return_body(fn: dict[str, Any], symbols: dict[str, Any]) -> bool:
    donor = None
    end = None
    for insn in fn.get('instructions') or []:
        if donor is None:
            donor = insn
        if insn.get('instructionId') == 'END_FUNCTION':
            end = deepcopy(insn)
    if donor is None or end is None:
        return False
    ret = ((symbols.get(fn['name']) or {}).get('type') or {}).get('namedSub', {}).get('return_type')
    body: list[dict[str, Any]] = []
    if isinstance(ret, dict) and ret.get('id') not in (None, 'empty', 'void'):
        zero = {'id': 'constant', 'namedSub': {'type': deepcopy(ret), 'value': {'id': '0'}}}
        set_ret = {
            'instructionId': 'SET_RETURN_VALUE',
            'locationNumber': 0,
            'code': irep_code('return', [zero]),
        }
        copy_location(set_ret, donor, mode=FULL)
        body.append(set_ret)
    end['locationNumber'] = len(body)
    end.pop('targets', None)
    body.append(end)
    fn['instructions'] = body
    fn['isBodyAvailable'] = True
    return True


def concretize_foreign_engines(functions: list[dict[str, Any]],
                               symbols: dict[str, Any],
                               case_ir: dict[str, Any],
                               plan: dict[str, Any]) -> list[str]:
    footprint = _veribin_footprint_bases(case_ir, plan)
    changed: list[str] = []
    for fn in functions:
        base = _base_name(str(fn.get('name') or ''), symbols)
        if base not in _HYBRID_ENGINE_BASES or base in footprint:
            continue
        if len(fn.get('instructions') or []) <= 24:
            continue
        if _constant_return_body(fn, symbols):
            changed.append(str(fn.get('name') or base))
    return changed


def apply_veribin_summaries(functions: list[dict[str, Any]],
                            symbols: dict[str, Any],
                            case_ir: dict[str, Any],
                            plan: dict[str, Any]) -> dict[str, Any]:
    engines = concretize_foreign_engines(functions, symbols, case_ir, plan)
    keep = veribin_keep_names(functions, symbols, case_ir, plan)
    summarized = 0
    collapsed = 0
    for fn in functions:
        name = str(fn.get('name') or '')
        if name in keep:
            collapsed += _collapse_indirect_calls(fn)
            continue
        if _summarize_function(fn):
            summarized += 1
    subtree = veribin_query_subtree(functions, keep)
    return {
        'encoding': 'veribin_uninterpreted_callees',
        'loop_unwind': VERIBIN_LOOP_UNWIND,
        'kept': len(keep),
        'summarized': summarized,
        'indirect_calls_collapsed': collapsed,
        'engines_concretized': engines,
        'subtree': subtree,
        'subtree_size': len(subtree),
    }


def shared_allocator_symbol(name: str) -> bool:
    base = name.split('::')[-1]
    if base.startswith(('__vg_alloc_', '__vg_ngx_', '__vg_apr_', '__vg_emalloc', '__vg_ecalloc', '__vg_safe_', '__vg_brigade')):
        return True
    return base in {
        'ngx_palloc', 'ngx_pnalloc', 'ngx_pcalloc', 'ngx_pfree',
        'apr_palloc', 'apr_brigade_create', 'apr_brigade_destroy', 'apr_brigade_cleanup',
        'apr_bucket_alloc', 'apr_bucket_free', 'apr_bucket_alloc_create', 'apr_bucket_alloc_destroy',
        '_emalloc', '_safe_emalloc', '_ecalloc', '_efree', '_zend_bailout',
        '__vg_heap_alloc', '__vg_mark_alloc',
        '__vg_brigade_consistent', '__vg_brigade_last',
    }


def clone_dual_world_goto(functions: list[dict[str, Any]],
                          symbols: dict[str, Any],
                          subtree_functions: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, dict[str, str]]]:
    fn_by_name = {f['name']: f for f in functions}
    subtree_set = {name for name in subtree_functions if not shared_readonly_symbol(name)}

    mutable_globals: set[str] = set()
    for sname, sym in symbols.items():
        owner = str((sym.get('location') or {}).get('function') or '')
        if sname.startswith(('__CPROVER_', '__vulgate_')) or shared_allocator_symbol(sname) or shared_readonly_symbol(sname) or shared_readonly_symbol(owner):
            continue
        loc_file = sym.get('location', {}).get('file', '')
        if any(rt in loc_file for rt in ('runtime/vm.c', 'runtime/experiment/state.c', 'vg_paired_helpers.c')):
            continue
        if (sym.get('isStaticLifetime') and not sym.get('isType') and
                not sym.get('isMacro') and sym.get('type', {}).get('id') != 'code'):
            is_const = sym.get('type', {}).get('namedSub', {}).get('#constant', {}).get('id') == '1'
            if not is_const:
                mutable_globals.add(sname)

    world_maps: dict[str, dict[str, str]] = {'w0': {}, 'w1': {}}
    new_symbols = deepcopy(symbols)
    new_functions = deepcopy(functions)

    for world in ('w0', 'w1'):
        prefix = f'__vg_{world}_'
        rmap: dict[str, str] = {}
        for gname in sorted(mutable_globals):
            if shared_allocator_symbol(gname):
                continue
            rmap[gname] = prefix + gname
        for fname in sorted(subtree_set):
            if fname not in fn_by_name or fname.startswith(('__CPROVER_', '__vulgate_')) or shared_allocator_symbol(fname):
                continue
            lib_file = symbols.get(fname, {}).get('location', {}).get('file', '')
            if lib_file.startswith('<builtin-library-'):
                continue
            rmap[fname] = prefix + fname
            fn_obj = fn_by_name[fname]
            for pid in fn_obj.get('parameterIdentifiers', []):
                if pid in symbols:
                    rmap[pid] = prefix + pid
            for insn in fn_obj.get('instructions', []):
                if insn.get('instructionId') in ('DECL', 'DEAD'):
                    ops = insn.get('code', {}).get('sub', [])
                    if ops and ops[0].get('id') == 'symbol':
                        lid = symbol_name(ops[0])
                        if lid in symbols:
                            rmap[lid] = prefix + lid
        for sname, sym in symbols.items():
            loc_fn = sym.get('location', {}).get('function')
            loc_file = sym.get('location', {}).get('file', '')
            if (loc_fn in subtree_set and not loc_file.startswith('<builtin-library-')
                    and sname not in rmap and not sname.startswith(('__CPROVER_', '__vulgate_'))
                    and not shared_allocator_symbol(sname) and not shared_readonly_symbol(sname)):
                rmap[sname] = prefix + sname

        world_maps[world] = rmap

        for old_sym, new_sym in rmap.items():
            if old_sym not in symbols:
                continue
            cloned_sym = deepcopy(symbols[old_sym])
            cloned_sym['name'] = new_sym
            old_base = cloned_sym.get('baseName', '')
            if '::' in new_sym:
                cloned_sym['baseName'] = old_base if old_base else new_sym.split('::')[-1]
            else:
                cloned_sym['baseName'] = prefix + old_base if old_base else new_sym
            old_pretty = cloned_sym.get('prettyName', '')
            cloned_sym['prettyName'] = (prefix + old_pretty) if old_pretty else ''
            cloned_sym['type'] = _rewrite_irep_symbols(cloned_sym['type'], rmap)
            cloned_sym['value'] = _rewrite_irep_symbols(cloned_sym['value'], rmap)
            old_loc_fn = cloned_sym.get('location', {}).get('function')
            if old_loc_fn and old_loc_fn in rmap and cloned_sym.get('locationIrep', {}).get('id') != 'nil':
                copy_location(cloned_sym, cloned_sym, mode=FULL, donor_kind='symbol', target_kind='symbol',
                              updates={'function': rmap[old_loc_fn]})
            else:
                copy_location(cloned_sym, cloned_sym, mode=FULL, donor_kind='symbol', target_kind='symbol')
            new_symbols[new_sym] = cloned_sym

        for fname in sorted(subtree_set):
            if fname not in fn_by_name or fname not in rmap:
                continue
            orig_fn = fn_by_name[fname]
            if not orig_fn.get('isBodyAvailable'):
                continue
            cloned_fn = deepcopy(orig_fn)
            cloned_fn['name'] = rmap[fname]
            cloned_fn['parameterIdentifiers'] = [rmap.get(p, p) for p in orig_fn.get('parameterIdentifiers', [])]
            for insn in cloned_fn.get('instructions', []):
                if 'code' in insn:
                    insn['code'] = _rewrite_irep_symbols(insn['code'], rmap)
                if 'guard' in insn:
                    insn['guard'] = _rewrite_irep_symbols(insn['guard'], rmap)
                if 'sourceLocationIrep' in insn and insn['sourceLocationIrep'].get('id') != 'nil':
                    copy_location(insn, insn, mode=FULL, updates={'function': rmap[fname]}, create_from_nil=False)
            new_functions.append(cloned_fn)

    init_fn = next((f for f in new_functions if f['name'] == '__CPROVER_initialize'), None)
    if init_fn is not None:
        extra_inits = []
        for insn in init_fn.get('instructions', []):
            if insn.get('instructionId') == 'ASSIGN':
                lhs = insn['code']['sub'][0]
                if lhs.get('id') == 'symbol':
                    orig_g = symbol_name(lhs)
                    for world in ('w0', 'w1'):
                        if orig_g in world_maps[world]:
                            dup = deepcopy(insn)
                            dup['code'] = _rewrite_irep_symbols(dup['code'], world_maps[world])
                            extra_inits.append(dup)
        if extra_inits and init_fn['instructions']:
            end_insn = init_fn['instructions'][-1]
            body_prefix = init_fn['instructions'][:-1] + extra_inits + [end_insn]
            old_to_new: dict[int, int] = {}
            for new_idx, item in enumerate(body_prefix):
                if 'locationNumber' in item and item['locationNumber'] not in old_to_new:
                    old_to_new[item['locationNumber']] = new_idx
                item['locationNumber'] = new_idx
            for item in body_prefix:
                if 'targets' in item:
                    item['targets'] = [old_to_new.get(t, t) for t in item['targets']]
            init_fn['instructions'] = body_prefix

    return new_functions, new_symbols, world_maps


def weave_guard_hooks_on_goto(functions: list[dict[str, Any]],
                              symbols: dict[str, Any],
                              w1_map: dict[str, str],
                              hook_bindings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    fn_by_name = {f['name']: f for f in functions}

    for hb in hook_bindings:
        orig_guard_fn = hb['guard_ir_function']
        w1_guard_fn = w1_map.get(orig_guard_fn, orig_guard_fn)
        helper_fn_name = hb['decision_helper_symbol']
        action_fn_name = hb.get('action_helper_symbol')
        blocked_flag_sym = hb['blocked_flag_symbol']

        if w1_guard_fn not in fn_by_name or helper_fn_name not in symbols:
            continue
        target_fn = fn_by_name[w1_guard_fn]
        orig_body = target_fn.get('instructions', [])
        if not orig_body:
            continue

        donor = symbols[w1_guard_fn]
        decision_var_name = f'{w1_guard_fn}::__vg_guard_decision_{hb["id"]}'
        u32_type = {'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}
        dec_sym = {
            'name': decision_var_name,
            'baseName': f'__vg_guard_decision_{hb["id"]}',
            'prettyName': decision_var_name,
            'mode': 'C',
            'module': donor.get('module', ''),
            'type': u32_type,
            'value': {'id': 'nil'},
            'isType': False, 'isMacro': False, 'isExported': False,
            'isInput': False, 'isOutput': False, 'isStateVar': False,
            'isProperty': False, 'isStaticLifetime': False, 'isThreadLocal': False,
            'isLvalue': True, 'isFileLocal': True, 'isExtern': False,
            'isVolatile': False, 'isParameter': False, 'isAuxiliary': True, 'isWeak': False,
        }
        copy_location(dec_sym, donor, mode=FULL, donor_kind='symbol', target_kind='symbol')
        symbols[decision_var_name] = dec_sym

        dec_var_expr = {'id': 'symbol', 'namedSub': {'identifier': {'id': decision_var_name}, 'type': u32_type}}
        param_exprs = []
        callee_params = symbols[helper_fn_name]['type'].get('namedSub', {}).get('parameters', {}).get('sub', [])
        for idx_p, pid in enumerate(target_fn.get('parameterIdentifiers', [])):
            if pid not in symbols:
                continue
            p_expr: dict[str, Any] = {'id': 'symbol', 'namedSub': {'identifier': {'id': pid}, 'type': deepcopy(symbols[pid]['type'])}}
            if idx_p < len(callee_params):
                expected_p_type = callee_params[idx_p].get('namedSub', {}).get('type')
                if expected_p_type and expected_p_type != symbols[pid]['type']:
                    p_expr = {'id': 'typecast', 'namedSub': {'type': deepcopy(expected_p_type)}, 'sub': [p_expr]}
            param_exprs.append(p_expr)

        helper_callee = {'id': 'symbol', 'namedSub': {
            'identifier': {'id': helper_fn_name},
            'type': deepcopy(symbols[helper_fn_name]['type']),
        }}
        call_args_irep = {'id': 'arguments', 'sub': param_exprs} if param_exprs else {'id': 'arguments'}

        decl_insn: dict[str, Any] = {
            'instructionId': 'DECL',
            'code': irep_code('decl', [deepcopy(dec_var_expr)]),
        }
        copy_location(decl_insn, orig_body[0], mode=FULL)

        call_insn: dict[str, Any] = {
            'instructionId': 'FUNCTION_CALL',
            'code': irep_code('function_call', [deepcopy(dec_var_expr), helper_callee, call_args_irep]),
        }
        copy_location(call_insn, orig_body[0], mode=FULL)

        zero_const = {'id': 'constant', 'namedSub': {'type': u32_type, 'value': {'id': '0'}}}
        skip_to_body_insn: dict[str, Any] = {
            'instructionId': 'GOTO',
            'guard': operation('=', deepcopy(dec_var_expr), zero_const),
            'targets': [],
        }
        copy_location(skip_to_body_insn, orig_body[0], mode=FULL)

        block_seq: list[dict[str, Any]] = []
        if blocked_flag_sym in symbols:
            flag_type = deepcopy(symbols[blocked_flag_sym]['type'])
            flag_lhs = {'id': 'symbol', 'namedSub': {'identifier': {'id': blocked_flag_sym}, 'type': flag_type}}
            one_val = {'id': 'constant', 'namedSub': {
                'type': flag_type,
                'value': {'id': 'true' if flag_type['id'] == 'bool' else '1'},
            }}
            set_flag_insn: dict[str, Any] = {
                'instructionId': 'ASSIGN',
                'code': irep_code('assign', [flag_lhs, one_val]),
            }
            copy_location(set_flag_insn, orig_body[0], mode=FULL)
            block_seq.append(set_flag_insn)

        ret_type = symbols[w1_guard_fn]['type'].get('namedSub', {}).get('return_type', {'id': 'empty'})
        if action_fn_name and action_fn_name in symbols:
            act_callee = {'id': 'symbol', 'namedSub': {
                'identifier': {'id': action_fn_name},
                'type': deepcopy(symbols[action_fn_name]['type']),
            }}
            if ret_type.get('id') in ('empty', 'void'):
                act_call: dict[str, Any] = {
                    'instructionId': 'FUNCTION_CALL',
                    'code': irep_code('function_call', [{'id': 'nil'}, act_callee, deepcopy(call_args_irep)]),
                }
                copy_location(act_call, orig_body[0], mode=FULL)
                block_seq.append(act_call)
            else:
                ret_tmp_name = f'{w1_guard_fn}::__vg_action_ret_{hb["id"]}'
                ret_tmp_sym = deepcopy(dec_sym)
                ret_tmp_sym.update({
                    'name': ret_tmp_name,
                    'baseName': f'__vg_action_ret_{hb["id"]}',
                    'prettyName': ret_tmp_name,
                    'type': deepcopy(ret_type),
                })
                symbols[ret_tmp_name] = ret_tmp_sym
                ret_tmp_expr = {'id': 'symbol', 'namedSub': {'identifier': {'id': ret_tmp_name}, 'type': deepcopy(ret_type)}}
                act_ret_type = symbols[action_fn_name]['type'].get('namedSub', {}).get('return_type', ret_type)
                if act_ret_type != ret_type:
                    raw_ret_name = f'{w1_guard_fn}::__vg_action_raw_{hb["id"]}'
                    raw_ret_sym = deepcopy(ret_tmp_sym)
                    raw_ret_sym.update({
                        'name': raw_ret_name,
                        'baseName': f'__vg_action_raw_{hb["id"]}',
                        'prettyName': raw_ret_name,
                        'type': deepcopy(act_ret_type),
                    })
                    symbols[raw_ret_name] = raw_ret_sym
                    raw_ret_expr = {'id': 'symbol', 'namedSub': {'identifier': {'id': raw_ret_name}, 'type': deepcopy(act_ret_type)}}
                    decl_raw: dict[str, Any] = {'instructionId': 'DECL', 'code': irep_code('decl', [deepcopy(raw_ret_expr)])}
                    copy_location(decl_raw, orig_body[0], mode=FULL)
                    decl_ret = {'instructionId': 'DECL', 'code': irep_code('decl', [deepcopy(ret_tmp_expr)])}
                    copy_location(decl_ret, orig_body[0], mode=FULL)
                    act_call = {
                        'instructionId': 'FUNCTION_CALL',
                        'code': irep_code('function_call', [deepcopy(raw_ret_expr), act_callee, deepcopy(call_args_irep)]),
                    }
                    copy_location(act_call, orig_body[0], mode=FULL)
                    cast_assign: dict[str, Any] = {
                        'instructionId': 'ASSIGN',
                        'code': irep_code('assign', [deepcopy(ret_tmp_expr), {'id': 'typecast', 'namedSub': {'type': deepcopy(ret_type)}, 'sub': [deepcopy(raw_ret_expr)]}]),
                    }
                    copy_location(cast_assign, orig_body[0], mode=FULL)
                    set_ret = {
                        'instructionId': 'SET_RETURN_VALUE',
                        'code': irep_code('return', [deepcopy(ret_tmp_expr)]),
                    }
                    copy_location(set_ret, orig_body[0], mode=FULL)
                    block_seq.extend([decl_raw, decl_ret, act_call, cast_assign, set_ret])
                else:
                    decl_ret = {'instructionId': 'DECL', 'code': irep_code('decl', [deepcopy(ret_tmp_expr)])}
                    copy_location(decl_ret, orig_body[0], mode=FULL)
                    act_call = {
                        'instructionId': 'FUNCTION_CALL',
                        'code': irep_code('function_call', [deepcopy(ret_tmp_expr), act_callee, deepcopy(call_args_irep)]),
                    }
                    copy_location(act_call, orig_body[0], mode=FULL)
                    set_ret = {
                        'instructionId': 'SET_RETURN_VALUE',
                        'code': irep_code('return', [deepcopy(ret_tmp_expr)]),
                    }
                    copy_location(set_ret, orig_body[0], mode=FULL)
                    block_seq.extend([decl_ret, act_call, set_ret])

        goto_end_insn: dict[str, Any] = {
            'instructionId': 'GOTO',
            'guard': TRUE,
            'targets': [],
        }
        copy_location(goto_end_insn, orig_body[0], mode=FULL)
        block_seq.append(goto_end_insn)

        prefix_insns = [decl_insn, call_insn, skip_to_body_insn, *block_seq]
        offset_shift = len(prefix_insns)

        old_num_to_idx = {ins['locationNumber']: idx for idx, ins in enumerate(orig_body)}
        combined = prefix_insns + orig_body
        for idx, ins in enumerate(combined):
            ins['locationNumber'] = idx

        skip_to_body_insn['targets'] = [offset_shift]
        end_idx = len(combined) - 1
        for idx in range(len(combined) - 1, -1, -1):
            if combined[idx]['instructionId'] == 'END_FUNCTION':
                end_idx = idx
                break
        goto_end_insn['targets'] = [end_idx]

        for orig_idx in range(offset_shift, len(combined)):
            ins = combined[orig_idx]
            if 'targets' in ins:
                ins['targets'] = [old_num_to_idx[t] + offset_shift for t in ins['targets']]

        target_fn['instructions'] = combined

        for helper_name in (helper_fn_name, action_fn_name):
            if not helper_name or helper_name not in fn_by_name:
                continue
            helper_fn = fn_by_name[helper_name]
            for insn in helper_fn.get('instructions', []):
                if 'code' in insn:
                    insn['code'] = _rewrite_irep_symbols(insn['code'], w1_map)
                if 'guard' in insn:
                    insn['guard'] = _rewrite_irep_symbols(insn['guard'], w1_map)

    return functions, symbols


def _parameter_index(function: dict[str, Any], symbols: dict[str, Any], wanted: str) -> int | None:
    for idx, pid in enumerate(function.get('parameterIdentifiers') or []):
        base = symbols.get(pid, {}).get('baseName', str(pid).split('::')[-1])
        if base == wanted:
            return idx
    return None


def _insert_instruction(function: dict[str, Any], index: int, insn: dict[str, Any]) -> None:
    body = list(function.get('instructions') or [])
    body.insert(index, insn)
    displaced_loc = body[index + 1].get('locationNumber') if index + 1 < len(body) else None
    old_to_new: dict[int, int] = {}
    for new_idx, item in enumerate(body):
        loc = item.get('locationNumber')
        if loc is not None and loc not in old_to_new:
            old_to_new[loc] = new_idx
        item['locationNumber'] = new_idx
    if displaced_loc is not None:
        old_to_new[displaced_loc] = index
    for item in body:
        if 'targets' in item:
            item['targets'] = [old_to_new.get(target, target) for target in item['targets']]
    function['instructions'] = body


def _resource_base_name(symbols: dict[str, Any], callee: str) -> str:
    base = str(symbols.get(callee, {}).get('baseName') or callee)
    for prefix in ('__vg_w0_', '__vg_w1_'):
        if base.startswith(prefix):
            return base[len(prefix):]
    return base.split(':')[-1]


def weave_resource_balance(functions: list[dict[str, Any]],
                           symbols: dict[str, Any],
                           w1_map: dict[str, str],
                           plan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from .planner import resource_event_names
    acquires, releases = resource_event_names(plan)
    acquire_name = '__vg_resource_acquire'
    release_name = '__vg_resource_release'
    if not acquires and not releases:
        return functions, symbols
    if acquire_name not in symbols or release_name not in symbols:
        return functions, symbols
    w1_names = set(w1_map.values())
    for fn in functions:
        if fn['name'] not in w1_names:
            continue
        sites: list[tuple[int, dict[str, Any], str]] = []
        for idx, insn in enumerate(fn.get('instructions') or []):
            if insn.get('instructionId') != 'FUNCTION_CALL':
                continue
            ops = insn.get('code', {}).get('sub') or []
            if len(ops) < 2 or ops[1].get('id') != 'symbol':
                continue
            raw = _resource_base_name(symbols, symbol_name(ops[1]))
            if raw in releases:
                sites.append((idx, insn, release_name))
            elif raw in acquires:
                sites.append((idx, insn, acquire_name))
        for idx, insn, helper in reversed(sites):
            helper_type = symbols[helper].get('type') or {'id': 'code'}
            helper_expr = {'id': 'symbol', 'namedSub': {
                'identifier': {'id': helper},
                'type': deepcopy(helper_type),
            }}
            call = {
                'instructionId': 'FUNCTION_CALL',
                'code': irep_code('function_call', [
                    {'id': 'nil'},
                    helper_expr,
                    {'id': 'arguments'},
                ]),
                'guard': deepcopy(insn.get('guard', TRUE)),
            }
            copy_location(call, insn, mode=FULL)
            _insert_instruction(fn, idx, call)
    return functions, symbols


def _irep_symbols(node: Any, found: dict[str, str], symbols: dict[str, Any]) -> None:
    if isinstance(node, list):
        for item in node:
            _irep_symbols(item, found, symbols)
        return
    if not isinstance(node, dict):
        return
    if node.get('id') == 'symbol':
        ident = (node.get('namedSub') or {}).get('identifier', {}).get('id')
        if ident:
            base = symbols.get(ident, {}).get('baseName', str(ident).split('::')[-1])
            found.setdefault(str(base), str(ident))
    for child in node.get('sub') or []:
        _irep_symbols(child, found, symbols)
    for value in (node.get('namedSub') or {}).values():
        if isinstance(value, (dict, list)):
            _irep_symbols(value, found, symbols)


def _function_base_symbols(function: dict[str, Any], symbols: dict[str, Any]) -> dict[str, str]:
    found: dict[str, str] = {}
    for ident in function.get('parameterIdentifiers') or []:
        base = symbols.get(ident, {}).get('baseName', str(ident).split('::')[-1])
        found.setdefault(str(base), str(ident))
    for insn in function.get('instructions') or []:
        _irep_symbols(insn.get('code'), found, symbols)
        _irep_symbols(insn.get('guard'), found, symbols)
    return found


def _word_irep(function: dict[str, Any], symbols: dict[str, Any], text: str, names: dict[str, str]) -> dict[str, Any] | None:
    u64 = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}
    raw = text.strip()
    if raw == '__vg_tid':
        return {'id': 'constant', 'namedSub': {'type': deepcopy(u64), 'value': {'id': '0'}}}
    if re.fullmatch(r'\d+', raw):
        return {'id': 'constant', 'namedSub': {'type': deepcopy(u64), 'value': {'id': str(int(raw))}}}
    member = re.fullmatch(r'([A-Za-z_]\w*)\s*(->|\.)\s*([A-Za-z_]\w*)', raw)
    if member:
        ident = names.get(member.group(1))
        if ident is None:
            return None
        sym_type = symbols.get(ident, {}).get('type') or u64
        accessed: dict[str, Any] = {'id': 'symbol', 'namedSub': {
            'identifier': {'id': ident}, 'type': deepcopy(sym_type),
        }}
        if member.group(2) == '->':
            accessed = {'id': 'dereference', 'namedSub': {'type': deepcopy(u64)}, 'sub': [accessed]}
        return {'id': 'member', 'namedSub': {
            'component_name': {'id': member.group(3)}, 'type': deepcopy(u64),
        }, 'sub': [accessed]}
    if re.fullmatch(r'[A-Za-z_]\w*', raw):
        ident = names.get(raw)
        if ident is None:
            return None
        sym_type = symbols.get(ident, {}).get('type') or u64
        return {'id': 'typecast', 'namedSub': {'type': deepcopy(u64)}, 'sub': [
            {'id': 'symbol', 'namedSub': {'identifier': {'id': ident}, 'type': deepcopy(sym_type)}},
        ]}
    return None


def _anchor_sites(function: dict[str, Any], symbols: dict[str, Any], anchor: str) -> list[int]:
    body = function.get('instructions') or []
    if anchor == 'function_exit':
        return [index for index, insn in enumerate(body) if insn.get('instructionId') == 'END_FUNCTION']
    match = re.fullmatch(r'after_assign_(.+)', anchor)
    if not match:
        return []
    rest = match.group(1)
    names = _function_base_symbols(function, symbols)
    candidates = []
    for base in names:
        prefix = base + '_'
        if rest.startswith(prefix) and rest[len(prefix):]:
            candidates.append((base, rest[len(prefix):]))
    if not candidates:
        return []
    base, field = max(candidates, key=lambda item: len(item[0]))
    sites = []
    for index, insn in enumerate(body):
        if insn.get('instructionId') != 'ASSIGN':
            continue
        lhs = ((insn.get('code') or {}).get('sub') or [None])[0]
        if not isinstance(lhs, dict) or lhs.get('id') != 'member':
            continue
        component = (lhs.get('namedSub') or {}).get('component_name', {}).get('id')
        if component != field:
            continue
        mentioned: dict[str, str] = {}
        _irep_symbols(lhs, mentioned, symbols)
        if base in mentioned:
            sites.append(index + 1)
    return sites


def _cast_word(expr: dict[str, Any] | None, param_type: dict[str, Any]) -> dict[str, Any]:
    if expr is None:
        expr = {'id': 'constant', 'namedSub': {'type': deepcopy(param_type), 'value': {'id': '0'}}}
    return {'id': 'typecast', 'namedSub': {'type': deepcopy(param_type)}, 'sub': [expr]}


def _insert_word_call(function: dict[str, Any], index: int, helper_name: str, helper_type: dict[str, Any],
                      words: list[dict[str, Any] | None], insn: dict[str, Any]) -> None:
    params = helper_type.get('namedSub', {}).get('parameters', {}).get('sub') or []
    param_types = []
    for param in params:
        ptype = param.get('namedSub', {}).get('type')
        if not ptype:
            return
        param_types.append(ptype)
    if len(param_types) < len(words):
        return
    helper_expr = {'id': 'symbol', 'namedSub': {
        'identifier': {'id': helper_name},
        'type': deepcopy(helper_type),
    }}
    rendered_args = [_cast_word(word, param_types[pos]) for pos, word in enumerate(words)]
    args_irep = {'id': 'arguments', 'sub': rendered_args} if rendered_args else {'id': 'arguments'}
    call = {
        'instructionId': 'FUNCTION_CALL',
        'code': irep_code('function_call', [
            {'id': 'nil'},
            helper_expr,
            args_irep,
        ]),
        'guard': deepcopy(insn.get('guard', TRUE)),
    }
    copy_location(call, insn, mode=FULL)
    _insert_instruction(function, index, call)


def _weave_structured_observer(functions: list[dict[str, Any]],
                               symbols: dict[str, Any],
                               w1_names: set[str],
                               obs: dict[str, Any],
                               map_def: dict[str, Any]) -> bool:
    from .case_compiler import bind_observer_words

    if obs.get('callsite') or 'key_expr' not in obs:
        return False
    from .oracle_compiler import _needs_word_store
    if not _needs_word_store(obs, map_def):
        return False
    site = obs.get('site') if isinstance(obs.get('site'), dict) else {}
    anchor = str(obs.get('anchor') or site.get('anchor') or '')
    function_name = str(obs.get('function') or site.get('function') or '')
    if not anchor or not function_name:
        return False
    try:
        bound = bind_observer_words(
            str(obs.get('map') or ''),
            map_def,
            obs,
            list(obs.get('parameter_names') or []),
        )
    except ValueError:
        return False
    operation = str(obs.get('operation') or 'set')
    map_name = str(obs.get('map') or '')
    if operation in ('delete', 'del', 'remove'):
        helper_name = f'__vulgate_table_del_words_{map_name}'
        value_exprs: list[str] = []
    elif operation == 'set':
        helper_name = f'__vulgate_table_set_words_{map_name}'
        value_exprs = list(bound.get('value_exprs') or [])
    else:
        return False
    helper_type = symbols.get(helper_name, {}).get('type') or {}
    if not helper_type:
        return False
    for fn in functions:
        if fn['name'] not in w1_names:
            continue
        base = symbols.get(fn['name'], {}).get('baseName', fn['name'])
        if base != function_name and fn['name'] != function_name:
            continue
        names = _function_base_symbols(fn, symbols)
        key_words = []
        for comp in bound['key_components']:
            if comp.get('scope'):
                key_words.append(_word_irep(fn, symbols, '__vg_tid', names))
            else:
                key_words.append(_word_irep(fn, symbols, str(comp.get('name') or ''), names))
        value_words = [_word_irep(fn, symbols, expr, names) for expr in value_exprs]
        if any(word is None for word in [*key_words, *value_words]):
            continue
        padded_keys = list(key_words) + [None] * (4 - len(key_words))
        count = {'id': 'constant', 'namedSub': {
            'type': {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}},
            'value': {'id': str(len(key_words))},
        }}
        words: list[dict[str, Any] | None] = [None, *padded_keys, count]
        if operation == 'set':
            padded_values = list(value_words) + [None] * (4 - len(value_words))
            fields = {'id': 'constant', 'namedSub': {
                'type': {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}},
                'value': {'id': str(len(value_words))},
            }}
            words.extend([*padded_values, fields])
        sites = _anchor_sites(fn, symbols, anchor)
        for index in reversed(sites):
            insn = (fn.get('instructions') or [])[min(index, len(fn.get('instructions') or []) - 1)]
            _insert_word_call(fn, index, helper_name, helper_type, words, insn)
    return True


def _irep_nodes(node: Any):
    if isinstance(node, list):
        for item in node:
            yield from _irep_nodes(item)
        return
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get('sub') or []:
        yield from _irep_nodes(child)
    for value in (node.get('namedSub') or {}).values():
        if isinstance(value, (dict, list)):
            yield from _irep_nodes(value)


def _output_pointer_argument(symbols: dict[str, Any], name: str, form: str, param_type: dict[str, Any]) -> dict[str, Any] | None:
    local = symbols.get(name)
    if not local or not local.get('type'):
        return None
    expr: dict[str, Any] = {'id': 'symbol', 'namedSub': {
        'identifier': {'id': name},
        'type': deepcopy(local['type']),
    }}
    if form == 'object':
        # A pointer type must carry the target's pointer width: CBMC rejects a
        # bitvector type without width when the exported GOTO is validated.
        pointer_width = deepcopy((param_type.get('namedSub') or {}).get('width') or {'id': '64'})
        expr = {'id': 'address_of', 'namedSub': {'type': {
            'id': 'pointer', 'namedSub': {'width': pointer_width}, 'sub': [deepcopy(local['type'])],
        }}, 'sub': [expr]}
    return {'id': 'typecast', 'namedSub': {'type': deepcopy(param_type)}, 'sub': [expr]}


def weave_caller_output_pointers(functions: list[dict[str, Any]],
                                 symbols: dict[str, Any],
                                 w1_map: dict[str, str],
                                 plan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _weave_forwarded_pointers(
        functions, symbols, w1_map, plan,
        '__vg_assert_caller_output', 'caller_output_pointers', 'ancestor_output_pointers',
    )


def weave_caller_brigades(functions: list[dict[str, Any]],
                          symbols: dict[str, Any],
                          w1_map: dict[str, str],
                          plan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _weave_forwarded_pointers(
        functions, symbols, w1_map, plan,
        '__vg_assert_brigade_ring', 'caller_brigades', 'ancestor_brigades',
    )


def _weave_forwarded_pointers(functions: list[dict[str, Any]],
                              symbols: dict[str, Any],
                              w1_map: dict[str, str],
                              plan: dict[str, Any],
                              helper: str,
                              direct_field: str,
                              ancestor_field: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    helper_type = symbols.get(helper, {}).get('type') or {}
    params = helper_type.get('namedSub', {}).get('parameters', {}).get('sub') or []
    if not params:
        return functions, symbols
    param_type = params[0].get('namedSub', {}).get('type')
    if not param_type:
        return functions, symbols
    fn_by_name = {fn['name']: fn for fn in functions}
    helper_expr = {'id': 'symbol', 'namedSub': {
        'identifier': {'id': helper},
        'type': deepcopy(helper_type),
    }}
    def insert_checks(fn: dict[str, Any],
                      callee_names: set[str],
                      allowed: dict[str, str],
                      allow_indirect: bool = False) -> None:
        sites: list[tuple[int, list[tuple[str, str]]]] = []
        for idx, insn in enumerate(fn.get('instructions') or []):
            if insn.get('instructionId') != 'FUNCTION_CALL':
                continue
            ops = insn.get('code', {}).get('sub') or []
            if len(ops) < 3:
                continue
            named = ops[1].get('id') == 'symbol' and symbol_name(ops[1]) in callee_names
            unnamed = allow_indirect and ops[1].get('id') != 'symbol'
            if not named and not unnamed:
                continue
            matched: list[tuple[str, str]] = []
            seen: set[tuple[str, str]] = set()
            for arg in ops[2].get('sub') or []:
                if arg.get('id') == 'symbol':
                    name = symbol_name(arg)
                    key = (name, 'pointer')
                    if allowed.get(name) == 'pointer' and key not in seen:
                        seen.add(key)
                        matched.append(key)
                for node in _irep_nodes(arg):
                    if node.get('id') != 'address_of' or not node.get('sub') or node['sub'][0].get('id') != 'symbol':
                        continue
                    name = symbol_name(node['sub'][0])
                    key = (name, 'object')
                    if allowed.get(name) == 'object' and key not in seen:
                        seen.add(key)
                        matched.append(key)
            if matched:
                sites.append((idx, matched))
        for idx, matched in reversed(sites):
            insn = fn['instructions'][idx]
            for name, form in reversed(matched):
                arg = _output_pointer_argument(symbols, name, form, param_type)
                if arg is None:
                    continue
                call = {
                    'instructionId': 'FUNCTION_CALL',
                    'code': irep_code('function_call', [
                        {'id': 'nil'},
                        deepcopy(helper_expr),
                        {'id': 'arguments', 'sub': [arg]},
                    ]),
                    'guard': deepcopy(insn.get('guard', TRUE)),
                }
                copy_location(call, insn, mode=FULL)
                _insert_instruction(fn, idx + 1, call)

    def allowed_outputs(row: dict[str, Any]) -> dict[str, str]:
        return {
            w1_map.get(item.get('symbol'), item.get('symbol')): item.get('form')
            for item in (row.get(direct_field) or [])
            if item.get('symbol') and item.get('form') in ('pointer', 'object')
        }

    for cont in plan.get('continuations') or []:
        if not cont.get('require_output_pointer_defined'):
            continue
        guards = {w1_map.get(name, name) for name in (cont.get('guard_ir_names') or [])}
        for row in cont.get('direct_callers') or []:
            allowed = allowed_outputs(row)
            if not allowed:
                continue
            caller = w1_map.get(row.get('caller'), row.get('caller'))
            fn = fn_by_name.get(caller)
            if fn is None:
                continue
            insert_checks(fn, guards, allowed, bool(row.get('indirect_call')))
        for row in cont.get(ancestor_field) or []:
            allowed = allowed_outputs(row)
            if not allowed:
                continue
            caller = w1_map.get(row.get('caller'), row.get('caller'))
            fn = fn_by_name.get(caller)
            child = str(row.get('callee') or '')
            if fn is None or not child:
                continue
            insert_checks(fn, {w1_map.get(child, child)}, allowed)
    return functions, symbols


def weave_unresolved_indirect_calls(functions: list[dict[str, Any]],
                                    symbols: dict[str, Any],
                                    w1_map: dict[str, str],
                                    plan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sites: list[tuple[str, int]] = []
    for task in plan.get('tasks') or []:
        for item in task.get('unresolved_external_calls') or []:
            if not str(item.get('callee') or '').startswith('<indirect:'):
                continue
            caller = str(item.get('caller') or '')
            index = item.get('index')
            if caller and isinstance(index, int):
                sites.append((caller, index))
    if not sites:
        return functions, symbols
    flag = '__vulgate_missing_callee_hit'
    if flag not in symbols:
        symbols = dict(symbols)
        symbols[flag] = {'baseName': flag, 'type': {'id': 'bool'}}
    flag_type = deepcopy(symbols[flag]['type'])
    fn_by_name = {fn['name']: fn for fn in functions}
    pending: dict[int, tuple[dict[str, Any], list[int]]] = {}
    for caller, index in sites:
        names = [w1_map.get(caller, caller)]
        mapped = names[0]
        if mapped.startswith('__vg_w1_'):
            names.append('__vg_w0_' + mapped[len('__vg_w1_'):])
        for name in names:
            fn = fn_by_name.get(name)
            if fn is None:
                continue
            row = pending.setdefault(id(fn), (fn, []))
            row[1].append(index)
    for fn, indexes in pending.values():
        for index in sorted(set(indexes), reverse=True):
            insns = fn.get('instructions') or []
            if index >= len(insns):
                continue
            insn = insns[index]
            ops = (insn.get('code') or {}).get('sub') or []
            if insn.get('instructionId') != 'FUNCTION_CALL' or len(ops) < 2 or ops[1].get('id') == 'symbol':
                continue
            value = 'true' if flag_type.get('id') == 'bool' else '1'
            store = {
                'instructionId': 'ASSIGN',
                'code': irep_code('assign', [
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': flag}, 'type': deepcopy(flag_type)}},
                    {'id': 'constant', 'namedSub': {'type': deepcopy(flag_type), 'value': {'id': value}}},
                ]),
                'guard': deepcopy(insn.get('guard', TRUE)),
            }
            copy_location(store, insn, mode=FULL)
            _insert_instruction(fn, index + 1, store)
    return functions, symbols


def apply_paired_weaves(functions: list[dict[str, Any]],
                        symbols: dict[str, Any],
                        w1_map: dict[str, str],
                        guard_specs: list[dict[str, Any]],
                        observers: list[dict[str, Any]],
                        maps: dict[str, Any] | None,
                        plan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    functions, symbols = weave_unresolved_indirect_calls(functions, symbols, w1_map, plan)
    functions, symbols = weave_guard_hooks_on_goto(functions, symbols, w1_map, guard_specs)
    functions, symbols = weave_observer_maps(functions, symbols, w1_map, observers, maps)
    functions, symbols = weave_resource_balance(functions, symbols, w1_map, plan)
    functions, symbols = weave_caller_output_pointers(functions, symbols, w1_map, plan)
    functions, symbols = weave_caller_brigades(functions, symbols, w1_map, plan)
    return functions, symbols


def _dsl_observer_param_irep(fn: dict[str, Any],
                             symbols: dict[str, Any],
                             arg_idx: int,
                             declared_arity: int,
                             call_args: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    u64 = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}
    zero = {'id': 'constant', 'namedSub': {'type': deepcopy(u64), 'value': {'id': '0'}}}
    if arg_idx < 0 or arg_idx >= declared_arity:
        return zero
    if call_args is not None:
        if arg_idx >= len(call_args):
            return zero
        return {'id': 'typecast', 'namedSub': {'type': deepcopy(u64)}, 'sub': [deepcopy(call_args[arg_idx])]}
    params = fn.get('parameterIdentifiers') or []
    if arg_idx >= len(params):
        return zero
    ident = str(params[arg_idx])
    sym_type = symbols.get(ident, {}).get('type') or u64
    return {'id': 'typecast', 'namedSub': {'type': deepcopy(u64)}, 'sub': [
        {'id': 'symbol', 'namedSub': {'identifier': {'id': ident}, 'type': deepcopy(sym_type)}},
    ]}


def _weave_dsl_observer(functions: list[dict[str, Any]],
                        symbols: dict[str, Any],
                        w1_names: set[str],
                        obs: dict[str, Any]) -> bool:
    if not obs.get('dsl_operations'):
        return False
    oid = re.sub(r'[^A-Za-z0-9_]', '_', str(obs.get('id') or 'obs'))
    helper_name = f'__vulgate_obs_{oid}'
    if helper_name not in symbols:
        return False
    helper_type = symbols[helper_name].get('type') or {}
    if not helper_type:
        return False
    arg_indices = [int(x) for x in (obs.get('arg_indices') or [])]
    local_names = [str(x) for x in (obs.get('local_names') or [])]
    declared_arity = len(obs.get('arg_types') or [])
    target_fn = str(obs.get('function') or '')
    dsl_cs = obs.get('dsl_callsite') if isinstance(obs.get('dsl_callsite'), dict) else None
    dsl_ln = obs.get('dsl_line') if isinstance(obs.get('dsl_line'), dict) else None
    u64 = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}
    zero = {'id': 'constant', 'namedSub': {'type': deepcopy(u64), 'value': {'id': '0'}}}
    wove_any = False
    for fn in functions:
        if fn['name'] not in w1_names:
            continue
        insns = fn.get('instructions') or []
        if not insns:
            continue
        base = symbols.get(fn['name'], {}).get('baseName', fn['name'])
        if target_fn and base != target_fn and fn['name'] != target_fn:
            continue
        names = _function_base_symbols(fn, symbols)
        local_ireps = [_word_irep(fn, symbols, lname, names) or deepcopy(zero) for lname in local_names]
        if dsl_cs is not None:
            want_callee = str(dsl_cs.get('callee') or '')
            want_line = str(dsl_cs['line']) if dsl_cs.get('line') is not None else None
            exact_sites: list[int] = []
            all_sites: list[int] = []
            for idx, insn in enumerate(insns):
                if insn.get('instructionId') != 'FUNCTION_CALL':
                    continue
                ops = (insn.get('code') or {}).get('sub') or []
                if len(ops) < 3 or ops[1].get('id') != 'symbol':
                    continue
                callee_name = symbol_name(ops[1])
                callee_base = symbols.get(callee_name, {}).get('baseName', callee_name)
                if callee_base != want_callee and callee_name != want_callee:
                    continue
                all_sites.append(idx)
                loc_line = ((insn.get('sourceLocation') or {}).get('namedSub') or {}).get('line', {}).get('id')
                if want_line is not None and str(loc_line or '') == want_line:
                    exact_sites.append(idx)
            chosen_sites = exact_sites if (want_line is not None and exact_sites) else all_sites
            for idx in reversed(chosen_sites):
                insn = fn['instructions'][idx]
                ops = (insn.get('code') or {}).get('sub') or []
                cargs = (ops[2].get('sub') or []) if len(ops) >= 3 else []
                words = [
                    *[_dsl_observer_param_irep(fn, symbols, a_idx, declared_arity, cargs) for a_idx in arg_indices],
                    *[deepcopy(item) for item in local_ireps],
                ]
                _insert_word_call(fn, idx, helper_name, helper_type, words, insn)
                wove_any = True
        elif dsl_ln is not None:
            want_line = str(dsl_ln['line']) if dsl_ln.get('line') is not None else ''
            want_file = Path(str(dsl_ln['file'])).name if dsl_ln.get('file') else ''
            line_idx: int | None = None
            for idx, insn in enumerate(insns):
                loc = (insn.get('sourceLocation') or {}).get('namedSub') or {}
                loc_line = str((loc.get('line') or {}).get('id') or '')
                loc_file = Path(str((loc.get('file') or {}).get('id') or '')).name
                if loc_line == want_line and (not want_file or loc_file == want_file):
                    line_idx = idx
                    break
            if line_idx is not None:
                insn = fn['instructions'][line_idx]
                words = [
                    *[_dsl_observer_param_irep(fn, symbols, a_idx, declared_arity, None) for a_idx in arg_indices],
                    *[deepcopy(item) for item in local_ireps],
                ]
                _insert_word_call(fn, line_idx, helper_name, helper_type, words, insn)
                wove_any = True
        else:
            insn = fn['instructions'][0]
            words = [
                *[_dsl_observer_param_irep(fn, symbols, a_idx, declared_arity, None) for a_idx in arg_indices],
                *[deepcopy(item) for item in local_ireps],
            ]
            _insert_word_call(fn, 0, helper_name, helper_type, words, insn)
            wove_any = True
    return wove_any


def weave_observer_maps(functions: list[dict[str, Any]],
                        symbols: dict[str, Any],
                        w1_map: dict[str, str],
                        observers: list[dict[str, Any]],
                        maps: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    fn_by_name = {fn['name']: fn for fn in functions}
    w1_names = set(w1_map.values())
    map_defs = maps or {}
    for obs in observers:
        if _weave_dsl_observer(functions, symbols, w1_names, obs):
            continue
        if _weave_structured_observer(
            functions, symbols, w1_names, obs, map_defs.get(str(obs.get('map') or ''), {}),
        ):
            continue
        callsite = obs.get('callsite') or {}
        operation = str(obs.get('operation', 'set'))
        if operation in ('delete', 'del', 'remove'):
            helper_name = f'__vulgate_table_del_{obs.get("map", "")}'
            arity = 2
        elif operation == 'set':
            helper_name = f'__vulgate_table_set_{obs.get("map", "")}'
            arity = 3
        else:
            continue
        if helper_name not in symbols:
            continue
        helper_type = symbols[helper_name].get('type') or {}
        params = helper_type.get('namedSub', {}).get('parameters', {}).get('sub') or []
        if len(params) < arity:
            continue
        param_types = []
        for param in params[:3]:
            ptype = param.get('namedSub', {}).get('type')
            if not ptype:
                ptype = None
            param_types.append(ptype)
        if any(item is None for item in param_types):
            continue
        for fn in functions:
            if fn['name'] not in w1_names:
                continue
            base = symbols.get(fn['name'], {}).get('baseName', fn['name'])
            if base != callsite.get('caller') and fn['name'] != callsite.get('caller'):
                continue
            sites: list[tuple[int, dict[str, Any]]] = []
            for idx, insn in enumerate(fn.get('instructions') or []):
                if insn.get('instructionId') != 'FUNCTION_CALL':
                    continue
                ops = insn.get('code', {}).get('sub') or []
                if len(ops) < 3 or ops[1].get('id') != 'symbol':
                    continue
                callee_name = symbol_name(ops[1])
                callee_base = symbols.get(callee_name, {}).get('baseName', callee_name)
                if callee_base != callsite.get('callee') and callee_name != callsite.get('callee'):
                    continue
                callee_fn = fn_by_name.get(callee_name) or fn_by_name.get(w1_map.get(callee_name, ''))
                if callee_fn is None:
                    for candidate in fn_by_name.values():
                        cand_base = symbols.get(candidate['name'], {}).get('baseName', candidate['name'])
                        if cand_base == callsite.get('callee'):
                            callee_fn = candidate
                            break
                if callee_fn is None:
                    continue
                key_idx = _parameter_index(callee_fn, symbols, str(callsite.get('key_parameter', '')))
                val_idx = _parameter_index(callee_fn, symbols, str(callsite.get('value_parameter', ''))) if arity == 3 else 0
                args = ops[2].get('sub') or []
                if key_idx is None or key_idx >= len(args):
                    continue
                if arity == 3 and (val_idx is None or val_idx >= len(args)):
                    continue
                sites.append((idx, insn))
            for idx, insn in reversed(sites):
                ops = insn.get('code', {}).get('sub') or []
                args = ops[2].get('sub') or []
                callee_name = symbol_name(ops[1])
                callee_fn = fn_by_name.get(callee_name)
                if callee_fn is None:
                    continue
                key_idx = _parameter_index(callee_fn, symbols, str(callsite.get('key_parameter', '')))
                val_idx = _parameter_index(callee_fn, symbols, str(callsite.get('value_parameter', ''))) if arity == 3 else 0
                if key_idx is None:
                    continue
                if arity == 3 and val_idx is None:
                    continue
                cast_args = []
                cast_args.append({'id': 'constant', 'namedSub': {'type': deepcopy(param_types[0]), 'value': {'id': '0'}}})
                paired = [(key_idx, 1)]
                if arity == 3:
                    paired.append((val_idx, 2))
                for arg_idx, type_idx in paired:
                    cast_args.append({
                        'id': 'typecast',
                        'namedSub': {'type': deepcopy(param_types[type_idx])},
                        'sub': [deepcopy(args[arg_idx])],
                    })
                helper_expr = {'id': 'symbol', 'namedSub': {
                    'identifier': {'id': helper_name},
                    'type': deepcopy(helper_type),
                }}
                call = {
                    'instructionId': 'FUNCTION_CALL',
                    'code': irep_code('function_call', [
                        {'id': 'nil'},
                        helper_expr,
                        {'id': 'arguments', 'sub': cast_args},
                    ]),
                    'guard': deepcopy(insn.get('guard', TRUE)),
                }
                copy_location(call, insn, mode=FULL)
                _insert_instruction(fn, idx, call)
    return functions, symbols


def finalize_and_export_goto(functions: list[dict[str, Any]],
                             symbols: dict[str, Any],
                             output_goto: Path,
                             tool_dir: Path,
                             work_dir: Path,
                             enable_shadow: bool = True,
                             object_bits: int = 8,
                             target_descriptions: tuple[str, ...] = (),
                             timeout: int = 180,
                             timeout_floor: int = 300) -> dict[str, Any]:
    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    goto_instrument = tool_dir / 'goto-instrument'
    symtab2gb = tool_dir / 'symtab2gb'

    encoding_info = configure_object_encoding(functions, symbols, object_bits)
    shadow_info = None
    if enable_shadow and any(f['name'] == '__vulgate_shadow_template' for f in functions):
        if '__vulgate_shadow_active' in symbols:
            one_b = {'id': 'constant', 'namedSub': {'type': deepcopy(symbols['__vulgate_shadow_active']['type']), 'value': {'id': '1'}}}
            symbols['__vulgate_shadow_active']['value'] = one_b
            init_f = next((f for f in functions if f['name'] == '__CPROVER_initialize'), None)
            if init_f is not None:
                for ins in init_f.get('instructions', []):
                    if ins.get('instructionId') == 'ASSIGN' and symbol_name(ins['code']['sub'][0]) == '__vulgate_shadow_active':
                        ins['code']['sub'][1] = deepcopy(one_b)
        functions, symbols, shadow_info = shadow_transform(
            functions, symbols, target_descriptions,
            implicit_zero_init=False, strict_flexible_arrays=False, transport_mode=FULL,
        )

    validate_model(functions, symbols, mode=FULL)
    fn_payload, sym_payload = transport_view(functions, symbols, mode=FULL)
    fn_file = work_dir / 'paired.functions.json'
    sym_file = work_dir / 'paired.symbols.json'
    raw_goto = work_dir / 'paired.raw.goto'
    export_timeout = max(int(timeout), int(timeout_floor))
    try:
        fn_file.write_text(json.dumps(fn_payload, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
        sym_file.write_text(json.dumps(sym_payload, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
        subprocess.run([str(symtab2gb), str(sym_file), '--goto-functions', str(fn_file), '--out', str(raw_goto)],
                       check=True, timeout=export_timeout, capture_output=True, text=True)
        if not os.environ.get('VULGATE_SKIP_GOTO_VALIDATION'):
            subprocess.run([str(goto_instrument), str(raw_goto), '--validate-goto-binary', '--json-ui'],
                           check=True, timeout=export_timeout, capture_output=True, text=True)
        subprocess.run([str(goto_instrument), '--drop-unused-functions', '--slice-global-inits',
                        str(raw_goto), str(output_goto)],
                       check=True, timeout=export_timeout, capture_output=True, text=True)
    finally:
        fn_file.unlink(missing_ok=True)
        sym_file.unlink(missing_ok=True)
        raw_goto.unlink(missing_ok=True)

    return {
        'output_goto': str(output_goto),
        'encoding': encoding_info,
        'shadow_initialization': shadow_info,
    }
