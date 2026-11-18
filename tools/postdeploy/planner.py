from __future__ import annotations

from collections import deque
import json
from pathlib import Path
from typing import Any

from tools.verification.shadow import symbol_name, typ
from tools.verification.typed_json_stream import stream_functions
from tools.verification.typed_transport import FULL, inspection_model, strict_loads


def _walk_irep(node: Any):
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get('sub', []):
        yield from _walk_irep(child)
    for child in node.get('namedSub', {}).values():
        yield from _walk_irep(child)


def load_typed_goto_model(goto_binary: Path, goto_instrument: Path, work_dir: Path, timeout: int = 180) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import subprocess

    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    fn_json = work_dir / 'raw-functions.json'
    sym_json = work_dir / 'raw-symbols.json'
    with fn_json.open('wb') as out, (work_dir / 'raw-functions.err').open('wb') as err:
        subprocess.run([str(goto_instrument), '--show-goto-functions-raw', '--json-ui', str(goto_binary)],
                       stdout=out, stderr=err, timeout=timeout, check=True)
    with sym_json.open('wb') as out, (work_dir / 'raw-symbols.err').open('wb') as err:
        subprocess.run([str(goto_instrument), '--show-symbol-table-raw', '--json-ui', str(goto_binary)],
                       stdout=out, stderr=err, timeout=timeout, check=True)
    fn_messages: list[dict[str, Any]] = []
    bodies = list(stream_functions(fn_json, messages=fn_messages))
    for group in fn_messages:
        if 'functions' in group:
            group['functions'] = bodies
    sym_messages = strict_loads(sym_json.read_text(encoding='utf-8'))
    functions, symbols, _ = inspection_model(fn_messages, sym_messages, mode=FULL)
    return functions, symbols


def _type_shape(value: Any) -> tuple[Any, ...] | None:
    if not isinstance(value, dict) or not value.get('id'):
        return None
    kind = value['id']
    named = value.get('namedSub') or {}
    if kind == 'pointer':
        subs = value.get('sub') or []
        return ('pointer', _type_shape(subs[0]) if subs else None)
    if kind in ('signedbv', 'unsignedbv', 'floatbv', 'bv'):
        return (kind, (named.get('width') or {}).get('id'))
    if kind in ('struct_tag', 'union_tag', 'c_enum_tag'):
        return (kind, (named.get('identifier') or {}).get('id'))
    if kind == 'code':
        params = tuple(
            _type_shape((item.get('namedSub') or {}).get('type') or {})
            for item in ((named.get('parameters') or {}).get('sub') or [])
        )
        return ('code', _type_shape(named.get('return_type') or {}), params)
    if kind in ('empty', 'bool', 'c_bool'):
        return (kind,)
    return (kind,)


def _function_shape(value: Any) -> tuple[Any, ...] | None:
    shape = _type_shape(value)
    if shape is None:
        return None
    if shape[0] == 'pointer' and isinstance(shape[1], tuple) and shape[1][0] == 'code':
        return shape[1]
    if shape[0] == 'code':
        return shape
    return None


def _call_type_matches(call_expr: dict[str, Any], callee: str, symbols: dict[str, Any]) -> bool:
    call_shape = _function_shape(typ(call_expr))
    callee_shape = _function_shape((symbols.get(callee) or {}).get('type') or {})
    if call_shape is None or callee_shape is None:
        return True
    return call_shape == callee_shape


def _direct_symbols(node: Any) -> list[str]:
    if not isinstance(node, dict) or node.get('id') != 'symbol':
        return []
    name = symbol_name(node)
    return [name] if name else []


def _symbol_ids(node: Any) -> list[str]:
    found: list[str] = []
    for item in _walk_irep(node):
        if item.get('id') == 'symbol':
            name = symbol_name(item)
            if name:
                found.append(name)
    return found


def instruction_symbol_access(insn: dict[str, Any]) -> tuple[list[str], list[str]]:
    kind = insn.get('instructionId')
    code = insn.get('code') or {}
    reads = _symbol_ids(insn.get('guard') or {})
    writes: list[str] = []
    subs = code.get('sub') if isinstance(code, dict) else None
    if kind == 'ASSIGN' and isinstance(subs, list) and len(subs) >= 2:
        writes = _direct_symbols(subs[0])
        reads.extend(name for name in _symbol_ids(subs[0]) if name not in writes)
        for item in subs[1:]:
            reads.extend(_symbol_ids(item))
    elif kind == 'FUNCTION_CALL' and isinstance(subs, list) and len(subs) >= 2:
        writes = _direct_symbols(subs[0])
        reads.extend(name for name in _symbol_ids(subs[0]) if name not in writes)
        if len(subs) >= 3:
            reads.extend(_symbol_ids(subs[2]))
    elif kind not in ('DECL', 'DEAD'):
        reads.extend(_symbol_ids(code))
    return reads, writes


def build_enhanced_icfg(functions: list[dict[str, Any]],
                        symbols: dict[str, Any],
                        dynamic_call_edges: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    fn_by_name: dict[str, dict[str, Any]] = {f['name']: f for f in functions}
    base_to_names: dict[str, list[str]] = {}
    for fname in fn_by_name:
        sym = symbols.get(fname, {})
        base = sym.get('baseName', fname.split(':')[-1])
        base_to_names.setdefault(base, []).append(fname)

    address_taken_by_arity: dict[int, set[str]] = {}
    for f in functions:
        for insn in f.get('instructions', []):
            for field in ('code', 'guard'):
                for node in _walk_irep(insn.get(field, {})):
                    if node.get('id') == 'address_of' and node.get('sub'):
                        target = node['sub'][0]
                        if target.get('id') == 'symbol':
                            sname = symbol_name(target)
                            if sname in fn_by_name and fn_by_name[sname].get('isBodyAvailable'):
                                arity = len(fn_by_name[sname].get('parameterIdentifiers', []))
                                address_taken_by_arity.setdefault(arity, set()).add(sname)

    direct_edges: list[dict[str, Any]] = []
    indirect_edges: list[dict[str, Any]] = []
    unresolved_external: list[dict[str, Any]] = []
    indirect_sites: dict[str, list[dict[str, Any]]] = {}
    callers_of: dict[str, set[str]] = {f['name']: set() for f in functions}
    callees_of: dict[str, set[str]] = {f['name']: set() for f in functions}
    concrete_callers_of: dict[str, set[str]] = {f['name']: set() for f in functions}
    concrete_callees_of: dict[str, set[str]] = {f['name']: set() for f in functions}

    def link(caller_name: str, callee_name: str, concrete: bool) -> None:
        callees_of.setdefault(caller_name, set()).add(callee_name)
        callers_of.setdefault(callee_name, set()).add(caller_name)
        if concrete:
            concrete_callees_of.setdefault(caller_name, set()).add(callee_name)
            concrete_callers_of.setdefault(callee_name, set()).add(caller_name)

    for f in functions:
        caller = f['name']
        if caller.startswith(('__CPROVER_', '__vulgate_')):
            continue
        for idx, insn in enumerate(f.get('instructions', [])):
            if insn.get('instructionId') != 'FUNCTION_CALL':
                continue
            ops = insn.get('code', {}).get('sub', [])
            if len(ops) < 3:
                continue
            callee_expr = ops[1]
            args_list = ops[2].get('sub', [])
            loc = insn.get('sourceLocation', {})
            if callee_expr.get('id') == 'symbol':
                cname = symbol_name(callee_expr)
                if cname.startswith(('__CPROVER_', '__vulgate_')):
                    continue
                direct_edges.append({'caller': caller, 'callee': cname, 'index': idx, 'location': loc})
                link(caller, cname, True)
                if cname not in fn_by_name or not fn_by_name[cname].get('isBodyAvailable'):
                    unresolved_external.append({
                        'caller': caller,
                        'callee': cname,
                        'kind': 'unresolved_external_edge',
                        'location': loc,
                    })
            else:
                arity = len(args_list)
                indirect_sites.setdefault(caller, []).append({
                    'index': idx,
                    'arity': arity,
                    'expr': callee_expr,
                })
                candidates = sorted(
                    cand for cand in address_taken_by_arity.get(arity, set())
                    if _call_type_matches(callee_expr, cand, symbols)
                )
                if not candidates:
                    unresolved_external.append({
                        'caller': caller,
                        'callee': f'<indirect:{idx}>',
                        'kind': 'unresolved_external_edge',
                        'arity': arity,
                        'index': idx,
                        'location': loc,
                    })
                for cand in candidates:
                    indirect_edges.append({
                        'caller': caller, 'callee': cand, 'index': idx,
                        'kind': 'static_address_taken', 'location': loc,
                    })
                    link(caller, cand, cand.startswith('vg_'))

    reads_of: dict[str, set[str]] = {f['name']: set() for f in functions}
    writes_of: dict[str, set[str]] = {f['name']: set() for f in functions}
    for f in functions:
        for insn in f.get('instructions') or []:
            reads, writes = instruction_symbol_access(insn)
            reads_of[f['name']].update(reads)
            writes_of[f['name']].update(writes)

    resolved_indirect: set[tuple[str, int]] = set()
    for dyn_caller, dyn_callee in (dynamic_call_edges or []):
        c_list = [dyn_caller] if dyn_caller in fn_by_name else base_to_names.get(dyn_caller, [])
        t_list = [dyn_callee] if dyn_callee in fn_by_name else base_to_names.get(dyn_callee, [])
        for c_fn in c_list:
            for t_fn in t_list:
                target = fn_by_name.get(t_fn)
                if not target or not target.get('isBodyAvailable'):
                    continue
                arity = len(target.get('parameterIdentifiers') or [])
                for site in indirect_sites.get(c_fn) or []:
                    if site['arity'] != arity or not _call_type_matches(site['expr'], t_fn, symbols):
                        continue
                    if not any(
                        edge.get('caller') == c_fn and edge.get('callee') == t_fn
                        and edge.get('index') == site['index'] and edge.get('kind') == 'dynamic_trace_observed'
                        for edge in indirect_edges
                    ):
                        indirect_edges.append({
                            'caller': c_fn, 'callee': t_fn, 'index': site['index'],
                            'kind': 'dynamic_trace_observed', 'location': {},
                        })
                    link(c_fn, t_fn, True)
                    resolved_indirect.add((c_fn, int(site['index'])))
    if resolved_indirect:
        unresolved_external = [
            item for item in unresolved_external
            if (item.get('caller'), item.get('index')) not in resolved_indirect
        ]

    return {
        'functions_by_name': fn_by_name,
        'base_to_names': base_to_names,
        'direct_edges': direct_edges,
        'indirect_edges': indirect_edges,
        'unresolved_external': unresolved_external,
        'callers_of': callers_of,
        'callees_of': callees_of,
        'concrete_callers_of': concrete_callers_of,
        'concrete_callees_of': concrete_callees_of,
        'reads_of': reads_of,
        'writes_of': writes_of,
    }


def resolve_ir_function_names(icfg: dict[str, Any], name: str) -> list[str]:
    if name in icfg['functions_by_name']:
        return [name]
    return sorted(icfg['base_to_names'].get(name, []))


def pointer_outputs_skipped_by_block(guard_fn: dict[str, Any],
                                     fn_map: dict[str, dict[str, Any]],
                                     symbols: dict[str, Any],
                                     action_written_args: set[int]) -> tuple[list[int], list[str]]:
    params = list(guard_fn.get('parameterIdentifiers') or [])
    aliases: dict[str, int] = {}
    for idx, pid in enumerate(params):
        if pid in symbols and symbols[pid].get('type', {}).get('id') == 'pointer':
            aliases[pid] = idx
    skipped = [idx for idx in function_writes_pointer_parameters(guard_fn, symbols) if idx not in action_written_args]
    callees: list[str] = []
    for insn in guard_fn.get('instructions') or []:
        kind = insn.get('instructionId')
        ops = insn.get('code', {}).get('sub') or []
        if kind == 'ASSIGN' and len(ops) == 2 and ops[0].get('id') == 'symbol':
            lname = symbol_name(ops[0])
            for node in _walk_irep(ops[1]):
                if node.get('id') == 'symbol' and symbol_name(node) in aliases:
                    aliases[lname] = aliases[symbol_name(node)]
            continue
        if kind != 'FUNCTION_CALL' or len(ops) < 3:
            continue
        callee_name = symbol_name(ops[1])
        callee = fn_map.get(callee_name)
        if not callee or not callee.get('isBodyAvailable'):
            continue
        written = set(function_writes_pointer_parameters(callee, symbols))
        if not written:
            continue
        recorded = False
        for arg_index, group in enumerate(_call_arg_symbols(ops)):
            if arg_index not in written:
                continue
            for sym in group:
                guard_index = aliases.get(sym)
                if guard_index is None or guard_index in action_written_args:
                    continue
                if guard_index not in skipped:
                    skipped.append(guard_index)
                recorded = True
        if recorded:
            base = callee_name.split(':')[-1]
            if base not in callees:
                callees.append(base)
    return skipped, callees


def function_writes_pointer_parameters(fn_obj: dict[str, Any], symbols: dict[str, Any]) -> list[int]:
    params = fn_obj.get('parameterIdentifiers', [])
    ptr_param_indices: dict[str, int] = {}
    for idx, pid in enumerate(params):
        if pid in symbols and symbols[pid].get('type', {}).get('id') == 'pointer':
            ptr_param_indices[pid] = idx
    if not ptr_param_indices:
        return []
    aliases: dict[str, int] = dict(ptr_param_indices)
    written: set[int] = set()
    for insn in fn_obj.get('instructions', []):
        if insn.get('instructionId') == 'ASSIGN':
            lhs, rhs = insn['code']['sub']
            if lhs.get('id') == 'symbol':
                lname = symbol_name(lhs)
                for node in _walk_irep(rhs):
                    if node.get('id') == 'symbol' and symbol_name(node) in aliases:
                        aliases[lname] = aliases[symbol_name(node)]
            else:
                for node in _walk_irep(lhs):
                    if node.get('id') == 'symbol' and symbol_name(node) in aliases:
                        written.add(aliases[symbol_name(node)])
    return sorted(written)


def _call_result_symbols(fn_obj: dict[str, Any], callees: set[str]) -> set[str]:
    found: set[str] = set()
    for insn in fn_obj.get('instructions', []):
        if insn.get('instructionId') != 'FUNCTION_CALL':
            continue
        ops = insn.get('code', {}).get('sub', [])
        if len(ops) < 2 or symbol_name(ops[1]) not in callees or ops[0].get('id') != 'symbol':
            continue
        found.add(symbol_name(ops[0]))
    return found


def _returns_tainted(fn_obj: dict[str, Any], seeds: set[str]) -> bool:
    tainted = set(seeds)
    propagates = False
    for insn in fn_obj.get('instructions', []):
        kind = insn.get('instructionId')
        ops = insn.get('code', {}).get('sub', [])
        if kind == 'ASSIGN' and len(ops) == 2 and ops[0].get('id') == 'symbol':
            if any(node.get('id') == 'symbol' and symbol_name(node) in tainted for node in _walk_irep(ops[1])):
                tainted.add(symbol_name(ops[0]))
        elif kind == 'SET_RETURN_VALUE' and ops:
            if any(node.get('id') == 'symbol' and symbol_name(node) in tainted for node in _walk_irep(ops[0])):
                propagates = True
    return propagates


def _callee_base(name: str) -> str:
    return name.split(':')[-1].lower()


def _is_release_callee(name: str) -> bool:
    base = _callee_base(name)
    if any(token in base for token in ('unlock', 'decref', 'release', 'cleanup', 'destroy')):
        return True
    return base == 'free' or base.endswith('_free') or 'pfree' in base


def _is_acquire_callee(name: str) -> bool:
    if _is_release_callee(name):
        return False
    base = _callee_base(name)
    return any(token in base for token in ('lock', 'incref', 'addref', 'acquire'))


def _is_owning_allocator(name: str) -> bool:
    base = _callee_base(name)
    if 'palloc' in base or 'pcalloc' in base or 'pnalloc' in base:
        return False
    if base in {'malloc', 'calloc', 'realloc'} or base.endswith(('_malloc', '_calloc', '_realloc')):
        return True
    if base in {'_emalloc', 'emalloc', '_ecalloc', 'ecalloc', '_safe_emalloc', 'safe_emalloc'}:
        return True
    return 'brigade_create' in base or 'bucket_alloc' in base


def _is_protocol_handoff(name: str) -> bool:
    base = _callee_base(name)
    if any(token in base for token in (
        'pass_brigade', 'output_filter', 'send_header', 'finalize_request', 'stream_write',
    )):
        return True
    return base in {'ap_rwrite', 'ap_rputs', 'ap_rflush', 'ap_fwrite', 'php_write'}


def _closes_owned_object(name: str) -> bool:
    return _is_release_callee(name) or _is_protocol_handoff(name)


def _call_arg_symbols(ops: list[dict[str, Any]]) -> list[set[str]]:
    if len(ops) < 3:
        return []
    groups: list[set[str]] = []
    for arg in ops[2].get('sub', []):
        found = {
            symbol_name(node)
            for node in _walk_irep(arg)
            if node.get('id') == 'symbol' and symbol_name(node)
        }
        groups.append(found)
    return groups


def _resources_around_guard(caller_obj: dict[str, Any],
                            guard_names: set[str],
                            preset_acquired: dict[str, str] | None = None) -> tuple[list[dict[str, str]], list[str], dict[str, str]]:
    acquired: dict[str, str] = dict(preset_acquired or {})
    seen_guard = False
    held: list[dict[str, str]] = []
    closed: set[str] = set()
    params = set(caller_obj.get('parameterIdentifiers') or [])
    guard_args: set[str] = set()
    for insn in caller_obj.get('instructions', []):
        if insn.get('instructionId') != 'FUNCTION_CALL':
            continue
        ops = insn.get('code', {}).get('sub', [])
        callee = symbol_name(ops[1]) if len(ops) > 1 else ''
        arg_sets = _call_arg_symbols(ops)
        args = set().union(*arg_sets) if arg_sets else set()
        if callee in guard_names:
            seen_guard = True
            guard_args |= args
            continue
        if not seen_guard and _is_owning_allocator(callee) and ops and ops[0].get('id') == 'symbol':
            acquired.setdefault(symbol_name(ops[0]), callee)
            continue
        if not seen_guard and _is_acquire_callee(callee):
            for sym in args:
                acquired.setdefault(sym, callee)
            continue
        if not seen_guard:
            continue
        if _is_release_callee(callee):
            for sym in args:
                if sym in closed:
                    continue
                if sym in acquired or sym in guard_args or sym in params:
                    held.append({
                        'symbol': sym,
                        'acquire': acquired.get(sym, ''),
                        'release': callee,
                    })
                    closed.add(sym)
            continue
        if _is_protocol_handoff(callee):
            for sym in args:
                if sym in acquired and sym not in closed:
                    held.append({
                        'symbol': sym,
                        'acquire': acquired.get(sym, ''),
                        'release': callee,
                        'disposition': 'protocol_handoff',
                    })
                    closed.add(sym)
    released = {item['symbol'] for item in held}
    open_symbols = [sym for sym in acquired if sym not in released]
    return held, open_symbols, acquired


def _parent_supplied_owned_params(parent_obj: dict[str, Any],
                                  callee: str,
                                  caller_params: list[str]) -> dict[str, str]:
    owned_results: dict[str, str] = {}
    supplied: dict[str, str] = {}
    for insn in parent_obj.get('instructions', []):
        if insn.get('instructionId') != 'FUNCTION_CALL':
            continue
        ops = insn.get('code', {}).get('sub', [])
        target = symbol_name(ops[1]) if len(ops) > 1 else ''
        if _is_owning_allocator(target) and ops and ops[0].get('id') == 'symbol':
            owned_results.setdefault(symbol_name(ops[0]), target)
            continue
        if target != callee:
            continue
        for index, group in enumerate(_call_arg_symbols(ops)):
            if index >= len(caller_params) or len(group) != 1:
                continue
            symbol = next(iter(group))
            creator = owned_results.get(symbol)
            if creator:
                supplied.setdefault(caller_params[index], creator)
    return supplied


def _action_returns_without_outputs(action: dict[str, Any]) -> bool:
    kind = str(action.get('kind') or '')
    if kind in ('return_null', 'return_void'):
        return True
    if kind == 'return_string':
        return str(action.get('value', '')) == ''
    if kind == 'return_int':
        try:
            return int(action.get('value', 0)) != 0
        except (TypeError, ValueError):
            return False
    return False


def _is_brigade_pointer_type(symbols: dict[str, Any], typ: dict[str, Any] | None) -> bool:
    if not isinstance(typ, dict) or typ.get('id') != 'pointer':
        return False
    current = (typ.get('sub') or [{}])[0]
    seen: set[str] = set()
    while isinstance(current, dict) and current.get('id') in ('struct_tag', 'union_tag', 'c_enum_tag'):
        tag = str(((current.get('namedSub') or {}).get('identifier') or {}).get('id') or '')
        base = str((symbols.get(tag) or {}).get('baseName') or tag.split('::')[-1])
        if 'bucket_brigade' in base or 'bucket_brigade' in tag:
            return True
        if not tag or tag in seen or tag not in symbols:
            return False
        seen.add(tag)
        current = (symbols.get(tag) or {}).get('type') or {}
    return False


def _brigade_parameter_indexes(fn_obj: dict[str, Any], symbols: dict[str, Any]) -> list[int]:
    found: list[int] = []
    for index, pid in enumerate(fn_obj.get('parameterIdentifiers') or []):
        if _is_brigade_pointer_type(symbols, (symbols.get(pid) or {}).get('type')):
            found.append(index)
    return found


def _ancestor_output_pointers(icfg: dict[str, Any],
                              fn_map: dict[str, Any],
                              direct_callers: list[dict[str, Any]],
                              field: str = 'caller_output_pointers') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_rows: set[tuple[Any, ...]] = set()
    queued: set[tuple[str, int]] = set()
    frontier: list[tuple[str, int]] = []
    for row in direct_callers:
        caller = str(row.get('caller') or '')
        caller_obj = fn_map.get(caller) or {}
        index_of = {
            name: index
            for index, name in enumerate(caller_obj.get('parameterIdentifiers') or [])
        }
        for item in row.get(field) or []:
            if item.get('form') != 'pointer':
                continue
            symbol = str(item.get('symbol') or '')
            if symbol not in index_of:
                continue
            step = (caller, index_of[symbol])
            if step not in queued:
                queued.add(step)
                frontier.append(step)
    while frontier:
        child, index = frontier.pop(0)
        for parent in sorted(icfg['callers_of'].get(child, set())):
            parent_obj = fn_map.get(parent)
            if not parent_obj or not parent_obj.get('isBodyAvailable'):
                continue
            outputs: list[dict[str, str]] = []
            seen_out: set[tuple[str, str]] = set()
            for insn in parent_obj.get('instructions') or []:
                if insn.get('instructionId') != 'FUNCTION_CALL':
                    continue
                ops = insn.get('code', {}).get('sub') or []
                if len(ops) < 3 or symbol_name(ops[1]) != child:
                    continue
                args = ops[2].get('sub') or []
                if index >= len(args):
                    continue
                arg = args[index]
                if arg.get('id') == 'symbol':
                    name = symbol_name(arg)
                    key = (name, 'pointer')
                    if name and key not in seen_out:
                        seen_out.add(key)
                        outputs.append({'symbol': name, 'form': 'pointer'})
                for node in _walk_irep(arg):
                    if node.get('id') != 'address_of' or not node.get('sub') or node['sub'][0].get('id') != 'symbol':
                        continue
                    name = symbol_name(node['sub'][0])
                    key = (name, 'object')
                    if name and key not in seen_out:
                        seen_out.add(key)
                        outputs.append({'symbol': name, 'form': 'object'})
            if not outputs:
                continue
            signature = (parent, child, tuple((item['symbol'], item['form']) for item in outputs))
            if signature not in seen_rows:
                seen_rows.add(signature)
                rows.append({
                    'caller': parent,
                    'callee': child,
                    field: outputs,
                })
            parent_index = {
                name: slot
                for slot, name in enumerate(parent_obj.get('parameterIdentifiers') or [])
            }
            for item in outputs:
                if item['form'] != 'pointer' or item['symbol'] not in parent_index:
                    continue
                step = (parent, parent_index[item['symbol']])
                if step not in queued:
                    queued.add(step)
                    frontier.append(step)
    return rows


def analyze_caller_continuation_closure(icfg: dict[str, Any],
                                        symbols: dict[str, Any],
                                        guard_fn: str,
                                        action: dict[str, Any]) -> dict[str, Any]:
    fn_map = icfg['functions_by_name']
    guard_ir_names = resolve_ir_function_names(icfg, guard_fn)
    action_written_args = {int(w['arg']) for w in action.get('writes', []) if 'arg' in w}
    brigade_indexes: list[int] = []
    skipped_param_writes: list[int] = []
    skipped_callees: list[str] = []
    for gname in guard_ir_names:
        guard_fn = fn_map.get(gname)
        if not guard_fn:
            continue
        indices, names = pointer_outputs_skipped_by_block(guard_fn, fn_map, symbols, action_written_args)
        for index in _brigade_parameter_indexes(guard_fn, symbols):
            if index not in brigade_indexes:
                brigade_indexes.append(index)
        for p_idx in indices:
            if p_idx not in skipped_param_writes:
                skipped_param_writes.append(p_idx)
        for name in names:
            if name not in skipped_callees:
                skipped_callees.append(name)

    direct_callers: list[dict[str, Any]] = []
    closure_functions: set[str] = set()
    for gname in guard_ir_names:
        for caller in sorted(icfg['callers_of'].get(gname, set())):
            caller_obj = fn_map.get(caller)
            if not caller_obj or not caller_obj.get('isBodyAvailable'):
                continue
            closure_functions.add(caller)
            caller_params = list(caller_obj.get('parameterIdentifiers') or [])
            preset_acquired: dict[str, str] = {}
            for parent in sorted(icfg['callers_of'].get(caller, set())):
                parent_obj = fn_map.get(parent)
                if not parent_obj or not parent_obj.get('isBodyAvailable'):
                    continue
                for param, creator in _parent_supplied_owned_params(parent_obj, caller, caller_params).items():
                    preset_acquired.setdefault(param, creator)
            held_resources, open_symbols, acquired = _resources_around_guard(
                caller_obj, {gname}, preset_acquired,
            )
            propagates_to_parent = False
            local_uninit_candidates: list[str] = []
            caller_outputs: list[dict[str, str]] = []
            caller_brigades: list[dict[str, str]] = []
            seen_outputs: set[tuple[str, str]] = set()
            seen_brigades: set[tuple[str, str]] = set()

            def note_output(sym: str, form: str) -> None:
                if sym and (sym, form) not in seen_outputs:
                    seen_outputs.add((sym, form))
                    caller_outputs.append({'symbol': sym, 'form': form})

            def note_brigade(sym: str, form: str) -> None:
                if sym and (sym, form) not in seen_brigades:
                    seen_brigades.add((sym, form))
                    caller_brigades.append({'symbol': sym, 'form': form})

            insns = caller_obj.get('instructions', [])
            tainted_syms: set[str] = set()
            indirect_insns = []
            has_direct = False
            for insn in insns:
                ops = insn.get('code', {}).get('sub', [])
                if insn.get('instructionId') != 'FUNCTION_CALL' or len(ops) < 3:
                    continue
                if symbol_name(ops[1]) == gname:
                    has_direct = True
                    continue
                if ops[1].get('id') != 'symbol':
                    indirect_insns.append(insn)
            indirect_insn = indirect_insns[0] if len(indirect_insns) == 1 and not has_direct else None
            saw_direct = False
            for insn in insns:
                kind = insn.get('instructionId')
                ops = insn.get('code', {}).get('sub', [])
                called = kind == 'FUNCTION_CALL' and len(ops) >= 3 and symbol_name(ops[1]) == gname
                if called:
                    saw_direct = True
                if called or (indirect_insn is insn and not saw_direct):
                    if ops[0].get('id') == 'symbol':
                        tainted_syms.add(symbol_name(ops[0]))
                    call_args = ops[2].get('sub', [])
                    for p_idx in skipped_param_writes:
                        if p_idx >= len(call_args):
                            continue
                        arg = call_args[p_idx]
                        if arg.get('id') == 'symbol':
                            note_output(symbol_name(arg), 'pointer')
                        for node in _walk_irep(arg):
                            if node.get('id') == 'address_of' and node.get('sub') and node['sub'][0].get('id') == 'symbol':
                                local_sym = symbol_name(node['sub'][0])
                                tainted_syms.add(local_sym)
                                local_uninit_candidates.append(local_sym)
                                note_output(local_sym, 'object')
                    for p_idx in brigade_indexes:
                        if p_idx >= len(call_args):
                            continue
                        arg = call_args[p_idx]
                        if arg.get('id') == 'symbol':
                            note_brigade(symbol_name(arg), 'pointer')
                        for node in _walk_irep(arg):
                            if node.get('id') == 'address_of' and node.get('sub') and node['sub'][0].get('id') == 'symbol':
                                note_brigade(symbol_name(node['sub'][0]), 'object')
                elif kind == 'ASSIGN' and len(ops) == 2 and ops[0].get('id') == 'symbol':
                    if any(n.get('id') == 'symbol' and symbol_name(n) in tainted_syms for n in _walk_irep(ops[1])):
                        tainted_syms.add(symbol_name(ops[0]))
                elif kind == 'SET_RETURN_VALUE' and ops:
                    if any(n.get('id') == 'symbol' and symbol_name(n) in tainted_syms for n in _walk_irep(ops[0])):
                        propagates_to_parent = True
            direct_callers.append({
                'caller': caller,
                'propagates_return_or_out_to_parent': propagates_to_parent,
                'skipped_out_param_locals': sorted(set(local_uninit_candidates)),
                'caller_output_pointers': sorted(caller_outputs, key=lambda item: (item['symbol'], item['form'])),
                'caller_brigades': sorted(caller_brigades, key=lambda item: (item['symbol'], item['form'])),
                'held_resources': held_resources,
                'acquired_resources': [
                    {'symbol': sym, 'acquire': callee}
                    for sym, callee in sorted(acquired.items())
                ],
                'open_resource_symbols': open_symbols,
                **({'indirect_call': True} if indirect_insn is not None else {}),
            })

    exits: list[str] = []
    open_frames: list[str] = []
    unreleased: list[str] = []
    release_callees_found: set[str] = set()
    for row in direct_callers:
        if row['propagates_return_or_out_to_parent']:
            frontier = [row['caller']]
            seen = {row['caller']}
            returning = {row['caller']}
            while frontier:
                nxt: list[str] = []
                for name in frontier:
                    parents: list[str] = []
                    for parent in sorted(icfg['callers_of'].get(name, set())):
                        parent_obj = fn_map.get(parent)
                        if not parent_obj or not parent_obj.get('isBodyAvailable'):
                            continue
                        parents.append(parent)
                    fresh = [parent for parent in parents if parent not in seen]
                    if not fresh:
                        exits.append(name)
                        if any(parent in returning for parent in parents):
                            open_frames.append(name)
                        continue
                    for parent in fresh:
                        parent_obj = fn_map[parent]
                        seen.add(parent)
                        closure_functions.add(parent)
                        seeds = _call_result_symbols(parent_obj, {name})
                        if not seeds or not _returns_tainted(parent_obj, seeds):
                            exits.append(parent)
                            continue
                        returning.add(parent)
                        nxt.append(parent)
                frontier = nxt
        resource_exits, resource_open, ancestor_releases = _resource_release_ancestors(
            icfg, fn_map, row['caller'], set(row['open_resource_symbols']), closure_functions,
        )
        exits.extend(resource_exits)
        unreleased.extend(resource_open)
        release_callees_found.update(ancestor_releases)

    release_callees = set(release_callees_found)
    release_callees.update(
        item['release']
        for row in direct_callers
        for item in row['held_resources']
        if item.get('release')
    )
    for row in direct_callers:
        caller_obj = fn_map.get(row['caller']) or {}
        params = list(caller_obj.get('parameterIdentifiers') or [])
        indexes = [index for index, name in enumerate(params) if name in set(row['open_resource_symbols'])]
        if not indexes:
            continue
        for parent in icfg['callers_of'].get(row['caller'], set()):
            parent_obj = fn_map.get(parent)
            if parent_obj:
                release_callees |= _parent_release_callees(parent_obj, row['caller'], indexes)
    release_callees_sorted = sorted(release_callees)
    return {
        'guard_ir_names': guard_ir_names,
        'skipped_pointer_param_indices': skipped_param_writes,
        'skipped_callee_writes': skipped_callees,
        'require_output_pointer_defined': _action_returns_without_outputs(action),
        'direct_callers': direct_callers,
        'ancestor_output_pointers': _ancestor_output_pointers(icfg, fn_map, direct_callers),
        'ancestor_brigades': _ancestor_output_pointers(icfg, fn_map, direct_callers, 'caller_brigades'),
        'required_continuation_ancestors': sorted(closure_functions),
        'continuation_exits': sorted(set(exits)),
        'continuation_open': bool(open_frames) or bool(unreleased),
        'unreleased_resources': sorted(set(unreleased)),
        'resource_release_callees': release_callees_sorted,
    }


def _released_argument_indexes(parent_obj: dict[str, Any], callee: str, indexes: list[int]) -> set[int]:
    passed: dict[int, set[str]] = {index: set() for index in indexes}
    releases: set[str] = set()
    for insn in parent_obj.get('instructions', []):
        if insn.get('instructionId') != 'FUNCTION_CALL':
            continue
        ops = insn.get('code', {}).get('sub', [])
        target = symbol_name(ops[1]) if len(ops) > 1 else ''
        groups = _call_arg_symbols(ops)
        if target == callee:
            for index in indexes:
                if index < len(groups):
                    passed[index] |= groups[index]
            continue
        if _closes_owned_object(target):
            for group in groups:
                releases |= group
    return {
        index for index, symbols_at_index in passed.items()
        if symbols_at_index and symbols_at_index <= releases
    }


def _resource_release_ancestors(icfg: dict[str, Any],
                                fn_map: dict[str, dict[str, Any]],
                                caller: str,
                                open_symbols: set[str],
                                closure_functions: set[str]) -> tuple[list[str], list[str], set[str]]:
    if not open_symbols:
        return [], [], set()
    caller_obj = fn_map.get(caller) or {}
    params = list(caller_obj.get('parameterIdentifiers') or [])
    index_of = {name: index for index, name in enumerate(params) if name in open_symbols}
    local_unreleased = sorted(sym for sym in open_symbols if sym not in index_of)
    if not index_of:
        return [], local_unreleased, set()
    remaining = set(index_of.values())
    exits: list[str] = []
    releases: set[str] = set()
    frontier = [caller]
    seen = {caller}
    while frontier and remaining:
        nxt: list[str] = []
        for name in frontier:
            parents: list[tuple[str, dict[str, Any]]] = []
            for parent in sorted(icfg['callers_of'].get(name, set())):
                parent_obj = fn_map.get(parent)
                if parent in seen or not parent_obj or not parent_obj.get('isBodyAvailable'):
                    continue
                parents.append((parent, parent_obj))
            if not parents:
                exits.append(name)
                continue
            for parent, parent_obj in parents:
                seen.add(parent)
                closure_functions.add(parent)
                open_indexes = sorted(remaining)
                releases |= _parent_release_callees(parent_obj, name, open_indexes)
                remaining -= _released_argument_indexes(parent_obj, name, open_indexes)
                if not remaining:
                    exits.append(parent)
                    continue
                nxt.append(parent)
        frontier = nxt
    if remaining:
        exits.extend(frontier)
    unreleased = [params[index] for index in sorted(remaining)]
    return exits, local_unreleased + unreleased, releases


def resource_event_names(plan: dict[str, Any]) -> tuple[set[str], set[str]]:
    acquires: set[str] = set()
    releases: set[str] = set()
    for cont in plan.get('continuations') or []:
        for name in cont.get('resource_release_callees') or []:
            releases.add(str(name).split(':')[-1])
        for row in cont.get('direct_callers') or []:
            for item in row.get('held_resources') or []:
                if item.get('acquire'):
                    acquires.add(str(item['acquire']).split(':')[-1])
                if item.get('release'):
                    releases.add(str(item['release']).split(':')[-1])
            for item in row.get('acquired_resources') or []:
                if item.get('acquire'):
                    acquires.add(str(item['acquire']).split(':')[-1])
    return acquires, releases


def continuation_closure_blocks_proof(plan: dict[str, Any]) -> bool:
    for cont in plan.get('continuations') or []:
        if cont.get('continuation_open') or cont.get('unreleased_resources'):
            return True
    return False


def limit_claim_to_activated_path(plan: dict[str, Any],
                                  continuation: str,
                                  target_global: str,
                                  pass_path: str) -> tuple[str, str, str]:
    proved = 'PROVED_IN_BOUNDED_DOMAIN'
    if plan.get('operation_begin_miss'):
        if continuation == proved:
            continuation = 'UNRESOLVED'
        if target_global in (proved, 'PARTIAL_COVERAGE'):
            target_global = 'UNRESOLVED'
        if pass_path == proved:
            pass_path = 'UNRESOLVED'
    elif plan.get('seed_trace_cut_miss'):
        if target_global == proved:
            target_global = 'UNRESOLVED'
        if pass_path == proved:
            pass_path = 'UNRESOLVED'
    return continuation, target_global, pass_path


def _parent_releases_arguments(parent_obj: dict[str, Any], callee: str, indexes: list[int]) -> bool:
    return bool(_parent_release_callees(parent_obj, callee, indexes))


def _parent_release_callees(parent_obj: dict[str, Any], callee: str, indexes: list[int]) -> set[str]:
    passed: set[str] = set()
    releases: dict[str, str] = {}
    for insn in parent_obj.get('instructions', []):
        if insn.get('instructionId') != 'FUNCTION_CALL':
            continue
        ops = insn.get('code', {}).get('sub', [])
        target = symbol_name(ops[1]) if len(ops) > 1 else ''
        groups = _call_arg_symbols(ops)
        if target == callee:
            for index in indexes:
                if index < len(groups):
                    passed |= groups[index]
            continue
        if _closes_owned_object(target):
            for group in groups:
                for sym in group:
                    releases.setdefault(sym, target)
    return {releases[sym] for sym in passed if sym in releases}


def compute_bypass_paths(icfg: dict[str, Any],
                         operation_roots: list[str],
                         sink_functions: list[str],
                         guard_functions: list[str]) -> list[list[str]]:
    roots_ir = [r for name in operation_roots for r in resolve_ir_function_names(icfg, name)]
    sinks_ir = set(s for name in sink_functions for s in resolve_ir_function_names(icfg, name))
    guards_ir = set(g for name in guard_functions for g in resolve_ir_function_names(icfg, name))
    if not roots_ir or not sinks_ir:
        return []

    bypasses: list[list[str]] = []
    for root in roots_ir:
        if root in guards_ir:
            continue
        prefixes: dict[str, list[list[str]]] = {root: [[root]]}
        distance = {root: 0}
        queue: deque[str] = deque([root])
        expanded: set[str] = set()
        while queue:
            curr = queue.popleft()
            if curr in expanded:
                continue
            expanded.add(curr)
            if curr in sinks_ir:
                bypasses.extend(prefixes[curr])
                continue
            for nxt in sorted(icfg['callees_of'].get(curr, set())):
                if nxt in guards_ir:
                    continue
                step = distance[curr] + 1
                if nxt in distance and step > distance[nxt]:
                    continue
                fresh = [[*prefix, nxt] for prefix in prefixes[curr] if nxt not in prefix]
                if not fresh:
                    continue
                if nxt not in distance:
                    distance[nxt] = step
                    prefixes[nxt] = fresh
                    queue.append(nxt)
                    continue
                prefixes[nxt].extend(fresh)
                if nxt in expanded and nxt in sinks_ir:
                    bypasses.extend(fresh)
    return bypasses


def _ancestors_including(icfg: dict[str, Any], seeds: set[str], max_hops: int = 16) -> dict[str, int]:
    dist: dict[str, int] = {s: 0 for s in seeds}
    queue = deque(seeds)
    while queue:
        curr = queue.popleft()
        if dist[curr] >= max_hops:
            continue
        for caller in sorted(icfg['callers_of'].get(curr, set())):
            if caller not in dist:
                dist[caller] = dist[curr] + 1
                queue.append(caller)
    return dist


def static_globals_referenced(functions: list[dict[str, Any]],
                              symbols: dict[str, Any],
                              subtree_names: set[str] | list[str]) -> list[str]:
    fn_names = {fn['name'] for fn in functions}
    found: list[str] = []
    seen: set[str] = set()
    wanted = set(subtree_names)
    for fn in functions:
        if fn['name'] not in wanted:
            continue
        for insn in fn.get('instructions') or []:
            reads, _writes = instruction_symbol_access(insn)
            for sname in reads:
                if not sname or sname in fn_names:
                    continue
                sym = symbols.get(sname) or {}
                if not sym.get('isStaticLifetime') or sym.get('isType') or sym.get('isParameter'):
                    continue
                base = str(sym.get('baseName') or sname)
                if base.startswith(('__CPROVER_', '__vulgate_', '__vg_')) or not base.isidentifier():
                    continue
                if base in seen:
                    continue
                seen.add(base)
                found.append(base)
    found.sort(key=lambda item: (0 if 'module' in item else 1, item))
    return found


def _reachable_from(icfg: dict[str, Any], start: str) -> set[str]:
    seen = {start}
    queue = deque([start])
    while queue:
        curr = queue.popleft()
        for nxt in (icfg.get('concrete_callees_of') or icfg['callees_of']).get(curr, set()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _json_footprint(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _json_footprint(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_footprint(item) for item in value]
    return str(value)


def _selector_read(name: str, spec: Any) -> dict[str, Any]:
    row: dict[str, Any] = {'name': str(name)}
    if isinstance(spec, dict):
        path = spec.get('c_expr', spec.get('c_param_expr', spec.get('field')))
        if path is not None:
            row['path'] = path if isinstance(path, str) else _json_footprint(path)
        if 'reads' in spec:
            row['reads'] = _json_footprint(spec['reads'])
        if 'constant' in spec and 'path' not in row and 'reads' not in row:
            row['constant'] = _json_footprint(spec['constant'])
        return row
    row['path'] = str(spec)
    return row


def _action_write_row(write: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for key in ('field', 'symbol_c_name', 'arg', 'offset', 'type'):
        if key in write:
            row[key] = _json_footprint(write[key])
    if not row:
        row['write'] = _json_footprint(write)
    return row


def extract_patch_footprint(case_ir: dict[str, Any],
                            continuations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from .oracle_compiler import observer_function_name, observer_phase, prior_observer_entries

    prior = {str(item['function']) for item in prior_observer_entries(case_ir) if item.get('function')}
    observer_reads: list[dict[str, Any]] = []
    observer_functions: list[str] = []
    map_ops: list[dict[str, Any]] = []
    hook_ids: list[str] = []
    for observer in case_ir.get('observer_specs') or []:
        function = observer_function_name(observer)
        operation = str(observer.get('operation') or 'set')
        map_name = observer.get('map')
        row: dict[str, Any] = {
            'id': observer.get('id'),
            'function': function,
            'map': map_name,
            'operation': operation,
            'phase': observer_phase(observer),
        }
        for key in ('key_expr', 'value_expr', 'key', 'value', 'initial_key', 'initial_value'):
            if key in observer:
                row[key] = _json_footprint(observer[key])
        observer_reads.append(row)
        if observer.get('id'):
            hook_ids.append(str(observer['id']))
        if function and function not in prior and function not in observer_functions:
            observer_functions.append(function)
        if map_name:
            map_ops.append({
                'map': str(map_name),
                'op': operation,
                'site': function,
                'kind': 'observer',
            })
    guard_reads: list[dict[str, Any]] = []
    guard_functions: list[str] = []
    action_writes: list[dict[str, Any]] = []
    for guard in case_ir.get('guards') or []:
        function = str(guard.get('function') or '')
        if function and function not in guard_functions:
            guard_functions.append(function)
        if guard.get('id'):
            hook_ids.append(str(guard['id']))
        reads = [
            _selector_read(name, spec)
            for name, spec in (guard.get('selectors') or {}).items()
        ]
        guard_reads.append({'id': guard.get('id'), 'function': function, 'reads': reads})
        for read in guard.get('map_reads') or []:
            if not read.get('map'):
                continue
            map_ops.append({
                'map': str(read['map']),
                'op': 'consume' if read.get('consume') else 'read',
                'site': function,
                'kind': 'guard',
            })
        action = guard.get('resolved_action') or {}
        action_writes.append({
            'guard': guard.get('id'),
            'action': guard.get('action_id') or action.get('id'),
            'kind': action.get('kind'),
            'writes': [_action_write_row(write) for write in action.get('writes') or [] if isinstance(write, dict)],
        })
    skipped: list[str] = []
    for continuation in continuations or []:
        for name in continuation.get('skipped_callee_writes') or []:
            text = str(name)
            if text and text not in skipped:
                skipped.append(text)
    anchors = case_ir.get('defect_anchors') or {}
    sink = (anchors.get('sink_site') or {}).get('function')
    root = (anchors.get('root_cause_site') or {}).get('function')
    slice_functions: list[str] = []
    for name in [*guard_functions, *observer_functions, *skipped]:
        if name and name not in slice_functions:
            slice_functions.append(name)
    if sink and str(sink) not in slice_functions:
        slice_functions.append(str(sink))
    elif not sink:
        for name in guard_functions:
            if name not in slice_functions:
                slice_functions.append(name)
    if root and str(root) not in slice_functions:
        slice_functions.append(str(root))
    return {
        'observer_reads': observer_reads,
        'map_ops': map_ops,
        'guard_reads': guard_reads,
        'action_writes': action_writes,
        'skipped_callee_writes': skipped,
        'observer_functions': observer_functions,
        'guard_functions': guard_functions,
        'hook_ids': hook_ids,
        'slice_functions': slice_functions,
    }


def operation_boundary(case_ir: dict[str, Any]) -> tuple[list[str], list[str]]:
    profile = case_ir.get('app_profile') or {}
    hooks = profile.get('lifecycle_hooks') or {}
    begin = hooks.get('operation_begin', profile.get('operation_roots') or [])
    end = hooks.get('operation_end') or []
    if isinstance(begin, str):
        begin = [begin]
    if isinstance(end, str):
        end = [end]
    return [str(name) for name in begin if name], [str(name) for name in end if name]


def plan_verification_boundaries(case_ir: dict[str, Any],
                                 functions: list[dict[str, Any]],
                                 symbols: dict[str, Any],
                                 dynamic_traces: list[dict[str, Any]] | None = None,
                                 output_dir: Path | None = None) -> dict[str, Any]:
    dyn_edges: list[tuple[str, str]] = []
    dyn_stacks: list[list[str]] = []
    for tr in (dynamic_traces or []):
        for edge in tr.get('call_edges', []):
            if len(edge) == 2:
                dyn_edges.append((edge[0], edge[1]))
        for stack in tr.get('call_stacks', []):
            if stack:
                dyn_stacks.append(list(stack))

    icfg = build_enhanced_icfg(functions, symbols, dyn_edges)
    fn_map = icfg['functions_by_name']
    activated_names: set[str] = set()
    for stack in dyn_stacks:
        activated_names.update(stack)

    def on_trace(name: str) -> bool:
        base = symbols.get(name, {}).get('baseName', name)
        return name in activated_names or base in activated_names

    guard_names = [g['function'] for g in case_ir['guards']]
    from .driver_synth import source_direct_callers
    from .oracle_compiler import prior_observer_entries
    for guard_name in guard_names:
        targets = resolve_ir_function_names(icfg, guard_name)
        for row in source_direct_callers(case_ir, guard_name):
            if row.get('via') != 'field':
                continue
            callers = resolve_ir_function_names(icfg, row['function'])
            for caller_ir in callers:
                if caller_ir not in fn_map:
                    continue
                for target in targets:
                    if target not in fn_map or target == caller_ir:
                        continue
                    if not fn_map[target].get('isBodyAvailable'):
                        continue
                    icfg['callees_of'].setdefault(caller_ir, set()).add(target)
                    icfg['callers_of'].setdefault(target, set()).add(caller_ir)
                    icfg['concrete_callees_of'].setdefault(caller_ir, set()).add(target)
                    icfg['concrete_callers_of'].setdefault(target, set()).add(caller_ir)
                    icfg['indirect_edges'].append({
                        'caller': caller_ir,
                        'callee': target,
                        'kind': 'source_field_call',
                        'location': {},
                    })
                    pending = [
                        item for item in icfg['unresolved_external']
                        if item.get('caller') == caller_ir
                        and str(item.get('callee') or '').startswith('<indirect:')
                    ]
                    if len(pending) == 1:
                        icfg['unresolved_external'] = [
                            item for item in icfg['unresolved_external']
                            if item is not pending[0]
                        ]
    initial_map_state = prior_observer_entries(case_ir)
    prior_functions = {item['function'] for item in initial_map_state if item.get('function')}
    observer_names = []
    for obs in case_ir.get('observer_specs', []):
        if 'callsite' in obs:
            name = obs['callsite']['caller']
        elif 'function' in obs:
            name = obs['function']
        elif isinstance(obs.get('site'), dict):
            name = obs['site'].get('function')
        else:
            name = None
        if name and name not in prior_functions:
            observer_names.append(name)

    anchors = case_ir.get('defect_anchors', {})
    sink_fn = anchors.get('sink_site', {}).get('function')
    root_cause_fn = anchors.get('root_cause_site', {}).get('function')
    sink_list = [sink_fn] if sink_fn else list(guard_names)

    continuations = [
        analyze_caller_continuation_closure(icfg, symbols, g['function'], g['resolved_action'])
        for g in case_ir['guards']
    ]

    footprint = extract_patch_footprint(case_ir, continuations)
    must_cover_raw = set(footprint['slice_functions'])
    if not must_cover_raw:
        must_cover_raw = set(guard_names) | set(observer_names) | set(sink_list)
        if root_cause_fn:
            must_cover_raw.add(root_cause_fn)
    must_cover_ir: set[str] = set()
    for name in must_cover_raw:
        must_cover_ir.update(resolve_ir_function_names(icfg, name))
    for cont in continuations:
        for dc in cont['direct_callers']:
            must_cover_ir.add(dc['caller'])
        for exit_name in cont.get('continuation_exits', []):
            must_cover_ir.add(exit_name)
        for release_name in cont.get('resource_release_callees', []):
            must_cover_ir.update(resolve_ir_function_names(icfg, release_name))

    begin_names, end_names = operation_boundary(case_ir)
    declared_roots = list(begin_names)
    if not declared_roots and dyn_stacks:
        declared_roots = [dyn_stacks[0][0]]
    root_reach: set[str] = set()
    for name in declared_roots:
        for ir_name in resolve_ir_function_names(icfg, name):
            root_reach |= _reachable_from(icfg, ir_name)

    common_candidates: list[tuple[int, int, str]] = []
    for cand_name, cand_fn in fn_map.items():
        if not cand_fn.get('isBodyAvailable') or cand_name.startswith(('__CPROVER_', '__vulgate_')):
            continue
        if root_reach and cand_name not in root_reach:
            continue
        sub = _reachable_from(icfg, cand_name)
        if must_cover_ir and must_cover_ir <= sub:
            guards_ir_set = {ir for g in guard_names for ir in resolve_ir_function_names(icfg, g)}
            if cand_name in guards_ir_set and any(c['direct_callers'] for c in continuations):
                continue
            common_candidates.append((len(sub), len(cand_fn.get('instructions', [])), cand_name))

    selected_cuts: list[str] = []
    forced_with_cut: dict[str, set[str]] = {}
    seed_trace_cut_miss = False
    if common_candidates:
        common_candidates.sort(key=lambda row: (row[0], row[1], row[2]))
        if dyn_stacks:
            traced_candidates = [row for row in common_candidates if on_trace(row[2])]
            if traced_candidates:
                selected_cuts = [traced_candidates[0][2]]
            else:
                selected_cuts = [common_candidates[0][2]]
                seed_trace_cut_miss = True
        else:
            selected_cuts = [common_candidates[0][2]]
    else:
        per_guard_cuts: set[str] = set()
        for cont in continuations:
            if cont['direct_callers']:
                for dc in cont['direct_callers']:
                    per_guard_cuts.add(dc['caller'])
            else:
                per_guard_cuts.update(cont['guard_ir_names'])
        root_irs = []
        if root_cause_fn:
            for name in resolve_ir_function_names(icfg, root_cause_fn):
                fn_obj = fn_map.get(name)
                if (fn_obj and fn_obj.get('isBodyAvailable')
                        and not name.startswith(('__vg_', '__CPROVER_', '__vulgate_'))):
                    root_irs.append(name)
        if len(root_irs) == 1 and per_guard_cuts:
            selected_cuts = [root_irs[0]]
            forced = set()
            for cont in continuations:
                forced.update(cont['guard_ir_names'])
            for sink_name in sink_list:
                forced.update(resolve_ir_function_names(icfg, sink_name))
            forced_with_cut[root_irs[0]] = forced
        else:
            if root_reach:
                inside = {name for name in per_guard_cuts if name in root_reach}
                if inside:
                    per_guard_cuts = inside
            selected_cuts = sorted(per_guard_cuts)

    operation_begin_absent = bool(declared_roots) and not root_reach
    operation_begin_miss = operation_begin_absent or (
        bool(root_reach) and not any(name in root_reach for name in selected_cuts)
    )
    end_irs = [ir_name for name in end_names for ir_name in resolve_ir_function_names(icfg, name)]
    covered_by_cuts: set[str] = set()
    for cut_name in selected_cuts:
        covered_by_cuts |= _reachable_from(icfg, cut_name)
    operation_end_outside_cut = [name for name in end_irs if name not in covered_by_cuts]

    bypass_paths = compute_bypass_paths(
        icfg,
        declared_roots or selected_cuts,
        sink_list,
        guard_names,
    )

    explicit_bypasses = list(case_ir.get('defect_anchors', {}).get('known_unhooked_entries', []))
    for eb in explicit_bypasses:
        if [eb] not in bypass_paths:
            bypass_paths.append([eb, *(sink_list[:1])])

    from tools.postdeploy.driver_synth import (
        carrier_increment_bypasses,
        direct_block_switches,
        discovered_unhooked_entries,
        handler_redirect_bypasses,
        non_multipart_oom_bypasses,
        null_input_branches,
        parallel_module_chains,
        request_finalize_bypasses,
        shutdown_other_global_bypasses,
        source_bypass_chains,
    )
    present = {path[0] for path in bypass_paths if path}

    def adopt(chain: list[str]) -> None:
        if not chain or not chain[0]:
            return
        for index, path in enumerate(bypass_paths):
            if not path or path[0] != chain[0]:
                continue
            if path != chain and path[1:] == list(sink_list[:1]):
                bypass_paths[index] = chain
            return
        bypass_paths.append(chain)
        present.add(chain[0])

    for name in discovered_unhooked_entries(case_ir, guard_names):
        if name not in present:
            adopt([name, *(sink_list[:1])])
    for chain in source_bypass_chains(case_ir, guard_names, sink_list):
        adopt(chain)
    for chain in parallel_module_chains(case_ir, guard_names, sink_list):
        adopt(chain)
    for name in carrier_increment_bypasses(case_ir, guard_names):
        if name not in present:
            adopt([name, *(sink_list[:1])])
    for name in request_finalize_bypasses(case_ir, guard_names):
        if name not in present:
            adopt([name, *(sink_list[:1])])
    for name in null_input_branches(case_ir, guard_names, sink_list):
        if name not in present:
            adopt([name, *(sink_list[:1])])
    for name in handler_redirect_bypasses(case_ir, guard_names):
        if name not in present:
            adopt([name, *(sink_list[:1])])
    for name in direct_block_switches(case_ir, guard_names):
        if name not in present:
            adopt([name, *(sink_list[:1])])
    for name in shutdown_other_global_bypasses(case_ir):
        if name not in present:
            adopt([name, *(sink_list[:1])])
    for name in non_multipart_oom_bypasses(case_ir, guard_names):
        if name not in present:
            adopt([name, *(sink_list[:1])])

    lifetime = anchors.get('state_carrier', {}).get('lifetime', 'call_tree')
    episode_length = max(
        int(case_ir['budgets'].get('episode_length', 1)),
        2 if lifetime in ('connection', 'worker') else 1,
    )

    cut_tasks: list[dict[str, Any]] = []
    for cut_fn in selected_cuts:
        subtree_set = _reachable_from(icfg, cut_fn)
        for seed in forced_with_cut.get(cut_fn, ()):
            subtree_set |= _reachable_from(icfg, seed)
        subtree = sorted(subtree_set)
        unresolved_in_slice = [
            u for u in icfg['unresolved_external']
            if u['caller'] in subtree
        ]
        cut_tasks.append({
            'cut_function': cut_fn,
            'base_name': symbols.get(cut_fn, {}).get('baseName', cut_fn),
            'parameters': list(fn_map[cut_fn].get('parameterIdentifiers', [])) if cut_fn in fn_map else [],
            'subtree_size': len(subtree),
            'subtree_functions': subtree,
            'episode_length': episode_length,
            'state_lifetime': lifetime,
            'unresolved_external_calls': unresolved_in_slice,
            'role': 'covering_cut',
            'seed_activated': on_trace(cut_fn) if dyn_stacks else True,
        })

    if dyn_stacks and any(task['role'] == 'covering_cut' and task['seed_activated'] for task in cut_tasks):
        for task in cut_tasks:
            if task['role'] == 'covering_cut' and not task['seed_activated']:
                task['role'] = 'caller_local'
        selected_cuts = [task['cut_function'] for task in cut_tasks if task['role'] == 'covering_cut']
    seen_cuts = {task['cut_function'] for task in cut_tasks}
    caller_rows: list[tuple[int, str, str]] = []
    for cont in continuations:
        for dc in cont['direct_callers']:
            caller = dc['caller']
            if caller in seen_cuts or caller.startswith(('__CPROVER_', '__vulgate_', '__vg_')):
                continue
            base = symbols.get(caller, {}).get('baseName', caller)
            seed_hit = base in activated_names or caller in activated_names
            caller_rows.append((0 if seed_hit else 1, caller, ''))
            seen_cuts.add(caller)
    from .driver_synth import source_direct_callers
    for guard_name in guard_names:
        for row in source_direct_callers(case_ir, guard_name):
            caller = row['function']
            if caller in seen_cuts or caller.startswith(('__CPROVER_', '__vulgate_', '__vg_')):
                continue
            seed_hit = caller in activated_names
            caller_rows.append((0 if seed_hit else 1, caller, row['file']))
            seen_cuts.add(caller)
    for seed_rank, caller, source_file in sorted(caller_rows):
        subtree_set = _reachable_from(icfg, caller)
        subtree = sorted(subtree_set)
        if caller not in subtree:
            subtree.append(caller)
        unresolved_in_slice = [
            u for u in icfg['unresolved_external']
            if u['caller'] in subtree
        ]
        task = {
            'cut_function': caller,
            'base_name': symbols.get(caller, {}).get('baseName', caller),
            'parameters': list(fn_map[caller].get('parameterIdentifiers', [])) if caller in fn_map else [],
            'subtree_size': len(subtree),
            'subtree_functions': subtree,
            'episode_length': episode_length,
            'state_lifetime': lifetime,
            'unresolved_external_calls': unresolved_in_slice,
            'role': 'caller_local',
            'seed_activated': seed_rank == 0,
        }
        if source_file:
            task['source_file'] = source_file
        cut_tasks.append(task)

    plan = {
        'schema': 'vulgate.boundary_plan/v2',
        'case_id': case_ir['case_id'],
        'declared_operation_roots': declared_roots,
        'operation_begin': begin_names,
        'operation_end': end_names,
        'operation_begin_absent': operation_begin_absent,
        'operation_begin_miss': operation_begin_miss,
        'operation_end_outside_cut': operation_end_outside_cut,
        'patch_footprint': footprint,
        'must_cover_ir_functions': sorted(must_cover_ir),
        'selected_cut_functions': selected_cuts,
        'seed_trace_cut_miss': seed_trace_cut_miss,
        'initial_map_state': initial_map_state,
        'continuations': continuations,
        'bypass_paths': bypass_paths,
        'operation_coverage_complete': len(bypass_paths) == 0 and len(selected_cuts) > 0,
        'tasks': cut_tasks,
    }
    if output_dir is not None:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        (Path(output_dir) / 'boundary-plan.json').write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    return plan
