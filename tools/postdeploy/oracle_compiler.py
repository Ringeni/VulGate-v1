from __future__ import annotations

import re
from typing import Any


HARNESS_ASSERTIONS: dict[str, dict[str, str]] = {
    'brotli_stream_refill': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && res1 == BROTLI_DECODER_RESULT_ERROR && obs1.ret_code < 0)',
        'violation_w1': '!(bad_cap && res1 != BROTLI_DECODER_RESULT_ERROR)',
    },
    'nginx_script_check_length': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && obs1.clean_exit && obs1.status == 500)',
        'violation_w1': 'obs1.pos_offset <= (__vg_in_alloc_len - __vg_in_reserved)',
    },
    'nginx_script_regex_start': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && obs1.clean_exit && obs1.status == 500)',
        'violation_w1': '!(__vg_in_invoke_regex == 1ULL && !__vulgate_any_blocked)',
    },
    'nginx_alias_map_uri': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && obs1.rc == NGX_HTTP_INTERNAL_SERVER_ERROR && !obs1.path_allocated)',
        'violation_w1': '!((__vg_in_alias != 0ULL && (!__vg_in_valid_loc || __vg_in_uri_changed != 0ULL)) && obs1.rc == NGX_OK)',
    },
    'nginx_copy_filter_aio': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == NGX_ERROR && obs1.blocked_after == __vg_in_counter)',
        'violation_w1': '!(__vg_in_counter >= 250ULL && obs1.blocked_after > __vg_in_counter)',
    },
    'nginx_map_variable': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == -1 && obs1.var_valid == 0)',
        'violation_w1': '!(__vg_in_use_map == 1ULL && !__vulgate_any_blocked)',
    },
    'nginx_regex_captures': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == NGX_ERROR)',
        'violation_w1': '!((__vg_in_captures != 0ULL && __vg_in_realloc != 0ULL) && rc1 != NGX_ERROR)',
    },
    'nginx_h2_grpc_serializers': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && obs1.finalized_status == NGX_HTTP_INTERNAL_SERVER_ERROR && !obs1.serialized)',
        'violation_w1': '!((__vg_in_proto_mode == 1ULL || __vg_in_proto_mode == 2ULL) && obs1.serialized)',
    },
    'nginx_dav_copy_move': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == 405)',
        'violation_w1': '!((__vg_in_method == NGX_HTTP_COPY || __vg_in_method == NGX_HTTP_MOVE) && rc1 != 405)',
    },
    'httpd_vhost_translate': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == 414 && fset1 == 0)',
        'violation_w1': '!(rc1 == OK)',
    },
    'httpd_h2_c1_setup': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && det1 == 1 && rc1 != OK)',
        'violation_w1': '!(__vg_in_is_h2 == 1ULL && rc1 == OK)',
    },
    'httpd_dav_proppatch': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == 503)',
        'violation_w1': '!(__vg_in_method == M_PROPPATCH && rc1 == 207)',
    },
    'httpd_session_proxy': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == 503)',
        'violation_w1': '!(__vg_in_previous == 1ULL && rc1 == OK)',
    },
    'httpd_xml2enc_filter': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == 20014)',
        'violation_w1': '!(__vg_in_filter_en == 1ULL && rc1 == APR_SUCCESS)',
    },
    'httpd_charset_out_filter': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && rc1 == 20014)',
        'violation_w1': '!(__vg_in_filter_en == 1ULL && rc1 == APR_SUCCESS)',
    },
    'httpd_proxy_html_comment': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && ctx1.emitted_body == 1 && ctx1.flushed_early == 0)',
        'violation_w1': '!ctx1.flushed_early',
    },
    'httpd_rewrite_lookup': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && elen1 == 0)',
        'violation_w1': '!(__vg_in_uses_var == 1ULL && !__vulgate_any_blocked)',
    },
    'php_multipart_startup': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && st1.content_type_freed == 1 && st1.parsed_fields == 0)',
        'violation_w1': '!(startup_mp && st1.parsed_fields != 0)',
    },
    'php_session_progress': {
        'continuation_w1': '!__vulgate_any_blocked || (__vulgate_action_write_ok && obs1.upload_saved == 1 && !obs1.stale_global_across_requests)',
        'violation_w1': '!obs1.stale_global_across_requests',
    },
}


CASE_ORACLE_BINDINGS: dict[str, dict[str, str]] = {
    'CVE-2026-111497': {
        'postcondition_expr': 'res1 == BROTLI_DECODER_RESULT_ERROR && obs1.ret_code < 0',
        'violation_expr': 'bad_cap && res1 != BROTLI_DECODER_RESULT_ERROR',
    },
    'CVE-2026-93479': {
        'postcondition_expr': 'obs1.clean_exit && obs1.status == 500',
        'ptr_expr': 'obs1.pos_offset',
        'width_expr': '0',
        'base_expr': '0',
        'logical_len_expr': '__vg_in_alloc_len - __vg_in_reserved',
    },
    'CVE-2026-97205': {
        'postcondition_expr': 'rc1 == NGX_ERROR && obs1.blocked_after == __vg_in_counter',
        'violation_expr': '__vg_in_counter >= 250ULL && obs1.blocked_after > __vg_in_counter',
    },
    'CVE-2026-15176': {
        'postcondition_expr': 'obs1.rc == NGX_HTTP_INTERNAL_SERVER_ERROR && !obs1.path_allocated',
        'violation_expr': '(__vg_in_alias != 0ULL && (!__vg_in_valid_loc || __vg_in_uri_changed != 0ULL)) && obs1.rc == NGX_OK',
    },
    'CVE-2026-42533': {
        'postcondition_expr': 'rc1 == -1 && obs1.var_valid == 0',
        'violation_expr': '__vg_in_use_map == 1ULL && !__vulgate_any_blocked',
    },
    'CVE-2026-60005': {
        'postcondition_expr': 'rc1 == NGX_ERROR',
        'violation_expr': '(__vg_in_captures != 0ULL && __vg_in_realloc != 0ULL) && rc1 != NGX_ERROR',
    },
    'CVE-2026-9256': {
        'postcondition_expr': 'obs1.clean_exit && obs1.status == 500',
        'violation_expr': '__vg_in_invoke_regex == 1ULL && !__vulgate_any_blocked',
    },
    'CVE-2026-42945': {
        'postcondition_expr': 'obs1.clean_exit && obs1.status == 500',
        'violation_expr': '__vg_in_invoke_regex == 1ULL && !__vulgate_any_blocked',
    },
    'CVE-2026-42055': {
        'postcondition_expr': 'obs1.finalized_status == NGX_HTTP_INTERNAL_SERVER_ERROR && !obs1.serialized',
        'violation_expr': '(__vg_in_proto_mode == 1ULL || __vg_in_proto_mode == 2ULL) && obs1.serialized',
    },
    'CVE-2026-27654': {
        'postcondition_expr': 'rc1 == 405',
        'violation_expr': '(__vg_in_method == NGX_HTTP_COPY || __vg_in_method == NGX_HTTP_MOVE) && rc1 != 405',
    },
    'CVE-2026-63292': {
        'postcondition_expr': 'rc1 == 414 && fset1 == 0',
        'violation_expr': 'rc1 == OK',
    },
    'CVE-2026-57941': {
        'postcondition_expr': 'det1 == 1 && rc1 != OK',
        'violation_expr': '__vg_in_is_h2 == 1ULL && rc1 == OK',
    },
    'CVE-2026-93546': {
        'postcondition_expr': 'rc1 == 503',
        'violation_expr': '__vg_in_method == M_PROPPATCH && rc1 == 207',
    },
    'CVE-2026-47360': {
        'postcondition_expr': 'rc1 == 503',
        'violation_expr': '__vg_in_previous == 1ULL && rc1 == OK',
    },
    'CVE-2026-63686': {
        'postcondition_expr': 'rc1 == 20014',
        'violation_expr': '__vg_in_filter_en == 1ULL && rc1 == APR_SUCCESS',
    },
    'CVE-2026-56153': {
        'postcondition_expr': 'rc1 == 20014',
        'violation_expr': '__vg_in_filter_en == 1ULL && rc1 == APR_SUCCESS',
    },
    'CVE-2026-56449': {
        'postcondition_expr': 'ctx1.emitted_body == 1 && ctx1.flushed_early == 0',
        'violation_expr': 'ctx1.flushed_early',
    },
    'CVE-2026-56154': {
        'postcondition_expr': 'elen1 == 0',
        'violation_expr': '__vg_in_uses_var == 1ULL && !__vulgate_any_blocked',
    },
    'CVE-2026-109618': {
        'postcondition_expr': 'st1.content_type_freed == 1 && st1.parsed_fields == 0',
        'violation_expr': 'startup_mp && st1.parsed_fields != 0',
    },
    'CVE-2026-109619': {
        'postcondition_expr': 'obs1.upload_saved == 1 && !obs1.stale_global_across_requests',
        'violation_expr': 'obs1.stale_global_across_requests',
    },
}


def _blocked_continuation(postcondition: str) -> str:
    return f'!__vulgate_any_blocked || (__vulgate_action_write_ok && {postcondition})'


def _temporal_validity(obj: str, refs: str, events: str | None) -> str:
    if not events:
        return f'!(({obj}) != 0 && ({refs}) == 0)'
    return (
        f'((({obj}) == 0) ? ((({refs}) == 0) && (({events}) == 0)) : (({refs}) > 0))'
        f' && (({events}) <= ({refs}))'
    )


def compile_kind_assertions(oracle: dict[str, Any]) -> dict[str, str]:
    bindings = dict(oracle.get('bindings') or {})
    kind = oracle.get('kind')
    compiled: dict[str, str] = {}
    for key in ('continuation_w1', 'violation_w1', 'nonvacuity_w0'):
        if bindings.get(key):
            compiled[key] = str(bindings[key])
    post = bindings.get('postcondition_expr')
    if post and 'continuation_w1' not in compiled:
        compiled['continuation_w1'] = _blocked_continuation(str(post))
    if bindings.get('violation_expr') and 'violation_w1' not in compiled:
        compiled['violation_w1'] = f'!({bindings["violation_expr"]})'
    if kind == 'logical_region_bounds':
        names = ('ptr_expr', 'width_expr', 'base_expr', 'logical_len_expr')
        if all(bindings.get(name) for name in names) and 'violation_w1' not in compiled:
            ptr, width, base, logical = (str(bindings[name]) for name in names)
            bound = f'(({ptr}) + ({width})) <= (({base}) + ({logical}))'
            compiled['violation_w1'] = bound
            compiled.setdefault('continuation_w1', _blocked_continuation(bound))
    elif kind == 'temporal_object_validity' and 'violation_w1' not in compiled:
        obj = bindings.get('object_expr')
        refs = bindings.get('refcount_expr')
        events = bindings.get('active_events')
        if obj and refs:
            live = _temporal_validity(str(obj), str(refs), str(events) if events else None)
            compiled['violation_w1'] = live
            compiled.setdefault('continuation_w1', _blocked_continuation(live))
    elif kind == 'state_invariant' and 'violation_w1' not in compiled:
        if bindings.get('invariant_expr'):
            expr = str(bindings['invariant_expr'])
            compiled['violation_w1'] = f'({expr})'
            compiled.setdefault('continuation_w1', _blocked_continuation(f'({expr})'))
        else:
            compiled.setdefault('continuation_w1', '!__vulgate_any_blocked || __vulgate_action_write_ok')
    elif kind == 'arithmetic_domain_safety' and 'violation_w1' not in compiled:
        if bindings.get('domain_expr'):
            expr = str(bindings['domain_expr'])
            compiled['violation_w1'] = f'({expr})'
            compiled.setdefault('continuation_w1', _blocked_continuation(f'({expr})'))
        else:
            compiled.setdefault('continuation_w1', '!__vulgate_any_blocked || __vulgate_action_write_ok')
            compiled['builtin_target'] = 'arithmetic'
    elif kind == 'physical_memory_safety':
        compiled.setdefault('continuation_w1', '!__vulgate_any_blocked || __vulgate_action_write_ok')
        if 'violation_w1' not in compiled:
            compiled['builtin_target'] = 'memory'
    elif kind == 'initialized_read_safety':
        compiled.setdefault('continuation_w1', '!__vulgate_any_blocked || __vulgate_action_write_ok')
        if 'violation_w1' not in compiled:
            compiled['builtin_target'] = 'initialized'
    return compiled


_PRIOR_OBSERVER_PHASES = frozenset({'install', 'previous_request', 'prior_request'})


def observer_phase(observer: dict[str, Any]) -> str:
    site = observer.get('site') if isinstance(observer.get('site'), dict) else {}
    return str(observer.get('phase') or site.get('phase') or '')


def observer_function_name(observer: dict[str, Any]) -> str | None:
    callsite = observer.get('callsite') if isinstance(observer.get('callsite'), dict) else {}
    if callsite.get('caller'):
        return str(callsite['caller'])
    dsl_cs = observer.get('dsl_callsite') if isinstance(observer.get('dsl_callsite'), dict) else {}
    if dsl_cs.get('caller'):
        return str(dsl_cs['caller'])
    if observer.get('function'):
        return str(observer['function'])
    site = observer.get('site') if isinstance(observer.get('site'), dict) else {}
    if site.get('function'):
        return str(site['function'])
    return None


def prior_observer_entries(case_ir: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for observer in case_ir.get('observer_specs') or []:
        if observer_phase(observer) not in _PRIOR_OBSERVER_PHASES:
            continue
        entries.append({
            'id': observer.get('id'),
            'map': observer.get('map'),
            'operation': observer.get('operation', 'set'),
            'function': observer_function_name(observer),
            'key_expr': observer.get('key_expr', observer.get('initial_key')),
            'value_expr': observer.get('value_expr', observer.get('initial_value')),
        })
    return entries


def _symbolic_input_names(case_ir: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in (case_ir.get('symbolization_scope') or {}).get('symbolic_inputs') or []:
        if isinstance(item, dict) and item.get('name'):
            names.add(str(item['name']))
        elif isinstance(item, str):
            names.add(item)
    return names


def _map_value_expr(raw: Any, symbolic_names: set[str], source: str) -> str | None:
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, int):
        return f'UINT64_C({int(raw)})'
    if not isinstance(raw, str) or not re.fullmatch(r'[0-9A-Za-z_+\-*/<>!=&|() \t]+', raw.strip()):
        return None
    rendered: list[str] = []
    for part in re.split(r'(\b[A-Za-z_]\w*\b)', raw.strip()):
        if not re.fullmatch(r'[A-Za-z_]\w*', part):
            rendered.append(part)
            continue
        if part == 'UINT64_C':
            rendered.append(part)
            continue
        token = part if part.startswith('__vg_in_') else f'__vg_in_{part}'
        if part not in symbolic_names and part not in source and token not in source:
            return None
        if token not in source:
            return None
        rendered.append(token)
    return ''.join(rendered)


def _c_word(raw: Any, names: set[str], source: str) -> str | None:
    if raw == '__vg_tid':
        return '0'
    return _map_value_expr(raw, names, source)


def _needs_word_store(entry: dict[str, Any], map_def: dict[str, Any]) -> bool:
    key = str(entry.get('key_expr') or '').strip()
    value = str(entry.get('value_expr') or '').strip()
    if key.startswith('[') or value.startswith('{'):
        return True
    key_type = map_def.get('key_type')
    value_type = map_def.get('value_type')
    if isinstance(key_type, dict) and key_type.get('tuple'):
        return True
    return isinstance(value_type, dict) and bool(value_type.get('struct'))


def _structured_initial_call(entry: dict[str, Any], map_def: dict[str, Any],
                             names: set[str], source: str) -> tuple[str, str] | None:
    from .case_compiler import bind_observer_words

    if not _needs_word_store(entry, map_def):
        return None
    map_name = str(entry.get('map') or '')
    try:
        bound = bind_observer_words(map_name, map_def, entry, [])
    except ValueError:
        return None
    key_words = []
    for comp in bound['key_components']:
        rendered = '0' if comp.get('scope') else _c_word(comp.get('name'), names, source)
        if rendered is None:
            return None
        key_words.append(rendered)
    value_words = []
    for expr in bound.get('value_exprs') or []:
        rendered = _c_word(expr, names, source)
        if rendered is None:
            return None
        value_words.append(rendered)
    keys = [*key_words, *['0'] * (4 - len(key_words))]
    values = [*value_words, *['0'] * (4 - len(value_words))]
    function = f'__vulgate_table_set_words_{map_name}'
    decl = (
        f'extern int {function}(uint64_t scope, uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3,'
        f' unsigned key_words, uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3, unsigned nfields);'
    )
    call = (
        f'{function}(0, {", ".join(keys)}, {len(key_words)},'
        f' {", ".join(values)}, {len(value_words)});'
    )
    return decl, call


def inject_initial_map_state(source: str, case_ir: dict[str, Any]) -> str:
    names = _symbolic_input_names(case_ir)
    maps = case_ir.get('maps') or {}
    calls: list[str] = []
    decls: list[str] = []
    for entry in prior_observer_entries(case_ir):
        if entry.get('operation') != 'set':
            continue
        map_name = entry.get('map')
        if not isinstance(map_name, str) or not re.fullmatch(r'[A-Za-z_]\w*', map_name) or map_name not in maps:
            continue
        structured = _structured_initial_call(entry, maps[map_name], names, source)
        if structured is not None:
            decls.append(structured[0])
            calls.append(structured[1])
            continue
        key = _map_value_expr(entry.get('key_expr'), names, source)
        value = _map_value_expr(entry.get('value_expr'), names, source)
        if key is None or value is None:
            continue
        function = f'__vulgate_table_set_{map_name}'
        decls.append(f'extern int {function}(uint64_t scope, uint64_t key, uint64_t val);')
        calls.append(f'{function}(0, {key}, {value});')
    if not calls:
        return source
    block = '\n    ' + '\n    '.join(calls)
    for function_name in ('__vg_verify_obligations', '__vg_impact_harness'):
        marker = f'void {function_name}('
        start = source.find(marker)
        if start < 0:
            continue
        brace = source.find('{', start)
        if brace < 0:
            continue
        source = source[:brace + 1] + block + source[brace + 1:]
    return '\n'.join(decls) + '\n' + source


_RETURN_ALIASES = ('rc1', 'res1', 'det1', 'elen1', 'fset1')
_ALWAYS_BOUND = {
    '__vulgate_any_blocked', '__vulgate_action_write_ok', '__vulgate_shadow_active',
    'obs0', 'obs1', 'ULL', 'LL', 'NULL',
}
_FAMILY_MACROS = {
    'ngx_http.h': {
        'NGX_OK', 'NGX_ERROR', 'NGX_DECLINED', 'NGX_AGAIN', 'NGX_DONE', 'NGX_ABORT',
        'NGX_HTTP_OK', 'NGX_HTTP_INTERNAL_SERVER_ERROR', 'NGX_HTTP_COPY', 'NGX_HTTP_MOVE',
        'NGX_HTTP_DELETE', 'NGX_HTTP_PUT', 'NGX_HTTP_MKCOL',
    },
    'httpd.h': {
        'OK', 'DECLINED', 'DONE', 'HTTP_OK', 'APR_SUCCESS', 'APR_EGENERAL',
        'M_PROPPATCH', 'M_COPY', 'M_MOVE', 'M_GET',
    },
    'brotli/decode.h': {
        'BROTLI_DECODER_RESULT_ERROR', 'BROTLI_DECODER_RESULT_SUCCESS',
        'BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT', 'BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT',
    },
}


def _struct_layouts(source: str) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    integer = r'(?:int|unsigned|signed|uint64_t|uint32_t|ngx_int_t|ngx_uint_t|size_t|_Bool|bool)'
    for match in re.finditer(r'(?:typedef\s+)?struct(?:\s+([A-Za-z_]\w*))?\s*\{', source):
        end = source.find('}', match.end())
        if end < 0:
            continue
        body = source[match.end():end]
        names = set(re.findall(rf'\b{integer}\s+([A-Za-z_]\w*)\s*;', body))
        embeds = [
            (field, type_name)
            for type_name, field in re.findall(
                r'\bstruct\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;',
                body,
            )
        ]
        tag = match.group(1) or ''
        alias = re.match(r'\s*([A-Za-z_]\w*)\s*;', source[end + 1:])
        for key in (tag, alias.group(1) if alias else ''):
            if key and key != 'vg_proto_obs':
                slot = found.setdefault(key, {'integers': set(), 'embeds': []})
                slot['integers'].update(names)
                slot['embeds'].extend(embeds)
    return found


def _top_level_objects(source: str, types: set[str] | None = None) -> list[tuple[str, str]]:
    visible: list[str] = []
    depth = 0
    for char in source:
        if char == '{':
            depth += 1
            visible.append(' ')
        elif char == '}':
            depth = max(0, depth - 1)
            visible.append(' ')
        elif depth == 0:
            visible.append(char)
        else:
            visible.append(' ')
    text = ''.join(visible)
    found = re.findall(
        r'(?:struct|union)\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;',
        text,
    )
    seen = set(found)
    for type_name in types or set():
        if not re.fullmatch(r'[A-Za-z_]\w*', type_name):
            continue
        for name in re.findall(rf'(?<![\w]){re.escape(type_name)}\s+([A-Za-z_]\w*)\s*;', text):
            row = (type_name, name)
            if row not in seen:
                seen.add(row)
                found.append(row)
    return found


def _obs_integer_paths(type_name: str,
                       prefix: str,
                       field: str,
                       layouts: dict[str, dict[str, Any]],
                       depth: int,
                       seen: set[str]) -> list[str]:
    if depth > 4 or type_name in seen:
        return []
    layout = layouts.get(type_name) or {}
    found: list[str] = []
    if field in layout.get('integers', set()):
        found.append(f'{prefix}.{field}')
    for embed_name, embed_type in layout.get('embeds', []):
        found.extend(_obs_integer_paths(
            embed_type,
            f'{prefix}.{embed_name}',
            field,
            layouts,
            depth + 1,
            seen | {type_name},
        ))
    return found


def _store_unique_obs_fields(source: str, needed: set[str], layout_text: str = '') -> str:
    if not needed or 'typedef struct vg_proto_obs' not in source:
        return source
    layouts = _struct_layouts(source + '\n' + layout_text)
    objects = _top_level_objects(source, set(layouts))
    stores: list[tuple[str, str]] = []
    for field in sorted(needed):
        if field in _proto_obs_fields(source):
            continue
        paths: list[str] = []
        for type_name, name in objects:
            paths.extend(_obs_integer_paths(type_name, name, field, layouts, 0, set()))
        if len(set(paths)) != 1:
            continue
        stores.append((field, paths[0]))
    if not stores:
        return source
    added = '\n'.join(f'    uint64_t {field};' for field, _path in stores)
    source = re.sub(
        r'(typedef struct vg_proto_obs\s*\{[^}]*)(\})',
        lambda match: match.group(1) + added + '\n' + match.group(2),
        source,
        count=1,
    )
    assigned = '\n'.join(f'    obs->{field} = (uint64_t){path};' for field, path in stores)
    source = re.sub(
        r'\n}\n+(\nint __vg_run_world_0)',
        lambda match: '\n' + assigned + match.group(0),
        source,
        count=1,
    )
    return source


def _proto_obs_fields(source: str) -> set[str]:
    match = re.search(r'typedef struct vg_proto_obs\s*\{([^}]*)\}', source)
    if not match:
        return set()
    return set(re.findall(r'\b([A-Za-z_]\w*)\s*;', match.group(1)))


def project_oracle_expression(expr: str, source: str) -> str | None:
    fields = _proto_obs_fields(source)
    if not fields:
        return None
    text = expr
    if 'status_code' in fields:
        for alias in _RETURN_ALIASES:
            if re.search(rf'(?<![\w]){alias}(?![\w])', text) and not re.search(rf'(?<![\w]){alias}(?![\w])', source):
                text = re.sub(rf'(?<![\w]){alias}(?![\w])', '(obs1.status_code)', text)
    for owner in ('obs0', 'obs1'):
        for field in re.findall(rf'(?<![\w]){owner}\.([A-Za-z_]\w*)', text):
            if field not in fields:
                return None
    if re.search(r'(?<![\w])(?:ctx1|st1)\.', text):
        return None
    macros: set[str] = set()
    for header, names in _FAMILY_MACROS.items():
        if header in source:
            macros |= names
    scrubbed = re.sub(r'\bobs[01]\.[A-Za-z_]\w*', ' ', text)
    for ident in set(re.findall(r'\b[A-Za-z_]\w*\b', scrubbed)):
        if ident in _ALWAYS_BOUND or ident in macros or ident in fields:
            continue
        if not re.search(rf'(?<![\w]){re.escape(ident)}(?![\w])', source):
            return None
    return text


def resolved_assertion_bindings(oracle: dict[str, Any], harness_kind: str | None = None) -> dict[str, str]:
    del harness_kind
    return compile_kind_assertions(oracle)


def included_layout_text(source: str, directories: list[str], limit: int = 64) -> str:
    from pathlib import Path
    queue: list[tuple[str, Path | None]] = [
        (name, None)
        for name in re.findall(r'#\s*include\s*[<"]([^>"]+)[>"]', source)
    ]
    seen: set[str] = set()
    texts: list[str] = []
    roots = [Path(str(item)) for item in directories if str(item)]
    while queue and len(texts) < limit:
        name, origin = queue.pop(0)
        candidates = []
        if origin is not None:
            candidates.append(origin / name)
        candidates.extend(root / name for root in roots)
        path = next((item for item in candidates if item.is_file()), None)
        if path is None:
            continue
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        texts.append(text)
        for nested in re.findall(r'#\s*include\s*[<"]([^>"]+)[>"]', text):
            queue.append((nested, path.parent))
    joined = '\n'.join(texts)
    missing = [
        name for name in _driver_object_types(source)
        if not _header_defines_type(source + '\n' + joined, name)
    ]
    reads = 0
    for type_name in list(missing):
        tokens = [part for part in type_name.lower().split('_') if len(part) > 2]
        files: list[Path] = []
        for root in roots:
            if root.is_dir():
                files.extend(item for item in root.rglob('*.h') if item.is_file())
        files.sort(key=lambda item: (0 if any(token in item.name.lower() for token in tokens) else 1, str(item)))
        for path in files:
            if reads >= 200 or type_name not in missing:
                break
            key = str(path.resolve())
            if key in seen:
                continue
            reads += 1
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            seen.add(key)
            if not _header_defines_type(text, type_name):
                continue
            texts.append(text)
            missing.remove(type_name)
    return '\n'.join(texts)


_NOT_LAYOUT_TYPES = {
    'int', 'unsigned', 'signed', 'void', 'static', 'const', 'struct', 'union', 'enum',
    'return', 'if', 'for', 'while', 'uint64_t', 'uint32_t', 'uint16_t', 'uint8_t',
    'int64_t', 'int32_t', 'size_t', 'ssize_t', '_Bool', 'bool', 'char', 'long', 'short',
    'ngx_int_t', 'ngx_uint_t',
}


def _driver_object_types(source: str) -> set[str]:
    names = set(re.findall(r'\bstruct\s+([A-Za-z_]\w*)\s+[A-Za-z_]\w*\s*;', source))
    for type_name in re.findall(r'(?<![\w])([A-Za-z_]\w*)\s+[A-Za-z_]\w*(?:_obj|_slot)\s*;', source):
        if type_name not in _NOT_LAYOUT_TYPES:
            names.add(type_name)
    return names


def _header_defines_type(text: str, type_name: str) -> bool:
    ident = re.escape(type_name)
    if re.search(rf'\bstruct\s+{ident}\s*\{{', text):
        return True
    if re.search(rf'\}}\s*{ident}\s*;', text):
        return True
    if re.search(rf'\btypedef\s+struct\s+[A-Za-z_]\w*\s+{ident}\s*;', text):
        return True
    return False


def apply_oracle_assertions(source: str,
                            oracle: dict[str, Any],
                            harness_kind: str | None,
                            layout_text: str = '') -> str:
    bindings = resolved_assertion_bindings(oracle, harness_kind)
    prototype = 'typedef struct vg_proto_obs' in source
    if prototype:
        needed = set()
        for expr in bindings.values():
            needed.update(re.findall(r'(?<![\w])obs[01]\.([A-Za-z_]\w*)', str(expr)))
        source = _store_unique_obs_fields(source, needed, layout_text)
    replacements = (
        ('continuation_w1', 'vg.obligation.action_continuation_safe'),
        ('violation_w1', 'vg.target.violation_w1'),
        ('nonvacuity_w0', 'vg.target.nonvacuity_w0'),
    )
    unbound = False
    for key, desc in replacements:
        expr = bindings.get(key)
        if not expr:
            continue
        if prototype:
            projected = project_oracle_expression(expr, source)
            if projected is None:
                unbound = True
                continue
            expr = projected
        pattern = re.compile(
            r'__CPROVER_assert\s*\((?:(?!__CPROVER_assert).)*?,\s*"' + re.escape(desc) + r'"\s*\)\s*;',
            re.S,
        )
        source, _count = pattern.subn(
            f'__CPROVER_assert({expr}, "{desc}");',
            source,
            count=1,
        )
    kind_name = str(oracle.get('kind') or '')
    builtin = {
        'physical_memory_safety': 'vg.target.builtin_memory',
        'initialized_read_safety': 'vg.target.builtin_initialized',
        'arithmetic_domain_safety': 'vg.target.builtin_arithmetic',
    }.get(kind_name)
    if kind_name == 'state_invariant' and 'violation_w1' not in bindings:
        builtin = 'vg.target.missing_invariant'
    if builtin and 'violation_w1' not in bindings:
        source = re.sub(
            r'__CPROVER_assert\s*\(\s*0\s*,\s*"vg\.target\.violation_w1"\s*\)\s*;',
            f'__CPROVER_assert(1, "{builtin}");',
            source,
        )
    if prototype and unbound:
        source = re.sub(
            r'__CPROVER_assert\s*\(\s*0\s*,\s*"vg\.(?:obligation\.action_continuation_safe|target\.violation_w1|target\.nonvacuity_w0)"\s*\)\s*;',
            '__CPROVER_assert(1, "vg.oracle.unbound");',
            source,
        )
    return source


_LENGTH_ALLOCATORS = {
    'malloc', 'calloc', 'realloc',
    'ngx_palloc', 'ngx_pnalloc', 'ngx_pcalloc',
    'apr_palloc', 'apr_pcalloc',
    '_emalloc', '_safe_emalloc', '_ecalloc',
}
_LENGTH_NAME_TOKENS = {
    'len', 'length', 'size', 'count', 'nmemb', 'nelts', 'nalloc', 'width', 'bytes',
}
_LENGTH_CAST_RE = re.compile(
    r'\(\s*(?P<type>unsigned\s+long\s+long|unsigned\s+long|unsigned\s+int|unsigned|'
    r'size_t|ngx_uint_t|apr_size_t|uint8_t|uint16_t|uint32_t|uint64_t)\s*\)\s*'
    r'(?P<inner>\([^()]*\)|[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)'
)


def _length_expression(expr: str) -> bool:
    tokens = {tok for tok in re.split(r'[^A-Za-z0-9]+', expr.lower()) if tok}
    if tokens & _LENGTH_NAME_TOKENS:
        return True
    return any(tok.endswith(('_len', '_size', '_count', '_nelts')) for tok in tokens)


def _enclosing_callee(source: str, index: int) -> str | None:
    depth = 0
    cursor = index
    while cursor >= 0:
        ch = source[cursor]
        if ch == ')':
            depth += 1
        elif ch == '(':
            if depth == 0:
                end = cursor
                while end > 0 and source[end - 1].isspace():
                    end -= 1
                start = end
                while start > 0 and (source[start - 1].isalnum() or source[start - 1] == '_'):
                    start -= 1
                name = source[start:end]
                return name or None
            depth -= 1
        cursor -= 1
    return None


def _statement_start(source: str, index: int) -> int:
    depth = 0
    cursor = index
    while cursor >= 0:
        ch = source[cursor]
        if ch == ')':
            depth += 1
        elif ch == '(':
            depth = max(0, depth - 1)
        elif depth == 0 and ch in ';{}':
            return cursor + 1
        cursor -= 1
    return 0


def inject_length_truncation_asserts(source: str) -> str:
    inserts: list[tuple[int, str]] = []
    for match in _LENGTH_CAST_RE.finditer(source):
        callee = _enclosing_callee(source, match.start() - 1)
        if callee in (None, '__CPROVER_assert', '__CPROVER_assume'):
            continue
        inner = match.group('inner')
        if callee not in _LENGTH_ALLOCATORS and not _length_expression(inner):
            continue
        origin = _statement_start(source, match.start())
        statement_end = source.find(';', match.end())
        statement = source[origin:statement_end + 1 if statement_end >= 0 else match.end()]
        cast_type = ' '.join(match.group('type').split())
        marker = f'({inner}) == (({cast_type})({inner}))'
        previous_end = origin - 1
        while previous_end >= 0 and source[previous_end].isspace():
            previous_end -= 1
        probe = previous_end - 1 if previous_end >= 0 and source[previous_end] in ';{}' else previous_end
        previous = source[_statement_start(source, probe):previous_end + 1] if probe >= 0 else ''
        if marker in statement or marker in previous:
            continue
        inserts.append((
            origin,
            f'__CPROVER_assert(({inner}) >= 0 && ({inner}) == (({cast_type})({inner})), "vg.target.length_truncation");\n',
        ))
    if not inserts:
        return source
    rewritten = source
    for origin, text in sorted(inserts, key=lambda item: item[0], reverse=True):
        rewritten = rewritten[:origin] + text + rewritten[origin:]
    return rewritten


def arithmetic_query_flags(case_ir: dict[str, Any]) -> list[str]:
    oracle = case_ir.get('safety_oracle') if isinstance(case_ir, dict) else None
    if not isinstance(oracle, dict):
        return []
    if compile_kind_assertions(oracle).get('builtin_target') == 'arithmetic':
        return ['--unsigned-overflow-check']
    return []


def _function_span(source: str, name: str) -> tuple[int, int] | None:
    marker = f'void {name}('
    start = source.find(marker)
    if start < 0:
        return None
    brace = source.find('{', start)
    if brace < 0:
        return None
    depth = 0
    for idx in range(brace, len(source)):
        ch = source[idx]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return start, idx + 1
    return None


def _statement_containing(text: str, token: str) -> tuple[int, int] | None:
    idx = text.find(token)
    if idx < 0:
        return None
    start = max(text.rfind(';', 0, idx), text.rfind('{', 0, idx)) + 1
    end = text.find(';', idx)
    if end < 0:
        return None
    return start, end + 1


def _baseline_observation_text(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        tok = match.group(0)
        if tok.startswith('__'):
            return tok
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*1', tok):
            return tok[:-1] + '0'
        return tok
    return re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\b', repl, text)


def _clone_observation_decl(line: str, name: str) -> str:
    baseline = name[:-1] + '0'
    if re.search(rf'\b{re.escape(baseline)}\b', line):
        return ''
    cloned = re.sub(rf'\b{re.escape(name)}\b', baseline, line)
    if not cloned.endswith('\n'):
        cloned += '\n'
    return cloned


_DEFINED_BASELINE_FLAGS = (
    '__vulgate_missing_callee_hit',
    '__vg_alloc_lifetime_overflow',
    '__vg_alloc_double_free',
    '__vg_brigade_truncated',
    '__vg_bailout_active',
)


def inject_benign_impact_domain(source: str, case_ir: dict[str, Any]) -> str:
    span = _function_span(source, '__vg_impact_harness')
    if span is None:
        return source
    fn = source[span[0]:span[1]]
    call = _statement_containing(fn, '__vg_run_world_0')
    if call is None:
        return source
    lines: list[str] = []
    for flag in _DEFINED_BASELINE_FLAGS:
        if re.search(rf'\b{re.escape(flag)}\b', source) and f'!{flag}' not in fn:
            lines.append(f'__CPROVER_assume(!{flag});')
    violation = ((case_ir.get('safety_oracle') or {}).get('bindings') or {}).get('violation_expr')
    if violation:
        bad = _baseline_observation_text(str(violation))
        blocked_token = '__vulgate_any_blocked' in bad or '__vulgate_action_write_ok' in bad
        names_ready = True
        if not blocked_token:
            for match in re.finditer(r'\b[A-Za-z_][A-Za-z0-9_]*\b', bad):
                prefix = bad[:match.start()]
                if prefix.endswith('.') or prefix.endswith('->'):
                    continue
                if match.group(0) not in fn:
                    names_ready = False
                    break
        if not blocked_token and names_ready and f'__CPROVER_assume(!({bad}));' not in fn:
            lines.append(f'__CPROVER_assume(!({bad}));')
    if not lines:
        return source
    statement = fn[call[0]:call[1]]
    indent = ''
    for line in statement.splitlines():
        if line.strip():
            indent = re.match(r'\s*', line).group(0)
            break
    block = ''.join(f'\n{indent}{line}' for line in lines)
    inserted = fn[:call[1]] + block + fn[call[1]:]
    return source[:span[0]] + inserted + source[span[1]:]


def inject_poc_baseline_nonvacuity(source: str, case_ir: dict[str, Any]) -> str:
    requests = (((case_ir.get('seed_traces') or {}).get('poc_reproducer') or {}).get('requests') or [])
    violation = ((case_ir.get('safety_oracle') or {}).get('bindings') or {}).get('violation_expr')
    if not requests or not violation:
        return source
    span = _function_span(source, '__vg_verify_obligations')
    if span is None:
        return source
    fn = source[span[0]:span[1]]
    if 'vg.target.nonvacuity_w0' in fn:
        return source
    bad = _baseline_observation_text(str(violation))
    if '__vg_run_world_0' in fn:
        call = _statement_containing(fn, '__vg_run_world_0')
        if call is None:
            return source
        indent = re.match(r'\s*', fn[call[0]:call[1]].lstrip('\n')).group(0)
        inserted = fn[:call[1]] + f'\n{indent}__CPROVER_assert(!({bad}), "vg.target.nonvacuity_w0");' + fn[call[1]:]
        return source[:span[0]] + inserted + source[span[1]:]
    call = _statement_containing(fn, '__vg_run_world_1')
    if call is None:
        return source
    statement = fn[call[0]:call[1]]
    indent = ''
    for line in statement.splitlines():
        if line.strip():
            indent = re.match(r'\s*', line).group(0)
            break
    names: list[str] = []
    for tok in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*1)\b', statement):
        if not tok.startswith('__') and tok not in names:
            names.append(tok)
    decls: list[str] = []
    prefix = fn[:call[0]]
    for name in names:
        for line in prefix.splitlines(True):
            if '__vg_run_world_' in line or ';' not in line:
                continue
            if not re.search(rf'\b{re.escape(name)}\b', line):
                continue
            cloned = _clone_observation_decl(line, name)
            if cloned and cloned not in prefix and cloned not in ''.join(decls):
                decls.append(cloned)
    cloned_call = _baseline_observation_text(statement).replace('__vg_run_world_1', '__vg_run_world_0')
    if not cloned_call.endswith('\n'):
        cloned_call += '\n'
    inserted = (
        fn[:call[0]]
        + ''.join(decls)
        + cloned_call
        + f'{indent}__CPROVER_assert(!({bad}), "vg.target.nonvacuity_w0");\n'
        + fn[call[0]:]
    )
    return source[:span[0]] + inserted + source[span[1]:]


def episode_count(case_ir: dict[str, Any]) -> int:
    lifetime = ((case_ir.get('defect_anchors') or {}).get('state_carrier') or {}).get('lifetime', 'call_tree')
    budgets = case_ir.get('budgets') or {}
    count = int(budgets.get('episode_length', 1))
    if lifetime in ('connection', 'worker'):
        count = max(count, 2)
    return count


def _split_depth1_statements(body: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for idx, ch in enumerate(body):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth = max(0, depth - 1)
        elif ch == ';' and depth == 0:
            parts.append(body[start:idx + 1])
            start = idx + 1
    if start < len(body):
        parts.append(body[start:])
    return parts


def _episode_cleanup_name(case_ir: dict[str, Any], source: str) -> str:
    names: list[str] = []
    carrier = ((case_ir.get('defect_anchors') or {}).get('state_carrier') or {}).get('cleanup')
    if isinstance(carrier, str):
        names.append(carrier)
    between = (((case_ir.get('app_profile') or {}).get('lifecycle_hooks') or {}).get('between_requests'))
    if isinstance(between, str):
        names.append(between)
    for name in names:
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name) and re.search(rf'\b{re.escape(name)}\b', source):
            return name
    return ''


def _episode_reset_lines(case_ir: dict[str, Any], source: str, cleanup: str) -> tuple[str, str]:
    hooks = ((case_ir.get('app_profile') or {}).get('lifecycle_hooks') or {})
    mode = str(hooks.get('request_reset') or '')
    lifetime = str(((case_ir.get('defect_anchors') or {}).get('state_carrier') or {}).get('lifetime') or 'call_tree')
    start = ''
    if mode == 'process_restart' and lifetime not in ('connection', 'worker') and '__vg_alloc_reset_process' in source:
        start = '__vg_alloc_reset_process();'
    tail = ''
    if mode == 'request_cleanup_then_snapshot' and cleanup and '__vg_request_live_empty' in source:
        tail = ' __CPROVER_assert(__vg_request_live_empty(), "vg.obligation.request_reset_snapshot");'
    return start, tail


def _wrap_episode_statement(stmt: str, count: int, cleanup: str, start: str = '', tail: str = '',
                            step_blocks: list[str] | None = None) -> str:
    stripped = stmt.strip()
    if '__vg_run_world_' not in stripped or stripped.startswith('for '):
        return stmt
    declared = re.match(
        r'^((?:const\s+)?(?:unsigned\s+|signed\s+)?[A-Za-z_][\w\s\*]*?)\s+([A-Za-z_]\w*)\s*=\s*(__vg_run_world_\w+\s*\(.*\))\s*;$',
        stripped,
        re.S,
    )
    indent = stmt[:len(stmt) - len(stmt.lstrip())]
    reset_line = f'{indent}    {start}\n' if start else ''
    between = f'{indent}    if (__vg_ep != 0U) {{ __vulgate_any_blocked = 0; __vulgate_action_write_ok = 1;{(" " + cleanup + "();") if cleanup else ""}{tail} }}\n'
    step_line = ''
    for index, block in enumerate(step_blocks or []):
        if block:
            step_line += f'{indent}    if (__vg_ep == {index}U) {{ {block} }}\n'
    if declared:
        ctype, name, call = declared.group(1).strip(), declared.group(2), declared.group(3)
        return (
            f'{indent}{ctype} {name} = 0;\n'
            f'{indent}for (unsigned __vg_ep = 0; __vg_ep < {count}U; ++__vg_ep) {{\n'
            f'{indent}    __vulgate_episode = __vg_ep;\n'
            f'{reset_line}{between}{step_line}'
            f'{indent}    {name} = {call};\n'
            f'{indent}}}'
        )
    bare = re.match(r'^(__vg_run_world_\w+\s*\(.*\))\s*;$', stripped, re.S)
    if not bare:
        return stmt
    return (
        f'{indent}for (unsigned __vg_ep = 0; __vg_ep < {count}U; ++__vg_ep) {{\n'
        f'{indent}    __vulgate_episode = __vg_ep;\n'
        f'{reset_line}{between}{step_line}'
        f'{indent}    {bare.group(1)};\n'
        f'{indent}}}'
    )


def _rewrite_function_body(source: str, function_name: str, count: int, cleanup: str,
                           reset_call: str = '', tail: str = '',
                           step_blocks: list[str] | None = None) -> str:
    marker = f'void {function_name}('
    start = source.find(marker)
    if start < 0:
        return source
    brace = source.find('{', start)
    if brace < 0:
        return source
    depth = 0
    end = None
    for idx in range(brace, len(source)):
        if source[idx] == '{':
            depth += 1
        elif source[idx] == '}':
            depth -= 1
            if depth == 0:
                end = idx
                break
    if end is None:
        return source
    body = source[brace + 1:end]
    rewritten = ''.join(
        _wrap_episode_statement(part, count, cleanup, reset_call, tail, step_blocks) for part in _split_depth1_statements(body)
    )
    if rewritten != body and 'vg.obligation.episode_carrier' not in body:
        rewritten += f'\n    __CPROVER_assert(__vulgate_episode + 1U == {count}U, "vg.obligation.episode_carrier");\n'
    return source[:brace + 1] + rewritten + source[end:]


def _carrier_identifiers(case_ir: dict[str, Any]) -> list[str]:
    expr = str(((case_ir.get('defect_anchors') or {}).get('state_carrier') or {}).get('expr') or '')
    names = []
    for token in re.findall(r'[A-Za-z_]\w*', expr):
        if token in ('struct', 'union', 'enum') or token in names:
            continue
        names.append(token)
    if len(names) >= 2 and re.search(r'(?:->|\.)\s*[A-Za-z_]\w*\s*$', expr):
        return names[-1:]
    return names


def _persist_carrier_objects(source: str, names: list[str]) -> str:
    persisted = False
    persisted_slots: list[str] = []
    queue: list[str] = []
    for name in names:
        for candidate in (name, f'{name}_obj', f'{name}_slot'):
            if candidate not in queue:
                queue.append(candidate)
        for match in re.finditer(rf'(?<![\w])([A-Za-z_]\w*_{re.escape(name)}_slot)\b', source):
            candidate = match.group(1)
            if candidate not in queue:
                queue.append(candidate)
    seen: set[str] = set()
    while queue and len(seen) < 16:
        name = queue.pop(0)
        if name in seen or not re.match(r'^[A-Za-z_]\w*$', name):
            continue
        seen.add(name)
        memset_pat = re.compile(
            rf'memset\s*\(\s*&{name}\s*,\s*0\s*,\s*sizeof\s*\(\s*{name}\s*\)\s*\)\s*;'
        )
        if not memset_pat.search(source):
            continue
        source = memset_pat.sub(
            f'if (__vulgate_episode == 0U) memset(&{name}, 0, sizeof({name}));',
            source,
        )
        decl_pat = re.compile(
            rf'(?<!static )(?:(?:struct|union|enum)\s+)?[A-Za-z_]\w*\s+{name}\b'
        )
        source, count = decl_pat.subn(lambda match: 'static ' + match.group(0), source, count=1)
        if count <= 0:
            continue
        persisted = True
        if not name.endswith('_slot'):
            continue
        persisted_slots.append(name)
        for match in re.finditer(
            rf'(?<![\w]){re.escape(name)}\s*(?:(?:\.|->)\s*[A-Za-z_]\w*)+\s*=\s*&([A-Za-z_]\w*)',
            source,
        ):
            child = match.group(1)
            if child not in seen:
                queue.append(child)
    for name in persisted_slots:
        assign_pat = re.compile(
            rf'^(?P<indent>[ \t]*)(?P<stmt>{re.escape(name)}\s*(?:(?:\.|->)\s*[A-Za-z_]\w*)+\s*=\s*[^;]+;)\s*$',
            re.M,
        )
        source = assign_pat.sub(
            lambda match: f'{match.group("indent")}if (__vulgate_episode == 0U) {{ {match.group("stmt")} }}',
            source,
        )
    if persisted and not re.search(r'\bunsigned\s+__vulgate_episode\s*;', source):
        source = 'unsigned __vulgate_episode;\n' + source
    return source


def _episode_step_blocks(source: str, abstract_snapshot: dict[str, Any] | None) -> list[str]:
    steps = (abstract_snapshot or {}).get('episode_step_constants') or []
    if not isinstance(steps, list) or len(steps) < 2:
        return []
    blocks: list[str] = []
    for step in steps:
        lines: list[str] = []
        if isinstance(step, dict):
            for name, value in step.items():
                leaf = str(name).split('.')[-1].replace(':', '_')
                token = leaf if leaf.startswith('__vg_in_') else f'__vg_in_{leaf}'
                if token in source:
                    lines.append(f'__CPROVER_assume({token} == {int(value)}ULL);')
        blocks.append(' '.join(lines))
    if not any(blocks):
        return []
    return blocks


def apply_episode_driver(source: str, case_ir: dict[str, Any],
                         abstract_snapshot: dict[str, Any] | None = None) -> str:
    count = episode_count(case_ir)
    if count < 2 or 'vg_two_request_worker_episode' in source:
        return source
    if not re.search(r'\bunsigned\s+__vulgate_episode\s*;', source):
        source = 'unsigned __vulgate_episode;\n' + source
    source = _persist_carrier_objects(source, _carrier_identifiers(case_ir))
    cleanup = _episode_cleanup_name(case_ir, source)
    start, tail = _episode_reset_lines(case_ir, source, cleanup)
    blocks = _episode_step_blocks(source, abstract_snapshot)
    source = _rewrite_function_body(source, '__vg_verify_obligations', count, cleanup, start, tail, blocks)
    return _rewrite_function_body(source, '__vg_impact_harness', count, cleanup, start, tail, blocks)


def apply_snapshot_seed(source: str, abstract_snapshot: dict[str, Any] | None,
                        defer_episode_steps: bool = False) -> str:
    if not abstract_snapshot:
        return source
    assumes: list[str] = []
    stepped: set[str] = set()
    if defer_episode_steps:
        for step in (abstract_snapshot.get('episode_step_constants') or []):
            if isinstance(step, dict):
                stepped.update(str(name) for name in step)
    for name, value in (abstract_snapshot.get('concrete_constants') or {}).items():
        if str(name) in stepped:
            continue
        leaf = str(name).split('.')[-1].replace(':', '_')
        token = leaf if leaf.startswith('__vg_in_') else f'__vg_in_{leaf}'
        if token in source:
            assumes.append(f'__CPROVER_assume({token} == {int(value)}ULL);')
    for expr in abstract_snapshot.get('pointer_order_constraints') or []:
        tokens = re.findall(r'__vg_in_\w+', expr) if isinstance(expr, str) else []
        if tokens and all(tok in source for tok in tokens):
            assumes.append(f'__CPROVER_assume({expr});')
    if not assumes:
        return source
    block = '\n    ' + '\n    '.join(assumes)
    for function_name in ('__vg_verify_obligations', '__vg_impact_harness'):
        marker = f'void {function_name}('
        start = source.find(marker)
        if start < 0:
            continue
        brace = source.find('{', start)
        if brace < 0:
            continue
        source = source[:brace + 1] + block + source[brace + 1:]
    return source


def inject_allocator_obligations(source: str) -> str:
    needle = '"vg.obligation.action_continuation_safe");'
    if needle not in source:
        return source
    extra = ''
    if '__vg_alloc_double_free' in source and 'vg.obligation.allocator_lifetime' not in source:
        extra += '\n    __CPROVER_assert(!__vg_alloc_double_free, "vg.obligation.allocator_lifetime");'
    if '__vg_brigade_consistent' in source and 'vg.obligation.brigade_ring' not in source:
        extra += '\n    __CPROVER_assert(__vg_brigade_consistent(__vg_brigade_last), "vg.obligation.brigade_ring");'
    if '__vg_alloc_lifetime_overflow' in source and 'vg.obligation.model_bound' not in source:
        bound = '!__vg_alloc_lifetime_overflow'
        if '__vg_brigade_truncated' in source:
            bound += ' && !__vg_brigade_truncated'
        extra += f'\n    __CPROVER_assert({bound}, "vg.obligation.model_bound");'
    if not extra:
        return source
    return source.replace(needle, needle + extra, 1)


_RESOURCE_BALANCE_DEFS = '''
static int __vg_resource_balance;
void __vg_resource_acquire(void) { __vg_resource_balance++; }
void __vg_resource_release(void) {
    if (__vg_resource_balance > 0) __vg_resource_balance--;
    else __vg_resource_balance = -1;
}
'''


def inject_resource_balance(source: str) -> str:
    if 'void __vg_resource_acquire' not in source:
        source = _RESOURCE_BALANCE_DEFS + source
    needle = '"vg.obligation.action_continuation_safe");'
    if needle not in source or 'vg.obligation.resource_release' in source:
        return source
    return source.replace(
        needle,
        needle + '\n    __CPROVER_assert(!__vulgate_any_blocked || __vg_resource_balance == 0, "vg.obligation.resource_release");',
        1,
    )


def inject_missing_callee_assert(source: str) -> str:
    needle = '"vg.obligation.action_continuation_safe");'
    if 'vg.obligation.missing_callee_model' in source or needle not in source:
        return source
    return source.replace(
        needle,
        needle + '\n    __CPROVER_assert(!__vulgate_missing_callee_hit, "vg.obligation.missing_callee_model");',
        1,
    )
