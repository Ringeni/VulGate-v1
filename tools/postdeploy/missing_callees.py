from __future__ import annotations

from pathlib import Path
import re
from typing import Any


LIBC_MODELED = {
    'memset', 'memcpy', 'memmove', 'memcmp', 'malloc', 'calloc', 'realloc', 'free',
    'strlen', 'strcmp', 'strncmp', 'strcpy', 'strncpy', 'strchr', 'memchr',
    'printf', 'fprintf', 'sprintf', 'snprintf', 'abort', 'exit', '__errno_location',
    'memcmp', 'bzero', 'strdup', 'strstr',
}


def _named(node: dict[str, Any], key: str) -> str | None:
    raw = node.get('namedSub', {}).get(key, {})
    if isinstance(raw, dict):
        ident = raw.get('id')
        if ident is not None:
            return str(ident)
    return None


def _tag_name(node: dict[str, Any]) -> str | None:
    ident = _named(node, 'identifier') or ''
    if ident.startswith('tag-'):
        ident = ident[4:]
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', ident):
        return ident
    return None


def c_type(node: dict[str, Any] | None) -> str | None:
    if not isinstance(node, dict):
        return None
    tid = node.get('id')
    if tid in ('empty', 'void', None):
        return 'void'
    if tid in ('bool', 'c_bool'):
        return '_Bool'
    if tid in ('signedbv', 'unsignedbv'):
        width = _named(node, '#width') or _named(node, 'width') or '32'
        try:
            bits = int(width)
        except ValueError:
            return None
        signed = tid == 'signedbv'
        table = {
            8: 'int8_t' if signed else 'uint8_t',
            16: 'int16_t' if signed else 'uint16_t',
            32: 'int32_t' if signed else 'uint32_t',
            64: 'int64_t' if signed else 'uint64_t',
        }
        return table.get(bits)
    if tid == 'pointer':
        subs = node.get('sub') or []
        inner = c_type(subs[0]) if subs else 'void'
        if inner is None:
            return 'void *'
        return f'{inner} *'
    if tid in ('struct_tag', 'union_tag', 'c_enum_tag'):
        ident = _tag_name(node)
        if ident is None:
            return None
        if ident.endswith('_t') or tid == 'c_enum_tag' and ident.endswith('_t'):
            return ident
        if tid == 'union_tag':
            return f'union {ident}'
        if tid == 'c_enum_tag':
            return f'enum {ident}'
        return f'struct {ident}'
    if tid in ('integer', 'natural'):
        return 'int'
    if tid == 'floatbv':
        return 'double'
    return None


def _split_type_list(inner: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, ch in enumerate(inner):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            parts.append(inner[start:index].strip())
            start = index + 1
    tail = inner[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _pretty_signature(name: str, pretty: str) -> tuple[str, list[str]] | None:
    text = pretty.strip()
    if not text or any(ch in text for ch in '#{}'):
        return None
    open_paren = text.find('(')
    if open_paren < 1 or not text.endswith(')'):
        return None
    ret = text[:open_paren].strip()
    if not ret or any(ch in ret for ch in '()'):
        return None
    inner = text[open_paren + 1:-1].strip()
    raw_args = [] if inner in ('', 'void') else _split_type_list(inner)
    type_words = {
        'void', 'int', 'char', 'long', 'short', 'signed', 'unsigned', 'float', 'double',
        'size_t', 'uintptr_t', 'intptr_t', 'ptrdiff_t', 'u_char', 'ngx_uint_t', 'ngx_int_t',
        'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
        '_Bool',
    }
    rendered: list[str] = []
    names: list[str] = []
    for index, arg in enumerate(raw_args):
        if arg == 'void':
            continue
        if arg.strip() == '...':
            rendered.append('...')
            continue
        arg = _structify_unknown_pointer(arg, type_words)
        tokens = arg.split()
        if len(tokens) > 1 and tokens[-1] not in type_words and not tokens[-1].endswith('*') and tokens[-1].isidentifier():
            pname = tokens[-1]
            rendered.append(arg)
        else:
            pname = f'a{index}'
            rendered.append(f'{arg} {pname}')
        names.append(pname)
    ret = _structify_unknown_pointer(ret, type_words)
    return f'{ret} {name}({", ".join(rendered) if rendered else "void"})', [ret, *rendered]


def _structify_unknown_pointer(text: str, known: set[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(2)
        if name in known or name.endswith('_t'):
            return match.group(0)
        return f'{match.group(1)}struct {name} *'

    return re.sub(
        r'(?<!struct )(?<!union )(?<!enum )(^|[\s*])([A-Za-z_][A-Za-z0-9_]*)\s*\*',
        replace,
        text,
    )


READONLY_READS = {
    'ngx_atoi': {'buffers': [(0, 1)], 'scalars': []},
    'ngx_atofp': {'buffers': [(0, 1)], 'scalars': [2]},
    'ngx_hextoi': {'buffers': [(0, 1)], 'scalars': []},
    'ngx_hash_key': {'buffers': [(0, 1)], 'scalars': []},
    'ngx_strncasecmp': {'buffers': [(0, 2), (1, 2)], 'scalars': []},
    'ngx_strncmp': {'buffers': [(0, 2), (1, 2)], 'scalars': []},
    'ngx_strcasecmp': {'buffers': [(0, None), (1, None)], 'scalars': []},
    'ngx_strcmp': {'buffers': [(0, None), (1, None)], 'scalars': []},
    'ngx_strchr': {'buffers': [(0, None)], 'scalars': [1]},
    'ngx_memn2cmp': {'buffers': [(0, 2), (1, 3)], 'scalars': []},
    'ngx_strlchr': {'span': (0, 1), 'scalars': [2]},
    'apr_cstr_casecmp': {'buffers': [(0, None), (1, None)], 'scalars': []},
    'apr_cstr_casecmpn': {'buffers': [(0, 2), (1, 2)], 'scalars': []},
    'apr_strnatcasecmp': {'buffers': [(0, None), (1, None)], 'scalars': []},
    'apr_atoi64': {'buffers': [(0, None)], 'scalars': []},
    'zend_atoi': {'buffers': [(0, 1)], 'scalars': []},
    'zend_atol': {'buffers': [(0, 1)], 'scalars': []},
    'zend_hash_func': {'buffers': [(0, 1)], 'scalars': []},
    'zend_binary_strcasecmp': {'buffers': [(0, 1), (2, 3)], 'scalars': []},
    'zend_binary_strcasecmp_l': {'buffers': [(0, 1), (2, 3)], 'scalars': []},
}


def _param_name(param: str) -> str:
    return param.split()[-1]


def _zero_stmt(ret: str) -> str:
    if ret == 'void':
        return 'return;'
    if '*' in ret or ret == '_Bool':
        return 'return 0;'
    return f'return ({ret})0;'


def _readonly_stub(name: str, signature: str, ret: str, params: list[str]) -> str | None:
    spec = READONLY_READS.get(name)
    if not spec:
        return None
    names = [_param_name(param) for param in params]
    buffers = list(spec.get('buffers') or [])
    span = spec.get('span')
    scalars = list(spec.get('scalars') or [])
    needed = [index for index, _length in buffers] + list(scalars)
    if span:
        needed.extend(span)
    if any(index >= len(params) for index in needed):
        return None
    if any('*' not in params[index] for index, _length in buffers):
        return None
    if span and ('*' not in params[span[0]] or '*' not in params[span[1]]):
        return None
    if any('*' in params[index] for index in scalars):
        return None
    if not buffers and not span:
        return None
    zero = _zero_stmt(ret)
    lines = [f'{signature} {{']
    captures: list[tuple[str, str]] = []
    if span:
        base, last = names[span[0]], names[span[1]]
        lines.append(f'    if (!{base} || !{last} || {last} < {base} || (size_t)({last} - {base}) > 16u) {{ __vulgate_missing_callee_hit = 1; {zero} }}')
        lines.append('    size_t __vg_len0 = (size_t)(%s - %s);' % (last, base))
        lines.append('    uint8_t __vg_cap0[16];')
        for index in range(16):
            lines.append(f'    if (__vg_len0 > {index}u) __vg_cap0[{index}] = ((unsigned char *){base})[{index}];')
        captures.append(('__vg_cap0', '__vg_len0'))
    for slot, (ptr_index, length_index) in enumerate(buffers):
        ptr = names[ptr_index]
        cap = f'__vg_cap{slot}'
        length = f'__vg_len{slot}'
        lines.append(f'    uint8_t {cap}[16];')
        lines.append(f'    size_t {length};')
        if length_index is None:
            lines.append(f'    if (!{ptr}) {{ __vulgate_missing_callee_hit = 1; {zero} }}')
            lines.append(f'    if (((unsigned char *){ptr})[0] == 0) {length} = 0;')
            for index in range(1, 17):
                stores = ' '.join(
                    f'{cap}[{byte}] = ((unsigned char *){ptr})[{byte}];' for byte in range(index)
                )
                lines.append(f'    else if (((unsigned char *){ptr})[{index}] == 0) {{ {stores} {length} = {index}; }}')
            lines.append(f'    else {{ __vulgate_missing_callee_hit = 1; {zero} }}')
        else:
            length_name = names[length_index]
            lines.append(f'    if (!{ptr} || (size_t){length_name} > 16u) {{ __vulgate_missing_callee_hit = 1; {zero} }}')
            lines.append(f'    {length} = (size_t){length_name};')
            for index in range(16):
                lines.append(f'    if ({length} > {index}u) {cap}[{index}] = ((unsigned char *){ptr})[{index}];')
        captures.append((cap, length))
    lines.append('    static int __vg_memo_used[4];')
    if '*' in ret:
        lines.append('    static uint64_t __vg_memo_choice[4];')
    elif ret != 'void':
        lines.append('    static uint64_t __vg_memo_ret[4];')
    for index, (cap, length) in enumerate(captures):
        lines.append(f'    static uint8_t __vg_memo_b{index}[4][16];')
        lines.append(f'    static size_t __vg_memo_n{index}[4];')
    for index in scalars:
        lines.append(f'    static uint64_t __vg_memo_s{index}[4];')
    lines.append('    unsigned __vg_slot;')
    lines.append('    for (__vg_slot = 0; __vg_slot < 4; ++__vg_slot) {')
    lines.append('        int __vg_same = __vg_memo_used[__vg_slot];')
    for index, (cap, length) in enumerate(captures):
        lines.append(f'        if (__vg_same && __vg_memo_n{index}[__vg_slot] != {length}) __vg_same = 0;')
        for byte in range(16):
            lines.append(
                f'        if (__vg_same && {length} > {byte}u && __vg_memo_b{index}[__vg_slot][{byte}] != {cap}[{byte}]) __vg_same = 0;'
            )
    for index in scalars:
        lines.append(f'        if (__vg_same && __vg_memo_s{index}[__vg_slot] != (uint64_t){names[index]}) __vg_same = 0;')
    lines.append('        if (__vg_same) {')
    if ret == 'void':
        lines.append('            return;')
    elif '*' in ret:
        base = names[span[0]] if span else names[buffers[0][0]]
        lines.append('            if (__vg_memo_choice[__vg_slot] & 1u) return 0;')
        lines.append(f'            return ({ret})((unsigned char *){base} + (size_t)(__vg_memo_choice[__vg_slot] >> 1));')
    else:
        lines.append(f'            return ({ret})__vg_memo_ret[__vg_slot];')
    lines.append('        }')
    lines.append('    }')
    lines.append('    for (__vg_slot = 0; __vg_slot < 4; ++__vg_slot) {')
    lines.append('        if (!__vg_memo_used[__vg_slot]) {')
    lines.append('            __vg_memo_used[__vg_slot] = 1;')
    for index, (cap, length) in enumerate(captures):
        lines.append(f'            __vg_memo_n{index}[__vg_slot] = {length};')
        for byte in range(16):
            lines.append(f'            if ({length} > {byte}u) __vg_memo_b{index}[__vg_slot][{byte}] = {cap}[{byte}];')
    for index in scalars:
        lines.append(f'            __vg_memo_s{index}[__vg_slot] = (uint64_t){names[index]};')
    if ret == 'void':
        lines.append('            return;')
    elif '*' in ret:
        length = captures[0][1]
        lines.append('            __vg_memo_choice[__vg_slot] = __vulgate_nondet_u64();')
        lines.append(f'            if ((size_t)(__vg_memo_choice[__vg_slot] >> 1) > {length}) __vg_memo_choice[__vg_slot] = (uint64_t){length} << 1;')
        lines.append('            if (__vg_memo_choice[__vg_slot] & 1u) return 0;')
        base = names[span[0]] if span else names[buffers[0][0]]
        lines.append(f'            return ({ret})((unsigned char *){base} + (size_t)(__vg_memo_choice[__vg_slot] >> 1));')
    else:
        lines.append('            __vg_memo_ret[__vg_slot] = __vulgate_nondet_u64();')
        lines.append(f'            return ({ret})__vg_memo_ret[__vg_slot];')
    lines.append('        }')
    lines.append('    }')
    lines.append(f'    __vulgate_missing_callee_hit = 1; {zero}')
    lines.append('}')
    return '\n'.join(lines)


def _stub_from_signature(signature: str, ret: str, params: list[str]) -> str:
    readonly = _readonly_stub(signature.split('(')[0].split()[-1], signature, ret, params)
    if readonly is not None:
        return readonly
    pointer_params = [item for item in params if '*' in item]
    scalar_params = [item for item in params if item not in pointer_params]
    if pointer_params or len(scalar_params) > 4:
        lines = [f'{signature} {{', '    __vulgate_missing_callee_hit = 1;']
        if ret != 'void':
            if '*' in ret:
                lines.append(f'    return ({ret})0;')
            elif ret == '_Bool':
                lines.append('    return 0;')
            else:
                lines.append(f'    return ({ret})__vulgate_nondet_u64();')
        lines.append('}')
        return '\n'.join(lines)
    names = [item.split()[-1] for item in scalar_params]
    lines = [f'{signature} {{']
    if not names:
        if ret == 'void':
            lines.append('}')
            return '\n'.join(lines)
        lines.extend([
            '    static int __vg_memo_ready;',
            '    static uint64_t __vg_memo_ret;',
            '    if (!__vg_memo_ready) {',
            '        __vg_memo_ready = 1;',
            '        __vg_memo_ret = __vulgate_nondet_u64();',
            '    }',
            f'    return ({ret})__vg_memo_ret;',
            '}',
        ])
        return '\n'.join(lines)
    if ret != 'void':
        lines.append('    static uint64_t __vg_memo_ret[4];')
    lines.append('    static int __vg_memo_used[4];')
    for index in range(len(names)):
        lines.append(f'    static uint64_t __vg_memo_a{index}[4];')
    lines.append('    unsigned __vg_slot;')
    lines.append('    for (__vg_slot = 0; __vg_slot < 4; ++__vg_slot) {')
    compares = ' && '.join(
        f'__vg_memo_a{index}[__vg_slot] == (uint64_t){pname}' for index, pname in enumerate(names)
    )
    lines.append(f'        if (__vg_memo_used[__vg_slot] && {compares}) {{')
    if ret != 'void':
        lines.append(f'            return ({ret})__vg_memo_ret[__vg_slot];')
    else:
        lines.append('            return;')
    lines.append('        }')
    lines.append('    }')
    lines.append('    for (__vg_slot = 0; __vg_slot < 4; ++__vg_slot) {')
    lines.append('        if (!__vg_memo_used[__vg_slot]) {')
    lines.append('            __vg_memo_used[__vg_slot] = 1;')
    for index, pname in enumerate(names):
        lines.append(f'            __vg_memo_a{index}[__vg_slot] = (uint64_t){pname};')
    if ret == 'void':
        lines.append('            return;')
    else:
        lines.append('            __vg_memo_ret[__vg_slot] = __vulgate_nondet_u64();')
        lines.append(f'            return ({ret})__vg_memo_ret[__vg_slot];')
    lines.append('        }')
    lines.append('    }')
    lines.append('    __vulgate_missing_callee_hit = 1;')
    if ret == 'void':
        lines.append('}')
    elif '*' in ret:
        lines.append(f'    return ({ret})0;')
        lines.append('}')
    elif ret == '_Bool':
        lines.append('    return 0;')
        lines.append('}')
    else:
        lines.append(f'    return ({ret})__vulgate_nondet_u64();')
        lines.append('}')
    return '\n'.join(lines)


def render_stub(name: str, symbol: dict[str, Any]) -> str | None:
    pretty = _pretty_signature(name, str(symbol.get('prettyType') or ''))
    if pretty is not None:
        signature, pieces = pretty
        return _stub_from_signature(signature, pieces[0], pieces[1:])
    typ = symbol.get('type') or {}
    if typ.get('id') != 'code':
        return None
    subs = typ.get('sub') or []
    ret = c_type(subs[0] if subs else {'id': 'empty'})
    if ret is None:
        return None
    params_node = typ.get('namedSub', {}).get('parameters', {})
    params = params_node.get('sub') if isinstance(params_node, dict) else None
    if not params:
        params = subs[1:]
    rendered: list[str] = []
    for idx, param in enumerate(params or []):
        ptype = param.get('namedSub', {}).get('type', param) if isinstance(param, dict) else None
        ct = c_type(ptype if isinstance(ptype, dict) else None)
        if ct is None:
            return None
        if ct == 'void':
            continue
        pname = _named(param, '#identifier') or _named(param, 'identifier') or f'a{idx}'
        pname = pname.replace(':', '_').replace('.', '_')
        if not pname.isidentifier():
            pname = f'a{idx}'
        rendered.append(f'{ct} {pname}')
    sig = ', '.join(rendered) if rendered else 'void'
    readonly = _readonly_stub(name, f'{ret} {name}({sig})', ret, rendered)
    if readonly is not None:
        return readonly
    pointer_params = [item for item in rendered if '*' in item]
    scalar_params = [item for item in rendered if item not in pointer_params]
    if pointer_params or len(scalar_params) > 4:
        lines = [f'{ret} {name}({sig}) {{', '    __vulgate_missing_callee_hit = 1;']
        if ret != 'void':
            if ret.endswith('*'):
                lines.append(f'    return ({ret})0;')
            elif ret == '_Bool':
                lines.append('    return 0;')
            else:
                lines.append(f'    return ({ret})__vulgate_nondet_u64();')
        lines.append('}')
        return '\n'.join(lines)
    names = [item.split()[-1] for item in scalar_params]
    lines = [f'{ret} {name}({sig}) {{']
    if not names:
        if ret == 'void':
            lines.append('}')
            return '\n'.join(lines)
        lines.extend([
            '    static int __vg_memo_ready;',
            '    static uint64_t __vg_memo_ret;',
            '    if (!__vg_memo_ready) {',
            '        __vg_memo_ready = 1;',
            '        __vg_memo_ret = __vulgate_nondet_u64();',
            '    }',
            f'    return ({ret})__vg_memo_ret;',
            '}',
        ])
        return '\n'.join(lines)
    if ret != 'void':
        lines.append('    static uint64_t __vg_memo_ret[4];')
    lines.append('    static int __vg_memo_used[4];')
    for index in range(len(names)):
        lines.append(f'    static uint64_t __vg_memo_a{index}[4];')
    lines.append('    unsigned __vg_slot;')
    lines.append('    for (__vg_slot = 0; __vg_slot < 4; ++__vg_slot) {')
    compares = ' && '.join(
        f'__vg_memo_a{index}[__vg_slot] == (uint64_t){pname}' for index, pname in enumerate(names)
    )
    lines.append(f'        if (__vg_memo_used[__vg_slot] && {compares}) {{')
    if ret != 'void':
        lines.append(f'            return ({ret})__vg_memo_ret[__vg_slot];')
    else:
        lines.append('            return;')
    lines.append('        }')
    lines.append('    }')
    lines.append('    for (__vg_slot = 0; __vg_slot < 4; ++__vg_slot) {')
    lines.append('        if (!__vg_memo_used[__vg_slot]) {')
    lines.append('            __vg_memo_used[__vg_slot] = 1;')
    for index, pname in enumerate(names):
        lines.append(f'            __vg_memo_a{index}[__vg_slot] = (uint64_t){pname};')
    if ret == 'void':
        lines.append('            return;')
    else:
        lines.append('            __vg_memo_ret[__vg_slot] = __vulgate_nondet_u64();')
        lines.append(f'            return ({ret})__vg_memo_ret[__vg_slot];')
    lines.append('        }')
    lines.append('    }')
    lines.append('    __vulgate_missing_callee_hit = 1;')
    if ret == 'void':
        lines.append('}')
    elif ret.endswith('*'):
        lines.append(f'    return ({ret})0;')
        lines.append('}')
    elif ret == '_Bool':
        lines.append('    return 0;')
        lines.append('}')
    else:
        lines.append(f'    return ({ret})__vulgate_nondet_u64();')
        lines.append('}')
    return '\n'.join(lines)


def header_lines(driver_path: Path) -> list[str]:
    lines: list[str] = []
    for line in driver_path.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if stripped.startswith('#include') and ('.h' in stripped or stripped.startswith('#include <')):
            lines.append(stripped)
    return lines


def proof_blocked_by_missing_callees(hit: bool, stub_info: dict[str, Any]) -> bool:
    if hit:
        return True
    if stub_info.get('unrendered'):
        return True
    wrote = bool(stub_info.get('path')) and bool(stub_info.get('stubbed'))
    if wrote and not stub_info.get('linked'):
        return True
    return False


def select_stub_callees(functions: list[dict[str, Any]], symbols: dict[str, Any]) -> list[str]:
    from .planner import build_enhanced_icfg

    icfg = build_enhanced_icfg(functions, symbols, [])
    names = sorted({item['callee'] for item in icfg['unresolved_external']})
    chosen: list[str] = []
    fn_by_name = {fn['name']: fn for fn in functions}
    for name in names:
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            continue
        if name in LIBC_MODELED or name.startswith(('__CPROVER_', '__vulgate_', '__builtin')):
            continue
        fn = fn_by_name.get(name)
        if fn and fn.get('isBodyAvailable'):
            continue
        loc = symbols.get(name, {}).get('location', {}).get('file', '')
        if str(loc).startswith('<builtin-library-'):
            continue
        chosen.append(name)
    return chosen


def write_missing_callee_stubs(functions: list[dict[str, Any]],
                               symbols: dict[str, Any],
                               driver_path: Path,
                               output_path: Path,
                               allow: set[str] | None = None) -> dict[str, Any]:
    chosen = select_stub_callees(functions, symbols)
    if allow is not None:
        chosen = [name for name in chosen if name in allow]
    rendered: list[str] = []
    skipped: list[str] = []
    for name in chosen:
        text = render_stub(name, symbols.get(name, {}))
        if text is None:
            skipped.append(name)
            continue
        rendered.append(text)
    if not rendered:
        return {
            'path': None,
            'stubbed': [],
            'unrendered': skipped,
            'candidates': chosen,
        }
    includes = header_lines(driver_path)
    body = [
        *includes,
        'extern _Bool __vulgate_missing_callee_hit;',
        'extern uint64_t __vulgate_nondet_u64(void);',
        '',
        *rendered,
        '',
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text('\n'.join(body), encoding='utf-8')
    return {
        'path': str(output_path),
        'stubbed': [name for name in chosen if name not in skipped],
        'unrendered': skipped,
        'candidates': chosen,
    }
