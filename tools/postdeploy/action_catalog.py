from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_MAX_ACTIONS = 32
_MAX_STEPS = 10000
_SCALARS = {
    'void', 'int', 'char', 'short', 'long', 'float', 'double', 'size_t', 'ssize_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t',
    'int64_t', 'unsigned', 'signed', 'ngx_int_t', 'ngx_uint_t', 'ngx_flag_t',
    'apr_status_t', 'apr_size_t', 'apr_int32_t', 'apr_off_t', 'zend_long',
    'zend_ulong', 'zend_result',
}
_STATUS_FIELDS = {'status', 'rc', 'code', 'http_status'}
_ASSIGN = re.compile(
    r'^(?:(?P<base>[A-Za-z_]\w*)\s*->\s*(?P<field>[A-Za-z_]\w*)'
    r'|\(\s*\*\s*(?P<star>[A-Za-z_]\w*)\s*\)\s*\.\s*(?P<star_field>[A-Za-z_]\w*))'
    r'\s*=\s*(?P<rhs>.+)$'
)


_HEADER_INDEX: dict[str, dict[str, str | None]] = {}
_HEADER_SUFFIXES = {'.h', '.c', '.inc', '.hpp'}


def _mask_comments(source: str) -> str:
    out: list[str] = []
    index = 0
    limit = len(source)
    while index < limit:
        if source.startswith('//', index):
            newline = source.find('\n', index)
            end = limit if newline < 0 else newline
            out.append(' ' * (end - index))
            index = end
            continue
        if source.startswith('/*', index):
            end = source.find('*/', index + 2)
            end = limit if end < 0 else end + 2
            out.append(''.join('\n' if char == '\n' else ' ' for char in source[index:end]))
            index = end
            continue
        if source[index] in '"\'':
            end = _skip_string(source, index)
            out.append(source[index:end])
            index = end
            continue
        out.append(source[index])
        index += 1
    return ''.join(out)


def _header_index(root: str) -> dict[str, str | None]:
    cached = _HEADER_INDEX.get(root)
    if cached is not None:
        return cached
    buckets: dict[str, list[str]] = {}
    base = Path(root)
    if base.is_dir():
        for path in base.rglob('*'):
            if not path.is_file() or path.suffix.lower() not in _HEADER_SUFFIXES:
                continue
            rel = path.relative_to(base).as_posix()
            buckets.setdefault(path.name, []).append(str(path))
            if rel != path.name:
                buckets.setdefault(rel, []).append(str(path))
    indexed = {key: (paths[0] if len(paths) == 1 else None) for key, paths in buckets.items()}
    _HEADER_INDEX[root] = indexed
    return indexed


def _resolve_header(name: str, roots: list[str]) -> str | None:
    found: list[str] = []
    for root in roots:
        path = _header_index(root).get(name)
        if path and path not in found:
            found.append(path)
    if len(found) == 1:
        return found[0]
    return None


def _certain_includes(source: str) -> list[str]:
    from tools.frontier.constants import _active_directives
    names: list[str] = []
    for _index, word, expression, certain in _active_directives(source):
        if word != 'include' or not certain:
            continue
        match = re.search(r'[<"]([^>"]+)[>"]', expression)
        if match and match.group(1) not in names:
            names.append(match.group(1))
    return names


def _follow_header_texts(source: str, roots: list[str], limit: int = 64) -> list[str]:
    texts: list[str] = []
    seen: set[str] = set()
    pending = [source]
    while pending and len(texts) < limit:
        current = pending.pop(0)
        for name in _certain_includes(_mask_comments(current)):
            if len(texts) >= limit:
                break
            path = _resolve_header(name, roots)
            if path is None or path in seen:
                continue
            seen.add(path)
            try:
                text = Path(path).read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            texts.append(_mask_comments(text))
            pending.append(text)
    return texts


def _macro_constants(source: str, roots: list[str] | None) -> dict[str, int]:
    from tools.frontier.constants import integer_macros
    masked = _mask_comments(source)
    texts = [masked]
    if roots and re.search(r'(?m)^[ \t]*#[ \t]*include\b', masked):
        texts.extend(_follow_header_texts(source, [str(root) for root in roots if str(root)]))
    return {str(name): int(value) for name, value in integer_macros(texts).items()}


def extract_error_return_actions(source: str,
                                 function: str,
                                 parameter_names: list[str] | None = None,
                                 struct_types: dict[str, str] | None = None,
                                 macro_roots: list[str] | None = None) -> dict[str, Any]:
    parameters = [str(name) for name in (parameter_names or [])]
    types = {str(key): str(value) for key, value in (struct_types or {}).items()}
    constants = _macro_constants(source, macro_roots)
    body = _function_body(_prepare_source(source), function)
    if body is None:
        return {'function': function, 'found': False, 'truncated': False, 'actions': []}
    actions: list[dict[str, Any]] = []
    seen: set[str] = set()
    truncated = False
    steps = 0
    stack: list[tuple[int, list[tuple[Any, ...]], dict[tuple[str, str], tuple[int, dict[str, Any]]]]] = [
        (0, _parse_block(body), {}),
    ]
    while stack and len(actions) < _MAX_ACTIONS and steps < _MAX_STEPS:
        steps += 1
        index, stmts, writes = stack.pop()
        if index >= len(stmts):
            continue
        kind, payload = stmts[index]
        if kind == 'return':
            classified = _classify_return(str(payload), writes, constants)
            if classified is not None:
                body_action = dict(classified)
                body_action['writes'] = _emit_writes(writes, parameters, types)
                signature = _signature(body_action)
                if signature not in seen:
                    seen.add(signature)
                    safe = re.sub(r'[^A-Za-z0-9_]', '_', function)
                    actions.append({
                        'id': f'SRC_{safe}_{signature[:12]}',
                        'signature': signature,
                        **body_action,
                    })
            continue
        if kind in ('label', 'case'):
            stack.append((index + 1, stmts, writes))
            continue
        if kind == 'stop':
            continue
        if kind == 'block':
            stack.append((0, list(payload) + stmts[index + 1:], writes))
            continue
        if kind == 'if':
            then_stmts, else_stmts = payload
            stack.append((0, list(else_stmts) + stmts[index + 1:], dict(writes)))
            stack.append((0, list(then_stmts) + stmts[index + 1:], dict(writes)))
            continue
        if kind == 'switch':
            after = stmts[index + 1:]
            for group in payload:
                stack.append((0, list(group) + after, dict(writes)))
            continue
        stack.append((index + 1, stmts, _apply_assign(writes, str(payload), constants)))
    if stack and (len(actions) >= _MAX_ACTIONS or steps >= _MAX_STEPS):
        truncated = True
    return {'function': function, 'found': True, 'truncated': truncated, 'actions': actions}


def bind_extracted_action(action: dict[str, Any], field_info) -> dict[str, Any] | None:
    writes: list[dict[str, Any]] = []
    for item in action.get('writes') or []:
        member = item.get('struct_member')
        if not (isinstance(member, (list, tuple)) and len(member) == 2):
            if 'offset' not in item:
                return None
            writes.append(dict(item))
            continue
        try:
            info = field_info(str(member[0]), str(member[1]))
        except (KeyError, OSError, ValueError):
            return None
        if not isinstance(info, dict) or info.get('bit_mask') is not None or 'offset' not in info:
            return None
        catalog_type = _catalog_type(item.get('type'), info)
        if catalog_type is None:
            return None
        bound = dict(item)
        bound['offset'] = int(info['offset'])
        bound['type'] = catalog_type
        if bound.get('symbol_name') and 'symbol_c_name' not in bound:
            bound['symbol_c_name'] = bound['symbol_name']
        writes.append(bound)
    entry: dict[str, Any] = {'kind': action.get('kind'), 'writes': writes}
    if 'value' in action:
        entry['value'] = action['value']
    if action.get('value_symbol'):
        entry['value_symbol'] = action['value_symbol']
    return entry


def install_extracted_actions(actions_catalog: dict[str, dict[str, Any]],
                              extraction: dict[str, Any],
                              field_info) -> list[dict[str, Any]]:
    installed: list[dict[str, Any]] = []
    seen = set(actions_catalog)
    for record in extraction.get('functions') or []:
        if not isinstance(record, dict):
            continue
        for action in record.get('actions') or []:
            if not isinstance(action, dict):
                continue
            if any(same_catalog_action(existing, action) for existing in actions_catalog.values() if isinstance(existing, dict)):
                continue
            bound = bind_extracted_action(action, field_info)
            if bound is None:
                continue
            action_id = str(action.get('id') or '')
            if not action_id or action_id in seen:
                continue
            actions_catalog[action_id] = bound
            seen.add(action_id)
            installed.append({
                'action_id': action_id,
                'function': record.get('function'),
                'writes': len(bound['writes']),
            })
    extraction['installed'] = installed
    return installed


def _catalog_type(extracted: Any, info: dict[str, Any]) -> str | None:
    if info.get('bit_mask') is not None:
        return None
    dwarf_kind = str(info.get('type') or '')
    if dwarf_kind == 'pointer':
        return 'pointer' if extracted in (None, 'pointer') else None
    if extracted == 'pointer':
        return None
    return {4: 'u32', 8: 'u64'}.get(int(info.get('byte_size') or 0))


def attest_catalog(actions_catalog: dict[str, dict[str, Any]],
                   catalog_source: dict[str, Any],
                   source_root: str | None,
                   guards: list[dict[str, Any]]) -> dict[str, Any]:
    report: dict[str, Any] = {'functions': [], 'attested': []}
    seen: set[tuple[str, str]] = set()
    texts: dict[str, str | None] = {}
    for guard in guards:
        function = str(guard.get('function') or '')
        source_file = str(guard.get('source_file') or '')
        key = (function, source_file)
        if not function or key in seen:
            continue
        seen.add(key)
        text = _read_guard_source(source_root, source_file, texts)
        if text is None:
            report['functions'].append({
                'function': function,
                'source': source_file,
                'status': 'source_unavailable',
                'truncated': False,
                'actions': [],
            })
            continue
        parameters = [str(name) for name in (guard.get('parameter_names') or [])]
        struct_types: dict[str, str] = {}
        arg_types = list(guard.get('arg_types') or [])
        for index, name in enumerate(parameters):
            if index >= len(arg_types):
                break
            struct_name = struct_name_from_arg_type(str(arg_types[index]))
            if struct_name:
                struct_types[name] = struct_name
        extracted = extract_error_return_actions(
            text, function, parameters, struct_types,
            [source_root] if source_root else None,
        )
        status = 'extracted' if extracted['found'] else 'function_not_found'
        report['functions'].append({
            'function': function,
            'source': source_file,
            'status': status,
            'truncated': extracted['truncated'],
            'actions': extracted['actions'],
        })
        action_id = guard.get('action_id')
        raw = catalog_source.get(action_id) if action_id else None
        if not action_id or not isinstance(raw, dict) or action_id not in actions_catalog:
            continue
        match = next((item for item in extracted['actions'] if same_catalog_action(raw, item)), None)
        if match is None or 'source_signature' in actions_catalog[action_id]:
            continue
        actions_catalog[action_id]['source_signature'] = match['signature']
        actions_catalog[action_id]['source_function'] = function
        report['attested'].append({
            'action_id': action_id,
            'function': function,
            'signature': match['signature'],
        })
    return report


def same_catalog_action(catalog_action: dict[str, Any], extracted: dict[str, Any]) -> bool:
    if catalog_action.get('kind') != extracted.get('kind'):
        return False
    if catalog_action.get('value') != extracted.get('value'):
        return False
    if (catalog_action.get('value_symbol') or None) != (extracted.get('value_symbol') or None):
        return False
    return _write_keys(catalog_action.get('writes')) == _write_keys(extracted.get('writes'))


def struct_name_from_arg_type(text: str) -> str | None:
    cleaned = text.replace('const', ' ').replace('volatile', ' ').replace('*', ' ')
    parts = cleaned.split()
    if not parts:
        return None
    name = parts[-1]
    if name in _SCALARS:
        return None
    if name.endswith('_t') or '_' in name:
        return name
    return None


def _prepare_source(source: str) -> str:
    return _drop_preprocessor(_strip_comments(source))


def _strip_comments(source: str) -> str:
    out: list[str] = []
    index = 0
    limit = len(source)
    while index < limit:
        if source.startswith('//', index):
            newline = source.find('\n', index)
            index = limit if newline < 0 else newline
            continue
        if source.startswith('/*', index):
            end = source.find('*/', index + 2)
            index = limit if end < 0 else end + 2
            continue
        if source[index] in '"\'':
            end = _skip_string(source, index)
            out.append(source[index:end])
            index = end
            continue
        out.append(source[index])
        index += 1
    return ''.join(out)


def _drop_preprocessor(source: str) -> str:
    kept: list[str] = []
    continued = False
    for line in source.splitlines(keepends=True):
        stripped = line.lstrip()
        if continued or stripped.startswith('#'):
            continued = stripped.rstrip().endswith('\\')
            continue
        kept.append(line)
    return ''.join(kept)


def _function_body(source: str, function: str) -> str | None:
    pattern = re.compile(rf'(?<![\w#]){re.escape(function)}\s*\(')
    for match in pattern.finditer(source):
        close = _matching(source, match.end() - 1, '(', ')')
        cursor = close + 1
        while True:
            cursor = _skip_ws(source, cursor)
            if source.startswith('__attribute__', cursor) or source.startswith('__declspec', cursor):
                cursor = source.find('(', cursor)
                if cursor < 0:
                    cursor = len(source)
                    break
                cursor = _matching(source, cursor, '(', ')') + 1
                continue
            break
        if cursor < len(source) and source[cursor] == '{':
            end = _matching(source, cursor, '{', '}')
            return source[cursor + 1:end]
    return None


def _parse_block(text: str) -> list[tuple[Any, ...]]:
    index = 0
    stmts: list[tuple[Any, ...]] = []
    limit = len(text)
    while index < limit:
        index = _skip_ws(text, index)
        if index >= limit or text[index] == '}':
            break
        previous = index
        stmt, index = _parse_one(text, index)
        if index <= previous:
            index = previous + 1
            continue
        stmts.append(stmt)
    return stmts


def _parse_one(text: str, index: int) -> tuple[tuple[Any, ...], int]:
    index = _skip_ws(text, index)
    if index >= len(text):
        return ('expr', ''), index
    if text[index] == ';':
        return ('expr', ''), index + 1
    if text[index] == '{':
        end = _matching(text, index, '{', '}')
        return ('block', _parse_block(text[index + 1:end])), end + 1
    if _kw(text, index, 'if'):
        header = _skip_ws(text, index + 2)
        if header < len(text) and text[header] == '(':
            close = _matching(text, header, '(', ')')
            then_stmt, index = _parse_one(text, close + 1)
            else_stmts: list[tuple[Any, ...]] = []
            probe = _skip_ws(text, index)
            if _kw(text, probe, 'else'):
                else_stmt, index = _parse_one(text, probe + 4)
                else_stmts = _stmt_list(else_stmt)
            return ('if', (_stmt_list(then_stmt), else_stmts)), index
    if _kw(text, index, 'for') or _kw(text, index, 'while'):
        word = 'for' if _kw(text, index, 'for') else 'while'
        header = _skip_ws(text, index + len(word))
        if header < len(text) and text[header] == '(':
            close = _matching(text, header, '(', ')')
            body, index = _parse_one(text, close + 1)
            return ('if', (_stmt_list(body), [])), index
    if _kw(text, index, 'do'):
        body, index = _parse_one(text, index + 2)
        probe = _skip_ws(text, index)
        if _kw(text, probe, 'while'):
            header = _skip_ws(text, probe + 5)
            if header < len(text) and text[header] == '(':
                close = _matching(text, header, '(', ')')
                index = close + 1
                if index < len(text) and text[index] == ';':
                    index += 1
        return ('block', _stmt_list(body)), index
    if _kw(text, index, 'switch'):
        header = _skip_ws(text, index + 6)
        if header < len(text) and text[header] == '(':
            close = _matching(text, header, '(', ')')
            cursor = _skip_ws(text, close + 1)
            if cursor < len(text) and text[cursor] == '{':
                end = _matching(text, cursor, '{', '}')
                return ('switch', _switch_groups(_parse_block(text[cursor + 1:end]))), end + 1
            stmt, index = _parse_one(text, cursor)
            return ('switch', _switch_groups(_stmt_list(stmt))), index
    if _kw(text, index, 'return'):
        expr, index = _read_until(text, _skip_ws(text, index + 6), {';'})
        if index < len(text) and text[index] == ';':
            index += 1
        return ('return', expr), index
    if _kw(text, index, 'case') or _kw(text, index, 'default'):
        word = 'case' if _kw(text, index, 'case') else 'default'
        cursor = index + len(word)
        if word == 'case':
            _expr, cursor = _read_until(text, cursor, {':'})
        else:
            cursor = _skip_ws(text, cursor)
        if cursor < len(text) and text[cursor] == ':':
            cursor += 1
        return ('case', None), cursor
    if _kw(text, index, 'break') or _kw(text, index, 'continue') or _kw(text, index, 'goto'):
        _expr, index = _read_until(text, index, {';'})
        if index < len(text) and text[index] == ';':
            index += 1
        return ('stop', None), index
    label = re.match(r'[A-Za-z_]\w*\s*:', text[index:])
    if label and not text[index:index + label.end()].rstrip().endswith('::'):
        return ('label', None), index + label.end()
    expr, index = _read_until(text, index, {';'})
    if index < len(text) and text[index] == ';':
        index += 1
    return ('expr', expr), index


def _stmt_list(stmt: tuple[Any, ...]) -> list[tuple[Any, ...]]:
    if stmt[0] == 'block':
        return list(stmt[1])
    return [stmt]


def _switch_groups(stmts: list[tuple[Any, ...]]) -> list[list[tuple[Any, ...]]]:
    groups: list[list[tuple[Any, ...]]] = []
    current: list[tuple[Any, ...]] = []
    saw_case = False
    for stmt in stmts:
        if stmt[0] == 'case':
            saw_case = True
            if current:
                groups.append(current)
            current = []
            continue
        current.append(stmt)
    if current:
        groups.append(current)
    if not saw_case:
        return [stmts]
    return groups


def _apply_assign(writes: dict[tuple[str, str], tuple[int, dict[str, Any]]],
                  statement: str,
                  constants: dict[str, int] | None = None) -> dict[tuple[str, str], tuple[int, dict[str, Any]]]:
    updated = dict(writes)
    match = _ASSIGN.match(statement.strip())
    if match is None:
        return updated
    base = match.group('base') or match.group('star')
    field = match.group('field') or match.group('star_field')
    parsed = _catalog_rhs(match.group('rhs').strip(), constants)
    key = (base, field)
    if parsed is None:
        updated.pop(key, None)
        return updated
    sequence = 1 + max((item[0] for item in updated.values()), default=0)
    updated[key] = (sequence, parsed)
    return updated


def _c_string_literal(text: str) -> str | None:
    if len(text) < 2 or text[0] != '"' or text[-1] != '"':
        return None
    body = text[1:-1]
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == '"':
            return None
        if char != '\\':
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(body):
            return None
        esc = body[index + 1]
        simple = {
            'n': '\n', 'r': '\r', 't': '\t', 'a': '\a', 'b': '\b', 'f': '\f', 'v': '\v',
            '\\': '\\', '"': '"', "'": "'", '?': '?',
        }
        if esc in simple:
            out.append(simple[esc])
            index += 2
            continue
        if esc in '01234567':
            digits = esc
            cursor = index + 2
            while cursor < len(body) and len(digits) < 3 and body[cursor] in '01234567':
                digits += body[cursor]
                cursor += 1
            out.append(chr(int(digits, 8)))
            index = cursor
            continue
        if esc == 'x':
            digits = ''
            cursor = index + 2
            while cursor < len(body) and body[cursor] in '0123456789abcdefABCDEF':
                digits += body[cursor]
                cursor += 1
            if not digits:
                return None
            out.append(chr(int(digits, 16) & 0xFF))
            index = cursor
            continue
        return None
    return ''.join(out)


def pointer_write_literal(write: dict[str, Any]) -> str | None:
    if write.get('null_pointer'):
        return '(void *)0'
    if 'string_value' in write:
        return c_string_pointer(str(write['string_value']))
    return None


def c_string_pointer(value: str) -> str:
    pieces: list[str] = []
    for char in value:
        code = ord(char)
        if char == '\\':
            pieces.append('\\\\')
        elif char == '"':
            pieces.append('\\"')
        elif 32 <= code < 127:
            pieces.append(char)
        else:
            pieces.append(f'\\{code:03o}')
    return '(void *)"' + ''.join(pieces) + '"'


def _c_div(left: int, right: int) -> int | None:
    if right == 0:
        return None
    negative = (left < 0) ^ (right < 0)
    value = abs(left) // abs(right)
    return -value if negative else value


def _c_mod(left: int, right: int) -> int | None:
    quot = _c_div(left, right)
    if quot is None:
        return None
    return left - quot * right


def _c_char_code(body: str) -> int | None:
    if not body or len(body) > 4 and not body.startswith('\\'):
        return None
    if body[0] != '\\':
        if len(body) != 1:
            return None
        return ord(body)
    if len(body) == 1:
        return None
    simple = {
        'n': 10, 'r': 13, 't': 9, 'a': 7, 'b': 8, 'f': 12, 'v': 11,
        '\\': 92, "'": 39, '"': 34, '?': 63, '0': 0,
    }
    if body[1] in simple and len(body) == 2:
        return simple[body[1]]
    if body[1] in '01234567':
        digits = body[1:4]
        if not digits.isdigit() or any(ch > '7' for ch in digits):
            return None
        if len(body) != 1 + len(digits):
            return None
        return int(digits, 8)
    if body[1] in 'xX':
        digits = body[2:]
        if not digits or any(ch not in '0123456789abcdefABCDEF' for ch in digits):
            return None
        return int(digits, 16) & 0xFF
    return None


def _c_const_tokens(text: str) -> list[tuple[str, Any]] | None:
    tokens: list[tuple[str, Any]] = []
    index = 0
    limit = len(text)
    ops = ('<<=', '>>=', '||', '&&', '==', '!=', '<=', '>=', '<<', '>>',
           '+', '-', '*', '/', '%', '&', '|', '^', '!', '~', '?', ':', '(', ')', ',')
    while index < limit:
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "'":
            end = index + 1
            while end < limit:
                if text[end] == '\\':
                    end += 2
                    continue
                if text[end] == "'":
                    break
                end += 1
            if end >= limit or text[end] != "'":
                return None
            code = _c_char_code(text[index + 1:end])
            if code is None:
                return None
            tokens.append(('num', code))
            index = end + 1
            continue
        if char.isdigit():
            start = index
            if text.startswith(('0x', '0X'), index):
                index += 2
                hex_start = index
                while index < limit and text[index] in '0123456789abcdefABCDEF':
                    index += 1
                if index == hex_start:
                    return None
                value = int(text[hex_start:index], 16)
            elif text.startswith(('0b', '0B'), index):
                index += 2
                bin_start = index
                while index < limit and text[index] in '01':
                    index += 1
                if index == bin_start:
                    return None
                value = int(text[bin_start:index], 2)
            elif char == '0' and index + 1 < limit and text[index + 1].isdigit():
                if text[index + 1] in '89':
                    return None
                index += 1
                while index < limit and text[index] in '01234567':
                    index += 1
                if index < limit and text[index].isdigit():
                    return None
                value = int(text[start:index], 8)
            else:
                index += 1
                while index < limit and text[index].isdigit():
                    index += 1
                value = int(text[start:index], 10)
            while index < limit and text[index] in 'uUlL':
                index += 1
            if index < limit and (text[index].isalnum() or text[index] == '_'):
                return None
            tokens.append(('num', value))
            continue
        if char.isalpha() or char == '_':
            end = index + 1
            while end < limit and (text[end].isalnum() or text[end] == '_'):
                end += 1
            tokens.append(('ident', text[index:end]))
            index = end
            continue
        if text.startswith(('++', '--'), index):
            return None
        matched = next((op for op in ops if text.startswith(op, index)), None)
        if matched is None or matched in {'<<=', '>>='}:
            return None
        tokens.append(('op', matched))
        index += len(matched)
        continue
    return tokens


class _CConstParser:
    def __init__(self, tokens: list[tuple[str, Any]], constants: dict[str, int]):
        self.tokens = tokens
        self.constants = constants
        self.index = 0

    def peek(self) -> tuple[str, Any] | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def eat_op(self, value: str) -> bool:
        tok = self.peek()
        if tok is None or tok != ('op', value):
            return False
        self.index += 1
        return True

    def parse(self) -> int | None:
        value = self._comma()
        if value is None or self.peek() is not None:
            return None
        return value

    def _comma(self) -> int | None:
        value = self._ternary()
        while self.eat_op(','):
            right = self._ternary()
            if value is None or right is None:
                return None
            value = right
        return value

    def _ternary(self) -> int | None:
        value = self._lor()
        if not self.eat_op('?'):
            return value
        yes = self._comma()
        if not self.eat_op(':'):
            return None
        no = self._ternary()
        if value is None or yes is None or no is None:
            return None
        return yes if value else no

    def _lor(self) -> int | None:
        return self._logic('||', self._land)

    def _land(self) -> int | None:
        return self._logic('&&', self._bor)

    def _logic(self, op: str, lower) -> int | None:
        value = lower()
        while self.eat_op(op):
            right = lower()
            if value is None or right is None:
                return None
            value = 1 if (value or right if op == '||' else value and right) else 0
        return value

    def _bor(self) -> int | None:
        return self._bitwise('|', self._bxor)

    def _bxor(self) -> int | None:
        return self._bitwise('^', self._band)

    def _band(self) -> int | None:
        return self._bitwise('&', self._eq)

    def _bitwise(self, op: str, lower) -> int | None:
        value = lower()
        while self.eat_op(op):
            right = lower()
            if value is None or right is None:
                return None
            if op == '|':
                value |= right
            elif op == '^':
                value ^= right
            else:
                value &= right
        return value

    def _eq(self) -> int | None:
        value = self._rel()
        while True:
            if self.eat_op('=='):
                right = self._rel()
                if value is None or right is None:
                    return None
                value = 1 if value == right else 0
                continue
            if self.eat_op('!='):
                right = self._rel()
                if value is None or right is None:
                    return None
                value = 1 if value != right else 0
                continue
            return value

    def _rel(self) -> int | None:
        value = self._shift()
        ops = {'<': lambda a, b: a < b, '<=': lambda a, b: a <= b,
               '>': lambda a, b: a > b, '>=': lambda a, b: a >= b}
        while True:
            tok = self.peek()
            if tok is None or tok[0] != 'op' or tok[1] not in ops:
                return value
            self.index += 1
            right = self._shift()
            if value is None or right is None:
                return None
            value = 1 if ops[tok[1]](value, right) else 0

    def _shift(self) -> int | None:
        value = self._add()
        while True:
            op = '<<' if self.eat_op('<<') else '>>' if self.eat_op('>>') else ''
            if not op:
                return value
            right = self._add()
            if value is None or right is None or right < 0 or right >= 64:
                return None
            value = value << right if op == '<<' else value >> right

    def _add(self) -> int | None:
        value = self._mul()
        while True:
            op = '+' if self.eat_op('+') else '-' if self.eat_op('-') else ''
            if not op:
                return value
            right = self._mul()
            if value is None or right is None:
                return None
            value = value + right if op == '+' else value - right

    def _mul(self) -> int | None:
        value = self._unary()
        while True:
            if self.eat_op('*'):
                right = self._unary()
                if value is None or right is None:
                    return None
                value *= right
                continue
            if self.eat_op('/'):
                right = self._unary()
                if value is None or right is None:
                    return None
                value = _c_div(value, right)
                if value is None:
                    return None
                continue
            if self.eat_op('%'):
                right = self._unary()
                if value is None or right is None:
                    return None
                value = _c_mod(value, right)
                if value is None:
                    return None
                continue
            return value

    def _unary(self) -> int | None:
        tok = self.peek()
        if tok is not None and tok[0] == 'op' and tok[1] in {'+', '-', '~', '!'}:
            self.index += 1
            value = self._unary()
            if value is None:
                return None
            if tok[1] == '+':
                return value
            if tok[1] == '-':
                return -value
            if tok[1] == '~':
                return ~value
            return 0 if value else 1
        return self._primary()

    def _primary(self) -> int | None:
        tok = self.peek()
        if tok is None:
            return None
        if tok[0] == 'num':
            self.index += 1
            return int(tok[1])
        if tok[0] == 'ident':
            self.index += 1
            if tok[1] not in self.constants:
                return None
            return int(self.constants[tok[1]])
        if not self.eat_op('('):
            return None
        value = self._comma()
        if not self.eat_op(')'):
            return None
        return value


def _c_integer_constant(text: str, constants: dict[str, int] | None = None) -> int | None:
    tokens = _c_const_tokens(text.strip())
    if not tokens:
        return None
    return _CConstParser(tokens, constants or {}).parse()


def _catalog_rhs(rhs: str, constants: dict[str, int] | None = None) -> dict[str, Any] | None:
    text = _unwrap_grouping(_strip_casts(rhs.strip()))
    address = re.fullmatch(r'&\s*([A-Za-z_]\w*)', text)
    if address:
        return {'type': 'pointer', 'symbol_name': address.group(1)}
    number = re.fullmatch(r'(-?\d+)[uUlL]*', text)
    if number:
        return {'type': 'u64', 'value': int(number.group(1))}
    decoded = _concatenated_string(text)
    if decoded is not None:
        return {'type': 'pointer', 'string_value': decoded}
    if text in ('NULL', 'nullptr', 'nil'):
        return {'type': 'pointer', 'null_pointer': True}
    ident = re.fullmatch(r'[A-Za-z_]\w*', text)
    if ident and constants and ident.group(0) in constants:
        return {'type': 'u64', 'value': int(constants[ident.group(0)])}
    value = _c_integer_constant(text, constants)
    if value is not None:
        return {'type': 'u64', 'value': value}
    return None


def _unwrap_grouping(text: str) -> str:
    current = text.strip()
    while current.startswith('('):
        close = _matching(current, 0, '(', ')')
        if close < 0 or close != len(current) - 1:
            break
        current = current[1:-1].strip()
    return current


def _concatenated_string(text: str) -> str | None:
    index = 0
    limit = len(text)
    parts: list[str] = []
    while True:
        while index < limit and text[index].isspace():
            index += 1
        if index >= limit:
            break
        if text[index] != '"':
            return None
        end = index + 1
        while end < limit:
            if text[end] == '\\':
                end += 2 if end + 1 < limit else end + 1
                continue
            if text[end] == '"':
                end += 1
                break
            end += 1
        else:
            return None
        decoded = _c_string_literal(text[index:end])
        if decoded is None:
            return None
        parts.append(decoded)
        index = end
    if not parts:
        return None
    return ''.join(parts)


def _classify_return(expr: str,
                     writes: dict[tuple[str, str], tuple[int, dict[str, Any]]],
                     constants: dict[str, int] | None = None) -> dict[str, Any] | None:
    text = _unwrap_grouping(_strip_casts(expr.strip()).strip())
    if text in ('', 'void'):
        if _error_status(writes):
            return {'kind': 'return_void'}
        return None
    if text in ('NULL', 'nullptr', 'nil'):
        return {'kind': 'return_null'}
    decoded = _concatenated_string(text)
    if decoded is not None:
        if decoded == '':
            return {'kind': 'return_string', 'value': ''}
        return None
    number = re.fullmatch(r'(-?\d+)[uUlL]*', text)
    if number:
        value = int(number.group(1))
        if value < 0 or value >= 400:
            return {'kind': 'return_int', 'value': value}
        return None
    if re.fullmatch(r'[A-Za-z_]\w*', text):
        resolved = int(constants[text]) if constants and text in constants else None
        named_error = re.search(r'ERROR|FAIL|DECLINED', text) is not None
        numeric_error = resolved is not None and (resolved < 0 or resolved >= 400)
        if not named_error and not numeric_error:
            return None
        action: dict[str, Any] = {'kind': 'return_int', 'value_symbol': text}
        if numeric_error:
            action['value'] = resolved
        return action
    resolved_expr = _c_integer_constant(text, constants)
    if resolved_expr is not None and (resolved_expr < 0 or resolved_expr >= 400):
        return {'kind': 'return_int', 'value': resolved_expr}
    return None


def _error_status(writes: dict[tuple[str, str], tuple[int, dict[str, Any]]]) -> bool:
    for (_base, field), (_sequence, spec) in writes.items():
        value = spec.get('value')
        if field in _STATUS_FIELDS and isinstance(value, int) and (value < 0 or value >= 400):
            return True
    return False


def _emit_writes(writes: dict[tuple[str, str], tuple[int, dict[str, Any]]],
                 parameters: list[str],
                 struct_types: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for (base, field), (_sequence, spec) in sorted(writes.items(), key=lambda item: item[1][0]):
        row = dict(spec)
        if base in parameters:
            row['arg'] = parameters.index(base)
            struct_name = struct_types.get(base)
            if struct_name:
                row['struct_member'] = [struct_name, field]
            else:
                row['base'] = base
                row['field'] = field
        else:
            row['base'] = base
            row['field'] = field
        rows.append(row)
    return rows


def _signature(action: dict[str, Any]) -> str:
    payload = {
        'kind': action.get('kind'),
        'value': action.get('value'),
        'value_symbol': action.get('value_symbol'),
        'writes': action.get('writes') or [],
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _write_keys(writes: Any) -> tuple[tuple[Any, ...], ...]:
    keys: list[tuple[Any, ...]] = []
    for item in writes or []:
        member = item.get('struct_member')
        if isinstance(member, (list, tuple)) and len(member) == 2:
            struct_name, field = member[0], member[1]
        else:
            struct_name, field = None, item.get('field')
        keys.append((
            item.get('arg'),
            struct_name,
            field,
            item.get('type'),
            item.get('value'),
            item.get('symbol_name'),
            item.get('string_value'),
            item.get('null_pointer'),
        ))
    return tuple(sorted(keys, key=lambda item: tuple('' if part is None else str(part) for part in item)))


def _read_guard_source(source_root: str | None,
                       source_file: str,
                       cache: dict[str, str | None]) -> str | None:
    if not source_root or not source_file:
        return None
    root = Path(source_root).resolve()
    path = (root / source_file).resolve()
    key = str(path)
    if key in cache:
        return cache[key]
    if not path.is_file() or root not in path.parents:
        cache[key] = None
        return None
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = None
    cache[key] = text
    return text


def _strip_casts(text: str) -> str:
    current = text.strip()
    while current.startswith('('):
        close = _matching(current, 0, '(', ')')
        inner = current[1:close].strip()
        rest = current[close + 1:].strip()
        if rest and _is_type_text(inner):
            current = rest
            continue
        break
    return current


def _is_type_text(text: str) -> bool:
    if any(token in text for token in ('+', '-', '=', ';', '{', '}', '?', ':')):
        return False
    parts = [part for part in text.replace('*', ' ').split() if part]
    return bool(parts) and all(re.fullmatch(r'[A-Za-z_]\w*', part) for part in parts)


def _kw(text: str, index: int, word: str) -> bool:
    if index < 0 or not text.startswith(word, index):
        return False
    before = text[index - 1] if index else ' '
    after_index = index + len(word)
    after = text[after_index] if after_index < len(text) else ' '
    if before == '#':
        return False
    ident = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'
    return before not in ident and after not in ident


def _skip_ws(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _skip_string(text: str, index: int) -> int:
    quote = text[index]
    index += 1
    while index < len(text):
        if text[index] == '\\':
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return index


def _matching(text: str, index: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    while index < len(text):
        if text[index] in '"\'':
            index = _skip_string(text, index)
            continue
        if text[index] == open_ch:
            depth += 1
        elif text[index] == close_ch:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return max(len(text) - 1, 0)


def _read_until(text: str, index: int, terminators: set[str]) -> tuple[str, int]:
    start = index
    paren = bracket = brace = 0
    while index < len(text):
        char = text[index]
        if char in '"\'':
            index = _skip_string(text, index)
            continue
        if char == '(':
            paren += 1
        elif char == ')':
            paren = max(0, paren - 1)
        elif char == '[':
            bracket += 1
        elif char == ']':
            bracket = max(0, bracket - 1)
        elif char == '{':
            brace += 1
        elif char == '}':
            if paren == 0 and bracket == 0 and brace == 0:
                return text[start:index].strip(), index
            brace = max(0, brace - 1)
        elif char in terminators and paren == bracket == brace == 0:
            return text[start:index].strip(), index
        index += 1
    return text[start:].strip(), index
