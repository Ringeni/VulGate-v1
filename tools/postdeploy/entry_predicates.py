from tools.verification.discovery import DiscoveryOptions, constant_value, translate, walk
from tools.verification.entry_context import entry_conditions
from tools.verification.shadow import symbol_name

from .expressions import parse

_COMPARE = ('=', 'notequal', '<', '<=', '>', '>=', 'and', 'or', 'not')
_BINARY = ('==', '!=', '<', '<=', '>', '>=', '+', '-', '*', '&', '|', '^', '<<', '>>')


def collect_entry_predicates(functions, symbols, cut_names, guards, input_names, field_map):
    inputs = set(input_names)
    admitted = []
    unmapped = 0
    flow_omitted = []
    entries = []
    for name in list(cut_names) + [guard.get('function') for guard in guards]:
        if name and name not in entries:
            entries.append(name)
    options = DiscoveryOptions(flow_steps=4096, call_depth=4)
    for entry in entries:
        prepared = _prepare(entry, functions, symbols)
        if prepared is None:
            continue
        _fn, local_symbols, bindings = prepared
        name_map = _name_map(entry, guards, inputs, field_map or {})
        conditions, omitted = entry_conditions(
            entry, functions, local_symbols, bindings, options, '__vg_verify_obligations',
        )
        for item in omitted:
            reason = item.get('reason')
            if reason and reason not in flow_omitted and len(flow_omitted) < 8:
                flow_omitted.append(reason)
        for condition in conditions:
            for expression in walk(condition['expression']):
                if expression.get('id') not in _COMPARE:
                    continue
                translated = translate(expression, bindings, local_symbols)
                if translated is None:
                    unmapped += 1
                    continue
                text = _input_text(translated[0], name_map, inputs)
                if text is None:
                    unmapped += 1
                    continue
                try:
                    parse(text, inputs)
                except ValueError:
                    unmapped += 1
                    continue
                if text not in admitted:
                    admitted.append(text)
    return {
        'admitted': admitted,
        'omitted_unmapped': unmapped,
        'flow_omitted': flow_omitted,
        'caller_return_conditions': caller_return_conditions(
            functions, symbols, guards, inputs, field_map,
        ),
    }


def _prepare(name, functions, symbols):
    function = next((item for item in functions if item.get('name') == name and item.get('isBodyAvailable')), None)
    if function is None:
        return None
    local = dict(symbols)
    bindings = {}
    for ident, base, value_type in _parameters(function, symbols):
        local.setdefault(ident, {'type': value_type, 'baseName': base})
        bindings[ident] = base
    return function, local, bindings


def _parameters(function, symbols):
    idents = list(function.get('parameterIdentifiers') or [])
    found = None
    for value in symbols.values():
        if value.get('baseName') != function.get('name') or value.get('type', {}).get('id') != 'code':
            continue
        subs = value.get('type', {}).get('namedSub', {}).get('parameters', {}).get('sub') or []
        got = [item.get('namedSub', {}).get('#identifier', {}).get('id') for item in subs]
        if idents and got == idents:
            found = subs
            break
        if found is None:
            found = subs
    if found:
        rows = []
        for item in found:
            named = item.get('namedSub', {})
            ident = named.get('#identifier', {}).get('id')
            base = named.get('#base_name', {}).get('id')
            if ident and base:
                rows.append((ident, base, named.get('type') or {'id': 'signedbv', 'namedSub': {'width': {'id': '64'}}}))
        if rows:
            return rows
    signed = {'id': 'signedbv', 'namedSub': {'width': {'id': '64'}}}
    return [(ident, ident.split('::')[-1], signed) for ident in idents]


def _name_map(entry, guards, inputs, field_map):
    mapping = {}
    for guard in guards:
        if guard.get('function') != entry:
            continue
        names = list(guard.get('parameter_names') or [])
        for sel_name, spec in (guard.get('selectors') or {}).items():
            if not isinstance(spec, dict) or 'arg' not in spec:
                continue
            index = int(spec['arg'])
            if not 0 <= index < len(names):
                continue
            text = field_map.get(sel_name)
            if text is None and sel_name in inputs:
                text = sel_name
            if isinstance(text, str):
                mapping[names[index]] = text
    for key, value in field_map.items():
        if isinstance(value, str):
            mapping.setdefault(key, value)
    for name in inputs:
        mapping.setdefault(name, name)
    return mapping


def _input_text(expr, name_map, inputs):
    if set(expr) == {'const'}:
        value = expr['const']
        if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
            return None
        return str(int(value))
    if set(expr) == {'var'}:
        name = expr['var']
        if name in inputs:
            return name
        mapped = name_map.get(name)
        if not isinstance(mapped, str):
            return None
        try:
            parse(mapped, inputs)
        except ValueError:
            return None
        return f'({mapped})'
    if set(expr) == {'base', 'field', 'pointer'} and set(expr.get('base', {})) == {'var'}:
        base = expr['base']['var']
        field = expr['field']
        for key in (f'{base}.{field}', f'{base}->{field}', field):
            if key in inputs:
                return key
            mapped = name_map.get(key)
            if isinstance(mapped, str):
                try:
                    parse(mapped, inputs)
                except ValueError:
                    return None
                return f'({mapped})'
        return None
    if set(expr) == {'op', 'args'}:
        parts = [_input_text(arg, name_map, inputs) for arg in expr.get('args', [])]
        if any(part is None for part in parts):
            return None
        op = expr.get('op')
        if len(parts) == 1 and op == '!':
            return f'(not {parts[0]})'
        if len(parts) == 2 and op == '&&':
            return f'({parts[0]} and {parts[1]})'
        if len(parts) == 2 and op == '||':
            return f'({parts[0]} or {parts[1]})'
        if len(parts) == 2 and op in _BINARY:
            return f'({parts[0]} {op} {parts[1]})'
    return None


_RETURN_OPS = {
    '=': '==',
    'notequal': '!=',
    '<': '<',
    '<=': '<=',
    '>': '>',
    '>=': '>=',
}
_SWAP_OPS = {'==': '==', '!=': '!=', '<': '>', '<=': '>=', '>': '<', '>=': '<='}


def _mentions_symbol(expr, name: str) -> bool:
    return any(
        node.get('id') == 'symbol' and symbol_name(node) == name
        for node in walk(expr or {})
    )


def _condition_atoms(expr):
    kind = (expr or {}).get('id')
    if kind in ('and', 'or', 'not'):
        rows = []
        for sub in expr.get('sub') or []:
            rows.extend(_condition_atoms(sub))
        return rows
    if kind in _RETURN_OPS:
        return [expr]
    return []


def _return_comparison(expr, ret: str):
    subs = expr.get('sub') or []
    if len(subs) != 2 or not _mentions_symbol(expr, ret):
        return None
    op = _RETURN_OPS.get(expr.get('id'))
    if op is None:
        return None
    left = _mentions_symbol(subs[0], ret)
    right = _mentions_symbol(subs[1], ret)
    if left and not right:
        value = constant_value(subs[1])
    elif right and not left:
        value = constant_value(subs[0])
        op = _SWAP_OPS[op]
    else:
        return None
    if type(value) is not int:
        return None
    return {'op': op, 'value': int(value)}


def _caller_name_map(bindings, inputs, field_map):
    mapping = {}
    inputs = set(inputs or [])
    field_map = field_map or {}
    for base in bindings.values():
        if base in inputs:
            mapping[base] = base
        mapped = field_map.get(base)
        if isinstance(mapped, str):
            mapping[base] = mapped
    for key, value in field_map.items():
        if isinstance(value, str):
            mapping.setdefault(key, value)
    for name in inputs:
        mapping.setdefault(name, name)
    return mapping


def caller_return_conditions(functions, symbols, guards, input_names, field_map):
    names = {guard.get('function') for guard in guards if guard.get('function')}
    inputs = set(input_names or [])
    found = []
    for function in functions:
        if not function.get('isBodyAvailable'):
            continue
        instructions = function.get('instructions') or []
        prepared = _prepare(function.get('name'), functions, symbols or {})
        bindings = prepared[2] if prepared else {}
        local_symbols = prepared[1] if prepared else (symbols or {})
        name_map = _caller_name_map(bindings, inputs, field_map)
        for index, instruction in enumerate(instructions):
            if instruction.get('instructionId') != 'FUNCTION_CALL':
                continue
            code = instruction.get('code', {}).get('sub', [])
            if len(code) < 2 or code[1].get('id') != 'symbol':
                continue
            callee = symbol_name(code[1])
            base = callee.split('::')[-1]
            if callee not in names and base not in names:
                continue
            if not code or code[0].get('id') != 'symbol':
                continue
            ret = symbol_name(code[0])
            matched = None
            for later in instructions[index + 1:]:
                if later.get('instructionId') not in ('GOTO', 'ASSERT', 'ASSUME'):
                    continue
                if _mentions_symbol(later.get('guard', {}), ret):
                    matched = later
                    break
            if matched is None:
                continue
            comparison = None
            predicates: list[str] = []
            for atom in _condition_atoms(matched.get('guard', {})):
                if _mentions_symbol(atom, ret):
                    if comparison is None:
                        comparison = _return_comparison(atom, ret)
                    continue
                translated = translate(atom, bindings, local_symbols)
                if translated is None:
                    continue
                text = _input_text(translated[0], name_map, inputs)
                if text is None:
                    continue
                try:
                    parse(text, inputs)
                except ValueError:
                    continue
                if text not in predicates:
                    predicates.append(text)
            row = {
                'caller': function.get('name'),
                'guard': base,
                'admitted': False,
                'reason': 'guard return is not a symbolic input',
                'input_predicates': predicates,
            }
            if comparison is not None:
                row['comparison'] = comparison
            found.append(row)
    return found
