"""Lossless typed export transport and a whole-model import/export gate.

Display locations are projections. They are never used to repair missing raw
locations. Legacy exports require an explicit mode and remain unqualified for
comments/raw-location preservation.
"""
from copy import deepcopy
import hashlib
import json
import math

from .spec import SpecificationError


FULL = 'full'
LEGACY = 'legacy'
FUNCTION_CAPABILITIES = {'irepCommentsIncluded': True, 'sourceLocationIrepIncluded': True}
SYMBOL_CAPABILITIES = {'irepCommentsIncluded': True, 'symbolLocationIrepIncluded': True}
CAPABILITY_KEYS = set(FUNCTION_CAPABILITIES) | set(SYMBOL_CAPABILITIES)
LOCATION_NAMES = {
    'working_directory': 'workingDirectory', 'file': 'file', 'line': 'line',
    'column': 'column', 'function': 'function', 'java_bytecode_index': 'bytecodeIndex',
    'property_id': 'propertyId', 'property_class': 'propertyClass', 'comment': 'comment',
    'switch_case_number': 'caseNumber',
}
BOOLEAN_NAMES = {'property_fatal': 'propertyFatal', 'hide': 'hide'}
SYMBOL_IDENTITIES = ('prettyName', 'name', 'baseName', 'mode', 'module')
SYMBOL_FLAGS = (
    'isType', 'isMacro', 'isExported', 'isInput', 'isOutput', 'isStateVar',
    'isProperty', 'isStaticLifetime', 'isThreadLocal', 'isLvalue', 'isFileLocal',
    'isExtern', 'isVolatile', 'isParameter', 'isAuxiliary', 'isWeak',
)


class TransportError(SpecificationError):
    pass


def check_mode(mode):
    if mode not in (FULL, LEGACY):
        raise TransportError('unsupported typed transport mode: ' + str(mode))


def strict_loads(text):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TransportError('duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid_constant(value):
        raise TransportError('nonfinite JSON constant: ' + value)

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise TransportError('nonfinite JSON number: ' + value)
        return result

    return json.loads(text, object_pairs_hook=object_pairs, parse_constant=invalid_constant,
                      parse_float=finite_float)


def canonical(value):
    # JSON distinguishes booleans from numbers, unlike Python ==.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def validate_irep(value):
    pending = [value]
    while pending:
        node = pending.pop()
        if (not isinstance(node, dict) or not isinstance(node.get('id'), str)
                or set(node) - {'id', 'sub', 'namedSub'}):
            raise TransportError('invalid typed IREP')
        if 'sub' in node:
            if not isinstance(node['sub'], list) or not node['sub']:
                raise TransportError('noncanonical IREP operands')
            pending.extend(node['sub'])
        if 'namedSub' in node:
            if (not isinstance(node['namedSub'], dict) or not node['namedSub']
                    or any(not isinstance(key, str) for key in node['namedSub'])):
                raise TransportError('noncanonical IREP named members')
            pending.extend(node['namedSub'].values())


def location_view(raw):
    """Projection in the pinned json(source_locationt), including nil symbols."""
    fields = raw.get('namedSub', {})
    view = {target: fields[source]['id'] for source, target in LOCATION_NAMES.items()
            if source in fields and fields[source]['id']}
    view.update({target: True for source, target in BOOLEAN_NAMES.items()
                 if fields.get(source, {}).get('id') == '1'})
    block = fields.get('basic_block_source_lines')
    if block is not None and block['id'] != 'nil':
        view['basicBlockSourceLines'] = deepcopy(block)
    pragmas = fields.get('pragma', {}).get('namedSub', {})
    if pragmas:
        view['pragma'] = sorted(pragmas)
    return view


def display_location(value):
    if not isinstance(value, dict):
        raise TransportError('display location is not an object')
    result = deepcopy(value)
    if 'pragma' in result:
        entries = result['pragma']
        if (not isinstance(entries, list) or any(not isinstance(entry, str) for entry in entries)
                or len(set(entries)) != len(entries)):
            raise TransportError('invalid display pragmas')
        result['pragma'] = sorted(entries)
    return result


def location_keys(kind):
    if kind == 'instruction':
        return 'sourceLocation', 'sourceLocationIrep'
    if kind == 'symbol':
        return 'location', 'locationIrep'
    raise TransportError('unknown location owner kind: ' + str(kind))


def validate_location(owner, *, kind, mode):
    check_mode(mode)
    display_key, raw_key = location_keys(kind)
    if mode == LEGACY:
        if raw_key in owner:
            raise TransportError('legacy mode cannot accept raw locations')
        if display_key in owner:
            display_location(owner[display_key])
        return
    if raw_key not in owner:
        raise TransportError('missing full raw location: ' + raw_key)
    raw = owner[raw_key]
    validate_irep(raw)
    if kind == 'instruction' and raw['id'] == 'nil':
        if display_key in owner:
            raise TransportError('nil instruction location has a display location')
    elif display_key not in owner or canonical(display_location(owner[display_key])) != canonical(location_view(raw)):
        raise TransportError('raw/display location disagreement: ' + display_key)


def copy_location(target, donor, *, mode, donor_kind='instruction', target_kind='instruction',
                  updates=None, remove=(), create_from_nil=False):
    """Replace from an explicit donor, preserving its opaque raw metadata.

    Converting a nil donor into a marked non-nil location is an explicit edit.
    No edits means nil identity (and its otherwise invisible payload) survives.
    """
    validate_location(donor, kind=donor_kind, mode=mode)
    display_key, raw_key = location_keys(target_kind)
    donor_display, donor_raw = location_keys(donor_kind)
    updates = updates or {}
    names = {view: raw for raw, view in {**LOCATION_NAMES, **BOOLEAN_NAMES}.items()}
    if set(updates) - names.keys() or set(remove) - names.keys():
        raise TransportError('unsupported explicit location edit')
    if set(updates) & set(remove):
        raise TransportError('location field both replaced and removed')
    if mode == LEGACY:
        if raw_key in target:
            raise TransportError('legacy edit cannot discard a target raw location')
        view = deepcopy(donor.get(donor_display, {}))
        view.update(updates)
        for field in remove:
            view.pop(field, None)
        target[display_key] = view
        return target
    raw = deepcopy(donor[donor_raw])
    if updates and raw['id'] == 'nil':
        if not create_from_nil:
            raise TransportError('marked nil location requires explicit construction')
        raw['id'] = ''
    if updates or remove:
        fields = raw.setdefault('namedSub', {})
        for field, value in updates.items():
            if names[field] in BOOLEAN_NAMES:
                if type(value) is not bool:
                    raise TransportError('location boolean replacement is not boolean')
                fields[names[field]] = {'id': '1' if value else '0'}
            else:
                if not isinstance(value, str):
                    raise TransportError('location string replacement is not a string')
                fields[names[field]] = {'id': value}
        for field in remove:
            fields.pop(names[field], None)
        if not fields:
            raw.pop('namedSub', None)
    target[raw_key] = raw
    if target_kind == 'instruction' and raw['id'] == 'nil':
        target.pop(display_key, None)
    else:
        target[display_key] = location_view(raw)
    return target


def validate_model(functions, symbols, *, mode):
    check_mode(mode)
    if not isinstance(functions, list) or not isinstance(symbols, dict):
        raise TransportError('invalid function/symbol collections')
    names = set()
    for function in functions:
        if not isinstance(function, dict) or not isinstance(function.get('name'), str) or function['name'] in names:
            raise TransportError('missing/duplicate function identity')
        names.add(function['name'])
        body = function.get('instructions', [])
        if not isinstance(body, list):
            raise TransportError('invalid instruction collection')
        if mode == FULL:
            if (any(type(function.get(key)) is not bool for key in ('isBodyAvailable', 'isInternal', 'isHidden'))
                    or function['isBodyAvailable'] != bool(body)
                    or not isinstance(function.get('parameterIdentifiers'), list)
                    or any(not isinstance(p, str) for p in function['parameterIdentifiers'])):
                raise TransportError('incomplete typed function metadata: ' + function['name'])
        numbers = set()
        for instruction in body:
            if not isinstance(instruction, dict) or not isinstance(instruction.get('instructionId'), str):
                raise TransportError('invalid instruction')
            number = instruction.get('locationNumber')
            if type(number) is not int or number < 0 or number in numbers:
                raise TransportError('invalid/duplicate instruction reference')
            numbers.add(number)
            validate_location(instruction, kind='instruction', mode=mode)
            for field in ('code', 'guard'):
                if field in instruction:
                    validate_irep(instruction[field])
            if instruction['instructionId'] in ('ASSERT', 'ASSUME', 'GOTO') and 'guard' not in instruction:
                raise TransportError('conditional instruction has no guard')
            if instruction['instructionId'] in ('ASSIGN', 'DECL', 'DEAD', 'SET_RETURN_VALUE', 'FUNCTION_CALL', 'OTHER') and 'code' not in instruction:
                raise TransportError('instruction has no required code')
            for field, element_type in (('targets', int), ('labels', str)):
                if field in instruction and (not isinstance(instruction[field], list)
                        or any(type(item) is not element_type for item in instruction[field])):
                    raise TransportError('invalid instruction ' + field)
        if any(t not in numbers for i in body for t in i.get('targets', [])):
            raise TransportError('unresolved intra-function target')
    for name, symbol in symbols.items():
        if not isinstance(symbol, dict) or symbol.get('name') != name:
            raise TransportError('invalid symbol identity: ' + str(name))
        validate_location(symbol, kind='symbol', mode=mode)
        if mode == FULL and (any(not isinstance(symbol.get(key), str) for key in SYMBOL_IDENTITIES)
                or any(type(symbol.get(key)) is not bool for key in SYMBOL_FLAGS)):
            raise TransportError('incomplete typed symbol metadata: ' + name)
        for field in ('type', 'value'):
            if field not in symbol:
                raise TransportError('missing symbol ' + field)
            validate_irep(symbol[field])


def inspection_model(function_messages, symbol_messages, *, mode):
    check_mode(mode)
    groups = []
    evidence = {'mode': mode, 'full_typed': mode == FULL}
    for messages, key, capabilities in ((function_messages, 'functions', FUNCTION_CAPABILITIES),
                                         (symbol_messages, 'symbolTable', SYMBOL_CAPABILITIES)):
        if not isinstance(messages, list) or any(not isinstance(m, dict) for m in messages):
            raise TransportError('invalid export message envelope')
        if any(m.get('messageType') == 'ERROR' for m in messages):
            raise TransportError('exporter emitted an ERROR')
        matched = [m for m in messages if key in m]
        if len(matched) != 1:
            raise TransportError('missing/duplicate ' + key + ' group')
        group = matched[0]
        present = CAPABILITY_KEYS & group.keys()
        if mode == FULL:
            if present != capabilities.keys() or any(group.get(k) is not v for k, v in capabilities.items()):
                raise TransportError('missing/partial full-typed export capabilities: ' + key)
        elif present:
            raise TransportError('legacy mode cannot consume typed export capabilities')
        evidence[key] = {k: deepcopy(v) for k, v in group.items() if k != key}
        groups.append(group[key])
    validate_model(*groups, mode=mode)
    return *groups, evidence


def transport_view(functions, symbols, *, mode):
    """Detached importer representation; validation always precedes projection."""
    validate_model(functions, symbols, mode=mode)
    functions, symbols = deepcopy(functions), deepcopy(symbols)
    if mode == FULL:
        for function in functions:
            for instruction in function.get('instructions', []):
                instruction['sourceLocation'] = instruction.pop('sourceLocationIrep')
        for symbol in symbols.values():
            symbol['location'] = symbol.pop('locationIrep')
    return {'functions': functions}, {'symbolTable': symbols}


def normalized_function(function):
    function = deepcopy(function)
    body = function.get('instructions', [])
    positions = {i['locationNumber']: index for index, i in enumerate(body)}
    for index, instruction in enumerate(body):
        instruction['locationNumber'] = index
        if 'targets' in instruction:
            instruction['targets'] = [positions[t] for t in instruction['targets']]
        instruction.pop('instruction', None)
        if 'sourceLocation' in instruction:
            instruction['sourceLocation'] = display_location(instruction['sourceLocation'])
    return function


def normalized_symbol(symbol):
    symbol = deepcopy(symbol)
    symbol.pop('prettyType', None)
    symbol.pop('prettyValue', None)
    if 'location' in symbol:
        symbol['location'] = display_location(symbol['location'])
    return symbol


def normalized_model(functions, symbols, *, mode):
    validate_model(functions, symbols, mode=mode)
    return {'functions': [normalized_function(f) for f in functions],
            'symbolTable': {name: normalized_symbol(s) for name, s in symbols.items()}}


def normalized_digest(functions, symbols):
    """Same canonical JSON digest without constructing another whole model."""
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    def value(item):
        for chunk in encoder.iterencode(item):
            digest.update(chunk.encode('utf-8'))
    digest.update(b'{"functions":[')
    for index, function in enumerate(functions):
        if index:
            digest.update(b',')
        value(normalized_function(function))
    digest.update(b'],"symbolTable":{')
    for index, name in enumerate(sorted(symbols)):
        if index:
            digest.update(b',')
        value(name)
        digest.update(b':')
        value(normalized_symbol(symbols[name]))
    digest.update(b'}}')
    return digest.hexdigest()


def first_difference(left, right, path='$'):
    if type(left) is not type(right):
        return {'path': path, 'reason': 'type changed', 'expected': type(left).__name__, 'actual': type(right).__name__}
    if isinstance(left, dict):
        for key in sorted(left.keys() | right.keys()):
            if key not in left or key not in right:
                return {'path': path + '/' + key, 'reason': 'field added' if key not in left else 'field removed'}
            difference = first_difference(left[key], right[key], path + '/' + key)
            if difference:
                return difference
    elif isinstance(left, list):
        if len(left) != len(right):
            return {'path': path, 'reason': 'array length changed', 'expected': len(left), 'actual': len(right)}
        for index, (a, b) in enumerate(zip(left, right)):
            difference = first_difference(a, b, path + '/' + str(index))
            if difference:
                return difference
    elif left != right:
        return {'path': path, 'reason': 'value changed', 'expected': str(left)[:512], 'actual': str(right)[:512]}
    return None


def compare_models(expected_functions, expected_symbols, actual_functions, actual_symbols, *, mode):
    validate_model(expected_functions, expected_symbols, mode=mode)
    validate_model(actual_functions, actual_symbols, mode=mode)
    difference = None
    if len(expected_functions) != len(actual_functions):
        difference = {'path': '$/functions', 'reason': 'array length changed',
                      'expected': len(expected_functions), 'actual': len(actual_functions)}
    else:
        for index, (expected, actual) in enumerate(zip(expected_functions, actual_functions)):
            difference = first_difference(normalized_function(expected), normalized_function(actual),
                                          '$/functions/' + str(index))
            if difference:
                break
    if not difference:
        for name in sorted(expected_symbols.keys() | actual_symbols.keys()):
            path = '$/symbolTable/' + name
            if name not in expected_symbols or name not in actual_symbols:
                difference = {'path': path, 'reason': 'field added' if name not in expected_symbols else 'field removed'}
            else:
                difference = first_difference(normalized_symbol(expected_symbols[name]),
                                              normalized_symbol(actual_symbols[name]), path)
            if difference:
                break
    return {'status': 'MISMATCH' if difference else 'MATCH', 'mode': mode,
            'full_typed': mode == FULL, 'first_difference': difference,
            'expected_sha256': normalized_digest(expected_functions, expected_symbols),
            'actual_sha256': normalized_digest(actual_functions, actual_symbols)}
