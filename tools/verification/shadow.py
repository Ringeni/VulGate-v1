"""Alias-aware initialization instrumentation on CBMC's typed GOTO IR.

The transformer uses the compiler's read/write expressions and Symbolic Shadow
Memory. It never interprets user C statements or recognizes fixture names.
Unsupported memory effects are reported explicitly and prevent a proof claim.
"""
from __future__ import annotations
from copy import deepcopy
import json

from .spec import SpecificationError
from .correspondence import sensitive_sites
from .storage_types import storage_type
from .build_semantics import contains_observable_storage, fixed_trailing_array_member
from .typed_transport import FULL, copy_location, location_keys


BOOL = {"id": "bool"}
TRUE = {"id": "constant", "namedSub": {"type": BOOL, "value": {"id": "true"}}}
_ALLOCATOR_SHADOW = {
    "malloc": ((0,), False),
    "ngx_palloc": ((1,), False),
    "ngx_pnalloc": ((1,), False),
    "apr_palloc": ((1,), False),
    "_emalloc": ((0,), False),
    "emalloc": ((0,), False),
    "_safe_emalloc": ((0, 1), False),
    "safe_emalloc": ((0, 1), False),
    "calloc": ((0, 1), True),
    "ngx_pcalloc": ((1,), True),
    "apr_pcalloc": ((1,), True),
    "_ecalloc": ((0, 1), True),
    "ecalloc": ((0, 1), True),
}


def typ(expression):
    return expression.get("namedSub", {}).get("type", {"id": "empty"})


def symbol_name(expression):
    return expression.get("namedSub", {}).get("identifier", {}).get("id", "")


def private_havoc_target(instruction, symbols, expected_name=None):
    """Recognize only a whole fresh private unsigned choice scalar."""
    code = instruction.get("code", {})
    if (instruction.get("instructionId") != "OTHER" or
            code.get("namedSub", {}).get("statement", {}).get("id") != "havoc_object" or len(code.get("sub", [])) != 1):
        return None
    target = code["sub"][0]
    while target.get("id") == "typecast" and len(target.get("sub", [])) == 1 and typ(target).get("id") == "pointer":
        target = target["sub"][0]
    if target.get("id") != "address_of" or len(target.get("sub", [])) != 1:
        return None
    target = target["sub"][0]
    symbol = symbols.get(symbol_name(target), {})
    name = symbol.get("baseName", "")
    width = typ(target).get("namedSub", {}).get("width", {}).get("id", "")
    if (target.get("id") != "symbol" or not name.startswith("__vulgate_sample_") or symbol.get("isStaticLifetime") or
            (expected_name is not None and name != expected_name) or typ(target).get("id") != "unsignedbv" or
            not str(width).isdigit() or not 5 <= int(width) <= 64):
        return None
    return target


def operation(name, *args):
    return {"id": name, "namedSub": {"type": BOOL}, "sub": list(args)}


def conjunction(left, right):
    return right if left == TRUE else operation("and", left, right)


def code(statement, args):
    return {"id": "code", "namedSub": {"statement": {"id": statement}, "type": {"id": "empty"}}, "sub": args}


def constant_false(expr):
    if expr.get("id") == "constant":
        return expr.get("namedSub", {}).get("value", {}).get("id") in ("0", "false")
    return (expr.get("id") == "notequal" and len(expr.get("sub", [])) == 2
            and expr["sub"][0].get("id") == "constant" and expr["sub"][0] == expr["sub"][1])


def inert_initializer_value(expr):
    """Compiler initial values without references, computation or side effects."""
    kind, operands = expr.get('id'), expr.get('sub', [])
    if kind == 'constant':
        return not operands
    if kind == 'side_effect':
        return not operands and expr.get('namedSub', {}).get('statement', {}).get('id') == 'nondet'
    return kind in ('array', 'array_of', 'struct', 'union') and all(
        inert_initializer_value(operand) for operand in operands)


def _allocator_shadow_marks(called, result, arguments, donor, functions, symbols, fresh, located):
    base = called.split("::")[-1]
    spec = _ALLOCATOR_SHADOW.get(base)
    if spec is None or result.get("id") != "symbol":
        return []
    indexes, zeroing = spec
    args = arguments.get("sub") or []
    if any(index >= len(args) for index in indexes):
        return []
    bodies = {fn.get("name"): fn for fn in functions}
    callee = bodies.get(called)
    if callee and callee.get("isBodyAvailable"):
        for insn in callee.get("instructions") or []:
            if insn.get("instructionId") != "FUNCTION_CALL":
                continue
            ops = insn.get("code", {}).get("sub") or []
            if len(ops) < 2 or ops[1].get("id") != "symbol":
                continue
            inner = symbol_name(ops[1]).split("::")[-1]
            if inner in ("__CPROVER_set_field", "__vg_mark_alloc"):
                return []
    mark_name = next((
        name for name, sym in symbols.items()
        if sym.get("baseName") == "__vg_mark_alloc" or name.split("::")[-1] == "__vg_mark_alloc"
    ), None)
    if mark_name is None:
        return []
    mark_type = symbols[mark_name].get("type") or {}
    params = mark_type.get("namedSub", {}).get("parameters", {}).get("sub") or []
    if len(params) < 3:
        return []
    size = deepcopy(args[indexes[0]])
    size_type = params[1].get("namedSub", {}).get("type") or {"id": "unsignedbv", "namedSub": {"width": {"id": "64"}}}
    for index in indexes[1:]:
        size = {"id": "*", "namedSub": {"type": deepcopy(size_type)}, "sub": [size, deepcopy(args[index])]}
    # Fallbacks must stay well-formed for CBMC validation: every bitvector
    # type needs an explicit width (pointer 64, C bool 8 in this model).
    pointer_type = params[0].get("namedSub", {}).get("type") or {
        "id": "pointer", "namedSub": {"width": {"id": "64"}}, "sub": [{"id": "empty"}]}
    dirty_type = params[2].get("namedSub", {}).get("type") or {"id": "c_bool", "namedSub": {"width": {"id": "8"}}}
    dirty = {"id": "constant", "namedSub": {"type": deepcopy(dirty_type), "value": {"id": "0" if zeroing else "1"}}}
    call = fresh(located({
        "instructionId": "FUNCTION_CALL",
        "code": code("function_call", [
            {"id": "nil"},
            {"id": "symbol", "namedSub": {"identifier": {"id": mark_name}, "type": deepcopy(mark_type)}},
            {"id": "arguments", "sub": [
                {"id": "typecast", "namedSub": {"type": deepcopy(pointer_type)}, "sub": [deepcopy(result)]},
                size,
                dirty,
            ]},
        ]),
    }, donor))
    return [call]


def transform(functions, symbols, target_descriptions=(), *, implicit_zero_init=False, strict_flexible_arrays=False,
              transport_mode=FULL):
    functions, symbols = deepcopy(functions), deepcopy(symbols)
    correspondence_sites = sensitive_sites(functions)
    correspondence_by_instruction = {}
    for site in correspondence_sites:
        correspondence_by_instruction.setdefault((site['function'], site['index']), []).append(site)
    # CBMC's shadow-memory implementation deliberately skips auxiliary local
    # objects. C lowering creates such objects for postfix operations and other
    # expressions; our checks read/write those objects like any other lvalue.
    # Make their shadow storage explicit without changing type, value, lifetime
    # or GOTO instructions. Private verification temporaries remain auxiliary.
    declared = {symbol_name(i.get('code', {}).get('sub', [{}])[0])
                for f in functions for i in f.get('instructions', [])
                if i.get('instructionId') == 'DECL'}
    tracked_temporaries = []
    for name in sorted(declared):
        symbol = symbols.get(name, {})
        if (symbol.get('isAuxiliary') and symbol.get('isLvalue') and not symbol.get('isStaticLifetime')
                and not name.startswith(('__CPROVER', '__vulgate_'))
                and not symbol.get('baseName', '').startswith('__vulgate_')
                and symbol.get('type', {}).get('id') != 'code'):
            symbol['isAuxiliary'] = False
            tracked_temporaries.append(name)
    template = next((f for f in functions if f["name"] == "__vulgate_shadow_template"), None)
    if template is None:
        raise SpecificationError("missing compiler-typed shadow instrumentation template")
    calls = {symbol_name(i["code"]["sub"][1]): i for i in template["instructions"]
             if i["instructionId"] == "FUNCTION_CALL"}
    get_template, set_template = calls["__CPROVER_get_field"], calls["__CPROVER_set_field"]
    literal_call_template = calls.get('__vulgate_literal_probe')
    temporary_template = symbols[symbol_name(get_template["code"]["sub"][0])]
    pointer_width = typ(get_template["code"]["sub"][2]["sub"][0]).get("namedSub", {}).get("width", {"id": "64"})
    unsupported, read_count, write_count, serial = set(), 0, 0, 0
    deferred_bit_field_writes = []
    active_issues = None
    original_strings = {}

    def located(instruction, donor, donor_kind='instruction', *, updates=None):
        return copy_location(instruction, donor, mode=transport_mode, donor_kind=donor_kind,
                             updates=updates, remove=('propertyId',) if updates else (),
                             create_from_nil=bool(updates))

    def record_unsupported(reason):
        (unsupported if active_issues is None else active_issues).add(reason)

    def contains_union(value_type, seen=()):
        kind = value_type.get('id')
        if kind in ('union', 'union_tag'):
            return True
        if kind == 'struct_tag':
            tag = value_type.get('namedSub', {}).get('identifier', {}).get('id')
            return tag not in seen and contains_union(symbols.get(tag, {}).get('type', {}), (*seen, tag))
        if kind == 'struct':
            return any(contains_union(component.get('namedSub', {}).get('type', {}), seen)
                       for component in value_type.get('namedSub', {}).get('components', {}).get('sub', []))
        return kind == 'array' and any(contains_union(child, seen) for child in value_type.get('sub', []))

    def strings(expr):
        if not isinstance(expr, dict):
            return
        if expr.get("id") == "string_constant":
            original_strings[json.dumps(expr, sort_keys=True)] = expr
        for child in expr.get("sub", []):
            strings(child)

    for function in functions:
        if function["name"].startswith("__vulgate_") and function["name"] != "__vulgate_family_initialize":
            continue
        for instruction in function.get("instructions", []):
            strings(instruction.get("code", {}))
            strings(instruction.get("guard", {}))

    # One compiler-typed helper tests literal object identity. Replicating the
    # full literal list at every read is quadratic in real translation units.
    # The helper is read-only and is built from the same comparisons, without
    # removing functions, changing assumptions or dropping memory checks.
    literal_helper = next((f for f in functions if f['name'] == '__vulgate_literal_probe'), None)
    literal_identity_checks = 0
    if literal_call_template is not None and literal_helper is not None:
        parameter = literal_helper['parameterIdentifiers'][0]
        pointer = {'id': 'symbol', 'namedSub': {'identifier': {'id': parameter},
                   'type': symbols[parameter]['type']}}
        literal_pointer_type = symbols[parameter]['type']
        return_type = typ(literal_call_template['code']['sub'][0])
        literal_true = {'id': 'constant', 'namedSub': {'type': return_type, 'value': {'id': '1'}}}
        literal_false = {'id': 'constant', 'namedSub': {'type': return_type, 'value': {'id': '0'}}}
        object_id_type = {'id': 'unsignedbv', 'namedSub': {'width': pointer_width}}
        comparisons = []
        for literal in original_strings.values():
            literal_pointer = {'id': 'address_of', 'namedSub': {'type': {
                'id': 'pointer', 'namedSub': {'width': pointer_width}, 'sub': [typ(literal)]}}, 'sub': [literal]}
            comparisons.append(operation('=',
                {'id': 'pointer_object', 'namedSub': {'type': object_id_type}, 'sub': [pointer]},
                {'id': 'pointer_object', 'namedSub': {'type': object_id_type}, 'sub': [
                    {'id': 'typecast', 'namedSub': {'type': literal_pointer_type}, 'sub': [literal_pointer]}]}))
        count = len(comparisons)
        instructions = [{'instructionId': 'GOTO', 'guard': comparison, 'targets': [count + 2]}
                        for comparison in comparisons]
        instructions.extend([
            {'instructionId': 'SET_RETURN_VALUE', 'code': code('return', [literal_false])},
            {'instructionId': 'GOTO', 'guard': TRUE, 'targets': [count + 3]},
            {'instructionId': 'SET_RETURN_VALUE', 'code': code('return', [literal_true])},
            {'instructionId': 'END_FUNCTION'}])
        for number, instruction in enumerate(instructions):
            instruction['locationNumber'] = number
            located(instruction, symbols['__vulgate_literal_probe'], 'symbol')
        literal_helper['instructions'] = instructions
        literal_identity_checks = count

    def fresh(instruction):
        nonlocal serial
        serial += 1
        result = deepcopy(instruction)
        result.pop("instruction", None)
        result.pop("locationNumber", None)
        result["_key"] = f"inserted:{serial}"
        return result

    def address(value):
        return {"id": "address_of", "namedSub": {"type": {
            "id": "pointer", "namedSub": {"width": pointer_width}, "sub": [typ(value)]}}, "sub": [value]}

    def trackable(value):
        if value.get("id") == "symbol":
            name = symbol_name(value)
            # Family storage is written by generated C and read by entry guards.
            # Track those actual writes, including array elements, rather than
            # treating the private namespace as proof of initialization.
            family_storage = (name.startswith(("__vulgate_choices_", "__vulgate_family_initialize::")) or
                              name == "__vulgate_family_initialized")
            if name.startswith(("__CPROVER", "__vulgate_")) and not family_storage:
                return False
        t = typ(value)
        if contains_union(t):
            record_unsupported('union storage initialization tracking')
        # CBMC's mathematical bool has no C sizeof/addressable storage. C _Bool
        # is c_bool and remains tracked, including _Bool structure members.
        if t["id"] in ("code", "empty", "nil", "bool"):
            return False
        if t["id"] == "c_bit_field":
            record_unsupported("bit-field initialization tracking")
            return False
        declared = storage_type(value, symbols)
        for qualifier in ('#volatile', '#atomic'):
            if any(type_.get('namedSub', {}).get(qualifier, {}).get('id') == '1' for type_ in (t, declared)):
                record_unsupported(qualifier[1:] + ' observation semantics')
                return False
        return True

    def reads(expr, activation=TRUE, address_only=False):
        kind, operands = expr.get("id"), expr.get("sub", [])
        if strict_flexible_arrays and fixed_trailing_array_member(expr, symbols):
            record_unsupported('strict trailing-array subobject bounds and address escape')
        # The backend does not consistently propagate shadow writes through
        # union storage. Include address-taking so aliases cannot bypass this
        # limitation after their pointer type loses the aggregate provenance.
        if contains_union(typ(expr)):
            record_unsupported('union storage initialization tracking')
        result = []
        if kind in ("nil", "constant", "string_constant", "sizeof"):
            return result
        if kind == "address_of":
            return reads(operands[0], activation, True)
        if kind == "symbol":
            return [(activation, expr)] if not address_only and trackable(expr) else []
        if kind == "dereference":
            result.extend(reads(operands[0], activation))
            if not address_only and trackable(expr):
                result.append((activation, expr))
            return result
        if kind == "member":
            result.extend(reads(operands[0], activation, True))
            if not address_only and trackable(expr):
                result.append((activation, expr))
            return result
        if kind == "index":
            result.extend(reads(operands[0], activation, typ(operands[0])["id"] == "array"))
            result.extend(reads(operands[1], activation))
            if not address_only and trackable(expr):
                result.append((activation, expr))
            return result
        if kind == "if":
            result.extend(reads(operands[0], activation))
            result.extend(reads(operands[1], conjunction(activation, operands[0]), address_only))
            result.extend(reads(operands[2], conjunction(activation, operation("not", operands[0])), address_only))
            return result
        if kind in ("and", "or"):
            for operand in operands:
                result.extend(reads(operand, activation))
                activation = conjunction(activation, operand if kind == "and" else operation("not", operand))
            return result
        if kind == "side_effect":
            effect = expr.get("namedSub", {}).get("statement", {}).get("id")
            if effect not in ("nondet", "malloc", "allocate"):
                record_unsupported(f"side effect {effect}")
            if effect == "allocate" and (len(operands) != 2 or not constant_false(operands[1])):
                record_unsupported("zero-initializing or conditional allocation effect")
            if any("calloc" in key or "zero" in key for key in expr.get("namedSub", {})):
                record_unsupported("zero-initializing allocation effect")
        elif kind not in {"typecast", "not", "bitnot", "unary-", "+", "-", "*", "/", "mod",
                          "=", "notequal", "<", "<=", ">", ">=", "bitand", "bitor", "bitxor",
                          "shl", "lshr", "ashr", "array", "struct", "union", "vector",
                          "pointer_object", "pointer_offset", "pointer_object_has_type", "same_object",
                          "is_dynamic_object", "is_invalid_pointer", "is_zero_string", "zero_string_length",
                          "r_ok", "w_ok", "rw_ok"}:
            record_unsupported(f"expression {kind}")
        for operand in operands:
            result.extend(reads(operand, activation, address_only))
        return result

    def set_initialized(value, donor, *, donor_kind='instruction', defer_bit_field=False):
        nonlocal write_count
        location = donor.get(location_keys(donor_kind)[0], {})
        if defer_bit_field and value.get('id') == 'member' and typ(value).get('id') == 'c_bit_field':
            declared = storage_type(value, symbols)
            base = typ(value.get('sub', [{}])[0])
            if (base.get('id') in ('struct', 'struct_tag') and declared.get('id') == 'c_bit_field'
                    and not any(contains_observable_storage(type_, symbols) for type_ in (typ(value), declared))):
                # A C bit-field is not addressable. Keep its original assignment
                # and all RHS/address checks, but grant no initialized bytes.
                # This under-approximates initialization without clearing the
                # shared byte that may contain an unwritten neighbour. Reads of
                # the bit-field itself still need precise bit-level semantics.
                # A later shadow failure may be due to this lost precision;
                # classify() must not export it as a definite counterexample.
                marker = f'__VG_REACH_DEFERRED_BIT_FIELD_WRITE:{len(deferred_bit_field_writes)}'
                deferred_bit_field_writes.append({'marker': marker, 'location': location,
                    'member': value.get('namedSub', {}).get('component_name', {}).get('id'),
                    'transfer': 'preserve original write; grant no initialized shadow bytes'})
                return [fresh(located({'instructionId': 'ASSERT', 'guard': operation('not', TRUE)},
                                     donor, donor_kind, updates={'comment': marker,
                                         'propertyClass': 'vulgate initialization precision'}))]
        if not trackable(value):
            return []
        if value.get("id") not in ("symbol", "dereference", "index", "member", "string_constant"):
            record_unsupported(f"assignment target {value.get('id')}")
            return []
        call = fresh(set_template)
        located(call, donor, donor_kind)
        call["code"]["sub"][2]["sub"][0] = address(value)
        write_count += 1
        return [call]

    def check_read(activation, value, temporary, literal_temporary, donor):
        nonlocal read_count
        # String literals are initialized C objects. CBMC allocates their shadow
        # state lazily; test object identity before consulting shadow storage.
        # Separate branches avoid a deeply nested short-circuit guard whose
        # pointer-property instrumentation can expand exponentially.
        object_id_type = {"id": "unsignedbv", "namedSub": {"width": pointer_width}}
        end = fresh(located({"instructionId": "SKIP"}, donor))
        prefix = []
        if activation != TRUE:
            prefix.append(fresh(located({"instructionId": "GOTO", "guard": operation("not", activation),
                                        "_target_keys": [end["_key"]]}, donor)))
        def could_be_literal(expression):
            if expression.get('id') == 'symbol':
                return False
            if expression.get('id') in ('member', 'index'):
                base = expression.get('sub', [{}])[0]
                if expression['id'] == 'index' and typ(base).get('id') == 'pointer':
                    return True
                return could_be_literal(base)
            return True

        if original_strings and could_be_literal(value):
            if literal_call_template is None or literal_helper is None or literal_temporary is None:
                raise SpecificationError('missing compiler-typed shared literal-check helper')
            literal_call = fresh(literal_call_template)
            located(literal_call, donor)
            literal_call['code']['sub'][0] = literal_temporary
            literal_call['code']['sub'][2]['sub'][0] = {'id': 'typecast',
                'namedSub': {'type': literal_pointer_type}, 'sub': [address(value)]}
            prefix.extend([literal_call, fresh(located({'instructionId': 'GOTO',
                'guard': operation('notequal', literal_temporary, {'id': 'constant', 'namedSub': {
                    'type': typ(literal_temporary), 'value': {'id': '0'}}}),
                '_target_keys': [end['_key']]}, donor))])
        call = fresh(get_template)
        located(call, donor)
        call["code"]["sub"][0] = temporary
        call["code"]["sub"][2]["sub"][0] = address(value)
        zero = {"id": "constant", "namedSub": {"type": typ(temporary), "value": {"id": "0"}}}
        assertion = fresh(located({"instructionId": "ASSERT", "guard": operation("=", temporary, zero)},
                                 donor, updates={"comment": "vulgate.initialized_read",
                                                 "propertyClass": "vulgate initialization"}))
        result = [*prefix, call, assertion, end] if prefix else [call, assertion]
        read_count += 1
        return result

    aliases, target_sites, guarded_unsupported, deferred_union_initializations = {}, [], [], []
    def issue_checks(issues, donor, donor_kind='instruction'):
        location = donor.get(location_keys(donor_kind)[0], {})
        checks = []
        for reason in sorted(issues):
            marker = f'__VG_UNMODELED_INIT:{len(guarded_unsupported)}'
            guarded_unsupported.append({'property': marker, 'reason': reason, 'location': location})
            checks.append(fresh(located({'instructionId': 'ASSERT', 'guard': operation('not', TRUE)},
                                       donor, donor_kind, updates={'comment': marker,
                                           'propertyClass': 'vulgate unsupported initialization'})))
        return checks

    global_initialization_marker = '__VG_GLOBAL_INITIALIZATION_INSTRUMENTED'
    for function in functions:
        name = function["name"]
        original = function.get("instructions", [])
        if not original:
            continue
        library_file = symbols.get(name, {}).get("location", {}).get("file", "")
        trusted_allocation_model = (
            (name in ("malloc", "free") and library_file.startswith("<builtin-library-"))
            or any(rt in library_file for rt in ("runtime/vm.c", "runtime/experiment/state.c"))
        )
        if ((name.startswith("__vulgate_") and name != "__vulgate_family_initialize") or trusted_allocation_model or
                (name.startswith("__CPROVER_") and name not in ("__CPROVER_initialize", "__CPROVER__start"))):
            for item in original:
                key = f"{name}:old:{item['locationNumber']}"
                item["_key"] = key
                item["_target_keys"] = [f"{name}:old:{n}" for n in item.pop("targets", [])]
            continue
        temporary_name = name + "::__vulgate_shadow_read"
        temporary_symbol = deepcopy(temporary_template)
        temporary_symbol.update({"name": temporary_name, "baseName": "__vulgate_shadow_read",
                                 "prettyName": temporary_name, "isAuxiliary": True})
        copy_location(temporary_symbol, symbols[name], mode=transport_mode,
                      donor_kind='symbol', target_kind='symbol')
        symbols[temporary_name] = temporary_symbol
        temporary = {"id": "symbol", "namedSub": {"identifier": {"id": temporary_name},
                                                     "type": temporary_symbol["type"]}}
        function_donor = symbols[name]
        prefix = [fresh(calls["__CPROVER_field_decl_local"]), fresh(calls["__CPROVER_field_decl_global"]),
                  fresh({"instructionId": "DECL", "code": code("decl", [temporary])})]
        # get_field returns the backend's integer type before C converts it to
        # _Bool. The literal helper has its own compiler-derived return type;
        # a GOTO call requires an exactly typed destination, with no implicit
        # C assignment conversion at this layer.
        literal_temporary = None
        if original_strings and literal_call_template is not None and literal_helper is not None:
            literal_name = name + '::__vulgate_literal_read'
            literal_symbol = deepcopy(symbols[symbol_name(literal_call_template['code']['sub'][0])])
            literal_symbol.update(name=literal_name, baseName='__vulgate_literal_read',
                                  prettyName=literal_name, isAuxiliary=True)
            copy_location(literal_symbol, function_donor, mode=transport_mode,
                          donor_kind='symbol', target_kind='symbol')
            symbols[literal_name] = literal_symbol
            literal_temporary = {'id': 'symbol', 'namedSub': {
                'identifier': {'id': literal_name}, 'type': literal_symbol['type']}}
            prefix.append(fresh({'instructionId': 'DECL', 'code': code('decl', [literal_temporary])}))
        for item in prefix:
            located(item, function_donor, 'symbol')
        if name == '__CPROVER_initialize':
            prefix.append(fresh(located({'instructionId': 'ASSERT', 'guard': TRUE}, function_donor, 'symbol',
                                       updates={'comment': global_initialization_marker,
                                                'propertyClass': 'vulgate instrumentation'})))
        active_issues = set()
        for parameter in function.get("parameterIdentifiers", []):
            if parameter:
                prefix.extend(set_initialized({"id": "symbol", "namedSub": {
                    "identifier": {"id": parameter}, "type": symbols[parameter]["type"]}},
                    function_donor, donor_kind='symbol'))
        transformed = [*prefix, *issue_checks(active_issues, function_donor, 'symbol')]
        for instruction_index, item in enumerate(original):
            active_issues = set()
            kind = item["instructionId"]
            location = item.get("sourceLocation", {})
            operands = item.get("code", {}).get("sub", [])
            to_read, to_write, alloc_marks, unmodeled = [], [], [], None
            if kind in ("ASSUME", "ASSERT", "GOTO"):
                to_read.extend(reads(item["guard"]))
            elif kind == "ASSIGN":
                lhs, rhs = operands
                declared = storage_type(lhs, symbols)
                if (name == '__CPROVER_initialize' and lhs.get('id') == 'symbol'
                        and symbols.get(symbol_name(lhs), {}).get('isStaticLifetime')
                        and contains_union(declared) and not contains_observable_storage(declared, symbols)
                        and inert_initializer_value(rhs)):
                    # Retained but unused header functions can introduce extern
                    # union-bearing globals into the compiler initializer. Keep
                    # their value assignment, without marking shadow bytes as
                    # initialized. Later reads, writes and address-taking still
                    # require the normal union-storage obligation. This does not
                    # admit union access or suppress RHS references/effects.
                    deferred_union_initializations.append({'symbol': symbol_name(lhs), 'location': location})
                else:
                    to_read.extend(reads(rhs))
                    to_read.extend(reads(lhs, address_only=True))
                    to_write.append(lhs)
            elif kind == "SET_RETURN_VALUE":
                to_read.extend(reads(operands[0]))
            elif kind == "FUNCTION_CALL":
                lhs, callee, arguments = operands
                for argument in arguments.get("sub", []):
                    to_read.extend(reads(argument))
                if callee.get("id") != "symbol":
                    to_read.extend(reads(callee))
                if lhs.get("id") != "nil":
                    to_read.extend(reads(lhs, address_only=True))
                    to_write.append(lhs)
                called = symbol_name(callee)
                if called.startswith("__CPROVER_") and called not in {
                    "__CPROVER_initialize", "__CPROVER_freeable", "__CPROVER_is_freeable",
                    "__CPROVER_r_ok", "__CPROVER_w_ok", "__CPROVER_POINTER_OBJECT", "__CPROVER_POINTER_OFFSET",
                    "__CPROVER_OBJECT_SIZE", "__CPROVER_same_object", "__CPROVER_malloc_object",
                    "__CPROVER_is_invalid_pointer",
                    "__CPROVER_deallocate", "__CPROVER_get_field", "__CPROVER_set_field"}:
                    record_unsupported(f"intrinsic effects {called}")
                else:
                    alloc_marks.extend(_allocator_shadow_marks(
                        called, lhs, arguments, item, functions, symbols, fresh, located,
                    ))
            elif kind == "DECL":
                declared_type = typ(operands[0])
                if implicit_zero_init and contains_observable_storage(storage_type(operands[0], symbols), symbols):
                    record_unsupported('implicit initialization of volatile/atomic automatic storage')
                if declared_type.get("id") == "array":
                    size = declared_type.get("namedSub", {}).get("size")
                    if size:
                        to_read.extend(reads(size))
            elif kind == "OTHER" and (target := private_havoc_target(item, symbols)) is not None:
                to_write.append(target)
            elif kind == "OTHER" and item.get("code", {}).get("namedSub", {}).get("statement", {}).get("id") == "expression":
                for operand in operands:
                    to_read.extend(reads(operand))
            elif kind == "OTHER":
                unmodeled = "unsupported instruction OTHER: " + item.get("code", {}).get("namedSub", {}).get("statement", {}).get("id", "unknown")
            elif kind not in ("DEAD", "SKIP", "LOCATION", "END_FUNCTION"):
                record_unsupported(f"instruction {kind}")
            checks = []
            for site in correspondence_by_instruction.get((name, instruction_index), []):
                checks.append(fresh(located({'instructionId': 'ASSERT', 'guard': operation('not', TRUE)}, item,
                                           updates={'comment': site['marker'],
                                                    'propertyClass': 'vulgate correspondence reachability'})))
            if unmodeled is not None:
                record_unsupported(unmodeled)
            unconditional_symbols = set()
            for activation, value in to_read:
                # GOTO expressions have no intervening assignments. One
                # unconditional read check covers repeated reads of the same
                # scalar symbol, including large compiler-emitted switch tests.
                if value.get("id") == "symbol":
                    read_symbol = symbol_name(value)
                    if read_symbol in unconditional_symbols:
                        continue
                    if activation == TRUE:
                        unconditional_symbols.add(read_symbol)
                checks.extend(check_read(activation, value, temporary, literal_temporary, item))
            if kind == "ASSERT" and location.get("comment") in target_descriptions:
                description = location["comment"]
                marker = f"__VG_REACH_TARGET:{len(target_sites)}"
                target_sites.append({"target": description, "marker": marker, "location": location})
                # This executes after evaluating the reads used by the target
                # assertion, and after assumptions on the actual path to it.
                checks.append(fresh(located({"instructionId": "ASSERT", "guard": operation("not", TRUE)}, item,
                                           updates={"comment": marker, "propertyClass": "vulgate reachability"})))
            updates = [update for value in to_write for update in
                       set_initialized(value, item, defer_bit_field=kind == 'ASSIGN')]
            updates.extend(alloc_marks)
            # Diagnose every unsupported read, write or instruction on its
            # actual path. Nothing is removed or assumed unreachable.
            checks[0:0] = issue_checks(active_issues, item)
            original_key = f"{name}:old:{item['locationNumber']}"
            item["_key"] = original_key
            item["_target_keys"] = [f"{name}:old:{n}" for n in item.pop("targets", [])]
            if checks:
                aliases[original_key] = checks[0]["_key"]
            transformed.extend(checks)
            transformed.append(item)
            transformed.extend(updates)
        function["instructions"] = transformed
        active_issues = None
    flat = [i for f in functions for i in f.get("instructions", [])]
    numbers = {i["_key"]: index for index, i in enumerate(flat)}
    for index, instruction in enumerate(flat):
        targets = instruction.pop("_target_keys", [])
        if targets:
            instruction["targets"] = [numbers[aliases.get(key, key)] for key in targets]
        instruction["locationNumber"] = index
        instruction.pop("_key")
        instruction.pop("instruction", None)
    return functions, symbols, {"backend": "CBMC symbolic shadow memory", "read_checks": read_count,
                                "write_updates": write_count, "unsupported": sorted(unsupported),
                                "target_sites": target_sites, "guarded_unsupported": guarded_unsupported,
                                "deferred_union_initializations": deferred_union_initializations,
                                "deferred_bit_field_writes": deferred_bit_field_writes,
                                "shared_literal_identity_checks": literal_identity_checks,
                                "tracked_compiler_temporaries": tracked_temporaries,
                                "correspondence_sites": correspondence_sites,
                                "global_initialization_marker": global_initialization_marker}
