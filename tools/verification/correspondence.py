"""Instruction-level obligations for the structural PASS argument.

The complete compiled program is retained. A context may discharge a sensitive
operation only by proving its inserted reachability marker unreachable.
"""
from hashlib import sha256
import json


def exposes_layout(expression):
    operands = expression.get('sub', [])
    kind = expression.get('id')
    if kind == 'typecast' and operands:
        source_type = operands[0].get('namedSub', {}).get('type', {}).get('id')
        target_type = expression.get('namedSub', {}).get('type', {}).get('id')
        # Casting a pointer expression to void discards its value. Still walk
        # the operand: an inner pointer-to-integer cast can observe layout.
        if source_type == 'pointer' and target_type not in ('pointer', 'bool', 'c_bool', 'empty'):
            return True
    if kind in ('pointer_object', 'object_descriptor'):
        return True
    if kind == 'symbol' and expression.get('namedSub', {}).get('identifier', {}).get('id') in {
            '__CPROVER_POINTER_OBJECT', '__builtin_frame_address', '__builtin_return_address'}:
        return True
    return any(exposes_layout(operand) for operand in operands)


def sensitive_sites(functions):
    result = []
    for function in functions:
        name = function['name']
        occurrences = {}
        for index, instruction in enumerate(function.get('instructions', [])):
            reasons = []
            if instruction['instructionId'] in ('START_THREAD', 'END_THREAD', 'ATOMIC_BEGIN', 'ATOMIC_END'):
                reasons.append('concurrent or atomic execution requires a separate correspondence model')
            if not name.startswith('__vulgate_') and any(
                    exposes_layout(instruction.get(key, {})) for key in ('code', 'guard')):
                reasons.append('program observes address representation; structural PASS correspondence is insufficient')
            for reason in reasons:
                # Library linking removes SKIPs and query binding can prepend
                # assertions. Identify the actual sensitive operation rather
                # than its position among those unrelated instructions. Keep
                # repeated identical operations as separate obligations.
                payload = {'function': name, 'reason': reason,
                           'instruction': instruction['instructionId'],
                           **{key: instruction.get(key, {}) for key in ('sourceLocation', 'code', 'guard')}}
                content = json.dumps(payload, sort_keys=True, separators=(',', ':'))
                occurrence = occurrences.get(content, 0)
                occurrences[content] = occurrence + 1
                identity = sha256(json.dumps([payload, occurrence], sort_keys=True,
                                             separators=(',', ':')).encode()).hexdigest()
                result.append({'function': name, 'index': index, 'instruction': instruction['instructionId'],
                               'location': instruction.get('sourceLocation', {}), 'reason': reason,
                               'marker': '__VG_REACH_SENSITIVE:' + identity})
    return result
