"""Qualify compiler-proposed indirect call targets with explicit obligations."""
from copy import deepcopy
import json

from .source import sha256
from .spec import SpecificationError
from .typed_transport import FULL, copy_location


MARKER = '__VG_INDIRECT_TARGET:'


def has_indirect_calls(functions):
    return any(i.get('instructionId') == 'FUNCTION_CALL' and
               len(i.get('code', {}).get('sub', [])) >= 2 and
               i['code']['sub'][1].get('id') != 'symbol'
               for f in functions for i in f.get('instructions', []))


def mark_target_checks(functions, *, transport_mode=FULL):
    """Name every target-set assertion emitted by function-pointer removal.

    The native pass retains the original pointer dereference and generates an
    assertion before truncating a path outside its proposed target set. Stable
    unique descriptions let result qualification require *every* such check,
    including unreachable call sites and the broad fallback target sets.
    """
    evidence = []
    for function in functions:
        for index, instruction in enumerate(function.get('instructions', [])):
            location = instruction.get('sourceLocation', {})
            description = location.get('comment', '')
            if (instruction.get('instructionId') != 'ASSERT' or
                    location.get('propertyClass') != 'pointer dereference' or
                    not (description.startswith('dereferenced function pointer must be ') or
                         description == 'no candidates for dereferenced function pointer')):
                continue
            record = {'function': function['name'], 'index': index,
                      'location': deepcopy(location), 'description': description}
            marker = MARKER + sha256(json.dumps(record, sort_keys=True, separators=(',', ':')).encode())
            evidence.append({**record, 'marker': marker})
            copy_location(instruction, instruction, mode=transport_mode,
                          updates={'comment': marker}, remove=('propertyId',), create_from_nil=True)
    if not evidence or has_indirect_calls(functions):
        raise SpecificationError('indirect-call transformation did not provide a complete set of target checks')
    return evidence


def qualify_targets(report, evidence):
    """A failed proposal cannot become a program or policy counterexample."""
    report = deepcopy(report)
    observed = {}
    for prop in report.get('properties', []):
        if prop.get('description', '').startswith(MARKER):
            observed.setdefault(prop['description'], []).append(prop.get('status'))
    expected = {item['marker'] for item in evidence}
    reasons = []
    if set(observed) != expected:
        reasons.append('indirect-call target assertions are missing or unrecorded')
    if any(status != 'SUCCESS' for values in observed.values() for status in values):
        reasons.append('an indirect-call target proposal is incomplete or unproved')
    if evidence and report.get('completeness') != 'COMPLETE_FOR_HARNESS':
        reasons.append('indirect-call target proof has incomplete execution semantics')
    report['indirect_call_targets'] = {
        'status': 'UNKNOWN' if reasons else 'PROVED_FOR_HARNESS',
        'method': 'Compiler value-set proposals with checked target-set assertions and broad fallback.',
        'sites': [{**item, 'statuses': observed.get(item['marker'], [])} for item in evidence],
        'reasons': reasons,
    }
    if reasons:
        keys = ('status', 'target', 'contracts_and_runtime_checks', 'initialization', 'completeness')
        report['indirect_call_targets']['abstract_model_statuses'] = {key: report.get(key) for key in keys}
        report.update({key: 'UNKNOWN' for key in keys})
        report['reachability'] = {key: 'UNKNOWN' for key in report.get('reachability', {})}
        report.setdefault('reasons', []).extend(reasons)
    return report
