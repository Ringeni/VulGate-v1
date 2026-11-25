from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import itertools
import re
from typing import Any, Callable

from tools.verification.shadow import code as irep_code, symbol_name


_EQ = re.compile(r'__vg_in_([A-Za-z_][A-Za-z0-9_]*)\s*==\s*(\d+)')
_LE = re.compile(r'__vg_in_([A-Za-z_][A-Za-z0-9_]*)\s*<=\s*(\d+)')
_GE = re.compile(r'__vg_in_([A-Za-z_][A-Za-z0-9_]*)\s*>=\s*(\d+)')
_NAME = re.compile(r'__vg_in_([A-Za-z_][A-Za-z0-9_]*)')
_NONDET = {
    '__vulgate_nondet_u64',
    '__vulgate_nondet_u8',
    '__vulgate_nondet_bool',
}

NO_HAZARD_ON_SEARCHED_POINTS = '已搜索点上未发现危险'
HYBRID_STAGE_TIMEOUT_SEC = 60


def _verify_body(driver: str) -> str:
    start = driver.find('void __vg_verify_obligations')
    if start < 0:
        return driver
    return driver[start:start + 6000]


def _default_domain(name: str) -> list[int]:
    lower = name.lower()
    if 'alias' in lower:
        return [0, 4]
    if any(token in lower for token in ('alloc', 'length', 'capacity', 'occupied', 'remaining', 'position', 'unread')):
        return [0, 4, 8, 16]
    if 'capture' in lower or lower.startswith('ncap'):
        return [0, 2, 4]
    return [0, 1]


def input_domains(driver: str) -> dict[str, list[int]]:
    body = _verify_body(driver)
    equals: dict[str, set[int]] = {}
    lowers: dict[str, int] = {}
    uppers: dict[str, int] = {}
    for name, raw in _EQ.findall(body):
        equals.setdefault(name, set()).add(int(raw))
    for name, raw in _GE.findall(body):
        value = int(raw)
        lowers[name] = value if name not in lowers else min(lowers[name], value)
    for name, raw in _LE.findall(body):
        value = int(raw)
        uppers[name] = value if name not in uppers else max(uppers[name], value)
    names = []
    for name in _NAME.findall(body):
        if name not in names:
            names.append(name)
    constrained = set(equals) | set(lowers) | set(uppers)
    domains: dict[str, list[int]] = {}
    for name in names:
        if name not in constrained:
            domains[name] = _default_domain(name)
            continue
        if name in equals and name not in lowers and name not in uppers:
            domains[name] = sorted(equals[name])
            continue
        low = lowers.get(name, 0)
        if name not in uppers:
            domains[name] = [low]
            continue
        high = uppers[name]
        if high < low:
            low, high = high, low
        if high - low <= 16:
            domains[name] = list(range(low, high + 1))
        else:
            domains[name] = sorted({low, high})
        if name in equals:
            domains[name] = sorted(set(domains[name]) | equals[name])
    return domains


def concrete_neighborhood(domains: dict[str, list[int]], product_limit: int = 24) -> list[dict[str, int]]:
    if not domains:
        return []
    product = 1
    for values in domains.values():
        product *= max(len(values), 1)
        if product > product_limit:
            break
    if product <= product_limit:
        names = list(domains)
        points = [
            dict(zip(names, combo))
            for combo in itertools.product(*(domains[name] for name in names))
        ]
    else:
        seed = {name: values[-1] for name, values in domains.items()}
        points = [dict(seed)]
        seen = {tuple(sorted(seed.items()))}
        for name, values in domains.items():
            ordered = list(values)
            current = seed[name]
            try:
                index = ordered.index(current)
            except ValueError:
                index = len(ordered) - 1
            chosen = {ordered[0], ordered[-1]}
            if index > 0:
                chosen.add(ordered[index - 1])
            if index + 1 < len(ordered):
                chosen.add(ordered[index + 1])
            for value in sorted(chosen):
                if value == current:
                    continue
                point = dict(seed)
                point[name] = value
                key = tuple(sorted(point.items()))
                if key in seen:
                    continue
                seen.add(key)
                points.append(point)
    return sorted(points, key=lambda item: sum(item.values()), reverse=True)


def _lhs_type(lhs: dict[str, Any]) -> dict[str, Any]:
    found = (lhs.get('namedSub') or {}).get('type')
    if isinstance(found, dict) and found.get('id'):
        return deepcopy(found)
    return {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}


def pin_concrete_assignments(functions: list[dict[str, Any]],
                             point: dict[str, int]) -> int:
    pinned = 0
    for fn in functions:
        for insn in fn.get('instructions') or []:
            if insn.get('instructionId') != 'FUNCTION_CALL':
                continue
            ops = (insn.get('code') or {}).get('sub') or []
            if len(ops) < 2 or ops[1].get('id') != 'symbol':
                continue
            callee = symbol_name(ops[1]).split('::')[-1]
            if callee not in _NONDET:
                continue
            lhs = ops[0]
            if not isinstance(lhs, dict) or lhs.get('id') in (None, 'nil'):
                continue
            value = 0
            if lhs.get('id') == 'symbol':
                base = symbol_name(lhs).split('::')[-1]
                if base.startswith('__vg_in_'):
                    value = int(point.get(base[len('__vg_in_'):], 0))
            constant = {
                'id': 'constant',
                'namedSub': {'type': _lhs_type(lhs), 'value': {'id': str(int(value))}},
            }
            insn['instructionId'] = 'ASSIGN'
            insn['code'] = irep_code('assign', [deepcopy(lhs), constant])
            insn.pop('targets', None)
            pinned += 1
    return pinned


def apply_searched_point_claim(status: str, neighborhood_clear: bool) -> str:
    if neighborhood_clear and status == 'PROVED_IN_BOUNDED_DOMAIN':
        return NO_HAZARD_ON_SEARCHED_POINTS
    return status


def successful_assertion_names(properties: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for prop in properties:
        if prop.get('status') != 'SUCCESS':
            continue
        text = str(prop.get('description') or prop.get('property') or '')
        if text and text not in names:
            names.append(text)
    return names


def searched_neighborhood_record(rows: list[dict[str, Any]], assertions: list[str], unwind: int) -> dict[str, Any]:
    points: list[dict[str, int]] = []
    for row in rows:
        if row.get('status') != 'completed':
            continue
        point = row.get('point')
        if isinstance(point, dict):
            points.append({str(key): int(value) for key, value in point.items()})
    names: list[str] = []
    for name in assertions:
        text = str(name)
        if text and text not in names:
            names.append(text)
    return {
        'claim': NO_HAZARD_ON_SEARCHED_POINTS,
        'unwind': int(unwind),
        'points': points,
        'assertions': names,
    }


def merge_hybrid_results(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [row for row in rows if row.get('status') == 'completed']
    failures = []
    for row in completed:
        for prop in row.get('properties') or []:
            if prop.get('status') == 'FAILURE':
                failures.append(prop)
    if failures:
        seen: set[str] = set()
        properties = []
        for prop in failures:
            key = str(prop.get('description') or prop.get('property') or '')
            if key in seen:
                continue
            seen.add(key)
            properties.append(prop)
        for row in completed:
            for prop in row.get('properties') or []:
                key = str(prop.get('description') or prop.get('property') or '')
                if key in seen or prop.get('status') == 'FAILURE':
                    continue
                seen.add(key)
                properties.append(prop)
        return {
            'status': 'completed',
            'properties': properties,
            'unwind_failures': [],
            'reason': 'hybrid_counterexample',
            'hybrid_neighborhood': True,
        }
    if len(completed) != len(rows) or not completed:
        reason = next((str(row.get('reason') or '') for row in rows if row.get('status') != 'completed'), 'hybrid_incomplete')
        return {
            'status': 'unresolved',
            'properties': [],
            'unwind_failures': [],
            'reason': reason or 'hybrid_incomplete',
            'hybrid_neighborhood': True,
        }
    properties = []
    seen = set()
    for prop in completed[0].get('properties') or []:
        key = str(prop.get('description') or prop.get('property') or '')
        if key in seen:
            continue
        if all(any((other.get('description') or other.get('property')) == (prop.get('description') or prop.get('property')) and other.get('status') == 'SUCCESS'
                   for other in (row.get('properties') or [])) for row in completed):
            seen.add(key)
            properties.append(prop)
    return {
        'status': 'completed' if properties else 'unresolved',
        'properties': properties,
        'unwind_failures': [],
        'reason': 'hybrid_neighborhood_clear' if properties else 'hybrid_no_properties',
        'hybrid_neighborhood': True,
    }


def run_hybrid_neighborhood(functions: list[dict[str, Any]],
                            symbols: dict[str, Any],
                            points: list[dict[str, int]],
                            work_dir: Path,
                            export_goto: Callable[..., dict[str, Any]],
                            run_query: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, point in enumerate(points):
        pinned_fns = deepcopy(functions)
        pinned_syms = deepcopy(symbols)
        replaced = pin_concrete_assignments(pinned_fns, point)
        point_dir = work_dir / f'point_{index:02d}'
        point_dir.mkdir(parents=True, exist_ok=True)
        goto_path = point_dir / 'pinned.goto'
        try:
            export_goto(pinned_fns, pinned_syms, goto_path, point_dir / 'export')
            solved = run_query(goto_path, point_dir / 'query')
        except Exception as exc:
            solved = {'status': 'unresolved', 'reason': type(exc).__name__, 'properties': []}
        solved = dict(solved)
        solved['point'] = point
        solved['pinned_nondet'] = replaced
        rows.append(solved)
        if any(prop.get('status') == 'FAILURE' for prop in solved.get('properties') or []):
            break
    merged = merge_hybrid_results(rows)
    merged['hybrid_points'] = [
        {
            'point': row.get('point'),
            'status': row.get('status'),
            'reason': row.get('reason'),
            'properties': len(row.get('properties') or []),
            'pinned_nondet': row.get('pinned_nondet'),
        }
        for row in rows
    ]
    return merged
