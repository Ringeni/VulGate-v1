from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path
import re
import struct
import subprocess
import time
from typing import Any

from tools.verification.source import functions as parse_c_functions

from tools.verification.typed_transport import FULL, TransportError
from .expressions import c_expression, evaluate, parse, policy_reference_c, predicates
from .driver_synth import synthesize_paired_goto_driver_c
from .paired_goto import apply_paired_weaves, clone_dual_world_goto, finalize_and_export_goto
from .planner import (
    _reachable_from,
    build_enhanced_icfg,
    load_typed_goto_model,
    continuation_closure_blocks_proof,
    limit_claim_to_activated_path,
    plan_verification_boundaries,
    resolve_ir_function_names,
    static_globals_referenced,
)
from .snapshot_lifter import lift_snapshot_to_abstract_spec

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_EXPERIMENT = ROOT / 'runtime/experiment'


def map_full_flag(name: str) -> str:
    return f'__vulgate_map_full_{name}'


def render_map_table_helpers(name: str, capacity: int, on_full: str) -> list[str]:
    lines = [
        f'vg_slot __vulgate_map_slots_{name}[{capacity}] = {{{{0}}}};',
        f'vg_table __vulgate_map_{name} = {{{capacity}, 0, __vulgate_map_slots_{name}}};',
    ]
    if on_full == 'block':
        flag = map_full_flag(name)
        lines.append(f'_Bool {flag} = 0;')
        lines.append(
            f'int __vulgate_table_set_{name}(uint64_t scope, uint64_t key, uint64_t val) {{'
            f' int __vg_set_status = vg_table_set(&__vulgate_map_{name}, scope, key, val);'
            f' if (__vg_set_status != 0) {flag} = 1;'
            f' return __vg_set_status; }}'
        )
        lines.append(
            f'void __vulgate_table_del_{name}(uint64_t scope, uint64_t key) {{'
            f' vg_table_delete(&__vulgate_map_{name}, scope, key);'
            f' {flag} = 0; }}'
        )
    else:
        lines.append(
            f'int __vulgate_table_set_{name}(uint64_t scope, uint64_t key, uint64_t val) {{'
            f' return vg_table_set(&__vulgate_map_{name}, scope, key, val); }}'
        )
        lines.append(
            f'void __vulgate_table_del_{name}(uint64_t scope, uint64_t key) {{'
            f' vg_table_delete(&__vulgate_map_{name}, scope, key); }}'
        )
    lines.append(
        f'int __vulgate_table_get_{name}(uint64_t scope, uint64_t key, uint64_t *out, int consume) {{'
        f' return vg_table_get(&__vulgate_map_{name}, scope, key, out, consume); }}'
    )
    lines.append(
        f'int __vulgate_table_get_words_{name}(uint64_t scope, const uint64_t *key, unsigned key_words,'
        f' uint64_t *out, unsigned nfields, int consume) {{'
        f' return vg_table_get_words(&__vulgate_map_{name}, scope, key, key_words, out, nfields, consume); }}'
    )
    flag_stmt = ''
    if on_full == 'block':
        flag_stmt = f' if (__vg_set_status != 0) {map_full_flag(name)} = 1;'
    lines.append(
        f'int __vulgate_table_set_words_{name}(uint64_t scope,'
        f' uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3, unsigned key_words,'
        f' uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3, unsigned nfields) {{'
        f' uint64_t __vg_kw[4] = {{k0, k1, k2, k3}};'
        f' uint64_t __vg_vw[4] = {{v0, v1, v2, v3}};'
        f' int __vg_set_status = vg_table_set_words(&__vulgate_map_{name}, scope, __vg_kw, key_words, __vg_vw, nfields);'
        f'{flag_stmt} return __vg_set_status; }}'
    )
    clear_stmt = f' {map_full_flag(name)} = 0;' if on_full == 'block' else ''
    lines.append(
        f'void __vulgate_table_del_words_{name}(uint64_t scope,'
        f' uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3, unsigned key_words) {{'
        f' uint64_t __vg_kw[4] = {{k0, k1, k2, k3}};'
        f' vg_table_delete_words(&__vulgate_map_{name}, scope, __vg_kw, key_words);'
        f'{clear_stmt} }}'
    )
    return lines


def structured_map_load_lines(read: dict[str, Any], param_names: list[str], ordinal: int) -> list[str]:
    words = int(read.get('words') or 1)
    if words <= 1:
        return []
    components = list(read.get('key_components') or [])
    if not components and 'key_arg' in read:
        components = [{'arg': int(read['key_arg'])}]
    if not components:
        components = [{'scope': True}]
    key_words = len(components)
    present = int(read['present_slot'])
    slots = [int(slot) for slot in read.get('word_slots') or []]
    name = read['map']
    lines = [
        f'uint64_t __vg_key_{ordinal}[{key_words}];',
        f'uint64_t __vg_words_{ordinal}[4] = {{0}};',
    ]
    for index, comp in enumerate(components):
        if comp.get('scope'):
            expr = '0'
        elif comp.get('name') in param_names:
            expr = f'(uint64_t)(uintptr_t){comp["name"]}'
        elif 'arg' in comp and int(comp['arg']) < len(param_names):
            expr = f'(uint64_t)(uintptr_t){param_names[int(comp["arg"])]}'
        else:
            expr = '0'
        lines.append(f'__vg_key_{ordinal}[{index}] = {expr};')
    lines.append(
        f'int __vg_mfound_{ordinal} = __vulgate_table_get_words_{name}(0, __vg_key_{ordinal}, {key_words},'
        f' __vg_words_{ordinal}, {words}, {1 if read.get("consume") else 0});'
    )
    lines.append(f'ctx.regs[{present}] = (uint64_t)__vg_mfound_{ordinal};')
    for index, slot in enumerate(slots):
        lines.append(
            f'ctx.regs[{slot}] = __vg_mfound_{ordinal} ? __vg_words_{ordinal}[{index}] : 0;'
        )
    if read.get('on_missing') != 'pass':
        lines.append(f'if (!__vg_mfound_{ordinal}) return 1;')
    return lines


def map_full_block_lines(case_ir: dict[str, Any], guard: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    maps = case_ir.get('maps') or {}
    for read in guard.get('map_reads') or []:
        name = str(read.get('map') or '')
        if not name or name in seen:
            continue
        if str((maps.get(name) or {}).get('on_full') or '') != 'block':
            continue
        seen.add(name)
        lines.append(f'if ({map_full_flag(name)}) return 1;')
    return lines


def declare_unlinked_snapshot_symbols(driver_path: Path, stderr: str) -> list[str]:
    names = re.findall(r"failed to find symbol '([A-Za-z_][A-Za-z0-9_]*)'", stderr or '')
    text = driver_path.read_text(encoding='utf-8')
    stubs: list[str] = []
    added: list[str] = []
    for name in dict.fromkeys(names):
        if not re.search(rf'&{re.escape(name)}\b', text):
            continue
        if re.search(rf'\bstatic\s+void\s+{re.escape(name)}\s*\(\s*void\s*\)', text):
            continue
        stubs.append(f'static void {name}(void) {{}}')
        added.append(name)
    if not stubs:
        return []
    block = '\n'.join(stubs) + '\n'
    anchor = 'extern _Bool __vulgate_nondet_bool(void);\n'
    if anchor in text:
        text = text.replace(anchor, anchor + '\n' + block, 1)
    else:
        text = block + text
    driver_path.write_text(text, encoding='utf-8')
    return added


def symbolization_constraints(case_ir: dict[str, Any],
                              abstract: dict[str, Any] | None) -> dict[str, Any]:
    scope = case_ir.get('symbolization_scope') or {}
    record: dict[str, Any] = {
        'pin_concrete': [str(item) for item in (scope.get('pin_concrete') or []) if str(item)],
        'force_symbolic': [str(item) for item in (scope.get('force_symbolic') or []) if str(item)],
    }
    if not abstract:
        return record
    record['symbolic_fields'] = [
        f"{item.get('object_id')}.{item.get('field')}"
        for item in (abstract.get('symbolic_scalars') or [])
        if isinstance(item, dict) and item.get('object_id') and item.get('field')
    ]
    record['symbolic_buffers'] = [
        str(item.get('object_id'))
        for item in (abstract.get('symbolic_buffers') or [])
        if isinstance(item, dict) and item.get('object_id')
    ]
    constants = abstract.get('concrete_constants') or {}
    record['concrete_fields'] = sorted(str(key) for key in constants) if isinstance(constants, dict) else []
    return record


def _verification_scope_kind(explicit: str | None, lift_mode: str | None) -> str:
    if explicit:
        return explicit
    if lift_mode == 'poc_or_seed_snapshot_lifted':
        return 'snapshot_neighborhood'
    return 'operation_bounded'


def _cbmc_entry_flags(entry: str) -> list[str]:
    return ['--function', entry]


def _obligation_query_flags(case_ir: dict[str, Any]) -> list[str]:
    from .oracle_compiler import arithmetic_query_flags
    return [*_cbmc_entry_flags('__vg_verify_obligations'), *arithmetic_query_flags(case_ir)]


def _slice_compile_flags(case_ir: dict[str, Any]) -> tuple[list[Path], list[str]]:
    sym_cfg = case_ir['app_profile'].get('symbolic_slice', {})
    case_sym_cfg = case_ir.get('symbolization_scope', {})
    slice_sources = [Path(p).resolve() for p in case_sym_cfg.get('slice_sources', sym_cfg.get('slice_sources', []))]
    include_dirs = [Path(p).resolve() for p in [*sym_cfg.get('include_dirs', []), *case_sym_cfg.get('include_dirs', [])]]
    defines = [*sym_cfg.get('defines', []), *case_sym_cfg.get('defines', [])]
    flags = [f'-I{ROOT / "runtime"}']
    flags += [f'-I{inc}' for inc in include_dirs]
    flags += [f'-D{d}' for d in defines]
    return slice_sources, flags


def declared_translation_units(case_ir: dict[str, Any]) -> list[Path]:
    profile = case_ir.get('app_profile') or {}
    source = ((profile.get('builds') or {}).get('baseline') or {}).get('source_dir')
    if not source:
        return []
    root = Path(str(source))
    rels: list[str] = []
    anchors = case_ir.get('defect_anchors') or {}
    for key in ('sink_site', 'root_cause_site'):
        site = anchors.get(key) or {}
        if site.get('file'):
            rels.append(str(site['file']))
    for guard in case_ir.get('guards') or []:
        if guard.get('source_file'):
            rels.append(str(guard['source_file']))
    listed = {
        Path(item).resolve()
        for item in (case_ir.get('symbolization_scope') or {}).get('slice_sources', [])
        if Path(item).exists()
    }
    listed |= {
        Path(item).resolve()
        for item in (profile.get('symbolic_slice') or {}).get('slice_sources', [])
        if Path(item).exists()
    }
    found: list[Path] = []
    seen: set[Path] = set()
    for rel in rels:
        path = Path(rel)
        if not path.is_absolute():
            path = root / rel
        if path.suffix not in {'.c', '.C'} or not path.is_file():
            continue
        path = path.resolve()
        if path in seen or path in listed:
            continue
        seen.add(path)
        found.append(path)
    return found


def admit_compilable_translations(candidates: list[Path],
                                  flags: list[str],
                                  goto_cc: Path,
                                  output_dir: Path,
                                  timeout: int) -> tuple[list[Path], list[dict[str, str]]]:
    accepted: list[Path] = []
    rejected: list[dict[str, str]] = []
    probe = output_dir / 'slice-probe'
    probe.mkdir(parents=True, exist_ok=True)
    for path in candidates:
        dest = probe / f'{path.stem}.goto'
        try:
            subprocess.run(
                [str(goto_cc), *flags, str(path), '-o', str(dest)],
                check=True,
                timeout=max(int(timeout), 1),
                capture_output=True,
                text=True,
            )
            accepted.append(path)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            err = getattr(exc, 'stderr', None) or getattr(exc, 'stdout', None) or str(exc)
            rejected.append({'path': str(path), 'error': str(err)[-500:]})
    (output_dir / 'slice-admission.json').write_text(
        json.dumps({'accepted': [str(path) for path in accepted], 'rejected': rejected}, indent=2) + '\n',
        encoding='utf-8',
    )
    return accepted, rejected


def prescan_static_globals(case_ir: dict[str, Any], cbmc_bin: Path, output_dir: Path) -> list[str]:
    slice_sources, flags = _slice_compile_flags(case_ir)
    if not slice_sources:
        return []
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    goto_cc = cbmc_bin.parent / 'goto-cc'
    goto_instrument = cbmc_bin.parent / 'goto-instrument'
    prescan_goto = output_dir / 'slice_prescan.goto'
    try:
        subprocess.run(
            [str(goto_cc), *flags, *[str(path) for path in slice_sources], '-o', str(prescan_goto)],
            check=True,
            timeout=max(int(case_ir['budgets']['solver_timeout_sec']), 180),
            capture_output=True,
            text=True,
        )
        functions, symbols = load_typed_goto_model(
            prescan_goto, goto_instrument, output_dir / 'inspect', timeout=180,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return []
    icfg = build_enhanced_icfg(functions, symbols)
    seeds: list[str] = []
    root_fn = ((case_ir.get('defect_anchors') or {}).get('root_cause_site') or {}).get('function')
    if root_fn:
        seeds.append(str(root_fn))
    for guard in case_ir.get('guards') or []:
        if guard.get('function'):
            seeds.append(str(guard['function']))
    subtree: set[str] = set()
    for seed in seeds:
        for ir_name in resolve_ir_function_names(icfg, seed):
            subtree |= _reachable_from(icfg, ir_name)
    if not subtree:
        subtree = {fn['name'] for fn in functions if fn.get('isBodyAvailable')}
    return static_globals_referenced(functions, symbols, subtree)


def initial_object_bits(driver_text: str) -> int:
    count = len(set(re.findall(r'__vulgate_snap_w0_obj_[A-Za-z0-9_]+', driver_text)))
    if count >= 40:
        return 14
    if count >= 16:
        return 11
    return 8


def _wider_object_bits(reason: str, object_bits: int) -> int | None:
    if object_bits >= 14 or 'too many addressed objects' not in reason:
        return None
    return min(14, object_bits + 3)


def _run_cbmc_json_once(goto_binary: Path,
                   cbmc_bin: Path,
                   work_dir: Path,
                   unwind: int = 32,
                   object_bits: int = 8,
                   timeout: int = 120,
                   extra_flags: list[str] | None = None) -> dict[str, Any]:
    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(cbmc_bin),
        str(goto_binary),
        '--json-ui',
        '--trace',
        '--unwind', str(unwind),
        '--object-bits', str(object_bits),
        '--unwinding-assertions',
        '--bounds-check',
        '--pointer-check',
        '--pointer-overflow-check',
        '--div-by-zero-check',
        '--signed-overflow-check',
        '--undefined-shift-check',
        '--slice-formula',
        '--verbosity', '1',
        *(extra_flags or []),
    ]
    (work_dir / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n', encoding='utf-8')
    stdout_path = work_dir / 'stdout.json'
    stderr_path = work_dir / 'stderr.log'
    started = time.monotonic()
    try:
        with stdout_path.open('w', encoding='utf-8') as out, stderr_path.open('w', encoding='utf-8') as err:
            proc = subprocess.run(cmd, stdout=out, stderr=err, timeout=timeout)
        messages = json.loads(stdout_path.read_text(encoding='utf-8'))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return {
            'status': 'unresolved',
            'reason': type(exc).__name__,
            'seconds': time.monotonic() - started,
            'properties': [],
            'witness': {},
        }

    elapsed = time.monotonic() - started
    errors = [m.get('messageText', 'error') for m in messages if m.get('messageType') == 'ERROR']
    if errors or proc.returncode not in (0, 10):
        return {
            'status': 'unresolved',
            'reason': '; '.join(errors) if errors else f'cbmc_exit_{proc.returncode}',
            'seconds': elapsed,
            'properties': [],
            'witness': {},
        }

    props = [p for m in messages for p in m.get('result', [])]
    unwind_failures = [
        p for p in props
        if p.get('status') == 'FAILURE' and ('.unwind.' in p.get('property', '') or '.recursion.' in p.get('property', ''))
    ]
    return {
        'status': 'completed',
        'returncode': proc.returncode,
        'seconds': elapsed,
        'properties': props,
        'unwind_failures': unwind_failures,
        'object_bits': object_bits,
    }


def _run_cbmc_json(goto_binary: Path,
                   cbmc_bin: Path,
                   work_dir: Path,
                   unwind: int = 32,
                   object_bits: int = 8,
                   timeout: int = 120,
                   extra_flags: list[str] | None = None) -> dict[str, Any]:
    bits = object_bits
    directory = Path(work_dir)
    while True:
        result = _run_cbmc_json_once(
            goto_binary, cbmc_bin, directory,
            unwind=unwind, object_bits=bits, timeout=timeout, extra_flags=extra_flags,
        )
        wider = _wider_object_bits(str(result.get('reason') or ''), bits)
        if wider is None:
            result['object_bits'] = bits
            return result
        bits = wider
        directory = Path(str(work_dir) + f'_ob{bits}')


def _harness_bridge_functions(functions: list[dict[str, Any]],
                              symbols: dict[str, Any],
                              subtree_functions: list[str]) -> list[str]:
    icfg = build_enhanced_icfg(functions, symbols)
    subtree = set(subtree_functions)
    reached: set[str] = set()
    for root in ('__vg_run_world_0', '__vg_run_world_1'):
        if root in icfg['functions_by_name']:
            frontier = [root]
            seen_walk = {root}
            while frontier:
                cur = frontier.pop()
                edge_map = icfg.get('concrete_callees_of') or icfg['callees_of']
                for nxt in edge_map.get(cur, ()):
                    if nxt not in seen_walk:
                        seen_walk.add(nxt)
                        reached.add(nxt)
                        frontier.append(nxt)
    candidates: set[str] = set()
    for name in reached:
        if name in subtree or name.startswith(('__CPROVER_', '__vulgate_', '__vg_run_', '__vg_verify', '__vg_impact')):
            continue
        loc_file = symbols.get(name, {}).get('location', {}).get('file', '')
        if loc_file.startswith('<builtin-library-'):
            continue
        fn = icfg['functions_by_name'].get(name)
        if not fn or not fn.get('isBodyAvailable'):
            continue
        candidates.add(name)
    bridges: list[str] = []
    seen: set[str] = set()
    queue: list[str] = []
    for name in subtree:
        caller_map = icfg.get('concrete_callers_of') or icfg['callers_of']
        for caller in caller_map.get(name, ()):
            if caller in candidates and caller not in seen:
                seen.add(caller)
                queue.append(caller)
    while queue:
        cur = queue.pop()
        bridges.append(cur)
        for caller in caller_map.get(cur, ()):
            if caller in candidates and caller not in seen:
                seen.add(caller)
                queue.append(caller)
    bridges.sort()
    return bridges


def _parse_scalar(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == 'true':
            return 1
        if lowered == 'false':
            return 0
        try:
            return int(value, 0)
        except ValueError:
            return None
    if isinstance(value, dict):
        if 'data' in value:
            return _parse_scalar(value['data'])
        if 'binary' in value:
            try:
                return int(str(value['binary']), 2)
            except ValueError:
                return None
        if 'value' in value:
            return _parse_scalar(value['value'])
    return None


def _step_scalar(step: dict[str, Any]) -> int | None:
    for key in ('value', 'lhsValue'):
        if key in step:
            parsed = _parse_scalar(step[key])
            if parsed is not None:
                return parsed
    return None


def _step_function(step: dict[str, Any]) -> str:
    function = step.get('function') or {}
    if isinstance(function, dict):
        name = function.get('displayName') or function.get('identifier') or ''
        if name:
            return str(name)
    return str((step.get('sourceLocation') or {}).get('function') or '')


def _is_harness_frame(name: str) -> bool:
    base = name.split('::')[-1]
    return base.startswith('__') or base in ('main', 'run_ebpf_vm')


def _counterexample_kind(description: str) -> str:
    text = description.lower()
    if 'initialized_read' in text or 'uninitialized' in text:
        return 'uninitialized_read'
    if 'action_write' in text:
        return 'action_write'
    if 'output_pointer' in text or 'continuation' in text or 'loop_exit' in text or 'brigade' in text or 'allocator_lifetime' in text:
        return 'continuation'
    if 'missing_callee' in text:
        return 'missing_callee'
    if any(token in text for token in ('pointer', 'bounds', 'overflow', 'dereference', 'array bounds')):
        return 'memory_bounds'
    return 'other'


def counterexample_site(prop: dict[str, Any]) -> dict[str, Any]:
    stack: list[str] = []
    blocked = False
    failure: dict[str, Any] | None = None
    for step in prop.get('trace') or []:
        if not isinstance(step, dict):
            continue
        kind = step.get('stepType')
        if kind == 'function-call':
            name = _step_function(step)
            if name:
                stack.append(name)
            continue
        if kind == 'function-return':
            if stack:
                stack.pop()
            continue
        if kind == 'assignment':
            lhs = str(step.get('lhs') or '')
            value = _step_scalar(step)
            if value not in (None, 0) and ('__vulgate_any_blocked' in lhs or '__vg_guard_decision' in lhs):
                blocked = True
            continue
        if kind == 'failure':
            failure = step
    location = (failure or {}).get('sourceLocation') or prop.get('sourceLocation') or {}
    function = str(location.get('function') or '')
    frames = [name for name in stack if not _is_harness_frame(name)]
    base = function.split('::')[-1]
    caller = function
    if base and any(name.split('::')[-1] == base for name in frames):
        caller = next(name for name in reversed(frames) if name.split('::')[-1] == base)
    else:
        for name in reversed(frames):
            if name.split('::')[-1] != base:
                caller = name
                break
    return {
        'caller': caller,
        'function': function,
        'file': str(location.get('file') or ''),
        'line': str(location.get('line') or ''),
        'after_block': blocked,
        'kind': _counterexample_kind(str(prop.get('description') or '')),
    }


def _failure_frames(prop: dict[str, Any]) -> list[str]:
    stack: list[str] = []
    captured: list[str] | None = None
    for step in prop.get('trace') or []:
        if not isinstance(step, dict):
            continue
        kind = step.get('stepType')
        if kind == 'function-call':
            name = _step_function(step)
            if name:
                stack.append(name)
            continue
        if kind == 'function-return':
            if stack:
                stack.pop()
            continue
        if kind == 'failure':
            captured = list(stack)
            loc = str((step.get('sourceLocation') or {}).get('function') or '')
            if loc:
                captured.append(loc)
    if captured is None:
        loc = str((prop.get('sourceLocation') or {}).get('function') or '')
        captured = [loc] if loc else []
    return captured


def _baseline_only_failure(prop: dict[str, Any]) -> bool:
    frames = _failure_frames(prop)
    has_w0 = any('__vg_w0_' in name for name in frames)
    has_w1 = any('__vg_w1_' in name for name in frames)
    return has_w0 and not has_w1


def classify_impact_query_result(properties: list[dict[str, Any]]) -> dict[str, Any]:
    q_props = [p for p in properties if p.get('description') == 'vg.impact.query']
    aux_fail = [
        p for p in properties
        if p.get('description') != 'vg.impact.query' and p.get('status') == 'FAILURE'
    ]
    if len(q_props) != 1:
        return {'status': 'unresolved', 'witness': {}}
    baseline_only = [p for p in aux_fail if _baseline_only_failure(p)]
    if any(p not in baseline_only for p in aux_fail):
        return {'status': 'unresolved', 'witness': {}}
    if q_props[0].get('status') == 'SUCCESS':
        return {'status': 'unsat', 'witness': {}}
    if q_props[0].get('status') == 'FAILURE' and not baseline_only:
        return {'status': 'sat', 'witness': _extract_trace_witness(q_props[0])}
    return {'status': 'unresolved', 'witness': {}}


def _extract_trace_witness(prop: dict[str, Any], prefix: str = '__vg_in_') -> dict[str, int]:
    witness: dict[str, int] = {}
    for step in prop.get('trace', []):
        lhs = step.get('lhs', '')
        if lhs.startswith(prefix):
            val = step.get('value', {})
            try:
                if 'binary' in val:
                    witness[lhs[len(prefix):]] = int(val['binary'], 2)
                elif 'data' in val:
                    witness[lhs[len(prefix):]] = int(str(val['data']), 0)
            except (ValueError, TypeError):
                continue
    return witness


def render_vm_equivalence_check(policy_src: str,
                                fields: dict[str, Any],
                                expr_map: dict[str, str],
                                has_backedge: bool) -> dict[str, Any]:
    is_single_expr = not any(tok in policy_src for tok in ('\n', ';', 'for ', 'BLOCK(', 'read_u'))
    step_assert = '__CPROVER_assert(stats.instructions <= policy.step_limit + 1ULL, "vg.vm.step_bound");'
    strict_mem = (
        'int safe_read(void *d, const void *s, size_t n) { (void)d; (void)s; (void)n; '
        '__CPROVER_assert(0, "vg.vm.unexpected_safe_read"); return -1; }'
    )
    if is_single_expr and not has_backedge:
        c_pred = c_expression(parse(policy_src, fields), expr_map)
        return {
            'mode': 'scalar_predicate',
            'prelude': '',
            'check_stmt': f'__CPROVER_assert(((decision == SHADOW_BLOCK) == !!({c_pred})), "vg.vm.equivalence");',
            'step_assert': step_assert,
            'mem_stub': strict_mem,
            'summary_expr': c_expression(parse(policy_src, fields), {k: f'__vg_f_{k}' for k in fields}),
        }
    reference = policy_reference_c(policy_src, expr_map)
    if reference:
        return {
            'mode': 'statement_reference',
            'prelude': reference,
            'check_stmt': '__CPROVER_assert((decision == SHADOW_BLOCK) == vg_ref_block, "vg.vm.equivalence");',
            'step_assert': step_assert,
            'mem_stub': strict_mem,
            'summary_expr': None,
        }
    return {
        'mode': 'decision_kind',
        'prelude': '',
        'check_stmt': '__CPROVER_assert(decision == SHADOW_PASS || decision == SHADOW_BLOCK || decision == SHADOW_UNKNOWN, "vg.vm.equivalence");',
        'step_assert': step_assert,
        'mem_stub': (
            'extern uint8_t nondet_vg_u8(void); extern int nondet_vg_rc(void);\n'
            'int safe_read(void *d, const void *s, size_t n) {\n'
            '  if (!d || !s || n > 8) return -1;\n'
            '  if (nondet_vg_rc()) return -1;\n'
            '  uint8_t *p = (uint8_t *)d; for (size_t i = 0; i < n; ++i) p[i] = nondet_vg_u8();\n'
            '  return 0;\n}'
        ),
        'summary_expr': None,
    }


def verify_vm_bytecode_equivalence(guard_ir: dict[str, Any],
                                   cbmc_bin: Path,
                                   output_dir: Path,
                                   timeout: int = 90) -> dict[str, Any]:
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = Path(guard_ir['rule_path']).read_bytes()
    rows = list(struct.iter_unpack('<BBhi', raw))
    fields = guard_ir['fields']
    policy_src = guard_ir['policy_source']

    has_backedge = any(((op & 0x07) in (0x05, 0x06)) and op not in (0x85, 0x95) and off < 0 for op, _, off, _ in rows)

    names = {name: f'__vg_in_{name}' for name in fields if 'constant' not in fields[name]}
    decls = '\n'.join(f'uint64_t {v};' for v in names.values())
    inits = '\n'.join(f'{v} = nondet_vg_u64();' for v in names.values())
    ctx_binds = []
    expr_map: dict[str, str] = {}
    for fname, fbind in fields.items():
        if 'constant' in fbind:
            expr_map[fname] = f'UINT64_C({int(fbind["constant"])})'
        else:
            dest = ('args' if fbind['source'] == 'arg' else 'regs') + f'[{int(fbind["index"])}]'
            ctx_binds.append(f'ctx.{dest} = {names[fname]};')
            expr_map[fname] = f'ctx.{dest}'

    insn_rows = ',\n'.join('{%d,%d,%d,%d}' % r for r in rows)
    rendered = render_vm_equivalence_check(policy_src, fields, expr_map, has_backedge)
    check_stmt = rendered['check_stmt']
    mem_stub = rendered['mem_stub']
    prelude = rendered['prelude']

    step_bound_estimate = len(rows) + 4
    for idx, (op, _, off, _) in enumerate(rows):
        if ((op & 0x07) in (0x05, 0x06)) and op not in (0x85, 0x95) and off < 0:
            target = idx + 1 + off
            bound_imm = rows[target - 1][3] if target >= 1 else 64
            step_bound_estimate += max(1, bound_imm) * (idx - target + 2)

    step_limit = max(int(guard_ir.get('step_limit', 4096)), step_bound_estimate + 8)
    c_code = f'''#include "autoshield.h"
extern uint64_t nondet_vg_u64(void);
{mem_stub}
{decls}
static const ebpf_insn vg_insns[] = {{
{insn_rows}
}};
int main(void) {{
    {inits}
    shadow_ctx ctx = {{0}};
    {' '.join(ctx_binds)}
    shadow_program program = {{vg_insns, {len(rows)}, 0, 0}};
    shadow_policy policy = {{{step_limit}ULL, SHADOW_UNKNOWN_BLOCK, 0}};
    shadow_stats stats;
    {prelude}
    shadow_decision decision = run_ebpf_vm(&ctx, &program, &policy, &stats);
    __CPROVER_assert(decision != SHADOW_VM_ERROR, "vg.vm.no_vm_error");
    {rendered['step_assert']}
    {check_stmt}
    return 0;
}}
#include "{ROOT / 'runtime/vm.c'}"
'''
    src_file = output_dir / 'vm_equiv.c'
    goto_file = output_dir / 'vm_equiv.goto'
    reduced_goto = output_dir / 'vm_equiv.reduced.goto'
    src_file.write_text(c_code, encoding='utf-8')
    tool_dir = cbmc_bin.parent
    subprocess.run([str(tool_dir / 'goto-cc'), str(src_file), '-I', str(ROOT / 'runtime'), '-o', str(goto_file)],
                   check=True, timeout=timeout, capture_output=True, text=True)
    subprocess.run([str(tool_dir / 'goto-instrument'), '--drop-unused-functions', '--slice-global-inits',
                    str(goto_file), str(reduced_goto)],
                   check=True, timeout=timeout, capture_output=True, text=True)
    res = _run_cbmc_json(
        reduced_goto, cbmc_bin, output_dir,
        unwind=step_bound_estimate + 4, timeout=timeout,
        extra_flags=['--paths', 'lifo'],
    )
    if res['status'] != 'completed' or res['unwind_failures']:
        status = 'UNRESOLVED'
    elif any(p.get('status') == 'FAILURE' for p in res['properties']):
        status = 'VIOLATED'
    else:
        status = 'PROVED'
    summary = {
        'guard_id': guard_ir['id'],
        'status': status,
        'checked_properties': len(res.get('properties', [])),
        'bytecode_instructions': len(rows),
        'has_bounded_loops': has_backedge,
        'equivalence_mode': rendered['mode'],
        'proved_c_summary': rendered['summary_expr'] if status == 'PROVED' else None,
        'seconds': res.get('seconds', 0.0),
    }
    (output_dir / 'vm-equivalence.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary


_SELECTOR_CTYPE = {
    'pointer': 'uintptr_t', 'u64': 'uint64_t', 's64': 'int64_t',
    'u32': 'uint32_t', 's32': 'int32_t', 'u16': 'uint16_t',
    's16': 'int16_t', 'u8': 'uint8_t', 's8': 'int8_t',
}


def _selector_c_expr(sel: dict[str, Any], param_names: list[str], w1_prefix: str = '__vg_w1_') -> tuple[str, list[str]]:
    del w1_prefix
    safety_checks: list[str] = []
    if 'constant' in sel and not sel.get('reads'):
        return f'UINT64_C({int(sel["constant"])})', safety_checks
    if 'c_expr' in sel and not sel.get('reads'):
        return f'((uint64_t)({sel["c_expr"]}))', safety_checks
    if 'arg' in sel:
        idx = int(sel['arg'])
        base = f'((uintptr_t)({param_names[idx]}))'
    elif 'global' in sel:
        global_ref = sel['global'] if isinstance(sel['global'], dict) else {}
        symbol = global_ref.get('symbol_c_name')
        if not symbol:
            raise ValueError('raw ELF offset global selector requires symbol name or c_expr for source-level GOTO')
        base = f'((uintptr_t)(void *)&{symbol})'
    elif 'constant' in sel:
        base = f'UINT64_C({int(sel["constant"])})'
    else:
        return '0ULL', safety_checks

    curr = base
    for step in sel.get('reads', []):
        off = int(step.get('offset', 0))
        addr = f'({curr} + {off}ULL)'
        if 'index' in step:
            idx_expr, sub_checks = _selector_c_expr(step['index'], param_names)
            safety_checks.extend(sub_checks)
            stride = int(step.get('stride', 8))
            limit = int(step.get('index_limit', 4096))
            safety_checks.append(
                f'if ((int64_t)({idx_expr}) < 0 || (uint64_t)({idx_expr}) >= {limit}ULL) return 1;'
            )
            addr = f'({addr} + ({idx_expr}) * {stride}ULL)'
        ctype = _SELECTOR_CTYPE[step['type']]
        safety_checks.append(
            f'if (!__CPROVER_r_ok((const void *)(uintptr_t)({addr}), sizeof({ctype}))) return 1;'
        )
        curr = f'((uint64_t)(*({ctype} *)(uintptr_t)({addr})))'
    return curr, safety_checks


def judge_pass_path_noninterference(regions: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    if 'regions' not in regions:
        return 'UNRESOLVED', []
    leaves = list(regions.get('regions') or [])
    if not leaves:
        return 'UNRESOLVED', []
    violated = [item for item in leaves if item.get('classification') == 'CHANGED_ON_PASS']
    if violated:
        return 'VIOLATED', [{
            'region': item.get('region'),
            'classification': 'CHANGED_ON_PASS',
        } for item in violated[:4]]
    if any(item.get('classification') in ('UNRESOLVED', 'MIXED') for item in leaves):
        return 'UNRESOLVED', []
    if any(item.get('classification') in ('UNCHANGED', 'CHANGED_BY_BLOCK') for item in leaves):
        return 'PROVED_IN_BOUNDED_DOMAIN', []
    return 'UNRESOLVED', []


_ZERO_WORD_LOOP = re.compile(
    r'while\s*\(\s*\*\s*\(\s*uintptr_t\s*\*\s*\)\s*[A-Za-z_]\w*\s*(?:->|\.)\s*([A-Za-z_]\w*)\s*\)'
)


def zero_word_loop_fields(text: str) -> set[str]:
    return {match.group(1) for match in _ZERO_WORD_LOOP.finditer(text or '')}


def symbol_is_zero_word(text: str, name: str) -> bool:
    if not name or not re.fullmatch(r'[A-Za-z_]\w*', name):
        return False
    return re.search(
        rf'\buintptr_t\s+{re.escape(name)}\s*=\s*(?:\(uintptr_t\)\s*)?(?:NULL|0)\b',
        text or '',
    ) is not None


def loop_exit_progress_assert(dest_ptr: str) -> str:
    return f'__CPROVER_assert(*(uintptr_t *)(*({dest_ptr})) == 0, "vg.obligation.loop_exit_progress");'


def action_return_statement(action: dict[str, Any], ret_c_type: str) -> str:
    kind = str(action.get('kind') or '')
    if kind == 'return_void':
        return 'return;'
    if kind == 'return_null':
        return 'return (void *)0;'
    if kind == 'return_string':
        from .action_catalog import c_string_pointer
        return f'return {c_string_pointer(str(action.get("value", "")))};'
    if kind == 'return_int':
        if 'value' in action:
            return f'return ({ret_c_type})({int(action["value"])}LL);'
        symbol = str(action.get('value_symbol') or '')
        if re.fullmatch(r'[A-Za-z_]\w*', symbol):
            return f'return ({ret_c_type})({symbol});'
        return f'return ({ret_c_type})(0);'
    return ''


def action_returns_without_defining_outputs(action: dict[str, Any]) -> bool:
    kind = action.get('kind')
    if kind in ('return_null', 'return_void'):
        return True
    if kind == 'return_string':
        return str(action.get('value', '')) == ''
    if kind == 'return_int':
        if 'value' in action:
            return int(action['value']) != 0
        symbol = str(action.get('value_symbol') or '')
        return re.search(r'ERROR|FAIL|DECLINED', symbol) is not None
    return False


def output_pointer_assert_lines(param_names: list[str], indices: list[int]) -> list[str]:
    lines: list[str] = []
    for index in indices:
        if index < 0 or index >= len(param_names):
            continue
        name = param_names[index]
        if not re.fullmatch(r'[A-Za-z_]\w*', str(name)):
            continue
        lines.append(
            f'if (({name}) && __vulgate_shadow_active) '
            f'{{ __CPROVER_assert(!__CPROVER_get_field((void *)({name}), "vulgate_uninitialized"), '
            f'"vg.obligation.output_pointer_defined"); }}'
        )
    return lines


def inject_output_pointer_asserts(source: str, function_name: str, asserts: list[str]) -> str:
    if not asserts or not re.fullmatch(r'[A-Za-z_]\w*', function_name):
        return source
    match = re.search(rf'\b{function_name}\s*\([^;{{]*\)\s*\{{', source)
    if not match:
        return source
    close = _matching_brace(source, match.end() - 1)
    if close is None:
        return source
    body = source[match.end():close]
    if 'vg.obligation.output_pointer_defined' in body:
        return source
    block = '\n    ' + '\n    '.join(asserts)
    return_at = re.search(r'\n([ \t]*)return\b', body)
    if return_at:
        inserted = body[:return_at.start()] + '\n' + return_at.group(1) + block.strip() + body[return_at.start():]
    else:
        inserted = block + '\n' + body
    return source[:match.end()] + inserted + source[close:]


def apply_planned_output_pointer_asserts(helper_path: Path,
                                         case_ir: dict[str, Any],
                                         plan: dict[str, Any]) -> bool:
    text = helper_path.read_text(encoding='utf-8')
    changed = text
    for guard, cont in zip(case_ir.get('guards') or [], plan.get('continuations') or []):
        action = guard.get('resolved_action') or {}
        if not action_returns_without_defining_outputs(action):
            continue
        lines = output_pointer_assert_lines(
            list(guard.get('parameter_names') or []),
            [int(index) for index in (cont.get('skipped_pointer_param_indices') or [])],
        )
        if not lines:
            continue
        gid = re.sub(r'[^A-Za-z0-9_]', '_', str(guard.get('id') or ''))
        changed = inject_output_pointer_asserts(changed, f'__vulgate_action_{gid}', lines)
    if changed == text:
        return False
    helper_path.write_text(changed, encoding='utf-8')
    return True


def _matching_brace(source: str, open_at: int) -> int | None:
    depth = 0
    index = open_at
    while index < len(source):
        if source.startswith('//', index):
            newline = source.find('\n', index)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith('/*', index):
            end = source.find('*/', index + 2)
            index = len(source) if end < 0 else end + 2
            continue
        if source[index] in ('"', "'"):
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == '\\':
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def model_bound_blocks_proof(props: list[dict[str, Any]]) -> bool:
    return any(
        item.get('description') == 'vg.obligation.model_bound' and item.get('status') == 'FAILURE'
        for item in props
    )


def _checked_obligation_names(driver_path: Path) -> list[str]:
    names = [
        'action_writes_valid',
        'no_uninitialized_read',
        'memory_bounds',
        'loop_exit_progress',
    ]
    try:
        text = Path(driver_path).read_text(encoding='utf-8', errors='replace')
        helper = Path(driver_path).parent / 'vg_paired_helpers.c'
        if helper.is_file():
            text += '\n' + helper.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return names
    if 'vg.obligation.output_pointer_defined' in text:
        names.append('output_pointer_defined')
    if 'vg.obligation.allocator_lifetime' in text:
        names.append('allocator_lifetime')
    if 'vg.obligation.brigade_ring' in text:
        names.append('brigade_ring')
    if 'vg.obligation.resource_release' in text:
        names.append('resource_release')
    for name in ('action_write_nonnull', 'action_write_live', 'action_write_writable', 'action_write_width'):
        if f'vg.obligation.{name}' in text:
            names.append(name)
    return names


def oracle_unbound_blocks_proof(properties: list[dict[str, Any]]) -> bool:
    return any(str(item.get('description') or '') == 'vg.oracle.unbound' for item in properties)


def demote_unbound_oracle(status: str, properties: list[dict[str, Any]]) -> str:
    if status == 'PROVED_IN_BOUNDED_DOMAIN' and oracle_unbound_blocks_proof(properties):
        return 'UNRESOLVED'
    return status


_BUILTIN_MEMORY = (
    'dereference failure',
    'array bounds',
    'pointer overflow',
    'dead object',
    'invalid pointer',
)
_BUILTIN_ARITHMETIC = (
    'arithmetic overflow',
    'division by zero',
    'float-divide-by-zero',
    'shift distance',
    'shift operand',
    'undefined shift',
    'vg.target.length_truncation',
)


def builtin_target_kind(properties: list[dict[str, Any]]) -> str | None:
    for item in properties:
        description = str(item.get('description') or '')
        if description == 'vg.target.builtin_memory':
            return 'memory'
        if description == 'vg.target.builtin_initialized':
            return 'initialized'
        if description == 'vg.target.builtin_arithmetic':
            return 'arithmetic'
    return None


def _patched_world_property(item: dict[str, Any]) -> bool:
    description = str(item.get('description') or '')
    name = str(item.get('property') or '')
    if '.unwind.' in name or '__vg_w0_' in name or '__vg_w0_' in description:
        return False
    location = item.get('sourceLocation') or {}
    function = str(location.get('function') or '') if isinstance(location, dict) else ''
    return '__vg_w1_' in name or '__vg_w1_' in description or function.startswith('__vg_w1_')


def properties_for_builtin_target(properties: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for item in properties:
        if not _patched_world_property(item):
            continue
        description = str(item.get('description') or '')
        lowered = description.lower()
        if kind == 'memory' and any(token in lowered for token in _BUILTIN_MEMORY):
            selected.append(item)
        elif kind == 'initialized' and description == 'vulgate.initialized_read':
            selected.append(item)
        elif kind == 'arithmetic' and any(token in lowered for token in _BUILTIN_ARITHMETIC):
            selected.append(item)
    return selected


def obligation_target_properties(properties: list[dict[str, Any]]) -> list[dict[str, Any]]:
    explicit = [item for item in properties if item.get('description') == 'vg.target.violation_w1']
    if explicit:
        return explicit
    kind = builtin_target_kind(properties)
    if not kind:
        return []
    return properties_for_builtin_target(properties, kind)


def classify_obligation_status(prop_list: list[dict[str, Any]],
                               unwind_failures: list[dict[str, Any]],
                               query_completed: bool,
                               *,
                               blocked_unwind_is_violation: bool) -> tuple[str, list[dict[str, Any]]]:
    blocked_unwind: list[dict[str, Any]] = []
    other_unwind: list[dict[str, Any]] = []
    for prop in unwind_failures or []:
        if counterexample_site(prop).get('after_block'):
            blocked_unwind.append(prop)
        else:
            other_unwind.append(prop)
    if not query_completed:
        return 'UNRESOLVED', []
    if blocked_unwind and blocked_unwind_is_violation:
        pass
    elif other_unwind or blocked_unwind:
        return 'UNRESOLVED', []
    failed = [p for p in prop_list if p.get('status') == 'FAILURE']
    if blocked_unwind_is_violation:
        for prop in blocked_unwind:
            named = dict(prop)
            named['description'] = 'vg.obligation.loop_exit_progress'
            failed.append(named)
    if failed:
        ces = [{
            'property': p.get('property'),
            'description': p.get('description'),
            'location': p.get('sourceLocation'),
            'witness': _extract_trace_witness(p),
            'site': counterexample_site(p),
        } for p in failed[:4]]
        return 'VIOLATED', ces
    if other_unwind or not prop_list:
        return 'UNRESOLVED', []
    return 'PROVED_IN_BOUNDED_DOMAIN', []


_ACTION_WRITE_OBLIGATIONS = (
    'vg.obligation.action_write_bounds',
    'vg.obligation.action_write_nonnull',
    'vg.obligation.action_write_live',
    'vg.obligation.action_write_writable',
    'vg.obligation.action_write_width',
)


def action_write_checks(param: str, dest_ptr: str, wtype: str) -> list[tuple[str, str]]:
    width = f'sizeof({wtype})'
    bounded = (
        f'__CPROVER_POINTER_OFFSET({dest_ptr}) >= 0 && '
        f'(__CPROVER_size_t)__CPROVER_POINTER_OFFSET({dest_ptr}) + {width} '
        f'<= __CPROVER_OBJECT_SIZE({dest_ptr})'
    )
    return [
        (f'({param}) != 0 && ({dest_ptr}) != 0', 'vg.obligation.action_write_nonnull'),
        (f'!__CPROVER_is_invalid_pointer({dest_ptr})', 'vg.obligation.action_write_live'),
        (f'__CPROVER_w_ok({dest_ptr}, 1)', 'vg.obligation.action_write_writable'),
        (bounded, 'vg.obligation.action_write_width'),
    ]


def action_write_guard(param: str, dest_ptr: str, wtype: str) -> list[str]:
    checks = action_write_checks(param, dest_ptr, wtype)
    lines = [f'__CPROVER_assert({expr}, "{name}");' for expr, name in checks]
    gate = ' && '.join(f'({expr})' for expr, _name in checks)
    lines.append(f'if (!({gate})) {{ __vulgate_action_write_ok = 0; }} else {{')
    return lines


def _local_continuation_properties(props: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    for prop in props:
        description = str(prop.get('description') or '')
        property_name = str(prop.get('property') or '')
        if description.startswith('dereference failure'):
            kept.append(prop)
            continue
        if description in {
            'vg.obligation.action_continuation_safe',
            *_ACTION_WRITE_OBLIGATIONS,
            'vg.obligation.loop_exit_progress',
            'vg.obligation.allocator_lifetime',
            'vg.obligation.brigade_ring',
            'vg.obligation.output_pointer_defined',
            'vg.obligation.resource_release',
            'vulgate.initialized_read',
        }:
            kept.append(prop)
            continue
        if (
            any(token in property_name for token in ('__vg_w1_', '__vulgate_action_'))
            and '.unwind.' not in property_name
            and not description.startswith('__VG_UNMODELED_INIT:')
            and 'vg.target.' not in description
        ):
            kept.append(prop)
    return kept


def query_outside_caller_locals(case_ir: dict[str, Any],
                                plan: dict[str, Any],
                                *,
                                stamped_sources: list[Path],
                                flags: list[str],
                                helper_c_path: Path,
                                hook_weave_specs: list[dict[str, Any]],
                                cbmc_bin: Path,
                                output_dir: Path,
                                unwind: int,
                                timeout_sec: int,
                                shadow_enabled: bool) -> None:
    profile = case_ir.get('app_profile') or {}
    if not profile.get('family') or not isinstance(case_ir.get('safety_oracle'), dict):
        return
    covering: set[str] = set()
    for task in plan.get('tasks') or []:
        if task.get('role') not in (None, 'covering_cut'):
            continue
        if task.get('cut_function'):
            covering.add(str(task['cut_function']))
        covering.update(str(name) for name in (task.get('subtree_functions') or []))
    tool_dir = cbmc_bin.parent
    goto_cc = tool_dir / 'goto-cc'
    goto_instrument = tool_dir / 'goto-instrument'
    from .driver_synth import parse_c_function_signature
    for task in plan.get('tasks') or []:
        if task.get('role') != 'caller_local':
            continue
        function = str(task.get('cut_function') or '')
        if not function or function in covering:
            continue
        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', function)
        work = output_dir / 'local_callers' / safe_name
        work.mkdir(parents=True, exist_ok=True)
        def _local_signature(source_path: Path) -> dict[str, Any] | None:
            text = source_path.read_text(encoding='utf-8', errors='replace')
            found = parse_c_function_signature(text, function)
            if found:
                return found
            return parse_c_function_signature(text, function, include_static=True)

        signature = None
        compile_sources = list(stamped_sources)
        for source_path in stamped_sources:
            try:
                signature = _local_signature(source_path)
            except OSError:
                signature = None
            if signature:
                break
        if signature is None:
            raw_source = Path(str(task.get('source_file') or ''))
            if raw_source.is_file():
                try:
                    signature = _local_signature(raw_source)
                except OSError:
                    signature = None
                if signature:
                    compile_sources.append(raw_source)
        if signature is None:
            task['local_obligation'] = {
                'status': 'UNRESOLVED',
                'reason': 'prototype_not_found',
                'checked_properties': 0,
            }
            continue
        scope = dict(case_ir.get('symbolization_scope') or {})
        scope['slice_sources'] = [str(path) for path in compile_sources]
        scope['cut_function'] = function
        scope.pop('cut_harness_kind', None)
        scope.pop('inline_driver_c', None)
        local_case = dict(case_ir)
        local_case['symbolization_scope'] = scope
        driver_path = work / 'local_driver.c'
        try:
            synthesize_paired_goto_driver_c(
                local_case,
                {'base_name': function},
                None,
                driver_path,
            )
        except (KeyError, ValueError, OSError) as exc:
            task['local_obligation'] = {
                'status': 'UNRESOLVED',
                'reason': 'driver_not_synthesized',
                'detail': str(exc)[:300],
                'checked_properties': 0,
            }
            continue
        from .driver_synth import align_anonymous_signatures, stamp_allocator_callsites
        exports = list(scope.get('static_exports') or [])
        stamped_ids = {path.resolve() for path in stamped_sources}
        if exports or any(path.resolve() not in stamped_ids for path in compile_sources):
            materialized: list[Path] = []
            for path in compile_sources:
                matched = [
                    str(item.get('source') or '')
                    for item in exports
                    if Path(str(item.get('file') or '')).resolve() == path.resolve()
                    and str(item.get('source') or '')
                ]
                if path.resolve() in stamped_ids and not matched:
                    materialized.append(path)
                    continue
                try:
                    text = path.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    materialized.append(path)
                    continue
                if path.resolve() not in stamped_ids:
                    text = stamp_allocator_callsites(text)
                text = align_anonymous_signatures(text, list(scope.get('anonymous_signatures') or []))
                addition = ''.join(item for item in matched if item not in text)
                if addition:
                    text += '\n' + addition
                dest = work / f'local_{path.name}'
                dest.write_text(text, encoding='utf-8')
                materialized.append(dest)
            compile_sources = materialized
        local_goto = work / 'local.goto'
        local_linked = work / 'local_linked.goto'
        try:
            subprocess.run(
                [str(goto_cc), *flags, *[str(path) for path in compile_sources], str(driver_path), str(helper_c_path),
                 '--function', '__vg_verify_obligations', '-o', str(local_goto)],
                check=True,
                timeout=max(int(timeout_sec), 120),
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [str(goto_instrument), '--add-library', str(local_goto), str(local_linked)],
                check=True,
                timeout=120,
                capture_output=True,
                text=True,
            )
            local_functions, local_symbols = load_typed_goto_model(
                local_linked, goto_instrument, work / 'inspect',
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            task['local_obligation'] = {
                'status': 'UNRESOLVED',
                'reason': 'compile_failed',
                'detail': (getattr(exc, 'stderr', None) or str(exc))[-500:],
                'checked_properties': 0,
            }
            continue
        local_names = {item['name'] for item in local_functions}
        subtree = [str(name) for name in (task.get('subtree_functions') or []) if str(name) in local_names]
        if function in local_names and function not in subtree:
            subtree.append(function)
        local_icfg = build_enhanced_icfg(local_functions, local_symbols)
        if function in local_icfg['functions_by_name']:
            for reached in _reachable_from(local_icfg, function):
                if reached in local_names and reached not in subtree:
                    subtree.append(reached)
        bridges = _harness_bridge_functions(local_functions, local_symbols, subtree)
        clone_names = list(subtree)
        for name in bridges:
            if name not in clone_names:
                clone_names.append(name)
        cloned_fns, cloned_syms, world_maps = clone_dual_world_goto(
            local_functions, local_symbols, clone_names,
        )
        resolved_specs = []
        for spec in hook_weave_specs:
            matches = [
                item['name'] for item in local_functions
                if local_symbols.get(item['name'], {}).get('baseName', item['name']) == spec.get('guard_base_name')
                or item['name'] == spec.get('guard_ir_function')
            ]
            for match in matches:
                copied = dict(spec)
                copied['guard_ir_function'] = match
                resolved_specs.append(copied)
        weaved_fns, weaved_syms = apply_paired_weaves(
            cloned_fns, cloned_syms, world_maps['w1'], resolved_specs,
            case_ir.get('observer_specs') or [], case_ir.get('maps') or {}, plan,
        )
        fn_by_name = {item['name']: item for item in weaved_fns}
        from .paired_goto import _rewrite_irep_symbols
        for harness_name, world_key in (('__vg_run_world_0', 'w0'), ('__vg_run_world_1', 'w1')):
            harness = fn_by_name.get(harness_name)
            if harness is None:
                continue
            for insn in harness.get('instructions', []):
                if 'code' in insn:
                    insn['code'] = _rewrite_irep_symbols(insn['code'], world_maps[world_key])
                if 'guard' in insn:
                    insn['guard'] = _rewrite_irep_symbols(insn['guard'], world_maps[world_key])
        object_bits = initial_object_bits(driver_path.read_text(encoding='utf-8', errors='replace'))
        paired_goto = work / 'paired.goto'
        use_shadow = shadow_enabled and object_bits < 14
        export_fns = deepcopy(weaved_fns)
        export_syms = deepcopy(weaved_syms)
        try:
            finalize_and_export_goto(
                export_fns, export_syms, paired_goto, tool_dir, work / 'export',
                enable_shadow=use_shadow, object_bits=object_bits, timeout=timeout_sec,
            )
            solved = _run_cbmc_json(
                paired_goto, cbmc_bin, work / 'query',
                unwind=unwind, object_bits=object_bits, timeout=timeout_sec,
                extra_flags=_obligation_query_flags(case_ir),
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, RuntimeError, TransportError) as exc:
            task['local_obligation'] = {
                'status': 'UNRESOLVED',
                'reason': 'query_failed',
                'detail': str(exc)[:300],
                'checked_properties': 0,
            }
            continue
        if solved.get('status') != 'completed' and use_shadow:
            try:
                finalize_and_export_goto(
                    weaved_fns, weaved_syms, paired_goto, tool_dir, work / 'export_noshadow',
                    enable_shadow=False, object_bits=object_bits, timeout=timeout_sec,
                )
                solved = _run_cbmc_json(
                    paired_goto, cbmc_bin, work / 'query_noshadow',
                    unwind=unwind, object_bits=object_bits, timeout=timeout_sec,
                    extra_flags=_obligation_query_flags(case_ir),
                )
                solved['shadow_fallback'] = True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, RuntimeError, TransportError) as exc:
                solved = {'status': 'incomplete', 'reason': str(exc)[:300], 'properties': []}
        props = list(solved.get('properties') or [])
        status, examples = classify_obligation_status(
            _local_continuation_properties(props),
            list(solved.get('unwind_failures') or []),
            solved.get('status') == 'completed',
            blocked_unwind_is_violation=True,
        )
        harness_sites = {
            '__vg_verify_obligations', '__vg_impact_harness',
            '__vg_run_world_0', '__vg_run_world_1', 'vg_proto_entry',
        }
        caller_examples = [
            item for item in examples
            if str((item.get('site') or {}).get('function') or '') not in harness_sites
        ]
        if status == 'VIOLATED' and examples and not caller_examples:
            status = 'PROVED_IN_BOUNDED_DOMAIN'
        status = demote_unbound_oracle(status, props)
        task['local_obligation'] = {
            'status': status,
            'reason': solved.get('reason'),
            'checked_properties': len(props),
            'shadow_fallback': bool(solved.get('shadow_fallback')),
            'failures': [
                f"{item.get('description')}@{((item.get('site') or {}).get('function'))}"
                for item in caller_examples
            ],
        }


def single_covering_base(plan: dict[str, Any] | None) -> str | None:
    names: list[str] = []
    for task in (plan or {}).get('tasks') or []:
        if task.get('role') not in (None, 'covering_cut'):
            continue
        base = str(task.get('base_name') or '').strip()
        if not base:
            raw = str(task.get('cut_function') or '')
            base = raw.split('::')[-1]
        if base and base not in names:
            names.append(base)
    if len(names) != 1:
        return None
    return names[0]


def covering_driver_target(plan: dict[str, Any] | None,
                           current_entry: str,
                           snapshot: dict[str, Any] | None,
                           *,
                           handwritten: bool,
                           explicit_cut: str) -> str | None:
    if handwritten or explicit_cut:
        return None
    if (snapshot or {}).get('mode') == 'poc_or_seed_snapshot_lifted':
        return None
    planned = single_covering_base(plan)
    if planned is None or not current_entry or planned == current_entry:
        return None
    return planned


def note_operation_prefix_scope(scope: dict[str, Any],
                                plan: dict[str, Any] | None,
                                snapshot: dict[str, Any] | None,
                                entry: str) -> None:
    if scope.get('scope_kind'):
        return
    if (snapshot or {}).get('mode') == 'poc_or_seed_snapshot_lifted':
        return
    begins = {str(name) for name in ((plan or {}).get('operation_begin') or []) if str(name)}
    if entry and entry in begins:
        scope['scope_kind'] = 'operation_prefix'


def retarget_driver_to_covering_cut(case_ir: dict[str, Any],
                                    plan: dict[str, Any],
                                    driver_path: Path,
                                    snapshot: dict[str, Any] | None,
                                    *,
                                    handwritten: bool,
                                    explicit_cut: str,
                                    slice_sources: list[Path],
                                    stamped_sources: list[Path],
                                    output_dir: Path,
                                    flags: list[str],
                                    all_c_files: list[Path],
                                    helper_c_path: Path,
                                    goto_cc: Path,
                                    goto_instrument: Path,
                                    compile_timeout: int,
                                    check_length_truncation: bool,
                                    ) -> tuple[dict[str, Any], Path, list[dict[str, Any]], dict[str, Any]] | None:
    scope = case_ir.setdefault('symbolization_scope', {})
    planned = covering_driver_target(
        plan,
        str(scope.get('driver_entry') or ''),
        snapshot,
        handwritten=handwritten,
        explicit_cut=explicit_cut,
    )
    if not planned:
        return None
    from .driver_synth import _signature_for_cut, _static_signature_in_sources, prefer_slice_function_bodies
    if _signature_for_cut(scope, planned) is None and _static_signature_in_sources(scope, planned)[0] is None:
        return None
    saved_driver = driver_path.read_text(encoding='utf-8')
    saved_cut = scope.get('cut_function')
    saved_entry = scope.get('driver_entry')
    saved_exports = list(scope.get('static_exports') or [])
    saved_stamped = [(path, path.read_text(encoding='utf-8')) for path in stamped_sources]
    plan_path = output_dir / 'boundary-plan.json'
    saved_plan_text = plan_path.read_text(encoding='utf-8') if plan_path.is_file() else None
    scope['cut_function'] = planned
    try:
        synthesize_paired_goto_driver_c(
            case_ir,
            {'base_name': planned},
            snapshot if (snapshot or {}).get('mode') == 'poc_or_seed_snapshot_lifted' else None,
            driver_path,
        )
        if slice_sources and output_dir in driver_path.resolve().parents:
            texts = []
            for path in slice_sources:
                try:
                    texts.append(path.read_text(encoding='utf-8', errors='replace'))
                except OSError:
                    continue
            updated = prefer_slice_function_bodies(
                driver_path.read_text(encoding='utf-8', errors='replace'),
                texts,
            )
            if check_length_truncation:
                from .oracle_compiler import inject_length_truncation_asserts
                updated = inject_length_truncation_asserts(updated)
            driver_path.write_text(updated, encoding='utf-8')
        old_keys = {(str(item.get('file') or ''), str(item.get('source') or '')) for item in saved_exports}
        for item in scope.get('static_exports') or []:
            key = (str(item.get('file') or ''), str(item.get('source') or ''))
            text = key[1]
            if not text or key in old_keys:
                continue
            file_key = Path(key[0]).resolve() if key[0] else None
            if file_key is None:
                continue
            for slice_path, stamped_path in zip(slice_sources, stamped_sources):
                if slice_path.resolve() != file_key:
                    continue
                current = stamped_path.read_text(encoding='utf-8', errors='replace')
                if text not in current:
                    stamped_path.write_text(current + '\n' + text, encoding='utf-8')
        retarget_goto = output_dir / 'slice_retarget.goto'
        retarget_linked = output_dir / 'slice_retarget_linked.goto'
        subprocess.run(
            [str(goto_cc), *flags, *[str(path) for path in all_c_files], str(helper_c_path),
             '--function', '__vg_verify_obligations', '-o', str(retarget_goto)],
            check=True, timeout=compile_timeout, capture_output=True, text=True,
        )
        subprocess.run(
            [str(goto_instrument), '--add-library', str(retarget_goto), str(retarget_linked)],
            check=True, timeout=120, capture_output=True, text=True,
        )
        functions, symbols = load_typed_goto_model(
            retarget_linked, goto_instrument, output_dir / 'inspect_retarget',
        )
        new_plan = plan_verification_boundaries(
            case_ir, functions, symbols,
            dynamic_traces=case_ir.get('dynamic_traces'),
            output_dir=output_dir,
        )
        if single_covering_base(new_plan) != planned:
            raise RuntimeError('covering cut changed after retarget')
        return new_plan, retarget_linked, functions, symbols
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError, RuntimeError, TransportError) as exc:
        driver_path.write_text(saved_driver, encoding='utf-8')
        if saved_cut is None:
            scope.pop('cut_function', None)
        else:
            scope['cut_function'] = saved_cut
        scope['driver_entry'] = saved_entry
        scope['static_exports'] = saved_exports
        for path, text in saved_stamped:
            path.write_text(text, encoding='utf-8')
        if saved_plan_text is not None:
            plan_path.write_text(saved_plan_text, encoding='utf-8')
        detail = getattr(exc, 'stderr', None) or str(exc)
        (output_dir / 'retarget-goto-cc.stderr').write_text(str(detail)[-2000:], encoding='utf-8')
        return None


def build_and_verify_paired_goto_slice(case_ir: dict[str, Any],
                                       vm_proofs: dict[str, dict[str, Any]],
                                       cbmc_bin: Path,
                                       output_dir: Path) -> dict[str, Any]:
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    tool_dir = cbmc_bin.parent
    goto_cc = tool_dir / 'goto-cc'
    goto_instrument = tool_dir / 'goto-instrument'

    sym_cfg = case_ir['app_profile'].get('symbolic_slice', {})
    case_sym_cfg = case_ir.get('symbolization_scope', {})
    slice_sources, flags = _slice_compile_flags(case_ir)
    already = {path.resolve() for path in slice_sources}
    candidates = [path for path in declared_translation_units(case_ir) if path not in already]
    if candidates:
        admitted, _rejected = admit_compilable_translations(
            candidates,
            flags,
            goto_cc,
            output_dir,
            max(int(case_ir.get('budgets', {}).get('solver_timeout_sec', 120)), 120),
        )
        slice_sources = [*slice_sources, *admitted]
        already.update(path.resolve() for path in admitted)

    definition_names: list[str] = []
    declared_cut = str(case_sym_cfg.get('cut_function') or '')
    if declared_cut:
        definition_names.append(declared_cut)
    for guard in case_ir.get('guards') or []:
        guard_name = str(guard.get('function') or '')
        if guard_name and guard_name not in definition_names:
            definition_names.append(guard_name)
    if definition_names and not (case_sym_cfg.get('slice_driver_c') or sym_cfg.get('slice_driver_c')):
        from .driver_synth import discover_definition_files
        defined = [
            path for path in discover_definition_files(case_ir, definition_names)
            if path.resolve() not in already
        ]
        if defined:
            admitted_defs, _rejected_defs = admit_compilable_translations(
                defined,
                flags,
                goto_cc,
                output_dir,
                max(int(case_ir.get('budgets', {}).get('solver_timeout_sec', 120)), 120),
            )
            slice_sources = [*slice_sources, *admitted_defs]
            if admitted_defs:
                scope = case_ir.setdefault('symbolization_scope', {})
                listed = [str(item) for item in (scope.get('slice_sources') or [])]
                for path in admitted_defs:
                    text = str(path)
                    if text not in listed:
                        listed.append(text)
                scope['slice_sources'] = listed
                case_sym_cfg = scope

    from .driver_synth import registration_caller_files, seed_activated_files
    registered_files = [
        path for path in [
            *registration_caller_files(case_ir, definition_names),
            *seed_activated_files(case_ir, definition_names),
        ]
        if path.resolve() not in already
    ]
    if registered_files:
        admitted_registered, _rejected_registered = admit_compilable_translations(
            registered_files,
            flags,
            goto_cc,
            output_dir,
            max(int(case_ir.get('budgets', {}).get('solver_timeout_sec', 120)), 120),
        )
        slice_sources = [*slice_sources, *admitted_registered]
        if admitted_registered:
            scope = case_ir.setdefault('symbolization_scope', {})
            listed = [str(item) for item in (scope.get('slice_sources') or [])]
            for path in admitted_registered:
                text = str(path)
                if text not in listed:
                    listed.append(text)
            scope['slice_sources'] = listed
            case_sym_cfg = scope
            already.update(path.resolve() for path in admitted_registered)

    from .driver_synth import guard_callee_files
    callee_files = [
        path for path in guard_callee_files(case_ir, definition_names)
        if path.resolve() not in already
    ]
    if callee_files:
        admitted_callees, _rejected_callees = admit_compilable_translations(
            callee_files,
            flags,
            goto_cc,
            output_dir,
            max(int(case_ir.get('budgets', {}).get('solver_timeout_sec', 120)), 120),
        )
        slice_sources = [*slice_sources, *admitted_callees]
        if admitted_callees:
            scope = case_ir.setdefault('symbolization_scope', {})
            listed = [str(item) for item in (scope.get('slice_sources') or [])]
            for path in admitted_callees:
                text = str(path)
                if text not in listed:
                    listed.append(text)
            scope['slice_sources'] = listed
            case_sym_cfg = scope
            already.update(path.resolve() for path in admitted_callees)

    abstract_snap: dict[str, Any] | None = None
    explicit_driver_cut = str(case_sym_cfg.get('cut_function') or '')
    base_harness_c = case_sym_cfg.get('slice_driver_c') or sym_cfg.get('slice_driver_c')
    if base_harness_c:
        driver_path = Path(base_harness_c).resolve() if Path(base_harness_c).exists() else (ROOT / base_harness_c).resolve()
    elif case_sym_cfg.get('cut_harness_kind') or case_sym_cfg.get('inline_driver_c') or case_ir['app_profile'].get('family'):
        abstract_snap = lift_snapshot_to_abstract_spec(
            case_sym_cfg.get('concrete_snapshot'),
            case_sym_cfg,
            max_symbolic_bytes=int(case_ir['budgets'].get('max_symbolic_bytes', 64)),
        )
        driver_path = output_dir / 'auto_synthesized_driver.c'
        synthesize_paired_goto_driver_c(
            case_ir,
            {'base_name': case_sym_cfg.get('cut_function', case_ir['guards'][0]['function'])},
            abstract_snap,
            driver_path,
        )
    else:
        return {
            'status': 'UNRESOLVED',
            'reason': 'missing_slice_driver_in_profile',
        }
    from .driver_synth import align_anonymous_signatures, prefer_slice_function_bodies, stamp_allocator_callsites
    from .oracle_compiler import compile_kind_assertions, inject_length_truncation_asserts
    oracle = case_ir.get('safety_oracle') if isinstance(case_ir.get('safety_oracle'), dict) else {}
    check_length_truncation = compile_kind_assertions(oracle).get('builtin_target') == 'arithmetic'
    if slice_sources and output_dir in driver_path.resolve().parents:
        slice_text = []
        for slice_path in slice_sources:
            try:
                slice_text.append(slice_path.read_text(encoding='utf-8', errors='replace'))
            except OSError:
                continue
        driver_text = driver_path.read_text(encoding='utf-8', errors='replace')
        preferred = prefer_slice_function_bodies(driver_text, slice_text)
        if check_length_truncation:
            preferred = inject_length_truncation_asserts(preferred)
        if preferred != driver_text:
            driver_path.write_text(preferred, encoding='utf-8')
    elif check_length_truncation and output_dir in driver_path.resolve().parents:
        driver_text = driver_path.read_text(encoding='utf-8', errors='replace')
        preferred = inject_length_truncation_asserts(driver_text)
        if preferred != driver_text:
            driver_path.write_text(preferred, encoding='utf-8')
    stamped_dir = output_dir / 'stamped-slices'
    stamped_dir.mkdir(parents=True, exist_ok=True)
    stamped_sources: list[Path] = []
    for index, slice_path in enumerate(slice_sources):
        stamped_path = stamped_dir / f'{index}_{slice_path.name}'
        stamped_text = stamp_allocator_callsites(slice_path.read_text(encoding='utf-8', errors='replace'))
        stamped_text = align_anonymous_signatures(
            stamped_text,
            list(case_sym_cfg.get('anonymous_signatures') or []),
        )
        if check_length_truncation:
            stamped_text = inject_length_truncation_asserts(stamped_text)
        exports = [
            str(item.get('source') or '')
            for item in (case_sym_cfg.get('static_exports') or [])
            if Path(str(item.get('file') or '')).resolve() == slice_path.resolve()
        ]
        if any(exports):
            stamped_text += '\n' + ''.join(exports)
        stamped_path.write_text(stamped_text, encoding='utf-8')
        stamped_sources.append(stamped_path)
    all_c_files = [*stamped_sources, driver_path]

    guard_helpers_c: list[str] = [
        '#include <stdint.h>',
        '#include <stddef.h>',
        '#include <string.h>',
        '#include "autoshield.h"',
        f'#include "{RUNTIME_EXPERIMENT / "state.h"}"',
        '_Bool __vulgate_any_blocked = 0;',
        '_Bool __vulgate_action_write_ok = 1;',
        '_Bool __vulgate_shadow_active = 0;',
        'uint64_t __vulgate_nondet_u64(void) { uint64_t __vulgate_sample_u64 = 0; __CPROVER_havoc_object(&__vulgate_sample_u64); return __vulgate_sample_u64; }',
        'uint8_t __vulgate_nondet_u8(void) { uint64_t __vulgate_sample_u8 = 0; __CPROVER_havoc_object(&__vulgate_sample_u8); return (uint8_t)__vulgate_sample_u8; }',
        '_Bool __vulgate_nondet_bool(void) { uint64_t __vulgate_sample_b = 0; __CPROVER_havoc_object(&__vulgate_sample_b); return (_Bool)(__vulgate_sample_b & 1ULL); }',
        '_Bool __vulgate_literal_probe(const void *object) { return 0; }',
        'void __vulgate_shadow_template(int *object) {',
        '  __CPROVER_field_decl_local("vulgate_uninitialized", (_Bool)1);',
        '  __CPROVER_field_decl_global("vulgate_uninitialized", (_Bool)1);',
        '  _Bool dirty = __CPROVER_get_field(object, "vulgate_uninitialized");',
        '  _Bool literal = __vulgate_literal_probe(object);',
        '  (void)literal;',
        '  __CPROVER_assert(!dirty, "vulgate.initialized_read");',
        '  __CPROVER_set_field(object, "vulgate_uninitialized", (_Bool)0);',
        '}',
        'void __vg_assert_caller_output(const void *ptr) {',
        '    if (__vulgate_any_blocked && ptr && __vulgate_shadow_active) {',
        '        __CPROVER_assert(!__CPROVER_get_field((void *)ptr, "vulgate_uninitialized"), "vg.obligation.output_pointer_defined");',
        '    }',
        '}',
    ]

    for h_inc in reversed(case_sym_cfg.get('helper_includes', sym_cfg.get('helper_includes', []))):
        guard_helpers_c.insert(0, f'#include {h_inc}')

    for mname, mdef in case_ir.get('maps', {}).items():
        cap = min(int(mdef.get('capacity', 16)), 16)
        guard_helpers_c.extend(render_map_table_helpers(mname, cap, str(mdef.get('on_full') or 'drop')))

    hook_weave_specs: list[dict[str, Any]] = []
    loop_chunks = []
    if driver_path.is_file():
        loop_chunks.append(driver_path.read_text(encoding='utf-8', errors='replace'))
    for slice_path in stamped_sources:
        loop_chunks.append(slice_path.read_text(encoding='utf-8', errors='replace'))
    loop_text = '\n'.join(loop_chunks)
    loop_fields = zero_word_loop_fields(loop_text)
    for g_idx, g in enumerate(case_ir['guards']):
        gid = re.sub(r'[^A-Za-z0-9_]', '_', g['id'])
        raw_bytes = Path(g['rule_path']).read_bytes()
        rows = list(struct.iter_unpack('<BBhi', raw_bytes))
        insn_lit = ','.join('{%d,%d,%d,%d}' % r for r in rows)

        arg_c_types = []
        param_decls = []
        param_names = []
        for p_i, at in enumerate(g['arg_types']):
            ct = {'int': 'int', 'uint': 'unsigned int', 'int64': 'int64_t', 'uint64': 'uint64_t', 'pointer': 'void *'}[at]
            arg_c_types.append(ct)
            pname = g['parameter_names'][p_i] if p_i < len(g.get('parameter_names', [])) else f'p{p_i}'
            param_names.append(pname)
            param_decls.append(f'{ct} {pname}')
        sig_params = ', '.join(param_decls) if param_decls else 'void'

        ret_c_type = {'int': 'int', 'uint': 'unsigned int', 'int64': 'int64_t', 'uint64': 'uint64_t',
                      'pointer': 'void *', 'void': 'void'}[g['return_type']]

        sel_assigns = []
        for f_name, f_bind in g['fields'].items():
            if 'constant' in f_bind:
                sel_assigns.append(f'uint64_t __vg_f_{f_name} = UINT64_C({int(f_bind["constant"])});')
            elif f_bind['source'] == 'reg':
                # Caller-local selector: the guard reads a register slot.  The
                # symbolic domain treats the local as a free input.
                sel_assigns.append(f'uint64_t __vg_f_{f_name} = __vulgate_nondet_u64();')
                sel_assigns.append(f'ctx.regs[{int(f_bind["index"])}] = __vg_f_{f_name};')
            elif f_bind['source'] == 'arg':
                raw_s = list(g['selectors'].values())[f_bind['index']]
                if raw_s.get('reads'):
                    _expr, checks = _selector_c_expr(raw_s, param_names)
                    sel_assigns.extend(checks)
                if 'c_param_expr' in raw_s:
                    sel_assigns.append(f'uint64_t __vg_f_{f_name} = (uint64_t)({raw_s["c_param_expr"]});')
                elif 'symbolic_var_expr' in raw_s:
                    ext_decl = raw_s.get('symbolic_var_decl')
                    if ext_decl and ext_decl not in guard_helpers_c:
                        guard_helpers_c.insert(6, ext_decl)
                    sel_assigns.append(f'uint64_t __vg_f_{f_name} = (uint64_t)({raw_s["symbolic_var_expr"]});')
                else:
                    cexpr, checks = _selector_c_expr(g['resolved_vm_args'][f_bind['index']], param_names)
                    if not raw_s.get('reads'):
                        sel_assigns.extend(checks)
                    sel_assigns.append(f'uint64_t __vg_f_{f_name} = {cexpr};')
                sel_assigns.append(f'ctx.args[{f_bind["index"]}] = __vg_f_{f_name};')

        map_read_stmts = []
        for mr_index, mr in enumerate(g.get('map_reads', [])):
            structured = structured_map_load_lines(mr, param_names, mr_index)
            if structured:
                map_read_stmts.extend(structured)
                continue
            mname = mr['map']
            if isinstance(mr.get('key'), dict) and mr['key'].get('reads'):
                key_c, key_checks = _selector_c_expr(mr['key'], param_names)
                map_read_stmts.extend(key_checks)
            else:
                key_c = f'(uint64_t)(uintptr_t)({param_names[mr.get("key_arg", 0)]})'
            slot_i = int(mr['slot'])
            cons_i = 1 if mr.get('consume') else 0
            map_read_stmts.append(f'uint64_t __vg_mval_{slot_i} = 0;')
            map_read_stmts.append(f'int __vg_mfound_{slot_i} = __vulgate_table_get_{mname}(0, {key_c}, &__vg_mval_{slot_i}, {cons_i});')
            map_read_stmts.append(f'ctx.regs[{slot_i}] = __vg_mval_{slot_i};')
            if 'present_slot' in mr:
                map_read_stmts.append(f'ctx.regs[{int(mr["present_slot"])}] = (uint64_t)__vg_mfound_{slot_i};')
            elif mr.get('on_missing') != 'pass':
                map_read_stmts.append(f'if (!__vg_mfound_{slot_i}) return 1;')

        for f_name, f_bind in g['fields'].items():
            if f_bind.get('source') == 'slot':
                sel_assigns.append(f'uint64_t __vg_f_{f_name} = ctx.regs[{int(f_bind["index"])}];')

        vmp = vm_proofs.get(g['id'], {})
        if vmp.get('proved_c_summary'):
            decide_body = f'return !!({vmp["proved_c_summary"]});'
        else:
            decide_body = f'''
    static const ebpf_insn insns[] = {{{insn_lit}}};
    shadow_program prog = {{insns, {len(rows)}, 0, 0}};
    shadow_policy pol = {{{g["step_limit"]}ULL, SHADOW_UNKNOWN_BLOCK, 0}};
    shadow_stats st;
    shadow_decision dec = run_ebpf_vm(&ctx, &prog, &pol, &st);
    return dec != SHADOW_PASS;
'''

        dec_fn_name = f'__vulgate_decide_{gid}'
        act_fn_name = f'__vulgate_action_{gid}'
        guard_helpers_c.append(f'''
int {dec_fn_name}({sig_params}) {{
    shadow_ctx ctx;
    shadow_ctx_init(&ctx);
    {' '.join(map_full_block_lines(case_ir, g))}
    {' '.join(map_read_stmts)}
    {' '.join(sel_assigns)}
    {decide_body}
}}
''')
        act = g['resolved_action']
        act_stmts: list[str] = []
        if act.get('c_writes'):
            for cw in act['c_writes']:
                act_stmts.append(cw)
        else:
            for wr in act.get('writes', []):
                p_arg = param_names[int(wr['arg'])]
                off = int(wr['offset'])
                wtype = {'pointer': 'void *', 'u64': 'uint64_t', 'u32': 'uint32_t'}[wr['type']]
                dest_ptr = f'(({wtype} *)((char *)({p_arg}) + {off}ULL))'
                act_stmts.extend(action_write_guard(p_arg, dest_ptr, wtype))
                wrote_zero_word = False
                if 'symbol_c_name' in wr:
                    sym_c = wr['symbol_c_name']
                    field_name = str(wr.get('field') or '')
                    zero_word = sym_c == 'ngx_http_script_exit_code' or (
                        field_name in loop_fields and symbol_is_zero_word(loop_text, sym_c)
                    )
                    if zero_word:
                        guard_helpers_c.insert(5, 'static uintptr_t __vulgate_ngx_script_exit_sentinel = 0;')
                        act_stmts.append(f'*{dest_ptr} = (void *)&__vulgate_ngx_script_exit_sentinel;')
                        wrote_zero_word = field_name in loop_fields
                    else:
                        guard_helpers_c.insert(5, f'extern char {sym_c}[];')
                        act_stmts.append(f'*{dest_ptr} = (void *){sym_c};')
                elif 'string_value' in wr or wr.get('null_pointer'):
                    from .action_catalog import pointer_write_literal
                    literal = pointer_write_literal(wr)
                    if literal is not None:
                        act_stmts.append(f'*{dest_ptr} = {literal};')
                else:
                    act_stmts.append(f'*{dest_ptr} = ({wtype})({int(wr["value"])}ULL);')
                if wrote_zero_word and str(wr.get('field') or '') in loop_fields:
                    act_stmts.append(loop_exit_progress_assert(dest_ptr))
                act_stmts.append(f'if (__vulgate_shadow_active) __CPROVER_set_field({dest_ptr}, "vulgate_uninitialized", (_Bool)0); }}')

        returned = action_return_statement(act, ret_c_type)
        if returned:
            act_stmts.append(returned)

        guard_helpers_c.append(f'''
{ret_c_type} {act_fn_name}({sig_params}) {{
    {' '.join(act_stmts)}
}}
''')
        hook_weave_specs.append({
            'id': gid,
            'guard_base_name': g['function'],
            'decision_helper_symbol': dec_fn_name,
            'action_helper_symbol': act_fn_name,
            'blocked_flag_symbol': '__vulgate_any_blocked',
        })

    guard_helpers_c.append(f'#include "{ROOT / "runtime/vm.c"}"')
    guard_helpers_c.append(f'#include "{ROOT / "runtime/experiment/state.c"}"')
    guard_helpers_c.append('int safe_read(void *d, const void *s, size_t n) { if (!d || !s) return -1; memcpy(d, s, n); return 0; }')

    helper_c_path = output_dir / 'vg_paired_helpers.c'
    helper_c_path.write_text('\n'.join(guard_helpers_c) + '\n', encoding='utf-8')

    base_goto = output_dir / 'slice_base.goto'
    compile_timeout = case_ir['budgets']['solver_timeout_sec']
    compile_cmd = [str(goto_cc), *flags, *[str(p) for p in all_c_files], str(helper_c_path),
                   '--function', '__vg_verify_obligations', '-o', str(base_goto)]
    for _round in range(32):
        try:
            subprocess.run(compile_cmd, check=True, timeout=compile_timeout, capture_output=True, text=True)
            break
        except subprocess.CalledProcessError as exc:
            (output_dir / 'goto-cc.stderr').write_text((exc.stderr or '') + (exc.stdout or ''), encoding='utf-8')
            if not declare_unlinked_snapshot_symbols(driver_path, exc.stderr or ''):
                raise
    else:
        raise RuntimeError('goto-cc kept reporting missing snapshot symbols')

    linked_goto = output_dir / 'slice_linked.goto'
    subprocess.run([str(goto_instrument), '--add-library', str(base_goto), str(linked_goto)],
                   check=True, timeout=120, capture_output=True, text=True)

    functions, symbols = load_typed_goto_model(linked_goto, goto_instrument, output_dir / 'inspect_base')
    plan = plan_verification_boundaries(
        case_ir, functions, symbols,
        dynamic_traces=case_ir.get('dynamic_traces'),
        output_dir=output_dir,
    )
    retargeted = retarget_driver_to_covering_cut(
        case_ir,
        plan,
        driver_path,
        abstract_snap,
        handwritten=bool(base_harness_c),
        explicit_cut=explicit_driver_cut,
        slice_sources=slice_sources,
        stamped_sources=stamped_sources,
        output_dir=output_dir,
        flags=flags,
        all_c_files=all_c_files,
        helper_c_path=helper_c_path,
        goto_cc=goto_cc,
        goto_instrument=goto_instrument,
        compile_timeout=compile_timeout,
        check_length_truncation=check_length_truncation,
    )
    if retargeted is not None:
        plan, linked_goto, functions, symbols = retargeted
    note_operation_prefix_scope(
        case_sym_cfg,
        plan,
        abstract_snap,
        str((case_ir.get('symbolization_scope') or {}).get('driver_entry') or ''),
    )
    from .missing_callees import write_missing_callee_stubs
    subtree_callees = {
        item['callee']
        for task in plan.get('tasks', [])
        for item in task.get('unresolved_external_calls', [])
    }
    stub_info = write_missing_callee_stubs(
        functions, symbols, driver_path, output_dir / 'missing_callees.c',
        allow=subtree_callees,
    )
    stub_info['linked'] = False
    if stub_info.get('path'):
        stub_path = Path(stub_info['path'])
        stub_goto = output_dir / 'slice_stubbed.goto'
        stub_linked = output_dir / 'slice_stubbed_linked.goto'
        try:
            subprocess.run(
                [str(goto_cc), *flags, *[str(p) for p in all_c_files], str(stub_path), str(helper_c_path),
                 '--function', '__vg_verify_obligations', '-o', str(stub_goto)],
                check=True, timeout=max(int(case_ir['budgets']['solver_timeout_sec']), 120),
                capture_output=True, text=True,
            )
            subprocess.run(
                [str(goto_instrument), '--add-library', str(stub_goto), str(stub_linked)],
                check=True, timeout=120, capture_output=True, text=True,
            )
            functions, symbols = load_typed_goto_model(
                stub_linked, goto_instrument, output_dir / 'inspect_stubbed',
            )
            linked_goto = stub_linked
            all_c_files = [*all_c_files, stub_path]
            stub_info['linked'] = True
            plan = plan_verification_boundaries(
                case_ir, functions, symbols,
                dynamic_traces=case_ir.get('dynamic_traces'),
                output_dir=output_dir,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            stub_info['compile_error'] = (getattr(exc, 'stderr', None) or str(exc))[-2000:]

    if not plan['tasks']:
        return {'status': 'UNRESOLVED', 'reason': 'no_cut_function_resolved', 'plan': plan}

    previous_helper = helper_c_path.read_text(encoding='utf-8')
    if apply_planned_output_pointer_asserts(helper_c_path, case_ir, plan):
        defined_goto = output_dir / 'slice_outputs.goto'
        defined_linked = output_dir / 'slice_outputs_linked.goto'
        try:
            subprocess.run(
                [str(goto_cc), *flags, *[str(p) for p in all_c_files], str(helper_c_path),
                 '--function', '__vg_verify_obligations', '-o', str(defined_goto)],
                check=True,
                timeout=max(int(case_ir['budgets']['solver_timeout_sec']), 120),
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [str(goto_instrument), '--add-library', str(defined_goto), str(defined_linked)],
                check=True, timeout=120, capture_output=True, text=True,
            )
            functions, symbols = load_typed_goto_model(
                defined_linked, goto_instrument, output_dir / 'inspect_outputs',
            )
            linked_goto = defined_linked
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            helper_c_path.write_text(previous_helper, encoding='utf-8')
            (output_dir / 'output-pointer-recompile.txt').write_text(
                (getattr(exc, 'stderr', None) or str(exc))[-2000:],
                encoding='utf-8',
            )

    all_task_subtrees: list[str] = []
    for t_obj in plan['tasks']:
        if t_obj.get('role') not in (None, 'covering_cut'):
            continue
        for fn_nm in t_obj['subtree_functions']:
            if fn_nm not in all_task_subtrees:
                all_task_subtrees.append(fn_nm)
    harness_bridges = _harness_bridge_functions(functions, symbols, all_task_subtrees)
    for fn_nm in harness_bridges:
        if fn_nm not in all_task_subtrees:
            all_task_subtrees.append(fn_nm)

    cloned_fns, cloned_syms, world_maps = clone_dual_world_goto(
        functions, symbols, all_task_subtrees
    )

    resolved_weave_specs = []
    for hs in hook_weave_specs:
        matches = [f['name'] for f in functions if symbols.get(f['name'], {}).get('baseName', f['name']) == hs['guard_base_name']]
        for m_fn in matches:
            spec_copy = dict(hs)
            spec_copy['guard_ir_function'] = m_fn
            resolved_weave_specs.append(spec_copy)

    weaved_fns, weaved_syms = apply_paired_weaves(
        cloned_fns, cloned_syms, world_maps['w1'], resolved_weave_specs,
        case_ir.get('observer_specs') or [], case_ir.get('maps') or {}, plan,
    )

    fn_by_name = {f['name']: f for f in weaved_fns}
    for harness_fn_name in ('__vg_run_world_0', '__vg_run_world_1'):
        if harness_fn_name in fn_by_name:
            w_key = 'w0' if harness_fn_name.endswith('0') else 'w1'
            rmap = world_maps[w_key]
            for insn in fn_by_name[harness_fn_name].get('instructions', []):
                if 'code' in insn:
                    from .paired_goto import _rewrite_irep_symbols
                    insn['code'] = _rewrite_irep_symbols(insn['code'], rmap)
                if 'guard' in insn:
                    from .paired_goto import _rewrite_irep_symbols
                    insn['guard'] = _rewrite_irep_symbols(insn['guard'], rmap)

    paired_goto = output_dir / 'paired_dual_world.goto'
    object_bits = initial_object_bits(driver_path.read_text(encoding='utf-8', errors='replace'))
    shadow_enabled = bool(case_sym_cfg.get('enable_uninitialized_shadow', True))
    unwind = int(case_ir['budgets']['loop_unwind'])
    timeout_sec = max(int(case_ir['budgets']['solver_timeout_sec']), 1200 if object_bits >= 14 else 600)

    if shadow_enabled and object_bits >= 14:
        export_meta = {
            'output_goto': '',
            'encoding': {'object_bits': object_bits},
            'shadow_initialization': None,
            'skipped': 'snapshot_object_encoding_skips_shadow_query',
        }
        o2_o3_res = {
            'status': 'incomplete',
            'reason': 'snapshot_object_encoding_skips_shadow_query',
            'properties': [],
            'unwind_failures': [],
            'object_bits': object_bits,
        }
    else:
        export_meta = finalize_and_export_goto(
            weaved_fns,
            weaved_syms,
            paired_goto,
            tool_dir,
            output_dir / 'export_paired',
            enable_shadow=shadow_enabled,
            object_bits=object_bits,
            timeout=case_ir['budgets']['solver_timeout_sec'],
        )
        o2_o3_res = _run_cbmc_json(
            paired_goto, cbmc_bin, output_dir / 'query_obligations',
            unwind=unwind, object_bits=object_bits, timeout=timeout_sec,
            extra_flags=_obligation_query_flags(case_ir),
        )

    def _compile_clean_noshadow_paired(dest_dir: Path) -> Path:
        dest_dir.mkdir(parents=True, exist_ok=True)
        ns_fns, ns_syms = load_typed_goto_model(linked_goto, goto_instrument, dest_dir / 'inspect')
        ns_cloned_fns, ns_cloned_syms, ns_wmaps = clone_dual_world_goto(
            ns_fns, ns_syms, all_task_subtrees
        )
        ns_weaved_fns, ns_weaved_syms = apply_paired_weaves(
            ns_cloned_fns, ns_cloned_syms, ns_wmaps['w1'], resolved_weave_specs,
            case_ir.get('observer_specs') or [], case_ir.get('maps') or {}, plan,
        )
        ns_fmap = {f['name']: f for f in ns_weaved_fns}
        from .paired_goto import _rewrite_irep_symbols
        for h_nm, w_k in (('__vg_run_world_0', 'w0'), ('__vg_run_world_1', 'w1')):
            if h_nm in ns_fmap:
                for ins in ns_fmap[h_nm].get('instructions', []):
                    if 'code' in ins:
                        ins['code'] = _rewrite_irep_symbols(ins['code'], ns_wmaps[w_k])
                    if 'guard' in ins:
                        ins['guard'] = _rewrite_irep_symbols(ins['guard'], ns_wmaps[w_k])
        ns_goto = dest_dir / 'paired_noshadow.goto'
        finalize_and_export_goto(
            ns_weaved_fns, ns_weaved_syms, ns_goto, tool_dir, dest_dir / 'export',
            enable_shadow=False, object_bits=object_bits, timeout=timeout_sec,
        )
        return ns_goto

    if o2_o3_res['status'] != 'completed' and bool(case_sym_cfg.get('enable_uninitialized_shadow', True)):
        noshadow_goto = _compile_clean_noshadow_paired(output_dir / 'clean_noshadow')
        o2_o3_res = _run_cbmc_json(
            noshadow_goto, cbmc_bin, output_dir / 'query_obligations_noshadow',
            unwind=unwind, object_bits=object_bits, timeout=timeout_sec,
            extra_flags=_obligation_query_flags(case_ir),
        )
        o2_o3_res['shadow_fallback'] = True

    props = o2_o3_res.get('properties', [])

    unmodeled_init_props = [p for p in props if p.get('description', '').startswith('__VG_UNMODELED_INIT:')]
    unmodeled_init_reached = any(p.get('status') == 'FAILURE' for p in unmodeled_init_props)
    if unmodeled_init_reached:
        noshadow_goto = _compile_clean_noshadow_paired(output_dir / 'clean_noshadow')
        ns_res = _run_cbmc_json(
            noshadow_goto, cbmc_bin, output_dir / 'query_obligations_noshadow',
            extra_flags=_obligation_query_flags(case_ir),
            unwind=unwind, object_bits=object_bits, timeout=timeout_sec,
        )
        if ns_res['status'] == 'completed':
            props = ns_res.get('properties', [])
            o2_o3_res = ns_res
            o2_o3_res['shadow_union_precision_note'] = 'union-bearing struct initialized checks deferred; pointer/bounds/assertion checks verified'

    cont_props = [p for p in props if (p.get('description') in (
        'vg.obligation.action_continuation_safe',
        *_ACTION_WRITE_OBLIGATIONS,
        'vg.obligation.loop_exit_progress',
        'vg.obligation.allocator_lifetime',
        'vg.obligation.brigade_ring',
        'vg.obligation.output_pointer_defined',
        'vg.obligation.resource_release',
        'vulgate.initialized_read',
    ) or ((any(tok in p.get('property', '') for tok in ('__vg_w1_', '__vulgate_action_')))
          and '.unwind.' not in p.get('property', '')
          and not p.get('description', '').startswith('__VG_UNMODELED_INIT:')
          and 'vg.target.' not in p.get('description', '')))]

    target_w1_props = obligation_target_properties(props)
    target_w0_nonvac = [p for p in props if p.get('description') == 'vg.target.nonvacuity_w0']
    pass_eq_props = [p for p in props if p.get('description') == 'vg.obligation.pass_noninterference']

    query_completed = o2_o3_res['status'] == 'completed'
    unwind_failures = list(o2_o3_res.get('unwind_failures') or [])

    def judge(prop_list: list[dict[str, Any]], *, blocked_unwind_is_violation: bool) -> tuple[str, list[dict[str, Any]]]:
        return classify_obligation_status(
            prop_list,
            unwind_failures,
            query_completed,
            blocked_unwind_is_violation=blocked_unwind_is_violation,
        )

    o2_status, o2_ces = judge(cont_props, blocked_unwind_is_violation=True)
    o3_cut_status, o3_ces = judge(target_w1_props, blocked_unwind_is_violation=False)
    o2_status = demote_unbound_oracle(o2_status, props)
    o3_cut_status = demote_unbound_oracle(o3_cut_status, props)
    w0_repro = any(p.get('status') == 'FAILURE' for p in target_w0_nonvac)
    from .missing_callees import proof_blocked_by_missing_callees
    missing_props = [p for p in props if p.get('description') == 'vg.obligation.missing_callee_model']
    missing_hit = any(p.get('status') == 'FAILURE' for p in missing_props)
    missing_block = proof_blocked_by_missing_callees(missing_hit, stub_info)
    if missing_block or model_bound_blocks_proof(props):
        if o2_status == 'PROVED_IN_BOUNDED_DOMAIN':
            o2_status = 'UNRESOLVED'
        if o3_cut_status == 'PROVED_IN_BOUNDED_DOMAIN':
            o3_cut_status = 'UNRESOLVED'
    unreleased_resources = sorted({
        sym
        for cont in plan.get('continuations') or []
        for sym in (cont.get('unreleased_resources') or [])
    })
    if o2_status == 'PROVED_IN_BOUNDED_DOMAIN' and continuation_closure_blocks_proof(plan):
        o2_status = 'UNRESOLVED'

    if o3_cut_status == 'PROVED_IN_BOUNDED_DOMAIN' and plan['bypass_paths']:
        o3_global_status = 'PARTIAL_COVERAGE'
    else:
        o3_global_status = o3_cut_status

    if o2_o3_res['status'] != 'completed':
        regions = {
            'candidate_predicates': [],
            'queries': 0,
            'regions': [{
                'region': 'True',
                'classification': 'UNRESOLVED',
                'reason': o2_o3_res.get('reason'),
            }],
        }
    else:
        regions = _discover_paired_impact_regions(
            case_ir, driver_path, all_c_files, helper_c_path, flags,
            world_maps, resolved_weave_specs, cbmc_bin, output_dir / 'impact_regions',
            functions=functions, symbols=symbols,
            cut_names=[
                task['cut_function'] for task in plan.get('tasks', [])
                if task.get('role') in (None, 'covering_cut') and task.get('cut_function')
            ],
            plan=plan,
        )
    if pass_eq_props:
        pass_status, pass_ces = judge(pass_eq_props, blocked_unwind_is_violation=False)
    else:
        pass_status, pass_ces = judge_pass_path_noninterference(regions)
    o2_status, o3_global_status, pass_status = limit_claim_to_activated_path(
        plan, o2_status, o3_global_status, pass_status,
    )

    query_outside_caller_locals(
        case_ir,
        plan,
        stamped_sources=stamped_sources,
        flags=flags,
        helper_c_path=helper_c_path,
        hook_weave_specs=hook_weave_specs,
        cbmc_bin=cbmc_bin,
        output_dir=output_dir,
        unwind=unwind,
        timeout_sec=timeout_sec,
        shadow_enabled=bool(case_sym_cfg.get('enable_uninitialized_shadow', True)),
    )

    from .entry_predicates import caller_return_conditions as _caller_return_conditions
    sym_inputs = case_ir.get('symbolization_scope', {}).get('symbolic_inputs', [])
    caller_returns = _caller_return_conditions(
        functions,
        symbols,
        case_ir.get('guards') or [],
        {item['name'] for item in sym_inputs if isinstance(item, dict) and item.get('name')},
        case_ir.get('symbolization_scope', {}).get('field_to_input_map') or {},
    )

    result = {
        'status': 'COMPLETED',
        'boundary_plan': plan,
        'caller_return_conditions': caller_returns,
        'export_metadata': export_meta,
        'action_and_caller_continuation': {
            'status': o2_status,
            'scope': {
                'kind': _verification_scope_kind(
                    case_sym_cfg.get('scope_kind'),
                    (abstract_snap or {}).get('mode'),
                ),
                'cut_functions': plan['selected_cut_functions'],
                'harness_bridge_functions': harness_bridges,
                'unwind': unwind,
                'uninitialized_shadow_enabled': bool(case_sym_cfg.get('enable_uninitialized_shadow', True)),
                'checked_obligations': _checked_obligation_names(driver_path),
                'unreleased_resources': unreleased_resources,
                'symbolization_constraints': symbolization_constraints(case_ir, abstract_snap),
            },
            'checked_properties': len(cont_props),
            'counterexamples': o2_ces,
        },
        'target_vulnerability_elimination': {
            'status': o3_global_status,
            'cut_local_status': o3_cut_status,
            'baseline_vulnerability_reproduced_in_model': w0_repro,
            'bypass_paths': plan['bypass_paths'],
            'counterexamples': o3_ces,
        },
        'pass_path_noninterference': {
            'status': pass_status,
            'counterexamples': pass_ces,
        },
        'missing_callee_model': {
            'blocked_proof': missing_block,
            'hit_on_harness_path': missing_hit,
            'stubbed': list(stub_info.get('stubbed') or []),
            'unrendered': list(stub_info.get('unrendered') or []),
            'linked': bool(stub_info.get('linked')),
            'compile_error': stub_info.get('compile_error'),
        },
        'snapshot_lift': {
            'mode': (abstract_snap or {}).get('mode', 'driver_supplied'),
            'dynamic_trace_count': len(case_ir.get('dynamic_traces') or []),
            'symbolization_constraints': symbolization_constraints(case_ir, abstract_snap),
        },
        'impact_regions': regions,
        'local_caller_obligations': [
            {
                'cut_function': task.get('cut_function'),
                **dict(task.get('local_obligation') or {}),
            }
            for task in plan.get('tasks') or []
            if task.get('local_obligation')
        ],
    }
    (output_dir / 'symbolic-verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def hook_parameter_snapshots(case_ir: dict[str, Any], witness: dict[str, Any]) -> list[dict[str, Any]]:
    shots: list[dict[str, Any]] = []
    for guard in case_ir.get('guards', []):
        slots: dict[str, dict[str, Any]] = {}
        for name, spec in (guard.get('fields') or {}).items():
            if not isinstance(spec, dict) or spec.get('source') != 'arg' or name not in witness:
                continue
            slots[name] = {'index': int(spec['index']), 'value': witness[name]}
        for index, pname in enumerate(guard.get('parameter_names') or []):
            if pname in witness and pname not in slots:
                slots[pname] = {'index': index, 'value': witness[pname]}
        mapped = set(slots)
        shots.append({
            'guard': guard.get('id'),
            'slots': slots,
            'unmapped_inputs': {key: value for key, value in witness.items() if key not in mapped},
        })
    return shots


def _discover_paired_impact_regions(case_ir: dict[str, Any],
                                    driver_path: Path,
                                    all_c_files: list[Path],
                                    helper_c_path: Path,
                                    flags: list[str],
                                    world_maps: dict[str, dict[str, str]],
                                    resolved_weave_specs: list[dict[str, Any]],
                                    cbmc_bin: Path,
                                    work_dir: Path,
                                    functions: list[dict[str, Any]] | None = None,
                                    symbols: dict[str, Any] | None = None,
                                    cut_names: list[str] | None = None,
                                    plan: dict[str, Any] | None = None) -> dict[str, Any]:
    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    driver_text = driver_path.read_text(encoding='utf-8')
    object_bits = initial_object_bits(driver_text)
    if '/*VG_IMPACT_REGION_ASSUME*/' not in driver_text or '/*VG_IMPACT_QUERY_ASSERT*/' not in driver_text:
        return {'regions': [], 'candidate_predicates': [], 'queries': 0}

    sym_inputs = case_ir.get('symbolization_scope', {}).get('symbolic_inputs', [])
    input_names = {item['name']: f'__vg_in_{item["name"]}' for item in sym_inputs}
    if not input_names:
        return {'regions': [], 'candidate_predicates': [], 'queries': 0}

    corr = case_ir.get('symbolization_scope', {}).get('field_to_input_map', {})
    cand_preds: list[str] = []
    for g in case_ir['guards']:
        for raw_p in g.get('extracted_predicates', []):
            try:
                class _Sub(ast.NodeTransformer):
                    def visit_Name(self, node):
                        if node.id in corr:
                            return ast.copy_location(ast.parse(corr[node.id], mode='eval').body, node)
                        if 'constant' in g['fields'].get(node.id, {}):
                            return ast.Constant(value=int(g['fields'][node.id]['constant']))
                        return node
                mapped = ast.unparse(_Sub().visit(ast.parse(raw_p, mode='eval')).body)
                parse(mapped, set(input_names.keys()))
                if mapped not in cand_preds:
                    cand_preds.append(mapped)
            except (ValueError, SyntaxError, KeyError):
                continue

    for extra_p in case_ir.get('symbolization_scope', {}).get('extra_predicates', []):
        try:
            parse(extra_p, set(input_names.keys()))
            if extra_p not in cand_preds:
                cand_preds.append(extra_p)
        except ValueError:
            continue

    entry_pool = {'admitted': [], 'omitted_unmapped': 0, 'flow_omitted': [], 'caller_return_conditions': []}
    if functions is not None and symbols is not None:
        from .entry_predicates import collect_entry_predicates
        entry_pool = collect_entry_predicates(
            functions, symbols, cut_names or [], case_ir.get('guards') or [],
            set(input_names), corr,
        )
        for pred in entry_pool['admitted']:
            if pred not in cand_preds:
                cand_preds.append(pred)

    tool_dir = cbmc_bin.parent
    goto_cc = tool_dir / 'goto-cc'
    goto_instrument = tool_dir / 'goto-instrument'
    unwind = int(case_ir['budgets']['loop_unwind'])
    timeout_sec = max(int(case_ir['budgets']['solver_timeout_sec']), 600)
    max_regions = int(case_ir['budgets']['max_impact_regions'])

    query_count = 0

    def run_region_query(region_expr: str, kind: str) -> dict[str, Any]:
        nonlocal query_count
        qdir = work_dir / f'r{query_count:03d}_{kind}'
        qdir.mkdir(parents=True, exist_ok=True)
        query_count += 1

        c_cond = c_expression(parse(region_expr, set(input_names.keys())), input_names)
        assert_expr = {
            'reach': '0',
            'diff': '!__vg_obs_diff',
            'equal': '__vg_obs_diff',
            'pass_diff': '!(!__vulgate_any_blocked && __vg_obs_diff)',
        }[kind]

        patched_driver = (
            driver_text
            .replace('/*VG_IMPACT_REGION_ASSUME*/', f'__CPROVER_assume({c_cond});')
            .replace('/*VG_IMPACT_QUERY_ASSERT*/', f'__CPROVER_assert({assert_expr}, "vg.impact.query");')
        )
        custom_driver_file = qdir / 'driver_region.c'
        custom_driver_file.write_text(patched_driver, encoding='utf-8')
        c_list = [p for p in all_c_files if p != driver_path] + [custom_driver_file, helper_c_path]

        q_base = qdir / 'q_base.goto'
        q_link = qdir / 'q_link.goto'
        try:
            subprocess.run([str(goto_cc), *flags, *[str(p) for p in c_list],
                            '--function', '__vg_impact_harness', '-o', str(q_base)],
                           check=True, timeout=timeout_sec, capture_output=True, text=True)
            subprocess.run([str(goto_instrument), '--add-library', str(q_base), str(q_link)],
                           check=True, timeout=timeout_sec, capture_output=True, text=True)
            fns, syms = load_typed_goto_model(q_link, goto_instrument, qdir / 'inspect')
            sub_fns = [k for k in world_maps['w0'] if any(f['name'] == k for f in fns)]
            cfns, csyms, wmaps = clone_dual_world_goto(fns, syms, sub_fns)
            wfns, wsyms = apply_paired_weaves(
                cfns, csyms, wmaps['w1'], resolved_weave_specs,
                case_ir.get('observer_specs') or [], case_ir.get('maps') or {},
                plan or {},
            )
            fmap = {f['name']: f for f in wfns}
            from .paired_goto import _rewrite_irep_symbols
            for hname, wk in (('__vg_run_world_0', 'w0'), ('__vg_run_world_1', 'w1')):
                if hname in fmap:
                    for ins in fmap[hname].get('instructions', []):
                        if 'code' in ins:
                            ins['code'] = _rewrite_irep_symbols(ins['code'], wmaps[wk])
                        if 'guard' in ins:
                            ins['guard'] = _rewrite_irep_symbols(ins['guard'], wmaps[wk])
            q_paired = qdir / 'q_paired.goto'
            finalize_and_export_goto(wfns, wsyms, q_paired, tool_dir, qdir / 'export', enable_shadow=False, object_bits=object_bits, timeout=timeout_sec)
            cbmc_res = _run_cbmc_json(
                q_paired, cbmc_bin, qdir / 'solve', unwind=unwind, object_bits=object_bits, timeout=timeout_sec,
                extra_flags=_cbmc_entry_flags('__vg_impact_harness'),
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
            return {'status': 'unresolved', 'witness': {}}
        if cbmc_res['status'] != 'completed' or cbmc_res['unwind_failures']:
            return {'status': 'unresolved', 'witness': {}}
        return classify_impact_query_result(cbmc_res['properties'])

    pending: list[tuple[str, list[str]]] = [('True', [])]
    leaves: list[dict[str, Any]] = []
    while pending:
        reg, used = pending.pop(0)
        r_reach = run_region_query(reg, 'reach')
        if r_reach['status'] == 'unsat':
            leaves.append({'region': reg, 'classification': 'UNREACHABLE'})
            continue
        if r_reach['status'] != 'sat':
            leaves.append({'region': reg, 'classification': 'UNRESOLVED'})
            continue
        r_diff = run_region_query(reg, 'diff')
        if r_diff['status'] == 'unsat':
            leaves.append({'region': reg, 'classification': 'UNCHANGED', 'witness': r_reach['witness']})
            continue
        if r_diff['status'] != 'sat':
            leaves.append({'region': reg, 'classification': 'UNRESOLVED'})
            continue
        r_eq = run_region_query(reg, 'equal')
        if r_eq['status'] == 'unsat':
            r_pdiff = run_region_query(reg, 'pass_diff')
            if r_pdiff['status'] == 'sat':
                cls_name = 'CHANGED_ON_PASS'
            elif r_pdiff['status'] == 'unsat':
                cls_name = 'CHANGED_BY_BLOCK'
            else:
                cls_name = 'UNRESOLVED'
            leaves.append({'region': reg, 'classification': cls_name, 'witness': r_diff['witness']})
            continue
        split_pred = None
        if r_eq['status'] == 'sat' and len(leaves) + len(pending) + 2 <= max_regions:
            for cand in cand_preds:
                if cand in used:
                    continue
                parsed_c = parse(cand, set(input_names.keys()))
                try:
                    v1 = bool(evaluate(parsed_c, r_diff['witness']))
                    v2 = bool(evaluate(parsed_c, r_eq['witness']))
                    if v1 != v2:
                        split_pred = cand
                        break
                except KeyError:
                    continue
        if split_pred:
            pending.append((f'({reg}) and ({split_pred})', [*used, split_pred]))
            pending.append((f'({reg}) and (not ({split_pred}))', [*used, split_pred]))
        else:
            leaves.append({
                'region': reg,
                'classification': 'MIXED' if r_eq['status'] == 'sat' else 'UNRESOLVED',
                'witness': r_diff['witness'],
            })

    for leaf in leaves:
        witness = leaf.get('witness') or {}
        if witness:
            leaf['hook_parameter_snapshot'] = hook_parameter_snapshots(case_ir, witness)

    return {
        'candidate_predicates': cand_preds,
        'entry_predicates': entry_pool,
        'queries': query_count,
        'regions': leaves,
    }
