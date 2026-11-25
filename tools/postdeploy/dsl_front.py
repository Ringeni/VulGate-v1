from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import re
from typing import Any

from runtime.dsl import parser as dsl_parser
from runtime.dsl import vm as dsl_vm

ROOT = Path(__file__).resolve().parents[2]
DSL_PATCH_DIR = ROOT / 'runtime' / 'dsl' / 'patches'

_READ_TYPES = {
    'vg_read_u8': 'u8',
    'vg_read_u16': 'u16',
    'vg_read_u32': 'u32',
    'vg_read_u64': 'u64',
    'vg_read_s8': 's8',
    'vg_read_s16': 's16',
    'vg_read_s32': 's32',
    'vg_read_s64': 's64',
    'vg_read_pointer': 'pointer',
}

_BOOL_OPS = {'&&': 'and', '||': 'or'}

_MAP_READ_OPS = ('mapget', 'mappresent')
_INLINE_LEAF_KINDS = ('arg', 'local', 'global', 'read', 'mapget', 'mappresent')


def patch_path(case_id: str) -> Path | None:
    for name in (f'{case_id}.vg', f'{case_id}-single.vg'):
        candidate = DSL_PATCH_DIR / name
        if candidate.is_file():
            return candidate
    return None


def serialize_dsl_ast(node: Any,
                      map_state: dsl_vm.MapState,
                      current_map: str | None = None) -> dict[str, Any]:
    kind = node[0]
    if kind == 'const':
        return {'kind': 'const', 'value': int(node[1])}
    if kind == 'string':
        if current_map is not None:
            return {'kind': 'const', 'value': int(map_state.key_id(current_map, str(node[1])))}
        return {'kind': 'string', 'value': str(node[1])}
    if kind == 'arg':
        return {'kind': 'arg', 'index': int(node[1])}
    if kind == 'local':
        return {'kind': 'local', 'name': str(node[1])}
    if kind == 'var':
        return {'kind': 'var', 'name': str(node[1])}
    if kind == 'global':
        return {'kind': 'global', 'name': str(node[1])}
    if kind == 'sel':
        return {'kind': 'sel', 'name': str(node[1])}
    if kind == 'read':
        return {
            'kind': 'read',
            'helper': str(node[1]),
            'address': serialize_dsl_ast(node[2], map_state),
        }
    if kind == 'mapget':
        mname = str(node[1])
        return {
            'kind': 'mapget',
            'map': mname,
            'key': serialize_dsl_ast(node[2], map_state, mname),
            'consume': bool(node[3]) if len(node) > 3 else False,
        }
    if kind == 'mappresent':
        mname = str(node[1])
        return {
            'kind': 'mappresent',
            'map': mname,
            'key': serialize_dsl_ast(node[2], map_state, mname),
        }
    if kind == 'unary':
        return {
            'kind': 'unary',
            'op': str(node[1]),
            'operand': serialize_dsl_ast(node[2], map_state),
        }
    if kind == 'bin':
        return {
            'kind': 'bin',
            'op': str(node[1]),
            'left': serialize_dsl_ast(node[2], map_state),
            'right': serialize_dsl_ast(node[3], map_state),
        }
    raise ValueError(f'unsupported DSL AST node: {kind}')


def _extract_loop_map_ops(loops: list[tuple[str, int, int, str]],
                          map_state: dsl_vm.MapState) -> list[dict[str, Any]]:
    rendered: list[dict[str, Any]] = []
    for variable, start, bound, body in loops:
        count = int(bound) - int(start)
        if int(start) < 0 or count < 1 or count > dsl_vm.MAX_LOOP_ITERATIONS:
            raise ValueError(f'loop bound must be in 1..{dsl_vm.MAX_LOOP_ITERATIONS}')
        ops: list[dict[str, Any]] = []
        for match in re.finditer(r'map\["([^"]+)"\]\[(.+?)\]\s*=\s*(.+?);', body, re.S):
            map_name, key_expr, val_expr = match.groups()
            key_node = dsl_vm.Parser(key_expr).parse()
            val_node = dsl_vm.Parser(val_expr).parse()
            ops.append({
                'kind': 'set',
                'map': map_name,
                'key': serialize_dsl_ast(key_node, map_state, map_name),
                'value': serialize_dsl_ast(val_node, map_state),
            })
        rendered.append({
            'kind': 'loop',
            'var': str(variable),
            'start': int(start),
            'bound': int(bound),
            'ops': ops,
        })
    return rendered


def _collect_ast_locals_and_args(item: Any,
                                 locals_out: list[str],
                                 args_out: list[int]) -> None:
    if isinstance(item, list):
        for child in item:
            _collect_ast_locals_and_args(child, locals_out, args_out)
        return
    if not isinstance(item, dict):
        return
    kind = item.get('kind')
    if kind == 'local':
        name = str(item['name'])
        if name not in locals_out:
            locals_out.append(name)
    elif kind == 'arg':
        idx = int(item['index'])
        if idx not in args_out:
            args_out.append(idx)
    for value in item.values():
        if isinstance(value, (dict, list)):
            _collect_ast_locals_and_args(value, locals_out, args_out)


def _observer_spec(mount: dsl_parser.MountSpec,
                   map_state: dsl_vm.MapState) -> dict[str, Any]:
    loops = dsl_vm._find_loops(mount.body)
    remaining = dsl_vm._strip_loops(mount.body)
    assignments = dsl_vm._extract_observer(remaining) if 'map[' in remaining else []
    if not loops and not assignments:
        raise ValueError(f'read_point mount {mount.id} has no map operations')
    dsl_ops = _extract_loop_map_ops(loops, map_state)
    for map_name, key_expr, val_expr in assignments:
        key_node = dsl_vm.Parser(key_expr).parse()
        val_node = dsl_vm.Parser(val_expr).parse()
        dsl_ops.append({
            'kind': 'set',
            'map': map_name,
            'key': serialize_dsl_ast(key_node, map_state, map_name),
            'value': serialize_dsl_ast(val_node, map_state),
        })
    primary_map = ''
    for entry in dsl_ops:
        if entry['kind'] == 'set':
            primary_map = str(entry['map'])
            break
        if entry['kind'] == 'loop' and entry.get('ops'):
            primary_map = str(entry['ops'][0]['map'])
            break
    if not primary_map:
        raise ValueError(f'read_point mount {mount.id} does not target a map')
    local_names: list[str] = []
    for raw_local in re.findall(r'local\("([^"]+)"\)', mount.body):
        if raw_local not in local_names:
            local_names.append(raw_local)
    arg_indices: list[int] = []
    _collect_ast_locals_and_args(dsl_ops, local_names, arg_indices)
    arg_indices.sort()
    obs: dict[str, Any] = {
        'id': mount.id.rsplit('/', 1)[-1],
        'dsl_mount_id': mount.id,
        'map': primary_map,
        'operation': 'set',
        'arg_types': list(mount.args),
        'dsl_operations': dsl_ops,
        'local_names': local_names,
        'arg_indices': arg_indices,
    }
    if mount.module:
        obs['module'] = mount.module
    if mount.offset is not None:
        obs['offset'] = int(mount.offset)
    if mount.location_kind == 'callsite':
        obs['function'] = mount.caller or mount.symbol
        obs['dsl_callsite'] = {
            'caller': mount.caller,
            'callee': mount.callee,
            'line': mount.line,
            'file': mount.file,
        }
    elif mount.location_kind == 'line':
        if mount.caller or mount.symbol:
            obs['function'] = mount.caller or mount.symbol
        obs['dsl_line'] = {
            'file': mount.file,
            'line': int(mount.line) if mount.line is not None else None,
        }
    else:
        obs['function'] = mount.symbol
        if mount.caller:
            obs['caller'] = mount.caller
    return obs


def derive_patch_spec(vg_path: Path | str, base_patch: dict[str, Any] | None = None) -> dict[str, Any]:
    vg_path = Path(vg_path)
    patch = dsl_parser.load(vg_path)
    map_state = dsl_vm.MapState(patch.maps)
    derived = copy.deepcopy(base_patch) if base_patch else {}
    derived['schema'] = derived.get('schema') or 'vulgate.patch/v2'
    derived['maps'] = {name: {'capacity': int(spec.capacity)} for name, spec in patch.maps.items()}
    observers: list[dict[str, Any]] = []
    guards: list[dict[str, Any]] = []
    for mount in patch.mounts:
        if mount.nature in ('读取点', 'read_point'):
            observers.append(_observer_spec(mount, map_state))
        else:
            guards.append(_guard_spec(mount, map_state))
    derived['observers'] = observers
    derived['guards'] = guards
    derived['actions'] = {name: _action_spec(spec) for name, spec in patch.actions.items()}
    derived['install_hook_count'] = len(patch.mounts)
    derived['dsl_patch'] = {
        'path': str(vg_path.resolve()),
        'sha256': hashlib.sha256(vg_path.read_bytes()).hexdigest(),
    }
    return derived


def _guard_spec(mount: dsl_parser.MountSpec, map_state: dsl_vm.MapState) -> dict[str, Any]:
    loops = dsl_vm._find_loops(mount.body)
    dsl_loops = _extract_loop_map_ops(loops, map_state) if loops else []
    selector_text, condition_text, action_id = dsl_vm._extract(dsl_vm._strip_loops(mount.body))
    raw_nodes = {name: dsl_vm.Parser(text).parse() for name, text in selector_text.items()}
    condition = dsl_vm.Parser(condition_text).parse()
    local_order: list[str] = []
    for lname in re.findall(r'local\("([^"]+)"\)', mount.body):
        if lname not in local_order:
            local_order.append(lname)
    converter = _Converter(mount, copy.deepcopy(raw_nodes), map_state)
    expr_text = converter.prepare_and_render(condition)
    guard: dict[str, Any] = {
        'id': mount.id.rsplit('/', 1)[-1],
        'dsl_mount_id': mount.id,
        'function': mount.symbol,
        'arg_types': list(mount.args),
        'return_type': mount.return_type,
        'selectors': converter.selectors(),
        'expression': expr_text,
        'action_id': action_id,
        'dsl_ast': {
            'loops': dsl_loops,
            'selectors': {name: serialize_dsl_ast(node, map_state) for name, node in raw_nodes.items()},
            'condition': serialize_dsl_ast(condition, map_state),
            'local_order': local_order,
        },
    }
    if dsl_loops:
        guard['dsl_loops'] = dsl_loops
    if mount.module:
        guard['module'] = mount.module
    if mount.offset is not None:
        guard['offset'] = int(mount.offset)
    if mount.caller:
        guard['caller'] = mount.caller
    map_reads = converter.map_reads()
    if map_reads:
        guard['map_reads'] = map_reads
    return guard


def _action_spec(action: dsl_parser.ActionSpec) -> dict[str, Any]:
    if action.return_type == 'void':
        return {'kind': 'return_void'}
    if action.return_type == 'string':
        return {'kind': 'return_string', 'value': str(action.value or '')}
    if action.value is None:
        return {'kind': 'return_null'}
    return {'kind': 'return_int', 'value': int(action.value)}


def _map_ops(node: Any) -> bool:
    return isinstance(node, tuple) and node[0] in _MAP_READ_OPS


class _Converter:
    def __init__(self,
                 mount: dsl_parser.MountSpec,
                 nodes: dict[str, tuple],
                 map_state: dsl_vm.MapState):
        self.mount = mount
        self.nodes = nodes
        self.map_state = map_state
        self._selectors: dict[str, dict[str, Any]] = {}
        self._referenced_names: set[str] = set()
        self._inline_by_repr: dict[str, str] = {}
        self._inline_counter = 0

    def _is_compound(self, node: tuple, seen: tuple[str, ...] = ()) -> bool:
        kind = node[0]
        if kind in ('bin', 'unary'):
            return True
        if kind == 'sel':
            name = str(node[1])
            if name in seen or name not in self.nodes:
                return False
            return self._is_compound(self.nodes[name], (*seen, name))
        return False

    def _alloc_inline_selector(self, node: tuple) -> str:
        key = repr(node)
        if key in self._inline_by_repr:
            name = self._inline_by_repr[key]
            self._referenced_names.add(name)
            return name
        if node[0] == 'arg':
            cand = f'arg{int(node[1])}'
            if cand not in self.nodes:
                self.nodes[cand] = node
                self._inline_by_repr[key] = cand
                self._referenced_names.add(cand)
                return cand
        if node[0] == 'local':
            base_cand = re.sub(r'[^A-Za-z0-9_]', '_', str(node[1]))
            cand = f'local_{base_cand}'
            if cand not in self.nodes:
                self.nodes[cand] = node
                self._inline_by_repr[key] = cand
                self._referenced_names.add(cand)
                return cand
        while True:
            cand = f'__vg_inline_{self._inline_counter}'
            self._inline_counter += 1
            if cand not in self.nodes:
                self.nodes[cand] = node
                self._inline_by_repr[key] = cand
                self._referenced_names.add(cand)
                return cand

    def prepare_and_render(self, condition: tuple) -> str:
        return self._render(condition, top=True, seen=())

    def selectors(self) -> dict[str, dict[str, Any]]:
        ordered: dict[str, dict[str, Any]] = {}
        for name, node in self.nodes.items():
            if _map_ops(node) or self._is_compound(node):
                continue
            keep = name in self._referenced_names or node[0] in ('const', 'local')
            if keep:
                ordered[name] = self._selector(name)
        return ordered

    def map_reads(self) -> list[dict[str, Any]]:
        reads: dict[tuple[str, str], dict[str, Any]] = {}
        for name, node in self.nodes.items():
            if not _map_ops(node):
                continue
            key = (node[1], self._key_text(node[2]))
            entry = reads.setdefault(key, {'map': node[1]})
            if node[0] == 'mapget':
                entry['into'] = name
                entry['consume'] = bool(node[3])
            else:
                entry['present_into'] = name
            if 'key_arg' not in entry and 'key' not in entry:
                if node[2][0] == 'arg':
                    entry['key_arg'] = int(node[2][1])
                elif node[2][0] == 'string':
                    entry['key'] = {'constant': int(self.map_state.key_id(node[1], str(node[2][1])))}
                else:
                    entry['key'] = self._chain(node[2], ())
        result: list[dict[str, Any]] = []
        for item in reads.values():
            if 'present_into' not in item:
                item['on_missing'] = 'pass'
            result.append(item)
        return result

    def _render(self, condition: tuple, top: bool = True, seen: tuple[str, ...] = ()) -> str:
        kind = condition[0]
        if kind == 'const':
            return ('True' if condition[1] else 'False') if top else str(int(condition[1]))
        if kind == 'sel':
            name = str(condition[1])
            if name in seen:
                raise ValueError('cyclic selector: ' + name)
            if name not in self.nodes:
                raise ValueError('unknown selector: ' + name)
            target = self.nodes[name]
            if self._is_compound(target):
                return self._render(target, False, (*seen, name))
            self._referenced_names.add(name)
            return name
        if kind in _INLINE_LEAF_KINDS:
            return self._alloc_inline_selector(condition)
        if kind == 'bin':
            operator = condition[1]
            text = _BOOL_OPS.get(operator, operator)
            if text in ('and', 'or'):
                parts: list[tuple] = []
                self._flatten(condition, operator, parts)
                return '(' + f' {text} '.join(self._render(part, False, seen) for part in parts) + ')'
            return f'({self._render(condition[2], False, seen)} {text} {self._render(condition[3], False, seen)})'
        if kind == 'unary':
            operand = self._render(condition[2], False, seen)
            if condition[1] == '!':
                return f'(not {operand})'
            if condition[1] == '-':
                return f'(0 - {operand})'
            if condition[1] == '~':
                return f'({operand} ^ 18446744073709551615)'
            raise ValueError(f'unsupported unary operator: {condition[1]}')
        raise ValueError(f'unsupported guard condition node: {kind}')

    def _flatten(self, node: tuple, operator: str, parts: list[tuple]) -> None:
        if node[0] == 'bin' and node[1] == operator:
            self._flatten(node[2], operator, parts)
            self._flatten(node[3], operator, parts)
        else:
            parts.append(node)

    def _selector(self, name: str) -> dict[str, Any]:
        if name not in self._selectors:
            self._selectors[name] = self._chain(self.nodes[name], (name,))
        return copy.deepcopy(self._selectors[name])

    def _chain(self, node: tuple, seen: tuple[str, ...]) -> dict[str, Any]:
        kind = node[0]
        if kind == 'const':
            return {'constant': int(node[1])}
        if kind == 'arg':
            index = int(node[1])
            return {'arg': index, 'type': self._arg_type(index)}
        if kind == 'sel':
            name = node[1]
            if name in seen:
                raise ValueError('cyclic selector: ' + name)
            if name not in self.nodes:
                raise ValueError('unknown selector: ' + name)
            return self._chain(self.nodes[name], (*seen, name))
        if kind == 'local':
            return {'local': node[1]}
        if kind == 'global':
            return {'global_symbol': node[1]}
        if kind == 'read':
            return self._read(node, seen)
        raise ValueError(f'unsupported selector expression node: {kind}')

    def _read(self, node: tuple, seen: tuple[str, ...]) -> dict[str, Any]:
        helper = node[1]
        if helper not in _READ_TYPES:
            raise ValueError('unsupported read helper: ' + helper)
        base, offset, index, stride = self._address(node[2], seen)
        step: dict[str, Any] = {'offset': offset, 'type': _READ_TYPES[helper]}
        if index is not None:
            step['stride'] = stride
            step['index'] = index
        if base[0] == 'arg':
            return {'arg': int(base[1]), 'reads': [step]}
        spec = self._chain(base, seen)
        if base[0] == 'global':
            return {'global_symbol': base[1], 'reads': [step]}
        if 'reads' not in spec:
            raise ValueError('read base must be an argument, global or pointer value')
        spec['reads'] = [*spec['reads'], step]
        return spec

    def _address(self, node: tuple, seen: tuple[str, ...]) -> tuple[tuple, int, dict[str, Any] | None, int]:
        if node[0] == 'bin' and node[1] == '+':
            left, right = node[2], node[3]
            if right[0] == 'const':
                base, offset, index, stride = self._address(left, seen)
                return base, offset + int(right[1]), index, stride
            if right[0] == 'bin' and right[1] == '*':
                first, second = right[2], right[3]
                if second[0] == 'const':
                    base, offset, _index, _stride = self._address(left, seen)
                    return base, offset, self._chain(first, seen), int(second[1])
                if first[0] == 'const':
                    base, offset, _index, _stride = self._address(left, seen)
                    return base, offset, self._chain(second, seen), int(first[1])
        return node, 0, None, 8

    def _arg_type(self, index: int) -> str:
        return str(self.mount.args[index]) if index < len(self.mount.args) else 'uint64'

    def _key_text(self, node: tuple) -> str:
        if node[0] == 'string':
            return repr(node)
        return repr(node)
