"""Derive the verification guard model from the main-chain DSL patch.

`runtime/dsl/patches/<case>.vg` is the patch installed by the DSL -> Shadow VM
-> Frida chain.  `tools/postdeploy/case_compiler.compile_case` consumes a
`vulgate.patch/v2` mapping (guards/actions/maps).  This module converts the same
`.vg` file into that mapping so the symbolic half verifies the installed patch
instead of the legacy guard declarations in `build/.../patch.yaml`.

Coordinates are taken verbatim from the DSL (no layout override, DWARF member
lookup or bit-field substitution), so the derived rule is exactly the predicate
the Shadow VM evaluates.  `.vg` read-point mounts are installation
instrumentation; the symbolic half consumes the guard's `map_reads`, so only
guards, actions and maps are derived here.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
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


def patch_path(case_id: str) -> Path | None:
    """Return the main-chain DSL file for a case id, or None.

    The install chain names patches `<case>.vg`; Brotli additionally ships a
    `<case>-single.vg` fusion.  The lookup order is deterministic.
    """
    for name in (f'{case_id}.vg', f'{case_id}-single.vg'):
        candidate = DSL_PATCH_DIR / name
        if candidate.is_file():
            return candidate
    return None


def derive_patch_spec(vg_path: Path | str, base_patch: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a `vulgate.patch/v2` mapping whose guards/actions/maps come from `vg_path`.

    Non-guard metadata from `base_patch` (e.g. `install_precondition`) is kept.
    """
    vg_path = Path(vg_path)
    patch = dsl_parser.load(vg_path)
    derived = copy.deepcopy(base_patch) if base_patch else {}
    derived['schema'] = derived.get('schema') or 'vulgate.patch/v2'
    derived['maps'] = {name: {'capacity': int(spec.capacity)} for name, spec in patch.maps.items()}
    derived['observers'] = []
    derived['guards'] = [
        _guard_spec(mount) for mount in patch.mounts
        if mount.nature not in ('读取点', 'read_point')]
    derived['actions'] = {name: _action_spec(spec) for name, spec in patch.actions.items()}
    # Every mount in the .vg is installed by the DSL chain, so the hook count
    # the installation receipt must match is the mount count (the legacy
    # mapping only knows guards, not read-point observers).
    derived['install_hook_count'] = len(patch.mounts)
    derived['dsl_patch'] = {
        'path': str(vg_path.resolve()),
        'sha256': hashlib.sha256(vg_path.read_bytes()).hexdigest(),
    }
    return derived


def _guard_spec(mount: dsl_parser.MountSpec) -> dict[str, Any]:
    selector_text, condition_text, action_id = dsl_vm._extract(dsl_vm._strip_loops(mount.body))
    nodes = {name: dsl_vm.Parser(text).parse() for name, text in selector_text.items()}
    converter = _Converter(mount, nodes)
    condition = dsl_vm.Parser(condition_text).parse()
    guard: dict[str, Any] = {
        'id': mount.id.rsplit('/', 1)[-1],
        'function': mount.symbol,
        'arg_types': list(mount.args),
        'return_type': mount.return_type,
        'selectors': converter.selectors(condition),
        'expression': converter.expression(condition),
        'action_id': action_id,
    }
    if mount.module:
        guard['module'] = mount.module
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


def _map_ops(node) -> bool:
    return isinstance(node, tuple) and node[0] in _MAP_READ_OPS


class _Converter:
    def __init__(self, mount: dsl_parser.MountSpec, nodes: dict[str, tuple]):
        self.mount = mount
        self.nodes = nodes
        self._selectors: dict[str, dict[str, Any]] = {}

    def selectors(self, condition) -> dict[str, dict[str, Any]]:
        referenced: set[str] = set()
        self._referenced(condition, referenced)
        ordered: dict[str, dict[str, Any]] = {}
        for name, node in self.nodes.items():
            if _map_ops(node):
                continue
            # Constant and caller-local values are kept even when the condition
            # ignores them: they are guard-space inputs, not inlined read
            # intermediates (those are folded into the selector that uses them).
            keep = name in referenced or node[0] in ('const', 'local')
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
                else:
                    entry['key'] = self._chain(node[2], ())
        return list(reads.values())

    def expression(self, condition, top: bool = True) -> str:
        kind = condition[0]
        if kind == 'const':
            return ('True' if condition[1] else 'False') if top else str(int(condition[1]))
        if kind == 'sel':
            return condition[1]
        if kind == 'bin':
            operator = condition[1]
            text = _BOOL_OPS.get(operator, operator)
            if text in ('and', 'or'):
                parts: list[tuple] = []
                self._flatten(condition, operator, parts)
                return '(' + f' {text} '.join(self.expression(part, False) for part in parts) + ')'
            return f'({self.expression(condition[2], False)} {text} {self.expression(condition[3], False)})'
        if kind == 'unary':
            operand = self.expression(condition[2], False)
            return f'(not {operand})' if condition[1] == '!' else f'({condition[1]}{operand})'
        raise ValueError(f'unsupported guard condition node: {kind}')

    def _flatten(self, node, operator: str, parts: list[tuple]) -> None:
        if node[0] == 'bin' and node[1] == operator:
            self._flatten(node[2], operator, parts)
            self._flatten(node[3], operator, parts)
        else:
            parts.append(node)

    def _referenced(self, node, names: set[str]) -> None:
        if not isinstance(node, tuple):
            return
        if node[0] == 'sel':
            names.add(node[1])
            return
        if _map_ops(node):
            raise ValueError('guard condition must compare assigned value[...] fields')
        for item in node[1:]:
            if isinstance(item, tuple):
                self._referenced(item, names)

    def _selector(self, name: str) -> dict[str, Any]:
        if name not in self._selectors:
            self._selectors[name] = self._chain(self.nodes[name], (name,))
        return copy.deepcopy(self._selectors[name])

    def _chain(self, node, seen: tuple[str, ...]) -> dict[str, Any]:
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

    def _read(self, node, seen: tuple[str, ...]) -> dict[str, Any]:
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

    def _address(self, node, seen: tuple[str, ...]) -> tuple[tuple, int, dict[str, Any] | None, int]:
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

    def _key_text(self, node) -> str:
        return repr(node)
