"""Parser for the VulGate patch DSL.

The DSL is intentionally small and text based:

    动作 NGX_ERROR_RETURN:
    {
        返回类型: int
        返回: -1
    }

    挂载点 CVE-2026-97205:
    {
        位置: module="nginx", symbol="ngx_http_copy_filter",
              参数=[pointer, pointer], 返回=int64
        性质: 拦截点
        行为:
        {
            value["counter"] = read_u32(arg0 + 1000);
            if ((value["counter"] & 255) >= 250) {
                return block("NGX_ERROR_RETURN");
            }
        }
    }

`性质` is `读取点` or `拦截点`.  A read point records values into the shared
`value[...]` map; an interception point evaluates the fall-through condition and
falls back to the original function (PASS) when the body does not `return block`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path


@dataclass
class MapSpec:
    id: str
    capacity: int = 1024


@dataclass
class ActionSpec:
    id: str
    return_type: str = 'int'
    value: object = 0
    errno: int | None = None
    writes: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class FlagRepairSpec:
    operation: str
    base: int | str
    offset: int
    mask: int
    source_register: str | None = None
    source_offset: int = 0


@dataclass
class MountSpec:
    id: str
    module: str | None
    symbol: str
    args: list[str]
    return_type: str
    nature: str
    body: str
    offset: int | None = None
    location_kind: str = 'symbol'
    caller: str | None = None
    callee: str | None = None
    file: str | None = None
    line: int | None = None
    local_recipes: dict = field(default_factory=dict)
    build_id: str | None = None
    flag_repair: FlagRepairSpec | None = None
    requires_spawn: bool = False


@dataclass
class PatchSpec:
    actions: dict[str, ActionSpec]
    mounts: list[MountSpec]
    maps: dict[str, MapSpec] = field(default_factory=dict)


class DSLParseError(ValueError):
    pass


def _strip_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('#'):
            continue
        lines.append(line)
    return '\n'.join(lines)


def _find_block(text: str, start: int) -> tuple[str, int]:
    """Return the text inside the first balanced { ... } block at/after start."""
    begin = text.find('{', start)
    if begin < 0:
        raise DSLParseError('missing "{"')
    depth = 0
    in_string = None
    index = begin
    while index < len(text):
        char = text[index]
        if in_string:
            if char == '\\':
                index += 2
                continue
            if char == in_string:
                in_string = None
        elif char in ('"', "'"):
            in_string = char
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return text[begin + 1:index], index + 1
        index += 1
    raise DSLParseError('unbalanced braces')


def _split_fields(body: str) -> dict[str, str]:
    """Split a mount/action block into top-level `key: value` fields."""
    fields: dict[str, str] = {}
    depth = 0
    bracket = 0
    in_string = None
    current = []
    pieces: list[str] = []
    for char in body:
        if in_string:
            current.append(char)
            if char == in_string:
                in_string = None
            continue
        if char in ('"', "'"):
            in_string = char
            current.append(char)
        elif char in '([{':
            depth += 1
            current.append(char)
        elif char in ')]}':
            depth -= 1
            current.append(char)
        elif char == '\n' and depth == 0:
            line = ''.join(current).strip()
            if line:
                pieces.append(line)
            current = []
        else:
            current.append(char)
    line = ''.join(current).strip()
    if line:
        pieces.append(line)
    for piece in pieces:
        match = re.match(r'([^:：]+)[:：]\s*(.*)$', piece, re.S)
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip()
        fields[key] = value
    return fields


def _split_commas(value: str) -> list[str]:
    pieces: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = None
    for char in value:
        if in_string:
            current.append(char)
            if char == in_string:
                in_string = None
        elif char in ('"', "'"):
            in_string = char
            current.append(char)
        elif char in '([':
            depth += 1
            current.append(char)
        elif char in ')]':
            depth -= 1
            current.append(char)
        elif char == ',' and depth == 0:
            pieces.append(''.join(current))
            current = []
        else:
            current.append(char)
    pieces.append(''.join(current))
    return [piece.strip() for piece in pieces if piece.strip()]


def _parse_call_location(text: str) -> tuple[str, dict]:
    match = re.match(r'^(callsite|line|address)\s*\((.*)\)\s*$', text, re.S)
    if not match:
        raise DSLParseError('invalid location call')
    kind, inner = match.group(1), match.group(2)
    attrs = {}
    for part in _split_commas(inner):
        if '=' not in part:
            raise DSLParseError('location attribute needs name=value: ' + part)
        key, value = part.split('=', 1)
        key = key.strip()
        value = value.strip()
        if key in ('args', 'arg_types'):
            attrs[key] = [item.strip().strip('"\'')
                          for item in value.strip('[]').split(',') if item.strip()]
        elif key == 'line':
            attrs[key] = int(value, 0)
        else:
            attrs[key] = value.strip('"\'')
    return kind, attrs


def _parse_location(text: str) -> tuple[str | None, str, list[str], str, int | None, str | None]:
    module = None
    symbol = None
    caller = None
    args: list[str] = []
    return_type = 'int'
    offset = None

    def split_commas(value: str) -> list[str]:
        pieces: list[str] = []
        current: list[str] = []
        depth = 0
        in_string = None
        for char in value:
            if in_string:
                current.append(char)
                if char == in_string:
                    in_string = None
            elif char in ('"', "'"):
                in_string = char
                current.append(char)
            elif char in '([':
                depth += 1
                current.append(char)
            elif char in ')]':
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                pieces.append(''.join(current))
                current = []
            else:
                current.append(char)
        pieces.append(''.join(current))
        return [piece.strip() for piece in pieces if piece.strip()]

    for part in split_commas(text):
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        key = key.strip()
        value = value.strip()
        if key in ('module', '模块'):
            module = value.strip('"\'')
        elif key in ('symbol', 'symbol_name', '符号', '函数'):
            symbol = value.strip('"\'')
        elif key in ('参数', 'args', 'arg_types'):
            args = [item.strip().strip('"\'')
                    for item in value.strip('[]').split(',') if item.strip()]
        elif key in ('返回', 'return', 'return_type'):
            return_type = value.strip('"\'')
        elif key in ('offset', '偏移'):
            offset = int(value.strip(), 0)
        elif key == 'caller':
            caller = value.strip('"\'')
        else:
            raise DSLParseError('unknown location field: ' + key)
    if not symbol:
        raise DSLParseError('location needs symbol')
    return module, symbol, args, return_type, offset, caller


def _parse_action(identifier: str, body: str) -> ActionSpec:
    fields = _split_fields(body)
    return_type = fields.get('返回类型', fields.get('return_type', 'int')).strip()
    raw_value = fields.get('返回', fields.get('return', fields.get('value', '0'))).strip()
    if raw_value in ('null', 'NULL', 'nil'):
        value: object = None
    elif raw_value.startswith(('"', "'")):
        value = raw_value.strip('"\'')
    else:
        value = int(raw_value, 0)
    errno = fields.get('errno')
    spec = ActionSpec(identifier, return_type, value, int(errno, 0) if errno else None)
    return spec


_REPAIR_OPERATIONS = {'clear_arg_u8': 'clear', 'clear_reg_u8': 'clear',
                      'set_reg_u8': 'set', 'copy_reg_u8': 'copy'}
_REPAIR_REGISTERS = {'rbx', 'rbp', 'rsp', 'r12', 'r13', 'r14', 'r15'}


def _parse_flag_repair(body: str, args: list[str], location_kind: str) -> FlagRepairSpec:
    match = re.fullmatch(r'\s*(\w+)\(([^()]*)\)\s*;\s*', body)
    if match is None or match[1] not in _REPAIR_OPERATIONS:
        raise DSLParseError('repair_point needs exactly one supported byte-mask operation')
    name = match[1]
    operation = _REPAIR_OPERATIONS[name]
    operands = [part.strip() for part in match[2].split(',')]
    if len(operands) != (5 if operation == 'copy' else 3):
        raise DSLParseError('wrong number of operands for ' + name)

    base = operands[0]
    source = operands[2] if operation == 'copy' else None
    if name == 'clear_arg_u8':
        if location_kind != 'symbol' or not re.fullmatch(r'arg[0-5]', base):
            raise DSLParseError('clear_arg_u8 requires a function-entry pointer argument')
        base = int(base[3:])
        if base >= len(args) or args[base] != 'pointer':
            raise DSLParseError('clear_arg_u8 requires a declared pointer argument')
    elif (location_kind != 'address' or base not in _REPAIR_REGISTERS or
          (source is not None and source not in _REPAIR_REGISTERS)):
        raise DSLParseError('register repair requires an address and supported x86-64 registers')

    try:
        offset = int(operands[1], 0)
        mask = int(operands[-1], 0)
        source_offset = int(operands[3], 0) if source is not None else 0
    except ValueError as exc:
        raise DSLParseError('byte-mask operands must use integer offsets and mask') from exc
    if not 0 <= offset <= 4095 or not 0 <= source_offset <= 4095 or not 1 <= mask <= 255:
        raise DSLParseError('repair offset must be 0..4095 and mask 1..255')
    return FlagRepairSpec(operation, base, offset, mask, source, source_offset)


def parse(text: str) -> PatchSpec:
    text = _strip_comments(text)
    actions: dict[str, ActionSpec] = {}
    maps: dict[str, MapSpec] = {}
    mounts: list[MountSpec] = []
    cursor = 0
    pattern = re.compile(r'^(动作|挂载点|action|mount|map)\s+([^\s:：]+)\s*[:：]\s*', re.M)
    while True:
        match = pattern.search(text, cursor)
        if not match:
            break
        kind, identifier = match.group(1), match.group(2)
        block, cursor = _find_block(text, match.end())
        if kind in ('动作', 'action'):
            actions[identifier] = _parse_action(identifier, block)
            continue
        if kind == 'map':
            fields = _split_fields(block)
            capacity = int(fields.get('capacity', fields.get('容量', '1024')), 0)
            maps[identifier] = MapSpec(identifier, capacity)
            continue
        fields = _split_fields(block)
        location = fields.get('位置', fields.get('location'))
        if not location:
            raise DSLParseError(f'mount {identifier} has no 位置')
        location = location.strip()
        location_kind = 'symbol'
        caller = callee = file_name = None
        line = None
        if re.match(r'^(callsite|line|address)\s*\(', location):
            location_kind, attrs = _parse_call_location(location)
            module = attrs.get('module')
            caller = attrs.get('caller')
            callee = attrs.get('callee')
            file_name = attrs.get('file')
            line = attrs.get('line')
            symbol = attrs.get('symbol') or caller or file_name or ''
            args = attrs.get('args') or []
            return_type = attrs.get('return') or 'int'
            offset = attrs.get('offset')
            offset = int(offset, 0) if isinstance(offset, str) else offset
        else:
            module, symbol, args, return_type, offset, location_caller = _parse_location(location)
            if location_caller:
                caller = location_caller
        nature = fields.get('性质', fields.get('nature', '拦截点')).strip()
        if nature not in ('拦截点', '读取点', 'intercept', 'read', 'read_point', 'repair_point'):
            raise DSLParseError(f'mount {identifier} has invalid 性质: {nature}')
        if nature != 'repair_point':
            nature = '读取点' if nature in ('读取点', 'read', 'read_point') else '拦截点'
        body = fields.get('行为', fields.get('behavior'))
        if body is None:
            # 行为 usually opens a nested block: split_fields sees "行为: {" ... "}"
            body = ''
        # The behavior block is nested inside fields parsing; extract it from
        # the raw block for robustness.
        behavior_match = re.search(r'(?:行为|behavior)\s*[:：]\s*', block)
        if not behavior_match:
            raise DSLParseError(f'mount {identifier} has no 行为')
        behavior, _ = _find_block(block, behavior_match.end())
        build_id = fields.get('build_id')
        requires_spawn = fields.get('requires_spawn')
        flag_repair = None
        if nature == 'repair_point':
            if (location_kind not in ('symbol', 'address') or module or caller or
                    (offset is not None and offset < 0) or
                    (location_kind == 'address' and offset is None)):
                raise DSLParseError('repair_point requires a function or explicit address in the main executable')
            if not build_id or not re.fullmatch(r'[0-9a-fA-F]{40}', build_id.strip('"\'')):
                raise DSLParseError('repair_point requires a 40-digit hexadecimal build_id')
            build_id = build_id.strip('"\'').lower()
            if requires_spawn not in (None, 'true', 'false'):
                raise DSLParseError('requires_spawn must be true or false')
            flag_repair = _parse_flag_repair(behavior, args, location_kind)
        elif build_id is not None:
            raise DSLParseError('build_id is supported on repair_point only')
        elif requires_spawn is not None:
            raise DSLParseError('requires_spawn is supported on repair_point only')
        mounts.append(MountSpec(
            identifier, module, symbol, args, return_type, nature, behavior, offset,
            location_kind=location_kind, caller=caller, callee=callee,
            file=file_name, line=line, build_id=build_id, flag_repair=flag_repair,
            requires_spawn=requires_spawn == 'true'))
    if not mounts:
        raise DSLParseError('DSL has no 挂载点')
    return PatchSpec(actions, mounts, maps)


def load(path: Path | str) -> PatchSpec:
    return parse(Path(path).read_text(encoding='utf-8'))
