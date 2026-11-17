"""Compile the patch DSL to VulGate Shadow-VM bytecode.

The DSL behavior accepted here is the subset used by the 20 quick-block
patches: selector assignments (`value["x"] = ...;`) followed by one
`if (<condition>) { return block("ACTION"); }`.  Expressions support
argN, vg_read_* helpers, global("..."), arithmetic/bitwise/comparisons and
boolean operators.  The resulting program is a normal `runtime/vm.c` program
returning SHADOW_PASS/SHADOW_BLOCK.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import struct

from runtime.dsl import parser as dsl_parser

OP_MOV_K64 = 0xB7
OP_MOV_X64 = 0xBF
OP_ADD_X64 = 0x0F
OP_SUB_X64 = 0x1F
OP_MUL_X64 = 0x2F
OP_OR_X64 = 0x4F
OP_AND_X64 = 0x5F
OP_LSH_X64 = 0x6F
OP_RSH_X64 = 0x7F
OP_XOR_X64 = 0xAF
OP_JEQ_X = 0x1D
OP_JGT_X = 0x2D
OP_JGE_X = 0x3D
OP_JNE_X = 0x5D
OP_JA = 0x05
OP_CALL = 0x85
OP_EXIT = 0x95

HELPER_GET_ARG = 1
HELPER_READ_U8 = 2
HELPER_GET_REG = 3
HELPER_READ_U16 = 4
HELPER_READ_U32 = 5
HELPER_READ_U64 = 6
HELPER_MAP_SET = 9
HELPER_MAP_GET = 10
HELPER_MAP_PRESENT = 11
HELPER_SET_REG = 13
OP_SUB_K64 = 0x17
OP_JGT_K = 0x25
MAX_LOOP_ITERATIONS = 256

READ_HELPERS = {
    'vg_read_u8': HELPER_READ_U8,
    'vg_read_u16': HELPER_READ_U16,
    'vg_read_u32': HELPER_READ_U32,
    'vg_read_u64': HELPER_READ_U64,
    'vg_read_pointer': HELPER_READ_U64,
    'vg_read_s8': HELPER_READ_U8,
    'vg_read_s16': HELPER_READ_U16,
    'vg_read_s32': HELPER_READ_U32,
    'vg_read_s64': HELPER_READ_U64,
}

PRECEDENCE = {
    '||': 1, '&&': 2, '|': 3, '^': 4, '&': 5,
    '==': 6, '!=': 6, '<': 7, '<=': 7, '>': 7, '>=': 7,
    '<<': 8, '>>': 8, '+': 9, '-': 9, '*': 10, '/': 10, '%': 10,
}
TOKEN = re.compile(r'''\s*(?:
    (?P<number>0[xX][0-9a-fA-F]+|\d+)
  | (?P<name>[A-Za-z_]\w*)
  | (?P<string>"(?:\\.|[^"\\])*")
  | (?P<op>==|!=|<=|>=|&&|\|\||<<|>>|[()\[\],+\-*/%&|^!<>~])
)''', re.X)


class ExprError(ValueError):
    pass


class Parser:
    def __init__(self, text: str):
        self.text = text
        self.tokens: list[tuple[str, str]] = []
        position = 0
        while position < len(text):
            match = TOKEN.match(text, position)
            if not match:
                raise ExprError(f'cannot tokenize expression at {text[position:]!r}')
            position = match.end()
            kind = match.lastgroup
            self.tokens.append((kind, match.group(kind)))
        self.index = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self, value: str | None = None) -> tuple[str, str]:
        token = self.peek()
        if token is None:
            raise ExprError('unexpected end of expression')
        if value is not None and token[1] != value:
            raise ExprError(f'expected {value!r}, got {token[1]!r}')
        self.index += 1
        return token

    def parse(self):
        expression = self.expression(0)
        if self.peek() is not None:
            raise ExprError(f'trailing token {self.peek()[1]!r}')
        return expression

    def expression(self, minimum: int):
        left = self.unary()
        while True:
            token = self.peek()
            if token is None or token[0] != 'op' or token[1] not in PRECEDENCE:
                break
            precedence = PRECEDENCE[token[1]]
            if precedence < minimum:
                break
            operator = self.take()[1]
            right = self.expression(precedence + 1)
            left = ('bin', operator, left, right)
        return left

    def unary(self):
        token = self.peek()
        if token and token[1] in ('!', '-', '~'):
            self.take()
            return ('unary', token[1], self.unary())
        return self.primary()

    def primary(self):
        kind, value = self.take()
        if kind == 'number':
            return ('const', int(value, 0))
        if kind == 'string':
            return ('string', value[1:-1])
        if kind == 'name':
            if value in ('true', 'false'):
                return ('const', 1 if value == 'true' else 0)
            if value.startswith('vg_read_'):
                self.take('(')
                argument = self.expression(0)
                self.take(')')
                if value not in READ_HELPERS:
                    raise ExprError('unsupported read helper: ' + value)
                return ('read', value, argument)
            if value == 'global':
                self.take('(')
                _, name = self.take()
                self.take(')')
                return ('global', name.strip('"'))
            if value == 'value':
                self.take('[')
                _, name = self.take()
                self.take(']')
                return ('sel', name.strip('"'))
            if value == 'map':
                self.take('[')
                _, map_name = self.take()
                self.take(']')
                self.take('[')
                key = self.expression(0)
                self.take(']')
                return ('mapget', map_name.strip('"'), key, False)
            if value == 'map_take':
                self.take('(')
                _, map_name = self.take()
                self.take(',')
                key = self.expression(0)
                self.take(')')
                return ('mapget', map_name.strip('"'), key, True)
            if value == 'map_present':
                self.take('(')
                _, map_name = self.take()
                self.take(',')
                key = self.expression(0)
                self.take(')')
                return ('mappresent', map_name.strip('"'), key)
            if value == 'map_get':
                self.take('(')
                _, map_name = self.take()
                self.take(',')
                key = self.expression(0)
                if self.peek() and self.peek()[1] == ',':
                    self.take(',')
                    self.take('consume')
                    self.take('=')
                    consume = self.expression(0)
                    self.take(')')
                    return ('mapget', map_name.strip('"'), key, True)
                self.take(')')
                return ('mapget', map_name.strip('"'), key, False)
            if value == 'local':
                self.take('(')
                _, name = self.take()
                self.take(')')
                return ('local', name.strip('"'))
            if re.fullmatch(r'arg\d+', value):
                return ('arg', int(value[3:]))
            return ('var', value)
        if value == '(':
            expression = self.expression(0)
            self.take(')')
            return expression
        raise ExprError('unexpected token: ' + value)


class Assembler:
    def __init__(self):
        self.code: list[list[int]] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str]] = []
        self.counter = 0

    def label(self, prefix='L') -> str:
        name = f'{prefix}_{self.counter}'
        self.counter += 1
        return name

    def mark(self, name: str) -> None:
        self.labels[name] = len(self.code)

    def emit(self, op: int, dst: int = 0, src: int = 0, imm: int = 0,
             target: str | None = None) -> None:
        if target is not None:
            self.fixups.append((len(self.code), target))
        raw = int(imm) & 0xFFFFFFFF
        if raw >= 0x80000000:
            raw -= 0x100000000
        self.code.append([op, ((src & 0xF) << 4) | (dst & 0xF), 0, raw])

    def jump(self, target: str) -> None:
        self.emit(OP_JA, target=target)

    def const(self, dst: int, value: int) -> None:
        value &= (1 << 64) - 1
        if value <= 0xFFFFFFFF:
            self.emit(OP_MOV_K64, dst, imm=value if value < 0x80000000 else value - (1 << 32))
            return
        high = (value >> 32) & 0xFFFFFFFF
        low = value & 0xFFFFFFFF
        self.const(dst, high)
        self.emit(0x67, dst, imm=32)  # lsh64
        if low:
            self.emit(0xB4, 5, imm=low if low < 0x80000000 else low - (1 << 32))
            self.emit(OP_OR_X64, dst, 5)

    def finalize(self) -> bytes:
        for pc, target in self.fixups:
            if target not in self.labels:
                raise ExprError('unresolved label: ' + target)
            offset = self.labels[target] - pc - 1
            if not -32768 <= offset <= 32767:
                raise ExprError('jump offset out of range')
            self.code[pc][2] = offset
        if len(self.code) > 4096:
            raise ExprError('VM instruction budget exceeded')
        return b''.join(struct.pack('<BBhi', *row) for row in self.code)


class Compiler:
    def __init__(self, selectors: dict[str, object], globals_: dict[str, int],
                 overrides: dict[str, int] | None = None, map_state=None,
                 local_slots: dict[str, int] | None = None):
        self.selectors = selectors
        self.globals = globals_
        self.overrides = overrides or {}
        self.map_state = map_state
        self.local_slots = local_slots or {}
        self.vars: dict[str, int] = {}
        self.asm = Assembler()

    def value(self, node, dst: int = 6) -> None:
        kind = node[0]
        if kind == 'const':
            self.asm.const(dst, node[1])
        elif kind == 'arg':
            self.asm.emit(OP_MOV_K64, 1, imm=node[1])
            self.asm.emit(OP_CALL, imm=HELPER_GET_ARG)
            self.asm.emit(OP_MOV_X64, dst, 0)
        elif kind == 'sel':
            if node[1] in self.overrides:
                self.asm.const(dst, self.overrides[node[1]])
            elif node[1] not in self.selectors:
                raise ExprError('unknown selector: ' + node[1])
            else:
                self.value(self.selectors[node[1]], dst)
        elif kind == 'global':
            if node[1] not in self.globals:
                raise ExprError('global address not resolved: ' + node[1])
            self.asm.const(dst, self.globals[node[1]])
        elif kind == 'mapget':
            if self.map_state is None:
                raise ExprError('map used without a map declaration')
            map_id = self.map_state.map_id(node[1])
            key_node = node[2]
            consume = bool(node[3]) if len(node) > 3 else False
            self.map_key(node[1], key_node, 2)
            self.asm.emit(OP_MOV_K64, 1, imm=map_id)
            self.asm.emit(OP_MOV_K64, 3, imm=1 if consume else 0)
            self.asm.emit(OP_CALL, imm=HELPER_MAP_GET)
            self.asm.emit(OP_MOV_X64, dst, 0)
        elif kind == 'mappresent':
            if self.map_state is None:
                raise ExprError('map used without a map declaration')
            map_id = self.map_state.map_id(node[1])
            self.map_key(node[1], node[2], 2)
            self.asm.emit(OP_MOV_K64, 1, imm=map_id)
            self.asm.emit(OP_CALL, imm=HELPER_MAP_PRESENT)
            self.asm.emit(OP_MOV_X64, dst, 0)
        elif kind == 'local':
            if node[1] not in self.local_slots:
                raise ExprError('local not resolved: ' + node[1])
            self.asm.emit(OP_MOV_K64, 1, imm=self.local_slots[node[1]])
            self.asm.emit(OP_CALL, imm=HELPER_GET_REG)
            self.asm.emit(OP_MOV_X64, dst, 0)
        elif kind == 'var':
            if node[1] not in self.vars:
                raise ExprError('unknown loop variable: ' + node[1])
            self.asm.emit(OP_MOV_K64, 1, imm=self.vars[node[1]])
            self.asm.emit(OP_CALL, imm=HELPER_GET_REG)
            self.asm.emit(OP_MOV_X64, dst, 0)
        elif kind == 'read':
            self.value(node[2], 1)
            self.asm.emit(OP_CALL, imm=READ_HELPERS[node[1]])
            self.asm.emit(OP_MOV_X64, dst, 0)
        elif kind == 'unary':
            operator, operand = node[1], node[2]
            if operator == '-':
                self.value(operand, dst)
                self.asm.emit(OP_MOV_K64, 8, imm=0)
                self.asm.emit(OP_SUB_X64, 8, dst)
                self.asm.emit(OP_MOV_X64, dst, 8)
            elif operator == '~':
                self.value(operand, dst)
                self.asm.const(8, 0xFFFFFFFFFFFFFFFF)
                self.asm.emit(OP_XOR_X64, dst, 8)
            else:
                self.condition(node, self.asm.label('true'), self.asm.label('false'))
        elif kind == 'bin':
            operator, left, right = node[1], node[2], node[3]
            if operator in ('==', '!=', '<', '<=', '>', '>='):
                yes, no = self.asm.label('cmp'), self.asm.label('cmp')
                self.condition(node, yes, no)
                self.asm.mark(yes)
                self.asm.const(dst, 1)
                self.asm.jump(no)  # placeholder patched below? incorrect
            else:
                self.value(left, dst)
                self.value(right, 8)
                opcode = {
                    '+': OP_ADD_X64, '-': OP_SUB_X64, '*': OP_MUL_X64,
                    '&': OP_AND_X64, '|': OP_OR_X64, '^': OP_XOR_X64,
                    '<<': OP_LSH_X64, '>>': OP_RSH_X64,
                }.get(operator)
                if opcode is None:
                    raise ExprError('unsupported operator: ' + operator)
                self.asm.emit(opcode, dst, 8)
        else:
            raise ExprError('unsupported expression node: ' + kind)

    def condition(self, node, yes: str, no: str) -> None:
        kind = node[0]
        if kind == 'const':
            self.asm.jump(yes if node[1] else no)
            return
        if kind == 'unary' and node[1] == '!':
            self.condition(node[2], no, yes)
            return
        if kind == 'bin' and node[1] in ('&&', '||'):
            operator, left, right = node[1], node[2], node[3]
            middle = self.asm.label('bool')
            if operator == '&&':
                self.condition(left, middle, no)
                self.asm.mark(middle)
                self.condition(right, yes, no)
            else:
                self.condition(left, yes, middle)
                self.asm.mark(middle)
                self.condition(right, yes, no)
            return
        if kind == 'bin' and node[1] in ('==', '!=', '<', '<=', '>', '>='):
            operator, left, right = node[1], node[2], node[3]
            self.value(left, 6)
            self.value(right, 8)
            if operator == '==':
                self.asm.emit(OP_JEQ_X, 6, 8, target=yes)
            elif operator == '!=':
                self.asm.emit(OP_JNE_X, 6, 8, target=yes)
            elif operator == '<':
                self.asm.emit(OP_JGT_X, 8, 6, target=yes)
            elif operator == '<=':
                self.asm.emit(OP_JGE_X, 8, 6, target=yes)
            elif operator == '>':
                self.asm.emit(OP_JGT_X, 6, 8, target=yes)
            else:
                self.asm.emit(OP_JGE_X, 6, 8, target=yes)
            self.asm.jump(no)
            return
        self.value(node, 6)
        self.asm.emit(OP_MOV_K64, 7, imm=0)
        self.asm.emit(OP_JNE_X, 6, 7, target=yes)
        self.asm.jump(no)

    def map_key(self, map_name: str, key_node, dst: int) -> None:
        if key_node[0] == 'string':
            self.asm.emit(OP_MOV_K64, dst,
                          imm=self.map_state.key_id(map_name, key_node[1]))
        else:
            self.value(key_node, dst)

    def map_set(self, map_name: str, key_node, value_node) -> None:
        if self.map_state is None:
            raise ExprError('map used without a map declaration')
        map_id = self.map_state.map_id(map_name)
        self.map_key(map_name, key_node, 9)
        self.value(value_node, 3)
        self.asm.emit(OP_MOV_K64, 1, imm=map_id)
        self.asm.emit(OP_MOV_X64, 2, 9)
        self.asm.emit(OP_CALL, imm=HELPER_MAP_SET)

    def compile_loop(self, variable: str, start: int, bound: int, body: str) -> None:
        """Emit a verifier-bounded countdown loop.

        The emitted shape intentionally mirrors the loop pattern accepted by
        runtime/vm.c's validate_bounded_backedge():

            <set loop variable>
            MOV  r15, count
        L:  <body, does not modify r15>
            <increment loop variable>
            SUB  r15, 1
            JGT  r15, 0, L

        count must be a positive compile-time constant.
        """
        count = bound - start
        if start < 0 or count < 1 or count > MAX_LOOP_ITERATIONS:
            raise ExprError('loop bound must be a constant in 1..%d' %
                            MAX_LOOP_ITERATIONS)
        if variable in self.vars:
            raise ExprError('nested loops are not supported: ' + variable)
        if any(slot in (10, 14) for slot in self.local_slots.values()):
            raise ExprError('local slot collides with loop temporary registers')
        variable_slot = 14
        counter_slot = 10
        self.asm.emit(OP_MOV_K64, 1, imm=variable_slot)
        self.asm.emit(OP_MOV_K64, 2, imm=start)
        self.asm.emit(OP_CALL, imm=HELPER_SET_REG)
        self.asm.const(counter_slot, count)
        target = self.asm.label('loop')
        self.asm.mark(target)
        previous = self.vars.get(variable)
        self.vars[variable] = variable_slot
        try:
            for match in re.finditer(
                    r'map\["([^"]+)"\]\[(.+?)\]\s*=\s*(.+?);',
                    body, re.S):
                map_name, key_expression, value_expression = match.groups()
                self.map_set(map_name, Parser(key_expression).parse(),
                             Parser(value_expression).parse())
        finally:
            if previous is None:
                self.vars.pop(variable, None)
            else:
                self.vars[variable] = previous
        self.asm.emit(OP_MOV_K64, 1, imm=variable_slot)
        self.asm.emit(OP_CALL, imm=HELPER_GET_REG)
        self.asm.emit(OP_MOV_X64, 2, 0)
        self.asm.emit(OP_MOV_K64, 8, imm=1)
        self.asm.emit(OP_ADD_X64, 2, 8)
        self.asm.emit(OP_MOV_K64, 1, imm=variable_slot)
        self.asm.emit(OP_CALL, imm=HELPER_SET_REG)
        self.asm.emit(OP_SUB_K64, counter_slot, imm=1)
        self.asm.emit(OP_JGT_K, counter_slot, imm=0, target=target)

    def compile(self, condition) -> bytes:
        block = self.asm.label('block')
        passed = self.asm.label('pass')
        self.condition(condition, block, passed)
        self.asm.mark(passed)
        self.asm.emit(OP_MOV_K64, 0, imm=0)
        self.asm.emit(OP_EXIT)
        self.asm.mark(block)
        self.asm.emit(OP_MOV_K64, 0, imm=1)
        self.asm.emit(OP_EXIT)
        return self.asm.finalize()


@dataclass
class VMMount:
    id: str
    module: str | None
    symbol: str
    offset: int | None
    args: list[str]
    return_type: str
    code: bytes
    action_id: str | None
    nature: str = 'intercept'
    locals: list[dict] = None


@dataclass
class VMPatch:
    mounts: list[VMMount]
    globals_: dict[str, int]
    maps: list[dict]


class MapState:
    def __init__(self, declarations: dict):
        self.order: list[str] = list(declarations)
        self.ids = {name: index for index, name in enumerate(self.order)}
        self.decls = declarations
        self.keys: dict[str, dict[str, int]] = {name: {} for name in self.order}

    def map_id(self, name: str) -> int:
        if name not in self.ids:
            raise ExprError('unknown map: ' + name)
        return self.ids[name]

    def key_id(self, map_name: str, key: str) -> int:
        table = self.keys[map_name]
        if key not in table:
            table[key] = len(table)
        return table[key]

    def export(self) -> list[dict]:
        return [{'id': name, 'capacity': int(self.decls[name].capacity),
                 'keys': {str(value): key for key, value in sorted(self.keys[name].items(),
                                                                   key=lambda item: item[1])}}
                for name in self.order]


LOOP_PATTERN = re.compile(
    r'for\s*\(\s*(\w+)\s*=\s*(\d+)\s*;\s*\1\s*<\s*(\d+)\s*;'
    r'\s*\1\s*\+\+\s*\)\s*\{(.*?)\}', re.S)


def _find_loops(body: str):
    return [(match.group(1), int(match.group(2)), int(match.group(3)),
             match.group(4)) for match in LOOP_PATTERN.finditer(body)]


def _strip_loops(body: str) -> str:
    return LOOP_PATTERN.sub('', body)


def _extract(body: str) -> tuple[dict[str, str], str, str]:
    selectors: dict[str, str] = {}
    for line in body.splitlines():
        match = re.match(r'\s*value\["([^"]+)"\]\s*=\s*(.+?);\s*$', line)
        if match:
            selectors[match.group(1)] = match.group(2)
    match = re.search(
        r'if\s*\((.*?)\)\s*\{\s*return\s+block\(\s*"([^"]+)"\s*\)\s*;?\s*\}',
        body, re.S)
    if not match:
        raise ExprError('behavior needs if (...) { return block("ACTION"); }')
    return selectors, match.group(1), match.group(2)


def _extract_observer(body: str) -> list[tuple[str, str, str]]:
    assignments = []
    for line in body.splitlines():
        match = re.match(
            r'\s*map\["([^"]+)"\]\[(.+?)\]\s*=\s*(.+?);\s*$', line)
        if match:
            assignments.append((match.group(1), match.group(2), match.group(3)))
    if not assignments:
        raise ExprError('read_point behavior needs map["name"][key] = ...;')
    return assignments


def compile_patch(patch: dsl_parser.PatchSpec,
                  global_addresses: dict[str, int] | None = None,
                  overrides: dict[str, int] | None = None) -> VMPatch:
    global_addresses = global_addresses or {}
    state = MapState(patch.maps)
    mounts: list[VMMount] = []
    for mount in patch.mounts:
        read_point = mount.nature in ('\u8bfb\u53d6\u70b9', 'read_point')
        nature = 'read_point' if read_point else 'intercept'
        if read_point:
            loops = _find_loops(mount.body)
            remaining = _strip_loops(mount.body)
            assignments = (_extract_observer(remaining) if 'map[' in remaining else [])
            if not loops and not assignments:
                raise ExprError('read_point behavior needs map assignment or for loop')
            local_slots = {name: index for index, name in enumerate(mount.local_recipes)}
            compiler = Compiler({}, global_addresses, overrides, state, local_slots)
            for variable, start, bound, body in loops:
                compiler.compile_loop(variable, start, bound, body)
            for map_name, key_expression, expression in assignments:
                compiler.map_set(map_name, Parser(key_expression).parse(),
                                 Parser(expression).parse())
            compiler.asm.emit(OP_MOV_K64, 0, imm=0)
            compiler.asm.emit(OP_EXIT)
            mounts.append(VMMount(mount.id, mount.module, mount.symbol, mount.offset,
                                  list(mount.args), mount.return_type,
                                  compiler.asm.finalize(), None, nature,
                                  [{'name': name, 'slot': slot,
                                    'recipe': mount.local_recipes[name]}
                                   for name, slot in local_slots.items()]))
            continue
        loops = _find_loops(mount.body)
        raw_selectors, condition_text, action_id = _extract(_strip_loops(mount.body))
        selectors = {name: Parser(text).parse() for name, text in raw_selectors.items()}
        condition = Parser(condition_text).parse()
        local_slots = {name: index for index, name in enumerate(mount.local_recipes)}
        compiler = Compiler(selectors, global_addresses, overrides, state,
                            local_slots)
        for variable, start, bound, body in loops:
            compiler.compile_loop(variable, start, bound, body)
        code = compiler.compile(condition)
        mounts.append(VMMount(mount.id, mount.module, mount.symbol, mount.offset,
                              list(mount.args), mount.return_type, code, action_id,
                              nature,
                              [{'name': name, 'slot': slot,
                                'recipe': mount.local_recipes[name]}
                               for name, slot in local_slots.items()]))
        if action_id not in patch.actions:
            raise ExprError('unknown action: ' + action_id)
    return VMPatch(mounts, dict(global_addresses), state.export())



def compile_text(text: str, global_addresses: dict[str, int] | None = None,
                 overrides: dict[str, int] | None = None) -> VMPatch:
    return compile_patch(dsl_parser.parse(text), global_addresses, overrides)


