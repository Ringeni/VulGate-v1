import ast
import re
import struct
import textwrap

MASK = (1 << 64) - 1

BPF_JA = 0x05
BPF_ADD_X64 = 0x0F
BPF_SUB_K64 = 0x17
BPF_SUB_X64 = 0x1F
BPF_MUL_X64 = 0x2F
BPF_OR_X64 = 0x4F
BPF_AND_X64 = 0x5F
BPF_LSH_X64 = 0x6F
BPF_RSH_X64 = 0x7F
BPF_XOR_X64 = 0xAF
BPF_MOV_K64 = 0xB7
BPF_MOV_X64 = 0xBF
BPF_JEQ_X = 0x1D
BPF_JGT_K = 0x25
BPF_JGT_X = 0x2D
BPF_JGE_X = 0x3D
BPF_JNE_X = 0x5D
BPF_JLT_X = 0xAD
BPF_JLE_X = 0xBD
BPF_CALL = 0x85
BPF_EXIT = 0x95

HELPER_GET_ARG = 1
HELPER_SAFE_READ_U8 = 2
HELPER_GET_REG = 3
HELPER_SAFE_READ_U16 = 4
HELPER_SAFE_READ_U32 = 5
HELPER_SAFE_READ_U64 = 6
HELPER_SCRATCH_LOAD = 7
HELPER_SCRATCH_STORE = 8


def parse(text, fields):
    root = ast.parse(text, mode='eval').body
    allowed = (ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.Compare,
               ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
               ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.BitAnd, ast.BitOr,
               ast.BitXor, ast.LShift, ast.RShift, ast.Name, ast.Load, ast.Constant)
    for node in ast.walk(root):
        if not isinstance(node, allowed):
            raise ValueError('unsupported scalar expression: ' + type(node).__name__)
        if isinstance(node, ast.Name) and node.id not in fields:
            raise ValueError('unknown field: ' + node.id)
        if isinstance(node, ast.Constant) and (type(node.value) not in (int, bool) or not 0 <= int(node.value) <= MASK):
            raise ValueError('constant outside unsigned 64-bit range')
        if isinstance(node, ast.Compare) and len(node.ops) != 1:
            raise ValueError('write comparisons separately')
    return root


def evaluate(node, values):
    if isinstance(node, ast.Name): return int(values[node.id]) & MASK
    if isinstance(node, ast.Constant): return int(node.value) & MASK if type(node.value) is int else node.value
    if isinstance(node, ast.UnaryOp): return not evaluate(node.operand, values)
    if isinstance(node, ast.BoolOp):
        items = (bool(evaluate(n, values)) for n in node.values)
        return all(items) if isinstance(node.op, ast.And) else any(items)
    if isinstance(node, ast.BinOp):
        a, b = evaluate(node.left, values), evaluate(node.right, values)
        return {
            ast.Add: lambda: a + b,
            ast.Sub: lambda: a - b,
            ast.Mult: lambda: a * b,
            ast.BitAnd: lambda: a & b,
            ast.BitOr: lambda: a | b,
            ast.BitXor: lambda: a ^ b,
            ast.LShift: lambda: a << (b & 63),
            ast.RShift: lambda: a >> (b & 63),
        }[type(node.op)]() & MASK
    a, b = evaluate(node.left, values), evaluate(node.comparators[0], values)
    return {ast.Eq: lambda: a == b, ast.NotEq: lambda: a != b,
            ast.Lt: lambda: a < b, ast.LtE: lambda: a <= b,
            ast.Gt: lambda: a > b, ast.GtE: lambda: a >= b}[type(node.ops[0])]()


def c_expression(node, names=None):
    names = names or {}
    if isinstance(node, ast.Name): return names.get(node.id, node.id)
    if isinstance(node, ast.Constant): return 'UINT64_C(%d)' % int(node.value)
    if isinstance(node, ast.UnaryOp): return '(!%s)' % c_expression(node.operand, names)
    if isinstance(node, ast.BoolOp):
        op = ' && ' if isinstance(node.op, ast.And) else ' || '
        return '(' + op.join(c_expression(n, names) for n in node.values) + ')'
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.LShift, ast.RShift)):
            op = '<<' if isinstance(node.op, ast.LShift) else '>>'
            return '((uint64_t)(%s %s (%s & 63ULL)))' % (
                c_expression(node.left, names), op, c_expression(node.right, names))
        op = {ast.Add: '+', ast.Sub: '-', ast.Mult: '*',
              ast.BitAnd: '&', ast.BitOr: '|', ast.BitXor: '^'}[type(node.op)]
        return '((uint64_t)(%s %s %s))' % (c_expression(node.left, names), op, c_expression(node.right, names))
    op = {ast.Eq: '==', ast.NotEq: '!=', ast.Lt: '<', ast.LtE: '<=', ast.Gt: '>', ast.GtE: '>='}[type(node.ops[0])]
    return '(%s %s %s)' % (c_expression(node.left, names), op, c_expression(node.comparators[0], names))


def predicates(root):
    return list(dict.fromkeys(ast.unparse(n) for n in ast.walk(root) if isinstance(n, ast.Compare)))


def _emit_u64_const(emit, dst, value):
    val = int(value) & MASK
    if val <= 0x7FFFFFFF:
        emit(BPF_MOV_K64, dst, imm=val)
    elif val <= 0xFFFFFFFF:
        emit(0xB4, dst, imm=val if val <= 0x7FFFFFFF else val - (1 << 32))
    else:
        hi = (val >> 32) & 0xFFFFFFFF
        lo = val & 0xFFFFFFFF
        _emit_u64_const(emit, dst, hi)
        emit(0x67, dst, imm=32)
        if lo:
            emit(0xB4, 5, imm=lo if lo <= 0x7FFFFFFF else lo - (1 << 32))
            emit(BPF_OR_X64, dst, 5)


class _Assembler:
    def __init__(self):
        self.code = []
        self.labels = {}
        self.fixups = []
        self.label_count = 0

    def new_label(self, prefix='L'):
        name = f'{prefix}_{self.label_count}'
        self.label_count += 1
        return name

    def mark(self, name):
        self.labels[name] = len(self.code)

    def emit(self, op, dst=0, src=0, imm=0, target=None):
        if target is not None:
            self.fixups.append((len(self.code), target))
        self.code.append([op, ((src & 0x0F) << 4) | (dst & 0x0F), 0, int(imm)])

    def jump(self, target):
        self.emit(BPF_JA, 0, 0, 0, target=target)

    def finalize(self):
        for pc, target in self.fixups:
            offset = self.labels[target] - pc - 1
            if not -32768 <= offset <= 32767:
                raise ValueError('jump offset out of signed 16-bit range')
            self.code[pc][2] = offset
        if len(self.code) > 4096:
            raise ValueError('VM instruction budget exceeded')
        return b''.join(struct.pack('<BBhi', *row) for row in self.code)


def _dotted_name(node):
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    return '.'.join(reversed(parts))


def compile_guard(text, fields):
    stripped = text.strip()
    if any(tok in stripped for tok in ('\n', ';', 'for ', 'for(', 'BLOCK(', 'PASS(', 'scratch_store', 'def ')):
        return compile_policy_dsl(text, fields)
    root = parse(text, fields)
    asm = _Assembler()
    temp_base = 24

    def eval_scalar(node, dst, depth=0):
        if depth > 7:
            raise ValueError('expression nesting exceeds scratch capacity')
        if isinstance(node, ast.Name) or isinstance(node, ast.Attribute):
            name = node.id if isinstance(node, ast.Name) else _dotted_name(node)
            if name is None or name not in fields:
                raise ValueError('expected scalar operand')
            source = fields[name]
            if 'constant' in source:
                _emit_u64_const(asm.emit, dst, source['constant'])
            else:
                asm.emit(BPF_MOV_K64, 1, imm=source['index'])
                asm.emit(BPF_CALL, imm=HELPER_GET_ARG if source['source'] == 'arg' else HELPER_GET_REG)
                asm.emit(BPF_MOV_X64, dst, 0)
        elif isinstance(node, ast.Constant):
            _emit_u64_const(asm.emit, dst, int(node.value))
        elif isinstance(node, ast.BinOp):
            eval_scalar(node.left, dst, depth)
            if isinstance(node.right, (ast.Constant, ast.Name)):
                eval_scalar(node.right, 8, depth + 1)
                rhs_reg = 8
            else:
                slot = temp_base + depth
                asm.emit(BPF_MOV_K64, 1, imm=slot)
                asm.emit(BPF_MOV_X64, 2, dst)
                asm.emit(BPF_CALL, imm=HELPER_SCRATCH_STORE)
                eval_scalar(node.right, 8, depth + 1)
                asm.emit(BPF_MOV_K64, 1, imm=slot)
                asm.emit(BPF_CALL, imm=HELPER_SCRATCH_LOAD)
                asm.emit(BPF_MOV_X64, dst, 0)
                rhs_reg = 8
            opcode = {
                ast.Add: BPF_ADD_X64,
                ast.Sub: BPF_SUB_X64,
                ast.Mult: BPF_MUL_X64,
                ast.BitAnd: BPF_AND_X64,
                ast.BitOr: BPF_OR_X64,
                ast.BitXor: BPF_XOR_X64,
                ast.LShift: BPF_LSH_X64,
                ast.RShift: BPF_RSH_X64,
            }[type(node.op)]
            asm.emit(opcode, dst, rhs_reg)
        else:
            raise ValueError('expected scalar operand')

    def condition(node, yes, no):
        if isinstance(node, ast.UnaryOp):
            return condition(node.operand, no, yes)
        if isinstance(node, ast.BoolOp):
            for n in node.values[:-1]:
                nxt = asm.new_label('next')
                condition(n, nxt if isinstance(node.op, ast.And) else yes,
                          no if isinstance(node.op, ast.And) else nxt)
                asm.mark(nxt)
            return condition(node.values[-1], yes, no)
        if isinstance(node, ast.Constant):
            return asm.jump(yes if node.value else no)
        if not isinstance(node, ast.Compare):
            eval_scalar(node, 6)
            asm.emit(BPF_MOV_K64, 7, imm=0)
            asm.emit(BPF_JNE_X, 6, 7, target=yes)
        else:
            eval_scalar(node.left, 6)
            if isinstance(node.comparators[0], (ast.Constant, ast.Name)):
                eval_scalar(node.comparators[0], 7)
            else:
                asm.emit(BPF_MOV_K64, 1, imm=31)
                asm.emit(BPF_MOV_X64, 2, 6)
                asm.emit(BPF_CALL, imm=HELPER_SCRATCH_STORE)
                eval_scalar(node.comparators[0], 7)
                asm.emit(BPF_MOV_K64, 1, imm=31)
                asm.emit(BPF_CALL, imm=HELPER_SCRATCH_LOAD)
                asm.emit(BPF_MOV_X64, 6, 0)
            op = type(node.ops[0])
            dst, src = (7, 6) if op in (ast.Lt, ast.LtE) else (6, 7)
            opcode = {ast.Eq: BPF_JEQ_X, ast.NotEq: BPF_JNE_X, ast.Lt: BPF_JGT_X,
                      ast.Gt: BPF_JGT_X, ast.LtE: BPF_JGE_X, ast.GtE: BPF_JGE_X}[op]
            asm.emit(opcode, dst, src, target=yes)
        asm.jump(no)

    condition(root, 'block', 'pass')
    asm.mark('pass')
    asm.emit(BPF_MOV_K64, 0, imm=0)
    asm.emit(BPF_EXIT)
    asm.mark('block')
    asm.emit(BPF_MOV_K64, 0, imm=1)
    asm.emit(BPF_EXIT)
    return asm.finalize()


def _policy_source_to_python(source_text):
    source_text = re.sub(r'\b(?:u64|u32|u8)\s+', '', source_text)
    source_text = source_text.replace('&&', ' and ').replace('||', ' or ')
    source_text = re.sub(r'!(?!=)', ' not ', source_text)
    source_text = re.sub(r'//[^\n]*', '', source_text)
    if '{' not in source_text and ';' not in source_text:
        return textwrap.dedent(source_text).strip()
    s = source_text
    n = len(s)
    lines = []

    def word_at(i, word):
        if not s.startswith(word, i):
            return False
        after = i + len(word)
        return after == n or not (s[after].isalnum() or s[after] == '_')

    def skip_ws(i):
        while i < n and s[i] in ' \t\r\n':
            i += 1
        return i

    def read_balanced(i, open_ch, close_ch):
        if i >= n or s[i] != open_ch:
            raise ValueError('policy condition must be parenthesized')
        depth = 0
        start = i
        while i < n:
            if s[i] in ('"', "'"):
                quote = s[i]
                i += 1
                while i < n and s[i] != quote:
                    i += 2 if s[i] == '\\' else 1
                continue
            if s[i] == open_ch:
                depth += 1
            elif s[i] == close_ch:
                depth -= 1
                if depth == 0:
                    return s[start:i + 1], i + 1
            i += 1
        raise ValueError('unbalanced ' + open_ch + ' in policy')

    def emit(indent, text):
        text = text.strip()
        if text:
            lines.append(('    ' * indent) + text)

    def parse_block(i, indent):
        i = skip_ws(i + 1)
        while i < n and s[i] != '}':
            i = parse_stmt(i, indent)
            i = skip_ws(i)
        if i >= n or s[i] != '}':
            raise ValueError('unbalanced { in policy')
        return i + 1

    def parse_stmt(i, indent):
        i = skip_ws(i)
        if i >= n:
            return i
        if word_at(i, 'if'):
            i = skip_ws(i + 2)
            cond, i = read_balanced(i, '(', ')')
            emit(indent, 'if ' + cond + ':')
            i = skip_ws(i)
            if i < n and s[i] == '{':
                return parse_block(i, indent + 1)
            return parse_stmt(i, indent + 1)
        if word_at(i, 'else'):
            i = skip_ws(i + 4)
            emit(indent, 'else:')
            if i < n and s[i] == '{':
                return parse_block(i, indent + 1)
            return parse_stmt(i, indent + 1)
        if s[i] == '{':
            return parse_block(i, indent)
        start = i
        while i < n and s[i] not in ';{}':
            i += 1
        emit(indent, s[start:i])
        if i < n and s[i] == ';':
            i += 1
        return i

    i = 0
    while i < n:
        i = parse_stmt(i, 0)
        nxt = skip_ws(i)
        if nxt == i and i < n and s[i] == '}':
            raise ValueError('unbalanced } in policy')
        i = nxt
    return '\n'.join(lines).strip()


def _bounded_iter(node):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return None
    kind = node.func.id
    args = list(node.args)
    if node.keywords:
        return None

    def const(item):
        return isinstance(item, ast.Constant) and type(item.value) is int and item.value >= 0

    if kind == 'range' and len(args) == 1 and const(args[0]) and 1 <= args[0].value <= 1024:
        return 0, int(args[0].value), None
    if kind != 'bounded_range' or not args or len(args) > 2:
        return None
    if len(args) == 1 and const(args[0]) and 1 <= args[0].value <= 1024:
        return 0, int(args[0].value), None
    if len(args) == 2 and const(args[0]) and const(args[1]):
        start, end = int(args[0].value), int(args[1].value)
        trips = end - start
        if 1 <= trips <= 1024:
            return start, trips, None
        return None
    if len(args) == 2 and const(args[0]) and isinstance(args[1], (ast.Name, ast.Attribute)):
        return int(args[0].value), 1024, args[1]
    return None


def compile_policy_dsl(source_text, fields):
    source_text = _policy_source_to_python(source_text)
    tree = ast.parse(source_text, mode='exec')
    asm = _Assembler()
    var_slots = {}
    next_slot = 0
    loop_counters = [10, 9]

    def alloc_var(name):
        nonlocal next_slot
        if name in fields:
            raise ValueError('cannot shadow input field: ' + name)
        if name not in var_slots:
            if next_slot >= 24:
                raise ValueError('policy local/scratch variable budget (24) exceeded')
            var_slots[name] = next_slot
            next_slot += 1
        return var_slots[name]

    def emit_load_var(slot, dst):
        asm.emit(BPF_MOV_K64, 1, imm=slot)
        asm.emit(BPF_CALL, imm=HELPER_SCRATCH_LOAD)
        if dst != 0:
            asm.emit(BPF_MOV_X64, dst, 0)

    def emit_store_var(slot, src):
        if src == 1:
            asm.emit(BPF_MOV_X64, 2, 1)
            asm.emit(BPF_MOV_K64, 1, imm=slot)
        else:
            asm.emit(BPF_MOV_K64, 1, imm=slot)
            if src != 2:
                asm.emit(BPF_MOV_X64, 2, src)
        asm.emit(BPF_CALL, imm=HELPER_SCRATCH_STORE)

    def eval_expr(node, dst, depth=0):
        if depth > 6:
            raise ValueError('expression depth exceeded in policy DSL')
        if isinstance(node, ast.Constant):
            if type(node.value) not in (int, bool) or not 0 <= int(node.value) <= MASK:
                raise ValueError('constant out of u64 range')
            _emit_u64_const(asm.emit, dst, int(node.value))
            return
        if isinstance(node, ast.Name) or isinstance(node, ast.Attribute):
            name = node.id if isinstance(node, ast.Name) else _dotted_name(node)
            if name is None:
                raise ValueError('unsupported field access in policy DSL')
            if name in fields:
                source = fields[name]
                if 'constant' in source:
                    _emit_u64_const(asm.emit, dst, source['constant'])
                else:
                    asm.emit(BPF_MOV_K64, 1, imm=source['index'])
                    asm.emit(BPF_CALL, imm=HELPER_GET_ARG if source['source'] == 'arg' else HELPER_GET_REG)
                    if dst != 0:
                        asm.emit(BPF_MOV_X64, dst, 0)
                return
            if isinstance(node, ast.Name) and name in var_slots:
                emit_load_var(var_slots[name], dst)
                return
            raise ValueError('unknown variable in policy DSL: ' + name)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            fn = node.func.id
            read_helpers = {
                'read_u8': HELPER_SAFE_READ_U8,
                'read_u16': HELPER_SAFE_READ_U16,
                'read_u32': HELPER_SAFE_READ_U32,
                'read_u64': HELPER_SAFE_READ_U64,
            }
            if fn in read_helpers:
                if len(node.args) not in (1, 2):
                    raise ValueError(f'{fn} expects (ptr[, offset])')
                eval_expr(node.args[0], 6, depth + 1)
                if len(node.args) == 2:
                    emit_store_var(24 + depth, 6)
                    eval_expr(node.args[1], 7, depth + 1)
                    emit_load_var(24 + depth, 6)
                    asm.emit(BPF_ADD_X64, 6, 7)
                asm.emit(BPF_MOV_X64, 1, 6)
                asm.emit(BPF_CALL, imm=read_helpers[fn])
                if dst != 0:
                    asm.emit(BPF_MOV_X64, dst, 0)
                return
            if fn == 'scratch_get':
                if len(node.args) != 1:
                    raise ValueError('scratch_get expects (index)')
                eval_expr(node.args[0], 1, depth + 1)
                asm.emit(BPF_CALL, imm=HELPER_SCRATCH_LOAD)
                if dst != 0:
                    asm.emit(BPF_MOV_X64, dst, 0)
                return
            raise ValueError('unsupported helper call in policy DSL: ' + fn)
        if isinstance(node, ast.BinOp):
            eval_expr(node.left, dst, depth)
            emit_store_var(24 + depth, dst)
            eval_expr(node.right, 8, depth + 1)
            emit_load_var(24 + depth, dst)
            opcode = {
                ast.Add: BPF_ADD_X64,
                ast.Sub: BPF_SUB_X64,
                ast.Mult: BPF_MUL_X64,
                ast.BitAnd: BPF_AND_X64,
                ast.BitOr: BPF_OR_X64,
                ast.BitXor: BPF_XOR_X64,
                ast.LShift: BPF_LSH_X64,
                ast.RShift: BPF_RSH_X64,
            }[type(node.op)]
            asm.emit(opcode, dst, 8)
            return
        raise ValueError('unsupported scalar expression in policy DSL: ' + type(node).__name__)

    def emit_cond(node, yes, no):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return emit_cond(node.operand, no, yes)
        if isinstance(node, ast.BoolOp):
            for sub in node.values[:-1]:
                nxt = asm.new_label('bool')
                emit_cond(sub, nxt if isinstance(node.op, ast.And) else yes,
                          no if isinstance(node.op, ast.And) else nxt)
                asm.mark(nxt)
            return emit_cond(node.values[-1], yes, no)
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return asm.jump(yes if node.value else no)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            eval_expr(node.left, 6)
            emit_store_var(30, 6)
            eval_expr(node.comparators[0], 7)
            emit_load_var(30, 6)
            op = type(node.ops[0])
            opcode = {
                ast.Eq: BPF_JEQ_X,
                ast.NotEq: BPF_JNE_X,
                ast.Gt: BPF_JGT_X,
                ast.GtE: BPF_JGE_X,
                ast.Lt: BPF_JLT_X,
                ast.LtE: BPF_JLE_X,
            }[op]
            asm.emit(opcode, 6, 7, target=yes)
            asm.jump(no)
            return
        eval_expr(node, 6)
        asm.emit(BPF_MOV_K64, 7, imm=0)
        asm.emit(BPF_JNE_X, 6, 7, target=yes)
        asm.jump(no)

    def emit_stmts(stmts, loop_depth=0, break_label=None, continue_label=None):
        for stmt in stmts:
            if isinstance(stmt, ast.Pass):
                continue
            if isinstance(stmt, ast.Assign):
                if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                    raise ValueError('assignment requires single variable target')
                slot = alloc_var(stmt.targets[0].id)
                eval_expr(stmt.value, 6)
                emit_store_var(slot, 6)
                continue
            if isinstance(stmt, ast.AugAssign):
                if not isinstance(stmt.target, ast.Name):
                    raise ValueError('augmented assignment requires variable target')
                slot = alloc_var(stmt.target.id)
                synthetic = ast.BinOp(left=ast.Name(id=stmt.target.id, ctx=ast.Load()), op=stmt.op, right=stmt.value)
                eval_expr(synthetic, 6)
                emit_store_var(slot, 6)
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name):
                fn = stmt.value.func.id
                if fn == 'BLOCK':
                    asm.jump('policy_block')
                    continue
                if fn == 'scratch_set':
                    if len(stmt.value.args) != 2:
                        raise ValueError('scratch_set expects (index, value)')
                    eval_expr(stmt.value.args[0], 6)
                    emit_store_var(30, 6)
                    eval_expr(stmt.value.args[1], 7)
                    emit_load_var(30, 1)
                    asm.emit(BPF_MOV_X64, 2, 7)
                    asm.emit(BPF_CALL, imm=HELPER_SCRATCH_STORE)
                    continue
                raise ValueError('unsupported statement call: ' + fn)
            if isinstance(stmt, ast.If):
                then_lbl = asm.new_label('if_then')
                else_lbl = asm.new_label('if_else')
                end_lbl = asm.new_label('if_end')
                emit_cond(stmt.test, then_lbl, else_lbl if stmt.orelse else end_lbl)
                asm.mark(then_lbl)
                emit_stmts(stmt.body, loop_depth, break_label, continue_label)
                if stmt.orelse:
                    asm.jump(end_lbl)
                    asm.mark(else_lbl)
                    emit_stmts(stmt.orelse, loop_depth, break_label, continue_label)
                asm.mark(end_lbl)
                continue
            if isinstance(stmt, ast.Break):
                if break_label is None:
                    raise ValueError('break outside bounded loop')
                asm.jump(break_label)
                continue
            if isinstance(stmt, ast.Continue):
                if continue_label is None:
                    raise ValueError('continue outside bounded loop')
                asm.jump(continue_label)
                continue
            if isinstance(stmt, ast.For):
                if loop_depth >= len(loop_counters):
                    raise ValueError('maximum bounded loop nesting depth is 2')
                parsed = _bounded_iter(stmt.iter) if isinstance(stmt.target, ast.Name) else None
                if parsed is None:
                    raise ValueError('bounded loop must be range(N) or bounded_range(start, end) with 1..1024 trips')
                start_at, bound, dynamic_end = parsed
                idx_slot = alloc_var(stmt.target.id)
                reg_c = loop_counters[loop_depth]
                asm.emit(BPF_MOV_K64, 6, imm=start_at)
                emit_store_var(idx_slot, 6)
                head_lbl = asm.new_label('loop_head')
                cont_lbl = asm.new_label('loop_cont')
                after_lbl = asm.new_label('loop_after')
                asm.emit(BPF_MOV_K64, reg_c, imm=bound)
                asm.mark(head_lbl)
                if dynamic_end is not None:
                    body_lbl = asm.new_label('loop_body')
                    emit_cond(ast.Compare(
                        left=ast.Name(id=stmt.target.id, ctx=ast.Load()),
                        ops=[ast.GtE()],
                        comparators=[dynamic_end],
                    ), cont_lbl, body_lbl)
                    asm.mark(body_lbl)
                emit_stmts(stmt.body, loop_depth + 1, after_lbl, cont_lbl)
                asm.mark(cont_lbl)
                emit_load_var(idx_slot, 6)
                asm.emit(BPF_MOV_K64, 7, imm=1)
                asm.emit(BPF_ADD_X64, 6, 7)
                emit_store_var(idx_slot, 6)
                asm.emit(BPF_SUB_K64, reg_c, imm=1)
                asm.emit(BPF_JGT_K, reg_c, 0, imm=0, target=head_lbl)
                asm.mark(after_lbl)
                continue
            raise ValueError('unsupported policy DSL statement: ' + type(stmt).__name__)

    emit_stmts(tree.body)
    asm.mark('policy_pass')
    asm.emit(BPF_MOV_K64, 0, imm=0)
    asm.emit(BPF_EXIT)
    asm.mark('policy_block')
    asm.emit(BPF_MOV_K64, 0, imm=1)
    asm.emit(BPF_EXIT)
    return asm.finalize()


def extract_dsl_predicates(source_text):
    try:
        tree = ast.parse(source_text, mode='exec')
    except SyntaxError:
        tree = ast.parse(source_text, mode='eval')
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            text = ast.unparse(node)
            if text not in found:
                found.append(text)
    return found


_REF_BINOPS = {
    ast.Add: '+',
    ast.Sub: '-',
    ast.Mult: '*',
    ast.BitAnd: '&',
    ast.BitOr: '|',
    ast.BitXor: '^',
}
_REF_CMPS = {
    ast.Eq: '==',
    ast.NotEq: '!=',
    ast.Lt: '<',
    ast.LtE: '<=',
    ast.Gt: '>',
    ast.GtE: '>=',
}
_REF_RESERVED = {
    'vg_ref_block', 'vg_ref_stop', 'decision', 'stats', 'program', 'policy', 'ctx',
    'if', 'else', 'for', 'while', 'return', 'break', 'continue', 'int', 'unsigned',
}


class _PolicyRefSkip(Exception):
    pass


def policy_reference_c(source_text, expr_map):
    try:
        tree = ast.parse(_policy_source_to_python(source_text), mode='exec')
    except (SyntaxError, ValueError):
        return None
    locals_found = []

    def add_local(name):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
            raise _PolicyRefSkip
        if name in _REF_RESERVED or name in expr_map:
            raise _PolicyRefSkip
        if name not in locals_found:
            locals_found.append(name)

    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ('range', 'bounded_range'):
                    continue
                if not isinstance(node.func, ast.Name) or node.func.id != 'BLOCK' or node.args or node.keywords:
                    raise _PolicyRefSkip
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                    raise _PolicyRefSkip
                add_local(targets[0].id)
            elif isinstance(node, ast.AugAssign):
                if not isinstance(node.target, ast.Name):
                    raise _PolicyRefSkip
                add_local(node.target.id)
            elif isinstance(node, ast.For):
                if not isinstance(node.target, ast.Name):
                    raise _PolicyRefSkip
                add_local(node.target.id)
        lines = ['int vg_ref_block = 0;', 'int vg_ref_stop = 0;']
        lines.extend(f'uint64_t {name} = 0;' for name in locals_found)
        _emit_policy_statements(tree.body, expr_map, set(locals_found), lines, 0)
    except _PolicyRefSkip:
        return None
    return '\n'.join(lines)


def _emit_policy_statements(stmts, expr_map, locals_set, lines, indent):
    pad = '    ' * indent
    for stmt in stmts:
        if isinstance(stmt, ast.Pass):
            continue
        lines.append(pad + 'if (!vg_ref_stop) {')
        inner = '    ' * (indent + 1)
        if isinstance(stmt, ast.Assign):
            lines.append(inner + f'{stmt.targets[0].id} = (uint64_t)({_policy_ref_expr(stmt.value, expr_map, locals_set)});')
        elif isinstance(stmt, ast.AugAssign):
            op = _REF_BINOPS.get(type(stmt.op))
            if op is None:
                if isinstance(stmt.op, ast.LShift):
                    op = '<<'
                elif isinstance(stmt.op, ast.RShift):
                    op = '>>'
                else:
                    raise _PolicyRefSkip
            rhs = _policy_ref_expr(stmt.value, expr_map, locals_set)
            if op in ('<<', '>>'):
                lines.append(inner + f'{stmt.target.id} = (uint64_t)({stmt.target.id} {op} (({rhs}) & 63ULL));')
            else:
                lines.append(inner + f'{stmt.target.id} = (uint64_t)({stmt.target.id} {op} ({rhs}));')
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            lines.append(inner + 'vg_ref_block = 1;')
            lines.append(inner + 'vg_ref_stop = 1;')
        elif isinstance(stmt, ast.If):
            lines.append(inner + f'if ({_policy_ref_cond(stmt.test, expr_map, locals_set)}) {{')
            _emit_policy_statements(stmt.body, expr_map, locals_set, lines, indent + 2)
            if stmt.orelse:
                lines.append(inner + '} else {')
                _emit_policy_statements(stmt.orelse, expr_map, locals_set, lines, indent + 2)
            lines.append(inner + '}')
        elif isinstance(stmt, ast.For):
            parsed = _bounded_iter(stmt.iter) if isinstance(stmt.target, ast.Name) else None
            if parsed is None:
                raise _PolicyRefSkip
            name = stmt.target.id
            start_at, bound, dynamic_end = parsed
            limit = start_at + bound
            lines.append(
                inner +
                f'for ({name} = {start_at}; ({name} < {limit}ULL) && !vg_ref_stop; {name} = (uint64_t)({name} + 1ULL)) {{'
            )
            if dynamic_end is not None:
                cap = _policy_ref_expr(dynamic_end, expr_map, locals_set)
                lines.append(inner + f'    if (!(({name}) < ({cap}))) continue;')
            _emit_policy_statements(stmt.body, expr_map, locals_set, lines, indent + 2)
            lines.append(inner + '}')
        elif isinstance(stmt, ast.Break):
            lines.append(inner + 'break;')
        elif isinstance(stmt, ast.Continue):
            lines.append(inner + 'continue;')
        else:
            raise _PolicyRefSkip
        lines.append(pad + '}')


def _policy_ref_expr(node, expr_map, locals_set):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return '1ULL' if node.value else '0ULL'
        if type(node.value) is int and 0 <= node.value <= MASK:
            return f'{node.value}ULL'
        raise _PolicyRefSkip
    if isinstance(node, ast.Name):
        if node.id in expr_map:
            return f'((uint64_t)({expr_map[node.id]}))'
        if node.id in locals_set:
            return node.id
        raise _PolicyRefSkip
    if isinstance(node, ast.Attribute):
        name = _dotted_name(node)
        if name is None or name not in expr_map:
            raise _PolicyRefSkip
        return f'((uint64_t)({expr_map[name]}))'
    if isinstance(node, ast.BinOp):
        left = _policy_ref_expr(node.left, expr_map, locals_set)
        right = _policy_ref_expr(node.right, expr_map, locals_set)
        op = _REF_BINOPS.get(type(node.op))
        if op is not None:
            return f'(({left}) {op} ({right}))'
        if isinstance(node.op, ast.LShift):
            return f'(({left}) << (({right}) & 63ULL))'
        if isinstance(node.op, ast.RShift):
            return f'(({left}) >> (({right}) & 63ULL))'
        raise _PolicyRefSkip
    raise _PolicyRefSkip


def _policy_ref_cond(node, expr_map, locals_set):
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return f'!({_policy_ref_cond(node.operand, expr_map, locals_set)})'
    if isinstance(node, ast.BoolOp):
        joiner = ' && ' if isinstance(node.op, ast.And) else ' || '
        parts = [_policy_ref_cond(item, expr_map, locals_set) for item in node.values]
        return '(' + joiner.join(f'({part})' for part in parts) + ')'
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        op = _REF_CMPS.get(type(node.ops[0]))
        if op is None:
            raise _PolicyRefSkip
        left = _policy_ref_expr(node.left, expr_map, locals_set)
        right = _policy_ref_expr(node.comparators[0], expr_map, locals_set)
        return f'(({left}) {op} ({right}))'
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return '1' if node.value else '0'
    return f'(({_policy_ref_expr(node, expr_map, locals_set)}) != 0ULL)'
