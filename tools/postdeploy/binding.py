"""Resolve research-build hooks from ELF symbols, source locations and DWARF."""
import re
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser


def bind_callsite(library, caller, callee, source_line, caller_parameter, key_parameter):
    with open(library, 'rb') as file:
        elf = ELFFile(file)
        if elf.elfclass != 64 or elf['e_machine'] != 'EM_X86_64':
            raise ValueError('binding requires x86-64 ELF')
        symbols = elf.get_section_by_name('.symtab')
        if symbols is None: raise ValueError('research build must retain symbols')
        matches = [s for s in symbols.iter_symbols() if s.name == callee and s['st_size']]
        if len(matches) != 1: raise ValueError('callee symbol is not unique')
        target = matches[0]['st_value']
        dwarf = elf.get_dwarf_info()
        variables, keys = [], []
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                name = die.attributes.get('DW_AT_name')
                if die.tag != 'DW_TAG_subprogram' or not name or name.value.decode() != caller:
                    continue
                if 'DW_AT_low_pc' not in die.attributes: continue
                frame = die.attributes.get('DW_AT_frame_base')
                parsed = DWARFExprParser(unit.structs).parse_expr(frame.value) if frame else []
                if [x.op_name for x in parsed] != ['DW_OP_call_frame_cfa']:
                    raise ValueError('unsupported caller frame base')
                for child in die.iter_children():
                    attr = child.attributes.get('DW_AT_name')
                    if child.tag == 'DW_TAG_formal_parameter' and attr and attr.value.decode() in (caller_parameter, key_parameter):
                        loc = DWARFExprParser(unit.structs).parse_expr(child.attributes['DW_AT_location'].value)
                        if len(loc) != 1 or loc[0].op_name != 'DW_OP_fbreg':
                            raise ValueError('parameter is not in a fixed frame slot')
                        (variables if attr.value.decode() == caller_parameter else keys).append(loc[0].args[0] + 16)
        if len(variables) != 1 or len(keys) != 1: raise ValueError('parameter binding is not unique')
    disassembly = subprocess.check_output(['objdump', '-d', '-l', '--no-show-raw-insn',
                                          '--disassemble=' + caller, str(library)], text=True)
    if not re.search(r'push\s+%rbp', disassembly) or not re.search(r'mov\s+%rsp,%rbp', disassembly):
        raise ValueError('caller does not use the required frame pointer')
    current_line, instructions, candidates, assembly = None, [], [], {}
    for line in disassembly.splitlines():
        source = re.search(r'\.c:(\d+)', line)
        if source: current_line = int(source[1])
        instruction = re.match(r'\s*([0-9a-f]+):\s+(.*)', line)
        if instruction:
            pc, text = int(instruction[1], 16), instruction[2]
            instructions.append(pc)
            assembly[pc] = text
            if current_line == source_line and re.search(r'\bcall\s+[0-9a-f]+\s+<' + re.escape(callee) + r'>', text):
                candidates.append(pc)
    if len(candidates) != 1: raise ValueError('source callsite does not bind uniquely')
    call = candidates[0]
    after = instructions[instructions.index(call) + 1]
    # Avoid relocating the CALL itself: that changes the return PC inspected by
    # the callee's guard. Sample before register-only argument setup instead.
    prior = instructions.index(call) - 1
    while prior >= 0 and re.match(r'(mov|lea)\w*\s+.*,%[a-z0-9]+$', assembly[instructions[prior]]):
        prior -= 1
    observe = instructions[prior + 1]
    if call - observe < 16: raise ValueError('no stable pre-call observation window')
    return {'callee_offset': target, 'call_offset': call, 'return_offset': after,
            'observation_offset': observe, 'key_rbp_offset': keys[0],
            'parameter_rbp_offset': variables[0], 'source_line': source_line,
            'caller': caller, 'callee': callee, 'parameter': caller_parameter}


def _die_name(die) -> str | None:
    attr = die.attributes.get('DW_AT_name')
    if not attr:
        return None
    value = attr.value
    return value.decode() if isinstance(value, bytes) else str(value)


def _member_location(die) -> int | None:
    attr = die.attributes.get('DW_AT_data_member_location')
    if attr is None:
        return None
    if isinstance(attr.value, int):
        return attr.value
    if not isinstance(attr.value, (bytes, bytearray)):
        return None
    parser = DWARFExprParser(die.cu.structs)
    expr = parser.parse_expr(attr.value)
    if len(expr) == 1 and expr[0].op_name in ('DW_OP_plus_uconst', 'DW_OP_constu'):
        return int(expr[0].args[0])
    return None


def _unwrap_layout_type(die):
    seen = set()
    while die is not None and id(die) not in seen:
        seen.add(id(die))
        if die.tag in (
            'DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type',
            'DW_TAG_restrict_type', 'DW_TAG_pointer_type',
        ):
            if 'DW_AT_type' not in die.attributes:
                return None
            die = die.get_DIE_from_attribute('DW_AT_type')
            continue
        return die
    return None


def _field_offset(type_die, field: str) -> int | None:
    layout = _unwrap_layout_type(type_die)
    if layout is None or layout.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_class_type'):
        return None
    for child in layout.iter_children():
        if child.tag == 'DW_TAG_member' and _die_name(child) == field:
            return _member_location(child)
    return None


def _store_displacement(text: str) -> int | None:
    opcode = text.split(None, 1)[0] if text.split() else ''
    if opcode not in ('mov', 'movb', 'movw', 'movl', 'movq'):
        return None
    match = re.search(r'(?:(-?(?:0x[0-9a-fA-F]+|\d+)))?\(%[A-Za-z0-9]+\)\s*$', text.strip())
    if not match:
        return None
    raw = match.group(1)
    if raw is None:
        return 0
    return int(raw, 16) if raw.lower().startswith(('0x', '-0x')) else int(raw)


def bind_after_assign(library, function: str, anchor: str) -> dict:
    if not str(anchor).startswith('after_assign_'):
        return {'offsets': [], 'reason': 'not_after_assign'}
    rest = str(anchor)[len('after_assign_'):]
    with open(library, 'rb') as file:
        elf = ELFFile(file)
        if not elf.has_dwarf_info():
            return {'offsets': [], 'reason': 'no_dwarf'}
        dwarf = elf.get_dwarf_info()
        names: list[str] = []
        field_offset = None
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag != 'DW_TAG_subprogram' or _die_name(die) != function:
                    continue
                if 'DW_AT_low_pc' not in die.attributes:
                    continue
                local_names = []
                typed = {}
                for child in die.iter_children():
                    if child.tag not in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
                        continue
                    name = _die_name(child)
                    if not name or 'DW_AT_type' not in child.attributes:
                        continue
                    local_names.append(name)
                    typed[name] = child.get_DIE_from_attribute('DW_AT_type')
                candidates = [
                    (name, rest[len(name) + 1:])
                    for name in local_names
                    if rest.startswith(name + '_') and rest[len(name) + 1:]
                ]
                if not candidates:
                    continue
                base, field = max(candidates, key=lambda item: len(item[0]))
                found = _field_offset(typed[base], field)
                if found is None:
                    continue
                names = local_names
                field_offset = found
                break
            if field_offset is not None:
                break
        symbols = elf.get_section_by_name('.symtab')
        matches = []
        if symbols is not None:
            matches = [sym for sym in symbols.iter_symbols() if sym.name == function and sym['st_size']]
        if field_offset is None or len(matches) != 1:
            return {'offsets': [], 'reason': 'field_not_found' if field_offset is None else 'symbol_not_unique'}
        symbol = matches[0]
        start = int(symbol['st_value'])
        end = start + int(symbol['st_size'])
    disassembly = subprocess.check_output(
        ['objdump', '-d', '--no-show-raw-insn', '--disassemble=' + function, str(library)],
        text=True,
    )
    pcs: list[int] = []
    texts: list[str] = []
    for line in disassembly.splitlines():
        instruction = re.match(r'\s*([0-9a-f]+):\s+(.*)', line)
        if not instruction:
            continue
        pc = int(instruction.group(1), 16)
        if start <= pc < end:
            pcs.append(pc)
            texts.append(instruction.group(2))
    offsets = []
    for index, text in enumerate(texts):
        if _store_displacement(text) != field_offset or index + 1 >= len(pcs):
            continue
        nxt = pcs[index + 1]
        if nxt not in offsets:
            offsets.append(nxt)
    return {
        'base': max(
            (name for name in names if rest.startswith(name + '_')),
            key=len,
            default='',
        ),
        'field_offset': field_offset,
        'offsets': offsets,
        'reason': 'bound' if offsets else 'store_not_found',
    }
