from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from elftools.elf.elffile import ELFFile
import yaml

from .action_catalog import attest_catalog, install_extracted_actions
from .binding import bind_after_assign, bind_callsite
from .expressions import compile_guard, evaluate, extract_dsl_predicates, parse

ROOT = Path(__file__).resolve().parents[2]


def _member_location(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, (bytes, bytearray)) or not value:
        return None
    opcode = value[0]
    if 0x30 <= opcode <= 0x4F:
        return opcode - 0x30
    if opcode == 0x23:
        shift = 0
        result = 0
        for byte in value[1:]:
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result
            shift += 7
            if shift > 28:
                return None
        return None
    widths = {0x08: 1, 0x0A: 2, 0x0C: 4}
    width = widths.get(opcode)
    if width is None or len(value) < 1 + width:
        return None
    return int.from_bytes(value[1:1 + width], 'little')


def deployment_quiescent_phase(patch_spec: dict[str, Any], app_profile: dict[str, Any]) -> str:
    declared = (patch_spec.get('install_precondition') or {}).get('quiescent_phase')
    if declared:
        return str(declared)
    attached = ((app_profile.get('lifecycle_hooks') or {}).get('quiescent_attach'))
    if attached:
        return str(attached)
    return 'pre_first_request'


def load_spec_file(path: Path | str) -> dict[str, Any]:
    path = Path(path).resolve()
    raw = path.read_text(encoding='utf-8')
    if path.suffix.lower() in ('.yaml', '.yml'):
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f'spec file must parse to a mapping: {path}')
    return data


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_json(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def elf_build_id(path: Path) -> str | None:
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_type'] != 'SHT_NOTE':
                continue
            for note in section.iter_notes():
                if note.get('n_type') == 'NT_GNU_BUILD_ID':
                    desc = note.get('n_desc')
                    return desc if isinstance(desc, str) else bytes(desc).hex()
    return None


def elf_unique_symbols(path: Path) -> tuple[dict[str, int], dict[str, list[int]]]:
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or elf['e_machine'] != 'EM_X86_64':
            raise ValueError(f'expected x86-64 ELF64 artifact: {path}')
        base = min(seg['p_vaddr'] for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD')
    output = subprocess.check_output(['nm', '-an', '--defined-only', str(path)], text=True)
    grouped: dict[str, list[int]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        addr_hex, _sym_type, name = parts
        offset = int(addr_hex, 16) - base
        grouped.setdefault(name, []).append(offset)
    unique = {k: sorted(set(v))[0] for k, v in grouped.items() if len(set(v)) == 1}
    ambiguous = {k: sorted(set(v)) for k, v in grouped.items() if len(set(v)) > 1}
    return unique, ambiguous


class DWARFLayoutResolver:
    def __init__(self, binary_paths: list[Path]):
        self.binary_paths = [Path(p).resolve() for p in binary_paths]
        self._struct_cache: dict[str, dict[str, dict[str, Any]]] | None = None

    def _ensure_loaded(self) -> dict[str, dict[str, dict[str, Any]]]:
        if self._struct_cache is not None:
            return self._struct_cache
        structs: dict[str, dict[str, dict[str, Any]]] = {}
        for binary in self.binary_paths:
            with binary.open('rb') as stream:
                elf = ELFFile(stream)
                if not elf.has_dwarf_info():
                    continue
                dwarf = elf.get_dwarf_info()
                for cu in dwarf.iter_CUs():
                    die_by_offset: dict[int, Any] = {}
                    typedefs: dict[str, int] = {}
                    for die in cu.iter_DIEs():
                        die_by_offset[die.offset] = die
                        if die.tag == 'DW_TAG_typedef' and 'DW_AT_name' in die.attributes and 'DW_AT_type' in die.attributes:
                            tname = die.attributes['DW_AT_name'].value.decode('utf-8', errors='replace')
                            ref_attr = die.attributes['DW_AT_type']
                            ref_off = ref_attr.value + (cu.cu_offset if ref_attr.form.startswith('DW_FORM_ref') and ref_attr.form != 'DW_FORM_ref_addr' else 0)
                            typedefs[tname] = ref_off

                    def resolve_die_type(ref_die: Any, depth: int = 0) -> dict[str, Any]:
                        if ref_die is None or depth > 12:
                            return {'kind': 'u64', 'byte_size': 8}
                        while ref_die is not None and ref_die.tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type', 'DW_TAG_restrict_type'):
                            if 'DW_AT_type' not in ref_die.attributes:
                                return {'kind': 'pointer', 'byte_size': 8}
                            attr = ref_die.attributes['DW_AT_type']
                            off = attr.value + (cu.cu_offset if attr.form.startswith('DW_FORM_ref') and attr.form != 'DW_FORM_ref_addr' else 0)
                            ref_die = die_by_offset.get(off)
                        if ref_die is None:
                            return {'kind': 'u64', 'byte_size': 8}
                        if ref_die.tag in ('DW_TAG_pointer_type', 'DW_TAG_subroutine_type'):
                            return {'kind': 'pointer', 'byte_size': 8}
                        bsize = ref_die.attributes['DW_AT_byte_size'].value if 'DW_AT_byte_size' in ref_die.attributes else 8
                        signed = False
                        if 'DW_AT_encoding' in ref_die.attributes:
                            enc = ref_die.attributes['DW_AT_encoding'].value
                            signed = enc in (5, 7)
                        width_map = {
                            (1, False): 'u8', (1, True): 's8',
                            (2, False): 'u16', (2, True): 's16',
                            (4, False): 'u32', (4, True): 's32',
                            (8, False): 'u64', (8, True): 's64',
                        }
                        return {'kind': width_map.get((bsize, signed), 'u64'), 'byte_size': bsize,
                                'tag': ref_die.tag, 'die_offset': ref_die.offset}

                    def extract_members(struct_die: Any, base_offset: int = 0) -> dict[str, dict[str, Any]]:
                        members: dict[str, dict[str, Any]] = {}
                        for child in struct_die.iter_children():
                            if child.tag != 'DW_TAG_member':
                                continue
                            loc_attr = child.attributes.get('DW_AT_data_member_location')
                            if loc_attr is None:
                                rel_off = 0
                            else:
                                decoded = _member_location(loc_attr.value)
                                if decoded is None:
                                    continue
                                rel_off = decoded
                            total_off = base_offset + rel_off
                            t_die = None
                            if 'DW_AT_type' in child.attributes:
                                t_attr = child.attributes['DW_AT_type']
                                t_off = t_attr.value + (cu.cu_offset if t_attr.form.startswith('DW_FORM_ref') and t_attr.form != 'DW_FORM_ref_addr' else 0)
                                t_die = die_by_offset.get(t_off)
                            if 'DW_AT_name' not in child.attributes:
                                while t_die is not None and t_die.tag in ('DW_TAG_typedef', 'DW_TAG_const_type'):
                                    if 'DW_AT_type' not in t_die.attributes:
                                        break
                                    ta = t_die.attributes['DW_AT_type']
                                    to = ta.value + (cu.cu_offset if ta.form.startswith('DW_FORM_ref') and ta.form != 'DW_FORM_ref_addr' else 0)
                                    t_die = die_by_offset.get(to)
                                if t_die is not None and t_die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                                    members.update(extract_members(t_die, total_off))
                                continue
                            mname = child.attributes['DW_AT_name'].value.decode('utf-8', errors='replace')
                            tinfo = resolve_die_type(t_die)
                            entry: dict[str, Any] = {
                                'offset': total_off,
                                'type': tinfo['kind'],
                                'byte_size': tinfo['byte_size'],
                            }
                            if 'DW_AT_bit_size' in child.attributes:
                                bsz = child.attributes['DW_AT_bit_size'].value
                                if 'DW_AT_data_bit_offset' in child.attributes:
                                    dbo = child.attributes['DW_AT_data_bit_offset'].value
                                    byte_off = dbo // 8
                                    bit_in_u32 = dbo - (byte_off // 4) * 32
                                    aligned_off = (byte_off // 4) * 4
                                    mask = ((1 << bsz) - 1) << bit_in_u32
                                    entry['offset'] = base_offset + aligned_off
                                    entry['type'] = 'u32'
                                    entry['bit_mask'] = mask
                                    entry['bit_shift'] = bit_in_u32
                                elif 'DW_AT_bit_offset' in child.attributes:
                                    bo = child.attributes['DW_AT_bit_offset'].value
                                    storage_bits = entry['byte_size'] * 8
                                    lsb = storage_bits - bo - bsz
                                    entry['bit_mask'] = ((1 << bsz) - 1) << max(0, lsb)
                                    entry['bit_shift'] = max(0, lsb)
                            members[mname] = entry
                            while t_die is not None and t_die.tag in ('DW_TAG_typedef', 'DW_TAG_const_type'):
                                if 'DW_AT_type' not in t_die.attributes:
                                    break
                                ta = t_die.attributes['DW_AT_type']
                                to = ta.value + (cu.cu_offset if ta.form.startswith('DW_FORM_ref') and ta.form != 'DW_FORM_ref_addr' else 0)
                                t_die = die_by_offset.get(to)
                            if t_die is not None and t_die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                                sub_members = extract_members(t_die, total_off)
                                for sub_k, sub_v in sub_members.items():
                                    members[f'{mname}.{sub_k}'] = sub_v
                        return members

                    for die in cu.iter_DIEs():
                        if die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type') and 'DW_AT_byte_size' in die.attributes:
                            if 'DW_AT_name' in die.attributes:
                                sname = die.attributes['DW_AT_name'].value.decode('utf-8', errors='replace')
                                if sname not in structs or len(structs[sname]) == 0:
                                    structs[sname] = extract_members(die)
                    for tname, ref_off in typedefs.items():
                        target_die = die_by_offset.get(ref_off)
                        if target_die is not None and target_die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type') and 'DW_AT_byte_size' in target_die.attributes:
                            if tname not in structs or len(structs[tname]) == 0:
                                structs[tname] = extract_members(target_die)
        self._struct_cache = structs
        return structs

    def field_info(self, type_name: str, member_path: str) -> dict[str, Any]:
        structs = self._ensure_loaded()
        clean = type_name.removeprefix('struct ').removeprefix('const ').rstrip('*').strip()
        if clean not in structs:
            raise KeyError(f'DWARF type not found: {clean}')
        if member_path not in structs[clean]:
            raise KeyError(f'DWARF member {member_path} not found in {clean}')
        return dict(structs[clean][member_path])


def _resolve_artifact(app_profile: dict[str, Any], module_name: str | None = None, mode: str = 'baseline') -> Path:
    builds = app_profile['builds'][mode]
    if not module_name or module_name == Path(builds['executable']).name:
        return Path(builds['executable']).resolve()
    modules = builds.get('modules', {})
    if module_name in modules:
        return Path(modules[module_name]).resolve()
    search_root = Path(builds.get('module_search_root', Path(builds['executable']).parent))
    candidates = [p for p in search_root.rglob(module_name) if p.is_file()]
    if len(candidates) != 1:
        raise ValueError(f'cannot uniquely resolve module {module_name} under {search_root}: {candidates}')
    return candidates[0].resolve()


def _resolve_selector_spec(raw_sel: dict[str, Any],
                           symbol_tables: dict[str, dict[str, int]],
                           default_module: str,
                           dwarf: DWARFLayoutResolver,
                           layout_overrides: dict[str, Any]) -> dict[str, Any]:
    sel = json.loads(json.dumps(raw_sel))
    for helper_only in ('c_param_expr', 'symbolic_var_expr', 'symbolic_var_decl'):
        sel.pop(helper_only, None)
    if 'constant' in sel or 'register' in sel:
        return sel
    if 'global_symbol' in sel:
        gmod = sel.get('module', default_module)
        gsym = sel.pop('global_symbol')
        sel.pop('module', None)
        if gsym not in symbol_tables[gmod]:
            raise ValueError(f'global symbol {gsym} missing or ambiguous in {gmod}')
        sel['global'] = {'module': gmod, 'offset': symbol_tables[gmod][gsym],
                         'symbol_c_name': gsym}
    resolved_reads = []
    for step in sel.get('reads', []):
        rstep = dict(step)
        if 'struct_member' in rstep:
            st_name, mem_name = rstep.pop('struct_member')
            override_key = f'{st_name}.{mem_name}'
            bit_key = f'bit.{mem_name}'
            if bit_key in layout_overrides and isinstance(layout_overrides[bit_key], dict):
                rstep['offset'] = int(layout_overrides[bit_key]['offset'])
                rstep.setdefault('type', 'u32')
            elif override_key in layout_overrides:
                rstep['offset'] = int(layout_overrides[override_key])
                if 'type' not in rstep:
                    rstep['type'] = dwarf.field_info(st_name, mem_name)['type']
            else:
                info = dwarf.field_info(st_name, mem_name)
                rstep['offset'] = info['offset']
                rstep.setdefault('type', info['type'])
        if 'index' in rstep and isinstance(rstep['index'], dict):
            rstep['index'] = _resolve_selector_spec(rstep['index'], symbol_tables, default_module, dwarf, layout_overrides)
        resolved_reads.append(rstep)
    if resolved_reads:
        sel['reads'] = resolved_reads
    return sel


def map_install_spec(name: str, map_def: dict[str, Any]) -> dict[str, Any]:
    policy = str(map_def.get('on_full') or 'drop')
    if policy not in ('drop', 'block'):
        raise ValueError(f'map {name} on_full must be drop or block')
    declared = map_def.get('scope')
    flagged = map_def.get('thread_scoped')
    if declared is None:
        scope = 'thread' if flagged else 'process'
    else:
        scope = str(declared)
        if scope not in ('thread', 'process'):
            raise ValueError(f'map {name} scope must be thread or process')
        if flagged is not None and bool(flagged) != (scope == 'thread'):
            raise ValueError(f'map {name} scope disagrees with thread_scoped')
    key_fields, value_fields = map_word_layout(name, map_def)
    return {
        'capacity': int(map_def.get('capacity', 1024)),
        'thread_scoped': scope == 'thread',
        'scope': scope,
        'on_full': policy,
        'key_words': len(key_fields),
        'value_fields': value_fields,
    }


def map_word_layout(name: str, map_def: dict[str, Any]) -> tuple[list[str], list[str]]:
    key = map_def.get('key_type')
    value = map_def.get('value_type')
    if key is None:
        key_fields = ['key']
    elif key in ('u64', 'pointer'):
        key_fields = ['key']
    elif isinstance(key, dict) and isinstance(key.get('tuple'), list):
        key_fields = []
        for index, kind in enumerate(key['tuple']):
            if kind not in ('u64', 'pointer'):
                raise ValueError(f'map {name} key word {index} must be u64 or pointer')
            key_fields.append(f'k{index}')
        if not key_fields or len(key_fields) > 4:
            raise ValueError(f'map {name} key tuple must contain 1 to 4 words')
    else:
        raise ValueError(f'map {name} key_type must be u64, pointer, or a tuple')
    if value is None:
        return key_fields, []
    if not isinstance(value, dict) or not isinstance(value.get('struct'), list):
        raise ValueError(f'map {name} value_type must be a struct')
    value_fields: list[str] = []
    for item in value['struct']:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError(f'map {name} value field must be a single typed name')
        field, kind = next(iter(item.items()))
        if kind not in ('u64', 'pointer'):
            raise ValueError(f'map {name} field {field} must be u64 or pointer')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', str(field)):
            raise ValueError(f'map {name} field {field} is not an identifier')
        value_fields.append(str(field))
    if not value_fields or len(value_fields) > 4:
        raise ValueError(f'map {name} value struct must contain 1 to 4 fields')
    return key_fields, value_fields


def resolve_key_components(expr: str, parameter_names: list[str]) -> list[dict[str, Any]]:
    text = expr.strip()
    if text.startswith('[') and text.endswith(']'):
        parts = [part.strip() for part in text[1:-1].split(',') if part.strip()]
    else:
        parts = [text]
    if not parts or len(parts) > 4:
        raise ValueError(f'map key expression {expr} must contain 1 to 4 words')
    components: list[dict[str, Any]] = []
    for part in parts:
        if part == '__vg_tid':
            components.append({'scope': True, 'name': part})
        elif part in parameter_names:
            components.append({'arg': parameter_names.index(part), 'name': part})
        elif re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', part):
            components.append({'name': part})
        else:
            raise ValueError(f'unsupported map key component {part}')
    return components


def parse_struct_value_expr(expr: str, fields: list[str]) -> list[str]:
    text = expr.strip()
    if not fields:
        if text.startswith('{'):
            raise ValueError('scalar map value cannot be a struct')
        if not text:
            raise ValueError('map value expression is empty')
        return [text]
    if not (text.startswith('{') and text.endswith('}')):
        raise ValueError('struct map value must be {field: expr, ...}')
    body = text[1:-1].strip()
    if not body:
        raise ValueError('struct map value is empty')
    parts: list[str] = []
    depth = 0
    start = 0
    for index, ch in enumerate(body):
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            parts.append(body[start:index])
            start = index + 1
    parts.append(body[start:])
    found: dict[str, str] = {}
    for part in parts:
        piece = part.strip()
        if ':' not in piece:
            raise ValueError('struct field needs a value expression')
        name, value = piece.split(':', 1)
        name = name.strip()
        value = value.strip()
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            raise ValueError(f'map field {name} is not an identifier')
        if name not in fields:
            raise ValueError(f'unknown map field {name}')
        if name in found:
            raise ValueError(f'duplicate map field {name}')
        if not value:
            raise ValueError(f'map field {name} needs a value expression')
        found[name] = value
    missing = [name for name in fields if name not in found]
    if missing:
        raise ValueError('struct map value misses ' + ', '.join(missing))
    return [found[name] for name in fields]


def lower_observer_word(expr: str, parameter_names: list[str]) -> dict[str, Any]:
    text = expr.strip()
    if text == '__vg_tid':
        return {'scope': True, 'name': text}
    if re.fullmatch(r'\d+', text):
        return {'constant': int(text)}
    if text in parameter_names:
        return {'arg': parameter_names.index(text), 'name': text}
    return {'expr': text}


def bind_observer_words(map_name: str, map_def: dict[str, Any], observer: dict[str, Any],
                        parameter_names: list[str]) -> dict[str, Any]:
    key_fields, value_fields = map_word_layout(map_name, map_def)
    if 'key_expr' not in observer:
        raise ValueError(f'map observer {map_name} needs key_expr')
    components = resolve_key_components(str(observer['key_expr']), parameter_names)
    if len(components) != len(key_fields):
        raise ValueError(f'map {map_name} key width does not match key_type')
    result: dict[str, Any] = {
        'key_components': components,
        'key_words': len(components),
    }
    if str(observer.get('operation') or 'set') == 'set':
        if 'value_expr' not in observer:
            raise ValueError(f'map observer {map_name} needs value_expr')
        exprs = parse_struct_value_expr(str(observer['value_expr']), value_fields)
        result['value_exprs'] = exprs
        result['value_words'] = [lower_observer_word(expr, parameter_names) for expr in exprs]
    return result


def bind_structured_map_read(map_name: str, map_def: dict[str, Any], read: dict[str, Any],
                             slot_cursor: int) -> tuple[dict[str, dict[str, Any]], dict[str, Any], int]:
    _key_fields, value_fields = map_word_layout(map_name, map_def)
    into = read.get('into') or read.get('into_slot')
    present_only = not (isinstance(into, str) and into) and isinstance(read.get('present_into'), str) and bool(read['present_into'])
    if not present_only and (not isinstance(into, str) or not into):
        raise ValueError(f'map read of {map_name} needs into or into_slot')
    if not value_fields:
        val_slot = int(read.get('slot', slot_cursor))
        slot_cursor = max(slot_cursor, val_slot + 1)
        fields: dict[str, dict[str, Any]] = {} if present_only else {str(into): {'source': 'slot', 'index': val_slot}}
        ref: dict[str, Any] = {
            'map': read['map'],
            'slot': val_slot,
            'consume': bool(read.get('consume', False)),
            'words': 1,
        }
        if 'present_into' in read:
            pres_slot = int(read.get('present_slot', slot_cursor))
            slot_cursor = max(slot_cursor, pres_slot + 1)
            ref['present_slot'] = pres_slot
            fields[read['present_into']] = {'source': 'slot', 'index': pres_slot}
        return fields, ref, slot_cursor
    present_name = str(read.get('present_into') or f'{into}.present')
    pres_slot = int(read.get('present_slot', slot_cursor))
    slot_cursor = max(slot_cursor, pres_slot + 1)
    fields = {present_name: {'source': 'slot', 'index': pres_slot}}
    base = int(read.get('slot', slot_cursor))
    word_slots: list[int] = []
    for offset, field in enumerate(value_fields):
        slot = base + offset
        slot_cursor = max(slot_cursor, slot + 1)
        if not present_only:
            fields[f'{into}.{field}'] = {'source': 'slot', 'index': slot}
        word_slots.append(slot)
    ref = {
        'map': read['map'],
        'slot': word_slots[0],
        'word_slots': word_slots,
        'words': len(value_fields),
        'consume': bool(read.get('consume', False)),
        'present_slot': pres_slot,
    }
    return fields, ref, slot_cursor


def compile_case(vuln_spec: dict[str, Any],
                 patch_spec: dict[str, Any],
                 app_profile: dict[str, Any],
                 output_dir: Path) -> dict[str, Any]:
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    deploy_dir = output_dir / 'deployment'
    deploy_dir.mkdir(parents=True, exist_ok=True)
    dsl_patch = patch_spec.get('dsl_patch') or {}

    exe_path = _resolve_artifact(app_profile, None, 'baseline')
    all_modules: dict[str, Path] = {exe_path.name: exe_path}
    for item in [*patch_spec.get('observers', []), *patch_spec.get('guards', [])]:
        mod = item.get('module')
        if mod and mod not in all_modules:
            all_modules[mod] = _resolve_artifact(app_profile, mod, 'baseline')

    symbol_tables: dict[str, dict[str, int]] = {}
    ambiguous_tables: dict[str, dict[str, list[int]]] = {}
    artifact_pins: dict[str, str] = {}
    build_ids: dict[str, str | None] = {}
    for mod_name, mod_path in all_modules.items():
        uniq, ambig = elf_unique_symbols(mod_path)
        symbol_tables[mod_name] = uniq
        ambiguous_tables[mod_name] = ambig
        artifact_pins[str(mod_path)] = sha256_file(mod_path)
        build_ids[mod_name] = elf_build_id(mod_path)

    dwarf = DWARFLayoutResolver(list(all_modules.values()))
    layout_overrides = dict(app_profile.get('layout', {}))

    maps_manifest: dict[str, dict[str, Any]] = {}
    for map_name, map_def in patch_spec.get('maps', {}).items():
        maps_manifest[map_name] = map_install_spec(map_name, map_def)

    callsite_bindings: dict[str, dict[str, Any]] = {}
    observers_manifest: list[dict[str, Any]] = []
    for obs in patch_spec.get('observers', []):
        mod_name = obs.get('module', exe_path.name)
        mod_path = all_modules[mod_name]
        obs_entry: dict[str, Any] = {
            'id': obs['id'],
            'module': mod_name,
            'arg_types': list(obs.get('arg_types', [])),
            'map': obs['map'],
            'operation': obs.get('operation', 'set'),
        }
        if 'dsl_operations' in obs:
            obs_entry['dsl_mount_id'] = obs.get('dsl_mount_id', obs['id'])
            obs_entry['dsl_operations'] = json.loads(json.dumps(obs['dsl_operations']))
            obs_entry['local_names'] = list(obs.get('local_names', []))
            obs_entry['arg_indices'] = list(obs.get('arg_indices', []))
            if obs.get('function'):
                obs_entry['function'] = obs['function']
            if 'offset' in obs:
                obs_entry['offset'] = int(obs['offset'])
            elif 'dsl_callsite' in obs:
                from runtime.dsl import dwarf_local as _dwarf_local
                from runtime.dsl import x86 as _dsl_x86
                cs = dict(obs['dsl_callsite'])
                obs_entry['dsl_callsite'] = cs
                resolved_cs_off: int | None = None
                try:
                    resolved_cs_off = int(_dsl_x86.resolve_callsite(
                        mod_path, cs['caller'], cs['callee'], cs.get('line'), cs.get('file'),
                    ))
                except Exception:
                    resolved_cs_off = symbol_tables[mod_name].get(str(cs.get('caller') or ''))
                if resolved_cs_off is None:
                    raise ValueError(f'observer {obs["id"]} callsite {cs.get("caller")}->{cs.get("callee")} unresolved in {mod_name}')
                obs_entry['offset'] = resolved_cs_off
                recipes: dict[str, Any] = {}
                for l_idx, lname in enumerate(obs_entry['local_names']):
                    try:
                        recipes[lname] = _dwarf_local.resolve_local(mod_path, str(cs['caller']), lname, resolved_cs_off)
                    except Exception:
                        recipes[lname] = {'kind': 'register', 'reg': f'r{8 + l_idx}'}
                if recipes:
                    obs_entry['local_recipes'] = recipes
            elif 'dsl_line' in obs:
                from runtime.dsl import x86 as _dsl_x86
                ln = dict(obs['dsl_line'])
                obs_entry['dsl_line'] = ln
                try:
                    obs_entry['offset'] = int(_dsl_x86.resolve_line(mod_path, str(ln['file']), int(ln['line'])))
                except Exception as exc:
                    fn_fallback = str(obs.get('function') or '')
                    if fn_fallback and fn_fallback in symbol_tables[mod_name]:
                        obs_entry['offset'] = symbol_tables[mod_name][fn_fallback]
                    else:
                        raise ValueError(f'observer {obs["id"]} line unresolved in {mod_name}: {exc}') from exc
            else:
                fn = obs.get('function')
                if not fn:
                    raise ValueError(f'observer {obs.get("id")} needs a function')
                if fn in ambiguous_tables[mod_name]:
                    raise ValueError(f'ambiguous observer function symbol {fn} in {mod_name}: {ambiguous_tables[mod_name][fn]}')
                if fn not in symbol_tables[mod_name]:
                    raise ValueError(f'missing observer function symbol {fn} in {mod_name}')
                obs_entry['offset'] = symbol_tables[mod_name][fn]
        elif 'callsite' in obs:
            cs = obs['callsite']
            bound = bind_callsite(
                mod_path, cs['caller'], cs['callee'], int(cs['source_line']),
                cs['value_parameter'], cs['key_parameter']
            )
            callsite_bindings[obs['id']] = bound
            obs_entry['offset'] = bound['observation_offset']
            obs_entry['key'] = {'register': 'rbp', 'reads': [{'offset': bound['key_rbp_offset'], 'type': 'pointer'}]}
            val_reads = [{'offset': bound['parameter_rbp_offset'], 'type': 'pointer'}]
            for extra in cs.get('deref_reads', []):
                val_reads.append(dict(extra))
            obs_entry['value'] = {'register': 'rbp', 'reads': val_reads}
        else:
            site = obs.get('site') if isinstance(obs.get('site'), dict) else {}
            if 'offset' in obs:
                obs_entry['offset'] = int(obs['offset'])
            else:
                fn = obs.get('function') or site.get('function')
                if not fn:
                    raise ValueError(f'observer {obs.get("id")} needs a function')
                if fn in ambiguous_tables[mod_name]:
                    raise ValueError(f'ambiguous observer function symbol {fn} in {mod_name}: {ambiguous_tables[mod_name][fn]}')
                if fn not in symbol_tables[mod_name]:
                    raise ValueError(f'missing observer function symbol {fn} in {mod_name}')
                obs_entry['offset'] = symbol_tables[mod_name][fn]
            if 'key_expr' in obs:
                map_def = patch_spec.get('maps', {}).get(obs['map'], {})
                obs_entry.update(bind_observer_words(
                    obs['map'], map_def, obs, list(obs.get('parameter_names') or []),
                ))
                anchor = obs.get('anchor') or site.get('anchor')
                if anchor:
                    obs_entry['anchor'] = anchor
                    if str(anchor).startswith('after_assign_'):
                        fn_name = obs.get('function') or site.get('function')
                        bound = {'offsets': []}
                        if fn_name:
                            try:
                                bound = bind_after_assign(mod_path, fn_name, str(anchor))
                            except (OSError, ValueError, subprocess.CalledProcessError):
                                bound = {'offsets': []}
                        if bound.get('offsets'):
                            obs_entry['anchor_offsets'] = [int(item) for item in bound['offsets']]
                        else:
                            obs_entry['anchor_unresolved'] = True
            elif 'key' in obs:
                obs_entry['key'] = _resolve_selector_spec(obs['key'], symbol_tables, mod_name, dwarf, layout_overrides)
            else:
                obs_entry['key_arg'] = int(obs['key_arg'])
            if obs_entry['operation'] == 'set' and 'key_expr' not in obs:
                if 'value' in obs:
                    obs_entry['value'] = _resolve_selector_spec(obs['value'], symbol_tables, mod_name, dwarf, layout_overrides)
                else:
                    obs_entry['value_arg'] = int(obs['value_arg'])
        observers_manifest.append(obs_entry)

    guards_manifest: list[dict[str, Any]] = []
    compiled_guards_ir: list[dict[str, Any]] = []
    actions_catalog: dict[str, dict[str, Any]] = {}
    catalog_source = {**app_profile.get('action_catalog', {}), **patch_spec.get('actions', {})}

    for g_idx, g in enumerate(patch_spec.get('guards', [])):
        mod_name = g.get('module', exe_path.name)
        fn = g['function']
        if 'offset' in g:
            g_offset = int(g['offset'])
        else:
            if fn in ambiguous_tables[mod_name]:
                raise ValueError(f'ambiguous guard function symbol {fn} in {mod_name}: {ambiguous_tables[mod_name][fn]}')
            if fn not in symbol_tables[mod_name]:
                raise ValueError(f'missing guard function symbol {fn} in {mod_name}')
            g_offset = symbol_tables[mod_name][fn]

        vm_args: list[dict[str, Any]] = []
        fields: dict[str, dict[str, Any]] = {}
        selector_names: list[str] = []
        reg_index = 0
        raw_selectors = g.get('selectors', {})
        if isinstance(raw_selectors, dict):
            items = list(raw_selectors.items())
        else:
            items = [(s['name'], s) for s in raw_selectors]
        # Caller-local selectors bind VM registers, not VM arguments.
        if len([item for item in items if 'local' not in item[1]]) > 6:
            raise ValueError(f'guard {g["id"]} exceeds 6 VM argument selectors')

        for idx, (sname, sdef) in enumerate(items):
            resolved_sel = _resolve_selector_spec(sdef, symbol_tables, mod_name, dwarf, layout_overrides)
            if 'local' in resolved_sel:
                if resolved_sel.get('reads'):
                    raise ValueError(f'guard {g["id"]} local selector cannot carry reads')
                fields[sname] = {'source': 'reg', 'index': reg_index}
                reg_index += 1
                continue
            if 'constant' in resolved_sel and not resolved_sel.get('reads') and not g.get('force_vm_arg_constant'):
                fields[sname] = {'constant': int(resolved_sel['constant'])}
            else:
                arg_idx = len(vm_args)
                vm_args.append(resolved_sel)
                fields[sname] = {'source': 'arg', 'index': arg_idx}
                selector_names.append(sname)

        obs_refs: list[dict[str, Any]] = []
        slot_cursor = 0
        parameter_names = list(g.get('parameter_names') or [])
        for mread in g.get('map_reads', []):
            map_def = patch_spec.get('maps', {}).get(mread['map'], {})
            bound_fields, ref_entry, slot_cursor = bind_structured_map_read(
                mread['map'], map_def, mread, slot_cursor,
            )
            fields.update(bound_fields)
            if 'on_missing' in mread:
                ref_entry['on_missing'] = mread['on_missing']
            key_fields, _value_fields = map_word_layout(mread['map'], map_def)
            if 'key' in mread:
                ref_entry['key'] = _resolve_selector_spec(mread['key'], symbol_tables, mod_name, dwarf, layout_overrides)
            elif 'key_expr' in mread:
                components = resolve_key_components(str(mread['key_expr']), parameter_names)
                if len(components) != len(key_fields):
                    raise ValueError(f'map read {mread["map"]} key width does not match key_type')
                ref_entry['key_components'] = components
                ref_entry['key_words'] = len(components)
                if len(components) == 1 and 'arg' in components[0]:
                    ref_entry['key_arg'] = components[0]['arg']
            else:
                ref_entry['key_arg'] = int(mread['key_arg'])
                if len(key_fields) != 1:
                    raise ValueError(f'map read {mread["map"]} needs one key component per key_type word')
            obs_refs.append(ref_entry)

        for cname, cval in g.get('constants', {}).items():
            if isinstance(cval, str) and cval.startswith('bit_mask:'):
                bkey = 'bit.' + cval.split(':', 1)[1]
                cval = int(layout_overrides[bkey]['mask'])
            elif isinstance(cval, str) and cval.startswith('bit_unit:'):
                bkey = 'bit.' + cval.split(':', 1)[1]
                m = int(layout_overrides[bkey]['mask'])
                cval = m & -m
            fields[cname] = {'constant': int(cval)}

        policy_source = g.get('policy_dsl') or g.get('expression') or 'True'
        resolved_selector_map = dict(items)
        for bk, bv in layout_overrides.items():
            if bk.startswith('bit.') and isinstance(bv, dict):
                short = bk[4:]
                mask_val = int(bv['mask'])
                unit_val = mask_val & -mask_val
                policy_source = policy_source.replace(f'__BIT_MASK_{short}__', str(mask_val))
                policy_source = policy_source.replace(f'__BIT_UNIT_{short}__', str(unit_val))
                for sel_k, sel_v in resolved_selector_map.items():
                    if 'c_param_expr' in sel_v and isinstance(sel_v['c_param_expr'], str):
                        sel_v = dict(sel_v)
                        sel_v['c_param_expr'] = (
                            sel_v['c_param_expr']
                            .replace(f'__BIT_MASK_{short}__', str(mask_val))
                            .replace(f'__BIT_UNIT_{short}__', str(unit_val))
                        )
                        resolved_selector_map[sel_k] = sel_v

        if 'bytecode_file' in g:
            bytecode = Path(g['bytecode_file']).read_bytes()
        else:
            bytecode = compile_guard(policy_source, fields)

        rule_filename = f'guard-{g_idx}-{g["id"]}.bin'
        rule_path = deploy_dir / rule_filename
        rule_path.write_bytes(bytecode)

        action_id = g['action_id']
        if action_id not in catalog_source:
            raise ValueError(f'action_id {action_id} missing from trusted catalog')
        raw_action = json.loads(json.dumps(catalog_source[action_id]))
        resolved_writes = []
        for wr in raw_action.get('writes', []):
            wcopy = dict(wr)
            if 'struct_member' in wcopy:
                st_name, mem_name = wcopy.pop('struct_member')
                wcopy['field'] = str(mem_name)
                key_ov = f'{st_name}.{mem_name}'
                if key_ov in layout_overrides:
                    wcopy['offset'] = int(layout_overrides[key_ov])
                else:
                    info = dwarf.field_info(st_name, mem_name)
                    wcopy['offset'] = info['offset']
                    wcopy.setdefault('type', info['type'])
            if 'symbol_name' in wcopy:
                sym_mod = wcopy.pop('symbol_module', mod_name)
                sym_nm = wcopy.pop('symbol_name')
                if sym_nm not in symbol_tables[sym_mod]:
                    raise ValueError(f'catalog write symbol {sym_nm} missing in {sym_mod}')
                wcopy['symbol'] = {'module': sym_mod, 'offset': symbol_tables[sym_mod][sym_nm]}
                wcopy['symbol_c_name'] = sym_nm
            resolved_writes.append(wcopy)
        if resolved_writes:
            raw_action['writes'] = resolved_writes
        actions_catalog[action_id] = {k: v for k, v in raw_action.items() if k != 'c_writes'}

        guard_manifest_entry: dict[str, Any] = {
            'id': g['id'],
            'module': mod_name,
            'offset': g_offset,
            'arg_types': list(g['arg_types']),
            'return_type': g['return_type'],
            'rule': rule_filename,
            'action_id': action_id,
            'step_limit': int(g.get('step_limit', 4096)),
        }
        if vm_args:
            guard_manifest_entry['vm_args'] = vm_args
        elif g['arg_types']:
            guard_manifest_entry['vm_args'] = [{'constant': 0}]
        if obs_refs:
            guard_manifest_entry['observations'] = obs_refs
        if 'return_from_observer' in g:
            bound = callsite_bindings[g['return_from_observer']]
            guard_manifest_entry['return_offsets'] = [bound['return_offset']]
        elif 'return_offsets' in g:
            guard_manifest_entry['return_offsets'] = [int(x) for x in g['return_offsets']]

        guards_manifest.append(guard_manifest_entry)
        guard_ir = {
            'id': g['id'],
            'function': fn,
            'source_file': g.get('source_file'),
            'module': mod_name,
            'offset': g_offset,
            'arg_types': list(g['arg_types']),
            'return_type': g['return_type'],
            'parameter_names': list(g.get('parameter_names', [])),
            'selectors': resolved_selector_map,
            'resolved_vm_args': vm_args,
            'fields': fields,
            'map_reads': obs_refs,
            'policy_source': policy_source,
            'extracted_predicates': extract_dsl_predicates(policy_source),
            'rule_path': str(rule_path),
            'bytecode_sha256': hashlib.sha256(bytecode).hexdigest(),
            'bytecode_instructions': len(bytecode) // 8,
            'action_id': action_id,
            'resolved_action': raw_action,
            'step_limit': int(g.get('step_limit', 4096)),
        }
        if g.get('caller'):
            guard_ir['caller'] = g['caller']
        if g.get('dsl_ast'):
            guard_ir['dsl_ast'] = json.loads(json.dumps(g['dsl_ast']))
        if g.get('dsl_loops'):
            guard_ir['dsl_loops'] = json.loads(json.dumps(g['dsl_loops']))
        if dsl_patch:
            guard_ir.update({
                'rule_source': 'dsl',
                'dsl_patch': dsl_patch.get('path'),
                'dsl_patch_sha256': dsl_patch.get('sha256'),
            })
        compiled_guards_ir.append(guard_ir)

    if dsl_patch and dsl_patch.get('path') and Path(dsl_patch['path']).is_file():
        from runtime.dsl import parser as _dsl_parser
        from runtime.dsl import vm as _dsl_vm
        vg_spec = _dsl_parser.load(Path(dsl_patch['path']))
        dsl_globals: dict[str, int] = {}
        synth_cursor = 0
        for mount in vg_spec.mounts:
            m_mod = mount.module if mount.module in symbol_tables else exe_path.name
            for gname in re.findall(r'global\("([^"]+)"\)', mount.body):
                if gname in dsl_globals:
                    continue
                found_off = symbol_tables.get(m_mod, {}).get(gname)
                if found_off is None:
                    for tbl in symbol_tables.values():
                        if gname in tbl:
                            found_off = tbl[gname]
                            break
                if found_off is not None:
                    dsl_globals[gname] = 0x40000000 + int(found_off)
                else:
                    synth_cursor += 1
                    dsl_globals[gname] = 0x50000000 + synth_cursor * 0x10000
            local_order: list[str] = []
            for lname in re.findall(r'local\("([^"]+)"\)', mount.body):
                if lname not in local_order:
                    local_order.append(lname)
            for l_slot, lname in enumerate(local_order):
                mount.local_recipes.setdefault(lname, {'kind': 'register', 'reg': f'r{l_slot}'})
        compiled_vg = _dsl_vm.compile_patch(vg_spec, dsl_globals)
        obs_cursor = 0
        guard_cursor = 0
        for m_idx, vm_mount in enumerate(compiled_vg.mounts):
            safe_mid = re.sub(r'[^A-Za-z0-9_.-]', '_', vm_mount.id.rsplit('/', 1)[-1])
            dsl_bin = deploy_dir / f'dsl-vm-{m_idx}-{safe_mid}.bin'
            dsl_bin.write_bytes(vm_mount.code)
            meta = {
                'dsl_vm_rule_path': str(dsl_bin),
                'dsl_vm_bytecode_sha256': hashlib.sha256(vm_mount.code).hexdigest(),
                'dsl_vm_bytecode_instructions': len(vm_mount.code) // 8,
                'dsl_vm_globals': dict(compiled_vg.globals_),
                'dsl_vm_maps': list(compiled_vg.maps),
                'dsl_vm_locals': list(vm_mount.locals),
                'dsl_mount_id': vm_mount.id,
            }
            if vm_mount.nature == 'read_point':
                if obs_cursor < len(observers_manifest):
                    observers_manifest[obs_cursor].update(meta)
                obs_cursor += 1
            else:
                if guard_cursor < len(compiled_guards_ir):
                    compiled_guards_ir[guard_cursor].update(meta)
                guard_cursor += 1

    source_root = ((app_profile.get('builds') or {}).get('baseline') or {}).get('source_dir')
    action_catalog_extraction = attest_catalog(
        actions_catalog,
        catalog_source,
        source_root,
        patch_spec.get('guards') or [],
    )
    install_extracted_actions(actions_catalog, action_catalog_extraction, dwarf.field_info)

    bridge_path = Path(app_profile.get('bridge', ROOT / 'build/frida-linux/vulgate_frida.so')).resolve()
    frida_manifest = {
        'schema': 1,
        'bridge': str(bridge_path),
        'telemetry': True,
        'maps': maps_manifest,
        'observers': observers_manifest,
        'guards': guards_manifest,
        'artifact_pins': artifact_pins,
    }
    catalog_manifest = {
        'schema': 1,
        'actions': actions_catalog,
    }
    patch_json_path = deploy_dir / 'patch.json'
    actions_json_path = deploy_dir / 'actions.json'
    patch_json_path.write_text(json.dumps(frida_manifest, indent=2) + '\n', encoding='utf-8')
    actions_json_path.write_text(json.dumps(catalog_manifest, indent=2) + '\n', encoding='utf-8')

    case_ir = {
        'schema': 'vulgate.case_ir/v2',
        'case_id': vuln_spec['case_id'],
        'application_name': app_profile['name'],
        'identities': {
            'vuln_spec_sha256': sha256_json(vuln_spec),
            'patch_spec_sha256': sha256_json(patch_spec),
            'app_profile_sha256': sha256_json(app_profile),
            'patch_manifest_sha256': sha256_file(patch_json_path),
            'actions_catalog_sha256': sha256_file(actions_json_path),
            'artifact_pins': artifact_pins,
            'gnu_build_ids': build_ids,
        },
        'deployment': {
            'patch_manifest': str(patch_json_path),
            'actions_catalog': str(actions_json_path),
            'bridge': str(bridge_path),
            'quiescent_phase': deployment_quiescent_phase(patch_spec, app_profile),
            'patch_source': 'dsl' if dsl_patch else 'yaml',
        },
        'maps': patch_spec.get('maps', {}),
        'observers': observers_manifest,
        'observer_specs': patch_spec.get('observers', []),
        'guards': compiled_guards_ir,
        'defect_anchors': vuln_spec['defect_anchors'],
        'safety_oracle': vuln_spec['safety_oracle'],
        'environment_fixture': vuln_spec.get('environment_fixture', {}),
        'seed_traces': vuln_spec.get('seed_traces', {}),
        'symbolization_scope': vuln_spec.get('symbolization_scope', {}),
        'budgets': {
            'loop_unwind': int(vuln_spec.get('budgets', {}).get('loop_unwind', 32)),
            'max_symbolic_bytes': int(vuln_spec.get('budgets', {}).get('max_symbolic_bytes', 128)),
            'max_impact_regions': int(vuln_spec.get('budgets', {}).get('max_impact_regions', 8)),
            'solver_timeout_sec': int(vuln_spec.get('budgets', {}).get('solver_timeout_sec', 120)),
            'episode_length': int(vuln_spec.get('budgets', {}).get('episode_length', 1)),
        },
        'app_profile': app_profile,
        'action_catalog_extraction': action_catalog_extraction,
    }
    if dsl_patch:
        case_ir['identities']['dsl_patch_sha256'] = dsl_patch.get('sha256')
        case_ir['deployment']['dsl_patch'] = dsl_patch.get('path')
        if patch_spec.get('install_hook_count') is not None:
            case_ir['deployment']['install_hook_count'] = int(patch_spec['install_hook_count'])
    sym_scope = dict(vuln_spec.get('symbolization_scope', {}))
    if 'field_to_input_map' in sym_scope and isinstance(sym_scope['field_to_input_map'], dict):
        fmap = dict(sym_scope['field_to_input_map'])
        for bk, bv in layout_overrides.items():
            if bk.startswith('bit.') and isinstance(bv, dict):
                short = bk[4:]
                mask_val = int(bv['mask'])
                unit_val = mask_val & -mask_val
                for fk, fv in list(fmap.items()):
                    if isinstance(fv, str):
                        fmap[fk] = fv.replace(f'__BIT_MASK_{short}__', str(mask_val)).replace(f'__BIT_UNIT_{short}__', str(unit_val))
        sym_scope['field_to_input_map'] = fmap
    case_ir['symbolization_scope'] = sym_scope
    plan_path = output_dir / 'case-ir.json'
    plan_path.write_text(json.dumps(case_ir, indent=2) + '\n', encoding='utf-8')
    return case_ir


def evaluate_snapshot_in_guard_space(guard_ir: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, int]:
    args = [int(x) for x in snapshot.get('args', [])]
    slots = [int(x) for x in snapshot.get('slots', [])]
    values: dict[str, int] = {}
    for fname, binding in guard_ir['fields'].items():
        if 'constant' in binding:
            values[fname] = int(binding['constant'])
        elif binding['source'] == 'arg' and binding['index'] < len(args):
            values[fname] = args[binding['index']]
        elif binding['source'] == 'slot' and binding['index'] < len(slots):
            values[fname] = slots[binding['index']]
    return values


def predicate_distance(pred_text: str, values: dict[str, int]) -> dict[str, Any] | None:
    import ast as _ast
    from .expressions import evaluate as _eval_expr

    try:
        node = parse(pred_text, set(values))
        if not isinstance(node, _ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
            return None
        lhs = int(_eval_expr(node.left, values))
        rhs = int(_eval_expr(node.comparators[0], values))
        truth = bool(_eval_expr(node, values))
    except (ValueError, KeyError, TypeError):
        return None
    gap = abs(lhs - rhs)
    return {
        'predicate': pred_text,
        'truth': truth,
        'lhs': lhs,
        'rhs': rhs,
        'abs_distance': gap,
        'normalized_distance': gap / (1.0 + max(abs(lhs), abs(rhs))),
    }


def snapshot_predicate_distances(guard_ir: dict[str, Any], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    import ast as _ast
    from .expressions import evaluate as _eval_expr

    values = evaluate_snapshot_in_guard_space(guard_ir, snapshot)
    distances: list[dict[str, Any]] = []
    for pred_text in guard_ir.get('extracted_predicates', []):
        try:
            node = parse(pred_text, guard_ir['fields'])
            if not isinstance(node, _ast.Compare):
                continue
            lhs = int(_eval_expr(node.left, values))
            rhs = int(_eval_expr(node.comparators[0], values))
            truth = bool(_eval_expr(node, values))
            gap = abs(lhs - rhs)
            norm = gap / (1.0 + max(abs(lhs), abs(rhs)))
            distances.append({
                'predicate': pred_text,
                'truth': truth,
                'lhs': lhs,
                'rhs': rhs,
                'abs_distance': gap,
                'normalized_distance': norm,
            })
        except (ValueError, KeyError):
            continue
    return distances


_REGION_WORDS = frozenset({'and', 'or', 'not', 'True', 'False'})


def _normalized_gap(gap: int, left: int, right: int) -> float:
    return abs(int(gap)) / (1.0 + max(abs(int(left)), abs(int(right))))


def distance_to_false(node: ast.AST, values: dict[str, int]) -> float | None:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return distance_to_true(node.operand, values)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        parts = [distance_to_false(item, values) for item in node.values]
        known = [part for part in parts if part is not None]
        return min(known) if known else None
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        parts = [distance_to_false(item, values) for item in node.values]
        if not parts or all(part is None for part in parts):
            return None
        return sum(1.0 if part is None else part for part in parts)
    if isinstance(node, ast.Compare):
        inverted = {
            ast.Eq: ast.NotEq(),
            ast.NotEq: ast.Eq(),
            ast.Lt: ast.GtE(),
            ast.LtE: ast.Gt(),
            ast.Gt: ast.LtE(),
            ast.GtE: ast.Lt(),
        }.get(type(node.ops[0]))
        if inverted is None:
            return None
        return distance_to_true(ast.Compare(left=node.left, ops=[inverted], comparators=list(node.comparators)), values)
    if isinstance(node, ast.Name):
        if node.id not in values:
            return None
        return 0.0 if not int(values[node.id]) else 1.0
    if isinstance(node, ast.Constant):
        return 0.0 if not node.value else 1.0
    return None


def distance_to_true(node: ast.AST, values: dict[str, int]) -> float | None:
    if isinstance(node, ast.Name):
        if node.id not in values:
            return None
        return 0.0 if int(values[node.id]) else 1.0
    if isinstance(node, ast.Constant):
        return 0.0 if node.value else 1.0
    if isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, ast.Not):
            return None
        return distance_to_false(node.operand, values)
    if isinstance(node, ast.BoolOp):
        parts = [distance_to_true(item, values) for item in node.values]
        if not parts or all(part is None for part in parts):
            return None
        if isinstance(node.op, ast.And):
            return sum(1.0 if part is None else part for part in parts)
        known = [part for part in parts if part is not None]
        return min(known) if known else None
    if not isinstance(node, ast.Compare):
        return None
    try:
        left = int(evaluate(node.left, values))
        right = int(evaluate(node.comparators[0], values))
    except (KeyError, TypeError, ValueError):
        return None
    op = node.ops[0]
    if isinstance(op, ast.Eq):
        return 0.0 if left == right else _normalized_gap(abs(left - right), left, right)
    if isinstance(op, ast.NotEq):
        return 0.0 if left != right else _normalized_gap(1, left, right)
    if isinstance(op, ast.Lt):
        return 0.0 if left < right else _normalized_gap(left - right + 1, left, right)
    if isinstance(op, ast.LtE):
        return 0.0 if left <= right else _normalized_gap(left - right, left, right)
    if isinstance(op, ast.Gt):
        return 0.0 if left > right else _normalized_gap(right - left + 1, left, right)
    if isinstance(op, ast.GtE):
        return 0.0 if left >= right else _normalized_gap(right - left, left, right)
    return None


def snapshot_guard_from_bindings(guard: dict[str, Any], symbolic: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(symbolic.get('vm_arg_names') or []):
        fields[str(name)] = {'source': 'arg', 'index': index}
    slot_names = {str(key): str(value) for key, value in (symbolic.get('slot_names') or {}).items()}
    for ref in guard.get('observations') or []:
        if 'slot' in ref:
            name = ref.get('into') or slot_names.get(str(ref.get('slot')))
            if name:
                fields[str(name)] = {'source': 'slot', 'index': int(ref['slot'])}
        if 'present_slot' in ref and ref.get('present_into'):
            fields[str(ref['present_into'])] = {'source': 'slot', 'index': int(ref['present_slot'])}
    return {
        'id': guard.get('id', ''),
        'fields': fields,
        'parameter_names': list(symbolic.get('hook_parameters') or []),
        'extracted_predicates': list(symbolic.get('extracted_predicates') or []),
    }


def project_snapshot_to_symbols(guard_ir: dict[str, Any],
                                snapshot: dict[str, Any],
                                symbolic_names: set[str],
                                field_formulas: dict[str, str] | None = None) -> dict[str, int]:
    fields = evaluate_snapshot_in_guard_space(guard_ir, snapshot)
    values = dict(fields)
    args = [int(item) for item in snapshot.get('args', [])]
    for index, pname in enumerate(guard_ir.get('parameter_names') or []):
        if index < len(args):
            values.setdefault(pname, args[index])
    for name in symbolic_names:
        if name in fields:
            values[name] = fields[name]
    for sym, formula in (field_formulas or {}).items():
        if not isinstance(formula, str):
            continue
        try:
            values[str(sym)] = int(evaluate(parse(formula, set(values)), values))
        except (KeyError, TypeError, ValueError):
            continue
    return values


def region_branch_distances(regions: list[dict[str, Any]],
                            values: dict[str, int]) -> tuple[list[int], dict[int, float]]:
    hits: list[int] = []
    distances: dict[int, float] = {}
    known = set(values)
    for index, region in enumerate(regions or []):
        if region.get('classification') == 'UNREACHABLE':
            continue
        text = str(region.get('region') or 'True')
        mentioned = set(re.findall(r'\b[A-Za-z_]\w*\b', text)) - _REGION_WORDS
        try:
            node = parse(text, known | mentioned)
            dist = distance_to_true(node, values)
        except (SyntaxError, ValueError):
            dist = None
        if dist == 0.0:
            hits.append(index)
        else:
            distances[index] = 1.0 if dist is None else float(dist)
    return hits, distances
