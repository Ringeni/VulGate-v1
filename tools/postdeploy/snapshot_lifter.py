from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import dataclass, field
import inspect
import json
from pathlib import Path
import re
import subprocess
from typing import Any


GDB_SNAPSHOT_SCRIPT = r'''
import gdb
import json
import os

cfg_path = os.environ["VG_GDB_CFG"]
with open(cfg_path, "r", encoding="utf-8") as fp:
    cfg = json.load(fp)

cut_fn = cfg["cut_function"]
max_depth = int(cfg.get("max_depth", 3))
max_bytes = int(cfg.get("max_object_bytes", 4096))
selector = cfg.get("invocation_selector", "last_before_fault")
invocation_count = 0
capture_phase = {"finished": False}
out_path = cfg["output_path"]

snapshots = []
call_stacks = []
call_edges = set()

def strip_typedefs(t):
    try:
        return t.strip_typedefs()
    except Exception:
        return t

def resolve_symbol_at_addr(addr):
    try:
        info = gdb.execute(f"info symbol {addr}", to_string=True).strip()
        if " in section " in info and not info.startswith("No symbol"):
            head = info.split(" in section ", 1)[0].strip()
            if "+" not in head:
                return head
    except Exception:
        pass
    return None

def dump_value_graph(frame):
    objects = {}
    addr_to_id = {}
    ptr_relations = []
    root_values = {}

    def record_code_words(addr):
        ptr_size = 8
        try:
            ptr_size = int(gdb.lookup_type("void").pointer().sizeof)
        except Exception:
            ptr_size = 8
        ptr_size = 8 if ptr_size <= 0 else ptr_size
        max_words = max(1, min(max_bytes // ptr_size, 512))
        try:
            mem = bytes(gdb.selected_inferior().read_memory(addr, max_words * ptr_size))
        except Exception:
            return None
        words = []
        for index in range(max_words):
            chunk = mem[index * ptr_size:(index + 1) * ptr_size]
            if len(chunk) < ptr_size:
                break
            words.append(int.from_bytes(chunk, "little"))
        kept = select_code_words(words, [resolve_symbol_at_addr(word) for word in words])
        if not kept:
            return None
        bsize = len(kept) * ptr_size
        oid = f"obj_{len(objects)}"
        fields = {}
        named_len = False
        for index, word in enumerate(kept):
            symbol = resolve_symbol_at_addr(word)
            if symbol:
                fields["w%d" % index] = {
                    "offset": index * ptr_size,
                    "kind": "pointer",
                    "target_c_type": "void",
                    "ref": {"kind": "function_ptr", "symbol": symbol},
                }
            elif word == 0:
                fields["w%d" % index] = {
                    "offset": index * ptr_size,
                    "kind": "scalar",
                    "c_type": "uintptr_t",
                    "bit_size": ptr_size * 8,
                    "value": 0,
                }
            else:
                fname = "len" if not named_len else ("w%d" % index)
                named_len = True
                fields[fname] = {
                    "offset": index * ptr_size,
                    "kind": "scalar",
                    "c_type": "uintptr_t",
                    "bit_size": ptr_size * 8,
                    "value": word,
                }
        objects[oid] = {
            "id": oid,
            "raw_addr": addr,
            "c_type": "uintptr_t",
            "type_code": int(gdb.TYPE_CODE_INT),
            "byte_size": bsize,
            "hex_bytes": mem[:bsize].hex(),
            "fields": fields,
            "code_words": True,
        }
        addr_to_id[addr] = oid
        return {"kind": "object_ref", "object_id": oid, "offset": 0}

    def placeholder_for(raw_addr):
        existing = addr_to_id.get(raw_addr)
        if existing:
            return {"kind": "object_ref", "object_id": existing, "offset": 0}
        pid = "obj_%d" % len(objects)
        objects[pid] = {
            "id": pid,
            "raw_addr": raw_addr,
            "c_type": "void",
            "type_code": int(gdb.TYPE_CODE_VOID),
            "byte_size": 8,
            "hex_bytes": "00" * 8,
            "fields": {},
            "unresolved_target": True,
        }
        addr_to_id[raw_addr] = pid
        return {"kind": "object_ref", "object_id": pid, "offset": 0}

    def record_pointer_words(addr, depth):
        ptr_size = 8
        try:
            ptr_size = int(gdb.lookup_type("void").pointer().sizeof)
        except Exception:
            ptr_size = 8
        ptr_size = 8 if ptr_size <= 0 else ptr_size
        max_words = max(1, min(max_bytes // ptr_size, 64))
        mem = None
        for count in (max_words, 8, 4, 2, 1):
            if count > max_words:
                continue
            try:
                mem = bytes(gdb.selected_inferior().read_memory(addr, count * ptr_size))
                break
            except Exception:
                continue
        if mem is None or len(mem) < ptr_size:
            return None
        limit = len(mem) // ptr_size
        words = [int.from_bytes(mem[index * ptr_size:(index + 1) * ptr_size], "little") for index in range(limit)]
        rows = classify_untyped_words(words, [resolve_symbol_at_addr(word) for word in words])
        if not rows:
            return None
        bsize = len(rows) * ptr_size
        oid = "obj_%d" % len(objects)
        obj_entry = {
            "id": oid,
            "raw_addr": addr,
            "c_type": "void",
            "type_code": int(gdb.TYPE_CODE_VOID),
            "byte_size": bsize,
            "hex_bytes": mem[:bsize].hex(),
            "fields": {},
            "pointer_words": True,
        }
        objects[oid] = obj_entry
        addr_to_id[addr] = oid
        followed = 0
        for index, row in enumerate(rows):
            kind, value, symbol = row
            offset = index * ptr_size
            if kind == "function":
                obj_entry["fields"]["w%d" % index] = {
                    "offset": offset,
                    "kind": "pointer",
                    "target_c_type": "void",
                    "ref": {"kind": "function_ptr", "symbol": symbol},
                }
                continue
            if kind == "scalar":
                obj_entry["fields"]["w%d" % index] = {
                    "offset": offset,
                    "kind": "scalar",
                    "c_type": "uintptr_t",
                    "bit_size": ptr_size * 8,
                    "value": int(value),
                }
                continue
            sub = {"kind": "unresolved_ptr"}
            if depth + 1 < max_depth and followed < 4 and len(objects) < 48:
                followed += 1
                try:
                    target_ptr = gdb.Value(int(value)).cast(gdb.lookup_type("void").pointer())
                    sub = record_object(target_ptr, gdb.lookup_type("void"), depth + 1)
                except Exception:
                    sub = {"kind": "unresolved_ptr"}
            if sub.get("kind") in ("unresolved_ptr", "unreadable_ptr"):
                sub = placeholder_for(int(value))
            obj_entry["fields"]["w%d" % index] = {
                "offset": offset,
                "kind": "pointer",
                "target_c_type": "void",
                "ref": sub,
            }
        return {"kind": "object_ref", "object_id": oid, "offset": 0}

    def record_byte_buffer(addr):
        limit = max(1, min(64, max_bytes))
        mem = None
        for size in (limit, 32, 16, 8, 4, 2):
            if size > limit:
                continue
            try:
                mem = bytes(gdb.selected_inferior().read_memory(addr, size))
                break
            except Exception:
                continue
        if mem is None or len(mem) <= 1:
            return None
        ptr_size = 8
        try:
            ptr_size = int(gdb.lookup_type("void").pointer().sizeof)
        except Exception:
            ptr_size = 8
        ptr_size = 8 if ptr_size <= 0 else ptr_size
        for index in range(0, len(mem) - ptr_size + 1, ptr_size):
            word = int.from_bytes(mem[index:index + ptr_size], "little")
            if word > 0x10000:
                return None
        oid = f"obj_{len(objects)}"
        objects[oid] = {
            "id": oid,
            "raw_addr": addr,
            "c_type": "unsigned char",
            "type_code": int(gdb.TYPE_CODE_INT),
            "byte_size": len(mem),
            "hex_bytes": mem.hex(),
            "fields": {},
            "byte_buffer": True,
        }
        addr_to_id[addr] = oid
        return {"kind": "object_ref", "object_id": oid, "offset": 0}

    def record_object(ptr_val, target_type, depth, byte_override=None):
        addr = int(ptr_val) & ((1 << 64) - 1)
        if addr == 0:
            ref = {"kind": "null"}
            st0 = strip_typedefs(target_type)
            if st0.code != gdb.TYPE_CODE_VOID:
                try:
                    size = int(st0.sizeof)
                except Exception:
                    size = 0
                if size > 0:
                    ref["target_byte_size"] = min(int(size), 4096)
            return ref
        fn_sym = resolve_symbol_at_addr(addr)
        st = strip_typedefs(target_type)
        data_codes = (
            gdb.TYPE_CODE_STRUCT,
            gdb.TYPE_CODE_UNION,
            gdb.TYPE_CODE_ARRAY,
            gdb.TYPE_CODE_INT,
            gdb.TYPE_CODE_ENUM,
            gdb.TYPE_CODE_BOOL,
        )
        for extra_code in ("TYPE_CODE_FLT", "TYPE_CODE_CHAR"):
            if hasattr(gdb, extra_code):
                data_codes = data_codes + (getattr(gdb, extra_code),)
        if address_names_a_function(st.code, fn_sym, gdb.TYPE_CODE_FUNC, data_codes):
            return {"kind": "function_ptr", "symbol": fn_sym or hex(addr)}
        for oid, oinfo in objects.items():
            base = oinfo["raw_addr"]
            size = oinfo["byte_size"]
            if base <= addr < base + max(1, size):
                return {"kind": "object_ref", "object_id": oid, "offset": addr - base}
        if st.code == gdb.TYPE_CODE_VOID:
            coded = record_code_words(addr)
            if coded is not None:
                return coded
            pointed = record_pointer_words(addr, depth)
            if pointed is not None:
                return pointed
            buffered = record_byte_buffer(addr)
            if buffered is not None:
                return buffered
            return {"kind": "unresolved_ptr"}
        oid = f"obj_{len(objects)}"
        candidates = []
        if byte_override:
            candidates.append(max(1, min(int(byte_override), max_bytes)))
        try:
            candidates.append(max(1, min(int(st.sizeof), max_bytes)))
        except Exception:
            candidates.append(64)
        inferior = gdb.selected_inferior()
        mem = None
        bsize = candidates[-1]
        for candidate in candidates:
            try:
                mem = bytes(inferior.read_memory(addr, candidate))
                bsize = candidate
                break
            except Exception:
                continue
        if mem is None:
            return {"kind": "unreadable_ptr"}
        type_str = str(target_type)
        obj_entry = {
            "id": oid,
            "raw_addr": addr,
            "c_type": type_str,
            "type_code": int(st.code),
            "byte_size": bsize,
            "hex_bytes": mem.hex(),
            "fields": {},
        }
        objects[oid] = obj_entry
        addr_to_id[addr] = oid
        if depth < max_depth and st.code == gdb.TYPE_CODE_STRUCT:
            deref = ptr_val.dereference()
            def store_struct_fields(struct_type, struct_val, base_offset, name_prefix):
                for fld in struct_type.fields():
                    fname = fld.name
                    if not fname:
                        continue
                    try:
                        fval = struct_val[fname]
                        fst = strip_typedefs(fld.type)
                        bitpos = base_offset + getattr(fld, "bitpos", 0) // 8
                        field_key = fname if not name_prefix else name_prefix + "." + fname
                        if fst.code == gdb.TYPE_CODE_PTR:
                            leaf_override = None
                            tst = strip_typedefs(fst.target())
                            try:
                                one_byte = tst.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_CHAR) and int(tst.sizeof) == 1
                            except Exception:
                                one_byte = False
                            if one_byte:
                                for sib_name in ("len", "length", "size"):
                                    try:
                                        leaf_override = int(struct_val[sib_name])
                                        break
                                    except Exception:
                                        continue
                                if leaf_override is not None:
                                    leaf_override = 1 if leaf_override <= 0 else min(int(leaf_override), 64, max_bytes)
                                elif fname.endswith("_start"):
                                    try:
                                        span = int(struct_val[fname[:-6] + "_end"]) - int(fval)
                                        if span > 0:
                                            leaf_override = min(int(span), 64, max_bytes)
                                    except Exception:
                                        pass
                            sub_ref = record_pointer_array(fval, fst, depth + 1, fname)
                            if sub_ref is None:
                                sub_ref = record_object(fval, fst.target(), depth + 1, leaf_override)
                            obj_entry["fields"][field_key] = {
                                "offset": bitpos,
                                "kind": "pointer",
                                "target_c_type": str(fst.target()),
                                "ref": sub_ref,
                            }
                        elif fst.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_ENUM, gdb.TYPE_CODE_BOOL):
                            obj_entry["fields"][field_key] = {
                                "offset": bitpos,
                                "kind": "scalar",
                                "c_type": str(fld.type),
                                "bit_size": getattr(fld, "bitsize", 0) or (int(fst.sizeof) * 8),
                                "value": int(fval),
                            }
                        elif fst.code == gdb.TYPE_CODE_STRUCT:
                            store_struct_fields(fst, fval, bitpos, field_key)
                    except Exception:
                        continue
            store_struct_fields(st, deref, 0, "")
        return {"kind": "object_ref", "object_id": oid, "offset": 0}

    def pointer_array_rule(fname):
        for item in cfg.get("pointer_arrays") or []:
            if item.get("field") == fname:
                return item
        return None

    def record_pointer_array(ptr_val, field_type, depth, fname):
        rule = pointer_array_rule(fname)
        if not rule:
            return None
        addr = int(ptr_val) & ((1 << 64) - 1)
        if addr == 0:
            ref = {"kind": "null"}
            try:
                size = int(strip_typedefs(field_type.target()).sizeof)
            except Exception:
                size = 0
            if size > 0:
                ref["target_byte_size"] = min(int(size), 4096)
            return ref
        cell = strip_typedefs(field_type.target())
        try:
            cell_size = max(1, int(cell.sizeof))
        except Exception:
            cell_size = 8
        count = 1
        if rule.get("count_symbol"):
            try:
                count = int(gdb.parse_and_eval(str(rule["count_symbol"])))
            except Exception:
                count = 1
        count = max(1, min(int(count), int(rule.get("max_count", 64))))
        if count * cell_size > max_bytes:
            count = max(1, max_bytes // cell_size)
        total = count * cell_size
        inferior = gdb.selected_inferior()
        try:
            mem = bytes(inferior.read_memory(addr, total))
        except Exception:
            return None
        oid = f"obj_{len(objects)}"
        obj_entry = {
            "id": oid,
            "raw_addr": addr,
            "c_type": str(field_type.target()),
            "type_code": int(cell.code),
            "byte_size": total,
            "hex_bytes": mem.hex(),
            "fields": {},
        }
        objects[oid] = obj_entry
        addr_to_id[addr] = oid
        slot_type_name = rule.get("slot_type")
        index_expr = rule.get("slot_index_symbol")
        if slot_type_name and index_expr and depth < max_depth:
            try:
                slot_index = int(gdb.parse_and_eval(str(index_expr)))
            except Exception:
                slot_index = -1
            if 0 <= slot_index < count:
                try:
                    cell_ptr = gdb.Value(addr + (slot_index * cell_size)).cast(cell.pointer())
                    slot_addr = int(cell_ptr.dereference()) & ((1 << 64) - 1)
                    if slot_addr:
                        slot_type = gdb.lookup_type(str(slot_type_name))
                        slot_ptr = gdb.Value(slot_addr).cast(slot_type.pointer())
                        slot_ref = record_object(slot_ptr, slot_type, depth + 1)
                        obj_entry["fields"]["typed_slot"] = {
                            "offset": slot_index * cell_size,
                            "kind": "pointer",
                            "target_c_type": str(slot_type),
                            "ref": slot_ref,
                        }
                except Exception:
                    pass
        return {"kind": "object_ref", "object_id": oid, "offset": 0}

    parameter_names = []
    block = frame.block()
    while block and not block.function:
        block = block.superblock
    if block:
        for sym in block:
            if not sym.is_argument:
                continue
            parameter_names.append(sym.name)
            val = frame.read_var(sym)
            st = strip_typedefs(sym.type)
            if st.code == gdb.TYPE_CODE_PTR:
                root_values[sym.name] = {
                    "kind": "pointer",
                    "c_type": str(sym.type),
                    "target_c_type": str(st.target()),
                    "ref": record_object(val, st.target(), 0),
                }
            elif st.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_ENUM, gdb.TYPE_CODE_BOOL):
                root_values[sym.name] = {
                    "kind": "scalar",
                    "c_type": str(sym.type),
                    "value": int(val),
                }

    for gname in cfg.get("globals", []):
        try:
            gsym = gdb.lookup_global_symbol(gname)
            if gsym is None:
                continue
            gval = gsym.value(frame)
            gst = strip_typedefs(gsym.type)
            if gst.code == gdb.TYPE_CODE_PTR:
                root_values["global:" + gname] = {
                    "kind": "pointer",
                    "c_type": str(gsym.type),
                    "target_c_type": str(gst.target()),
                    "ref": record_object(gval, gst.target(), 0),
                }
            elif gst.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_ENUM, gdb.TYPE_CODE_BOOL):
                root_values["global:" + gname] = {
                    "kind": "scalar",
                    "c_type": str(gsym.type),
                    "value": int(gval),
                }
            elif gst.code == gdb.TYPE_CODE_STRUCT:
                root_values["global:" + gname] = {
                    "kind": "pointer",
                    "c_type": str(gsym.type) + " *",
                    "target_c_type": str(gsym.type),
                    "ref": record_object(gval.address, gst, 0),
                }
        except Exception:
            continue

    for oid, oinfo in objects.items():
        ptr_fields_by_target = {}
        for fname, finfo in oinfo["fields"].items():
            if finfo.get("kind") == "pointer" and finfo.get("ref", {}).get("kind") == "object_ref":
                t_oid = finfo["ref"]["object_id"]
                t_off = finfo["ref"]["offset"]
                ptr_fields_by_target.setdefault(t_oid, []).append((t_off, fname))
        for t_oid, pairs in ptr_fields_by_target.items():
            if len(pairs) >= 2:
                pairs.sort(key=lambda x: x[0])
                ptr_relations.append({
                    "owner_object": oid,
                    "target_object": t_oid,
                    "ordered_fields": [{"field": fnm, "observed_offset": off} for off, fnm in pairs],
                })
        oinfo.pop("raw_addr", None)

    return {
        "cut_function": cut_fn,
        "parameter_names": parameter_names,
        "roots": root_values,
        "objects": objects,
        "pointer_order_relations": ptr_relations,
    }

class CutBreakpoint(gdb.Breakpoint):
    def stop(self):
        frame = gdb.newest_frame()
        stack = []
        f = frame
        while f is not None:
            nm = f.name()
            if nm:
                stack.append(nm)
            f = f.older()
        stack.reverse()
        call_stacks.append(stack)
        if len(call_stacks) > 16:
            del call_stacks[:-16]
        for a, b in zip(stack, stack[1:]):
            call_edges.add((a, b))
        global invocation_count
        invocation_count += 1
        try:
            snap = dump_value_graph(frame)
            snapshots.append(snap)
            keep = 16 if selector == "all_in_episode" else 1
            if len(snapshots) > keep:
                del snapshots[:-keep]
        except Exception:
            pass
        return selector == "first"

def _send_http_requests():
    import socket
    import time
    for req in cfg.get("http_requests") or []:
        host = req.get("host", "127.0.0.1")
        port = int(req["port"])
        method = req.get("method", "GET")
        path = req.get("path") or "/"
        header_lines = "".join(
            "%s: %s\r\n" % (key, value)
            for key, value in (req.get("headers") or {}).items()
        )
        body = req.get("body") or ""
        payload = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n%s" % (method, path, host, header_lines)
        if body:
            payload += "Content-Length: %d\r\n\r\n%s" % (len(body), body)
        else:
            payload += "\r\n"
        raw = payload.encode("utf-8", errors="replace")
        deadline = time.time() + float(req.get("wait_sec", 12))
        while time.time() < deadline:
            try:
                sock = socket.create_connection((host, port), timeout=0.5)
                sock.sendall(raw)
                try:
                    sock.recv(128)
                except Exception:
                    pass
                sock.close()
                break
            except Exception:
                time.sleep(0.05)
    if selector != "first":
        def _kick():
            if capture_phase.get("finished"):
                return
            try:
                gdb.execute("interrupt")
            except Exception:
                pass
        try:
            gdb.post_event(_kick)
        except Exception:
            pass

if cfg.get("http_requests"):
    import threading
    threading.Thread(target=_send_http_requests, daemon=True).start()

for _gdb_cmd in ("set pagination off", "set confirm off", "set follow-fork-mode child"):
    try:
        gdb.execute(_gdb_cmd)
    except Exception:
        pass
CutBreakpoint(cut_fn)
if cfg.get("run_args") is not None:
    args_str = " ".join(gdb.string_to_argv(x)[0] if x else '""' for x in cfg["run_args"])
    try:
        gdb.execute("run " + " ".join(f"'{a}'" for a in cfg["run_args"]))
    except Exception:
        pass

capture_phase["finished"] = True
try:
    gdb.execute("kill")
except Exception:
    pass

chosen = None
if snapshots:
    chosen = snapshots[0] if selector == "first" else snapshots[-1]

result = {
    "captured": chosen is not None,
    "invocations": invocation_count,
    "invocation_selector": selector,
    "call_stacks": call_stacks[:16],
    "call_edges": sorted([list(e) for e in call_edges]),
    "snapshot": chosen,
}
if selector == "all_in_episode":
    result["episode_snapshots"] = snapshots
with open(out_path, "w", encoding="utf-8") as fp:
    json.dump(result, fp, indent=2)
gdb.execute("quit 0")
'''


def address_names_a_function(type_code, symbol, func_code, data_codes):
    if type_code == func_code:
        return True
    if not symbol:
        return False
    return type_code not in data_codes


def select_code_words(words, symbols):
    kept = []
    saw_fn = False
    scalar_run = 0
    leading = 0
    for word, symbol in zip(words, symbols):
        if symbol:
            saw_fn = True
            scalar_run = 0
            kept.append(int(word))
            continue
        value = int(word)
        if value > 0x10000:
            break
        if not saw_fn:
            leading += 1
            if leading > 4:
                return None
            kept.append(value)
            continue
        scalar_run += 1
        if scalar_run > 4:
            break
        kept.append(value)
    if not saw_fn:
        return None
    while kept and kept[-1] == 0:
        kept.pop()
    if not kept:
        return None
    return kept


def classify_untyped_words(words, symbols):
    rows = []
    saw_pointer = False
    for word, symbol in zip(words, symbols):
        value = int(word)
        if symbol:
            rows.append(('function', value, symbol))
            saw_pointer = True
            continue
        if value > 0x10000:
            rows.append(('pointer', value, None))
            saw_pointer = True
            continue
        rows.append(('scalar', value, None))
    if not saw_pointer:
        return None
    return rows


GDB_SNAPSHOT_SCRIPT = GDB_SNAPSHOT_SCRIPT.replace(
    'def dump_value_graph(frame):',
    inspect.getsource(address_names_a_function) + '\n' + inspect.getsource(select_code_words) + '\n' + inspect.getsource(classify_untyped_words) + '\ndef dump_value_graph(frame):',
    1,
)


def invocation_selector_from_case(case_ir: dict[str, Any]) -> str:
    raw = (((case_ir.get('seed_traces') or {}).get('poc_reproducer') or {}).get('invocation_selector'))
    if raw in ('first', 'last', 'last_before_fault', 'all_in_episode'):
        return str(raw)
    return 'last_before_fault'


def choose_invocation_snapshot(snapshots: list[dict[str, Any]], selector: str) -> dict[str, Any] | None:
    if not snapshots:
        return None
    if selector == 'first':
        return snapshots[0]
    return snapshots[-1]


def capture_concrete_snapshot_via_gdb(executable: Path,
                                      run_args: list[str],
                                      cut_function: str,
                                      output_dir: Path,
                                      globals_to_read: list[str] | None = None,
                                      pointer_arrays: list[dict[str, Any]] | None = None,
                                      invocation_selector: str = 'last_before_fault',
                                      stdin_bytes: bytes | None = None,
                                      env_overrides: dict[str, str] | None = None,
                                      http_requests: list[dict[str, Any]] | None = None,
                                      stop_on_first: bool = False,
                                      max_depth: int = 3,
                                      timeout: int = 60) -> dict[str, Any]:
    import os

    if stop_on_first:
        invocation_selector = 'first'
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = output_dir / 'gdb-capture-cfg.json'
    script_file = output_dir / 'gdb_capture.py'
    out_file = output_dir / 'concrete-snapshot.json'

    cfg = {
        'cut_function': cut_function,
        'run_args': list(map(str, run_args)),
        'globals': list(globals_to_read or []),
        'pointer_arrays': list(pointer_arrays or []),
        'invocation_selector': invocation_selector,
        'max_depth': int(max_depth),
        'max_object_bytes': 4096,
        'output_path': str(out_file),
        'http_requests': list(http_requests or []),
        'stop_on_first': invocation_selector == 'first',
    }
    cfg_file.write_text(json.dumps(cfg, indent=2) + '\n', encoding='utf-8')
    script_file.write_text(GDB_SNAPSHOT_SCRIPT, encoding='utf-8')

    env = dict(os.environ)
    if env_overrides:
        env.update(env_overrides)
    env['VG_GDB_CFG'] = str(cfg_file)

    subprocess.run(
        ['gdb', '-batch', '-nx', '-x', str(script_file), str(executable)],
        input=stdin_bytes,
        env=env,
        stdout=(output_dir / 'gdb.stdout.log').open('wb'),
        stderr=(output_dir / 'gdb.stderr.log').open('wb'),
        timeout=timeout,
        check=False,
    )
    if not out_file.is_file():
        return {'captured': False, 'invocations': 0, 'call_stacks': [], 'call_edges': [], 'snapshot': None}
    return json.loads(out_file.read_text(encoding='utf-8'))


def _scalar_symbol_width(finfo: dict[str, Any]) -> int:
    return max(1, min(8, int(finfo.get('bit_size') or 64) // 8))


def _scalar_symbol_rank(fname: str, finfo: dict[str, Any]) -> tuple[int, str]:
    tokens = set(re.split(r'[^A-Za-z0-9]+', fname.lower()))
    bit_size = int(finfo.get('bit_size') or 64)
    bitfield = bit_size < 8 or bit_size % 8 != 0
    if tokens & {'len', 'length', 'size', 'count', 'status', 'nelts', 'n'}:
        rank = 0
    elif bitfield:
        rank = 1
    else:
        rank = 2
    return rank, fname


_FD_TYPES = {'ngx_fd_t', 'apr_os_file_t', 'php_socket_t', 'apr_file_t'}


def _config_skeleton(ctype: str) -> bool:
    text = str(ctype or '')
    return text.endswith('conf_t') or text.endswith('module_t')


def _request_period_scalar(name: str, info: dict[str, Any]) -> bool:
    base = str(name).split('.')[-1].split('->')[-1].lower()
    if base in {'len', 'length', 'size', 'count', 'nelts', 'method', 'status', 'flags', 'n'}:
        return True
    if base.endswith(('_len', '_size', '_count', '_nelts', '_status')):
        return True
    bits = int(info.get('bit_size') or 64)
    return bits < 8 or (bits % 8 != 0)


def _optional_null_pointer(owner_type: str, field: str, finfo: dict[str, Any],
                           readonly_prefixes: tuple[str, ...]) -> bool:
    if _config_skeleton(owner_type):
        return False
    if any(str(field).startswith(prefix.replace('->', '.')) for prefix in readonly_prefixes):
        return False
    ref = (finfo or {}).get('ref') or {}
    return (finfo or {}).get('kind') == 'pointer' and ref.get('kind') == 'null'


def _null_object_size(info: dict[str, Any]) -> int:
    ref = (info or {}).get('ref') or {}
    raw = ref.get('target_byte_size', (info or {}).get('target_byte_size'))
    try:
        size = int(raw)
    except (TypeError, ValueError):
        return 16
    if size < 1:
        return 16
    return min(size, 4096)


def _lift_null_input_pointers(objects: dict[str, Any], roots: dict[str, Any],
                              readonly_prefixes: tuple[str, ...]) -> None:
    pending: list[tuple[dict[str, Any], str, str, int]] = []
    for oid, oinfo in objects.items():
        owner_type = str(oinfo.get('c_type') or '')
        for fname, finfo in (oinfo.get('fields') or {}).items():
            if _optional_null_pointer(owner_type, str(fname), finfo, readonly_prefixes):
                pending.append((finfo, f'obj_null_{_c_ident(oid)}_{_c_ident(fname)}', str(finfo.get('target_c_type') or 'unsigned char'), _null_object_size(finfo)))
    for rname, rinfo in roots.items():
        if str(rname).startswith('global:'):
            continue
        if rinfo.get('kind') == 'pointer' and (rinfo.get('ref') or {}).get('kind') == 'null':
            pending.append((rinfo, f'obj_null_root_{_c_ident(rname)}', str(rinfo.get('target_c_type') or 'unsigned char'), _null_object_size(rinfo)))
    for owner, new_id, target, size in pending:
        objects[new_id] = {
            'id': new_id,
            'c_type': target,
            'byte_size': size,
            'hex_bytes': '00' * size,
            'fields': {},
        }
        owner['ref'] = {'kind': 'object_ref', 'object_id': new_id, 'offset': 0}


def _descriptor_field(name: str, info: dict[str, Any]) -> bool:
    base = str(name).split('.')[-1].split('->')[-1]
    if base == 'fd' or base.endswith('_fd'):
        return True
    ctype = str(info.get('c_type') or '')
    return ctype in _FD_TYPES or ctype.endswith('fd_t')


def lift_snapshot_to_abstract_spec(concrete: dict[str, Any] | None,
                                   symbolization_scope: dict[str, Any],
                                   max_symbolic_bytes: int = 64) -> dict[str, Any]:
    pin_concrete = set(symbolization_scope.get('pin_concrete', []))
    force_symbolic = set(symbolization_scope.get('force_symbolic', []))
    readonly_prefixes = tuple(symbolization_scope.get('readonly_field_prefixes', [
        'loc_conf', 'srv_conf', 'main_conf', 'module_config', 'pool', 'connection->log', 'log',
    ]))

    if not concrete or not concrete.get('snapshot'):
        return {
            'mode': 'type_bounded_default',
            'symbolic_scalars': list(symbolization_scope.get('symbolic_scalars', [])),
            'symbolic_buffers': list(symbolization_scope.get('symbolic_buffers', [])),
            'pinned_function_pointers': dict(symbolization_scope.get('pinned_function_pointers', {})),
            'pointer_order_constraints': list(symbolization_scope.get('pointer_order_constraints', [])),
            'concrete_constants': dict(symbolization_scope.get('concrete_constants', {})),
        }

    episode_step_constants = None
    series = [item for item in (concrete.get('episode_snapshots') or []) if isinstance(item, dict)]
    if concrete.get('invocation_selector') == 'all_in_episode' and len(series) >= 2:
        episode_step_constants = [
            lift_snapshot_to_abstract_spec(
                {'snapshot': item},
                symbolization_scope,
                max_symbolic_bytes=max_symbolic_bytes,
            ).get('concrete_constants') or {}
            for item in series[-2:]
        ]

    snap = concrete['snapshot']
    sym_scalars: list[dict[str, Any]] = []
    sym_buffers: list[dict[str, Any]] = []
    pinned_fn_ptrs: dict[str, str] = {}
    concrete_consts: dict[str, int] = {}
    roots = deepcopy(snap.get('roots') or {})
    objects = deepcopy(snap.get('objects') or {})
    _lift_null_input_pointers(objects, roots, readonly_prefixes)

    for rname, rinfo in roots.items():
        if rinfo.get('kind') == 'scalar':
            if rname in pin_concrete or (_descriptor_field(str(rname), rinfo) and rname not in force_symbolic):
                concrete_consts[rname] = int(rinfo['value'])
            else:
                sym_scalars.append({
                    'name': rname.replace(':', '_'),
                    'path': rname,
                    'c_type': rinfo.get('c_type', 'uint64_t'),
                    'seed_value': int(rinfo['value']),
                })
        elif rinfo.get('kind') == 'pointer' and rinfo.get('ref', {}).get('kind') == 'function_ptr':
            pinned_fn_ptrs[rname] = rinfo['ref']['symbol']

    root_object_ids = set()
    for rinfo in roots.values():
        ref = (rinfo or {}).get('ref') or {}
        if isinstance(ref, dict) and ref.get('kind') == 'object_ref':
            root_object_ids.add(ref.get('object_id'))
    referenced_targets = set()
    scalar_candidates: list[tuple[tuple[int, str], dict[str, Any], int, bool]] = []
    for oid, oinfo in objects.items():
        for fname, finfo in oinfo.get('fields', {}).items():
            full_path = f'{oid}.{fname}'
            if finfo.get('kind') == 'pointer':
                ref = finfo.get('ref', {})
                if ref.get('kind') == 'function_ptr':
                    pinned_fn_ptrs[full_path] = ref['symbol']
                elif ref.get('kind') == 'object_ref':
                    referenced_targets.add(ref['object_id'])
            elif finfo.get('kind') == 'scalar':
                forced = full_path in force_symbolic or fname in force_symbolic
                is_ro = any(fname.startswith(p.replace('->', '.')) for p in readonly_prefixes)
                is_fd = _descriptor_field(str(fname), finfo)
                is_conf = _config_skeleton(str(oinfo.get('c_type') or ''))
                if full_path in pin_concrete or ((is_ro or is_fd or is_conf) and not forced):
                    concrete_consts[full_path] = int(finfo['value'])
                elif forced or oid in root_object_ids or _request_period_scalar(str(fname), finfo):
                    scalar_candidates.append((
                        _scalar_symbol_rank(fname, finfo),
                        {
                            'name': f'{oid}_{fname}',
                            'object_id': oid,
                            'field': fname,
                            'c_type': finfo.get('c_type', 'uint64_t'),
                            'bit_size': finfo.get('bit_size', 64),
                            'seed_value': int(finfo['value']),
                        },
                        _scalar_symbol_width(finfo),
                        forced,
                    ))
    scalar_budget = max(0, int(max_symbolic_bytes))
    scalar_used = 0
    bitfield_used = 0
    for rank, item, width, forced in sorted(scalar_candidates, key=lambda row: (0 if row[3] else 1, row[0])):
        bitfield = rank[0] == 1
        if not forced and bitfield and bitfield_used + width > min(8, scalar_budget):
            continue
        if not forced and scalar_used + width > scalar_budget:
            continue
        sym_scalars.append(item)
        scalar_used += width
        if bitfield:
            bitfield_used += width

    direct_targets = set()
    for oid in root_object_ids:
        for finfo in (objects.get(oid) or {}).get('fields', {}).values():
            ref = (finfo or {}).get('ref') or {}
            if ref.get('kind') == 'object_ref':
                direct_targets.add(ref['object_id'])
    buffer_used = 0
    buffer_candidates = []
    for oid, oinfo in objects.items():
        if oinfo.get('fields') or oid not in referenced_targets:
            continue
        blen = min(max(1, int(oinfo.get('byte_size') or 1)), max(1, int(max_symbolic_bytes)))
        buffer_candidates.append((0 if oid in direct_targets else 1, -blen, oid, blen, oinfo))
    for _prio, _size, oid, blen, oinfo in sorted(buffer_candidates):
        if buffer_used + blen > scalar_budget:
            continue
        buffer_used += blen
        sym_buffers.append({
            'object_id': oid,
            'c_type': oinfo.get('c_type', 'uint8_t'),
            'byte_size': blen,
            'seed_hex': oinfo.get('hex_bytes', '')[:blen * 2],
        })

    return {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': snap['cut_function'],
        'parameter_names': list(snap.get('parameter_names') or [
            name for name in snap.get('roots', {}) if not str(name).startswith('global:')
        ]),
        'objects': objects,
        'roots': roots,
        'symbolic_scalars': sym_scalars,
        'symbolic_buffers': sym_buffers,
        'pinned_function_pointers': pinned_fn_ptrs,
        'pointer_order_constraints': _buffer_pointer_orders(snap.get('pointer_order_relations', []), objects),
        'max_pointer_hops': int(symbolization_scope.get('max_pointer_hops', 2)),
        'concrete_constants': concrete_consts,
        **({'episode_step_constants': episode_step_constants} if episode_step_constants is not None else {}),
    }


_BYTE_TYPES = {'u_char', 'char', 'unsigned char', 'uint8_t', 'int8_t', 'void'}
_CURSOR_NAMES = {'start', 'pos', 'last', 'end', 'data'}
_SKELETON_TYPES = ('conf_t', 'ngx_pool_t', 'ngx_listening_t', 'ngx_module_t')


def _prefix_nonempty(obj: dict[str, Any]) -> bool:
    raw = bytes.fromhex(str(obj.get('hex_bytes') or ''))
    return any(raw)


def _nullable_pointee(obj: dict[str, Any]) -> bool:
    if obj.get('code_words') or obj.get('pointer_words') or obj.get('unresolved_target'):
        return False
    return not _prefix_nonempty(obj)


def _byte_buffer_type(ctype: str) -> bool:
    text = ' '.join(ctype.replace('*', ' ').split())
    for token in ('const', 'volatile', 'signed', 'unsigned'):
        text = text.replace(token + ' ', '')
    return text.strip() in _BYTE_TYPES


def _cursor_rank(name: str) -> int | None:
    base = str(name).split('.')[-1]
    if base in ('start', 'data') or base.endswith('_start'):
        return 0
    if base == 'pos' or base.endswith('_pos'):
        return 1
    if base == 'last' or base.endswith('_last'):
        return 2
    if base == 'end' or base.endswith('_end'):
        return 3
    return None


def _cursor_field(name: str) -> bool:
    return _cursor_rank(name) is not None


def _sort_cursor_group(fields: list[Any]) -> list[Any]:
    ranks = [_cursor_rank(str(item.get('field') if isinstance(item, dict) else item[0])) for item in fields]
    if any(rank is None for rank in ranks):
        return fields
    return [item for _rank, item in sorted(enumerate(fields), key=lambda pair: (ranks[pair[0]], pair[0]))]


def _buffer_pointer_orders(relations: list[Any], objects: dict[str, Any]) -> list[Any]:
    kept: list[Any] = []
    for rel in relations or []:
        if not isinstance(rel, dict):
            continue
        fields = [item for item in rel.get('ordered_fields') or [] if isinstance(item, dict) and item.get('field')]
        if len(fields) < 2:
            continue
        target = objects.get(str(rel.get('target_object') or '')) or {}
        owner = objects.get(str(rel.get('owner_object') or '')) or {}
        target_type = str(target.get('c_type') or '')
        owner_type = str(owner.get('c_type') or '')
        names = [str(item.get('field')) for item in fields]
        if _byte_buffer_type(target_type):
            if any(token in owner_type for token in _SKELETON_TYPES):
                continue
            kept.append({**rel, 'ordered_fields': _sort_cursor_group(fields)})
            continue
        if target_type.endswith('_t') or target_type.startswith('struct ') or target_type.startswith('union '):
            continue
        if all(_cursor_field(name) for name in names):
            kept.append({**rel, 'ordered_fields': _sort_cursor_group(fields)})
    return kept


_C_IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _c_ident(text: str) -> str:
    cleaned = re.sub(r'[^A-Za-z0-9_]', '_', str(text))
    if not cleaned or cleaned[0].isdigit():
        cleaned = 'v_' + cleaned
    return cleaned


def _selected_object_ids(abstract: dict[str, Any]) -> list[str]:
    objects = abstract.get('objects') or {}
    if not isinstance(objects, dict) or not objects:
        return []
    max_hops = int(abstract.get('max_pointer_hops', 2))
    roots = abstract.get('roots') or {}
    seeds: list[str] = []
    if isinstance(roots, dict):
        for info in roots.values():
            ref = (info or {}).get('ref') or {}
            if ref.get('kind') == 'object_ref' and ref.get('object_id') in objects:
                seeds.append(str(ref['object_id']))
    if not seeds:
        return list(objects.keys())[:48]
    selected: list[str] = []
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque((oid, 0) for oid in seeds)
    while queue and len(selected) < 48:
        oid, hop = queue.popleft()
        if oid in seen or oid not in objects or hop > max_hops:
            continue
        seen.add(oid)
        selected.append(oid)
        if hop == max_hops:
            continue
        for finfo in (objects[oid].get('fields') or {}).values():
            ref = (finfo or {}).get('ref') or {}
            child = ref.get('object_id')
            if ref.get('kind') == 'object_ref' and child in objects:
                queue.append((str(child), hop + 1))
    return selected


def _object_image(oinfo: dict[str, Any],
                  pointer_spans: list[tuple[int, int]],
                  scalar_spans: list[tuple[int, int]]) -> bytes:
    size = max(1, min(int(oinfo.get('byte_size') or 1), 4096))
    raw = bytes.fromhex(str(oinfo.get('hex_bytes') or ''))
    image = bytearray(size)
    image[:min(len(raw), size)] = raw[:size]
    for start, width in [*pointer_spans, *scalar_spans]:
        for index in range(start, min(size, start + width)):
            image[index] = 0
    return bytes(image)


def _scalar_parameter_roots(abstract: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not abstract:
        return []
    roots = abstract.get('roots') or {}
    if not isinstance(roots, dict):
        return []
    found: list[dict[str, Any]] = []
    for name in abstract.get('parameter_names') or []:
        info = roots.get(name)
        if not isinstance(info, dict) or info.get('kind') != 'scalar':
            continue
        if not _C_IDENT.match(str(name)):
            continue
        ctype = str(info.get('c_type') or 'uint64_t')
        if not _C_IDENT.match(ctype):
            ctype = 'uint64_t'
        found.append({
            'name': str(name),
            'c_type': ctype,
            'symbol': f'__vulgate_snap_arg_{_c_ident(str(name))}',
        })
    return found


def render_snapshot_state_c(abstract: dict[str, Any] | None) -> dict[str, Any]:
    if not abstract or abstract.get('mode') != 'poc_or_seed_snapshot_lifted':
        return {'code': '', 'roots': [], 'world_prologue': {'0': '', '1': ''}}
    objects = abstract.get('objects') or {}
    selected = _selected_object_ids(abstract)
    if not selected:
        return {'code': '', 'roots': [], 'world_prologue': {'0': '', '1': ''}}

    pointer_spans: dict[str, list[tuple[int, int]]] = {oid: [] for oid in selected}
    scalar_spans: dict[str, list[tuple[int, int]]] = {oid: [] for oid in selected}
    scalar_writes: list[tuple[str, int, int, int]] = []
    code_len_slot = None
    for item in abstract.get('symbolic_scalars') or []:
        oid = item.get('object_id')
        fname = item.get('field')
        if oid not in pointer_spans or not fname:
            continue
        finfo = (objects[oid].get('fields') or {}).get(fname) or {}
        offset = int(finfo.get('offset') or 0)
        width = max(1, min(8, int(item.get('bit_size') or 64) // 8))
        size = max(1, min(int(objects[oid].get('byte_size') or 1), 4096))
        if offset < 0 or offset >= size:
            continue
        width = min(width, size - offset)
        if objects[oid].get('code_words') and fname == 'len':
            code_len_slot = len(scalar_writes)
        scalar_spans[oid].append((offset, width))
        scalar_writes.append((oid, offset, width, len(scalar_writes)))

    buffer_writes: list[tuple[str, int]] = []
    for item in abstract.get('symbolic_buffers') or []:
        oid = item.get('object_id')
        if oid not in pointer_spans:
            continue
        size = max(1, min(int(objects[oid].get('byte_size') or 1), 64))
        buffer_writes.append((oid, size))

    ordered_fields: set[tuple[str, str]] = set()
    order_groups: list[dict[str, Any]] = []
    for rel in abstract.get('pointer_order_constraints') or []:
        if not isinstance(rel, dict):
            continue
        owner = str(rel.get('owner_object') or '')
        target = str(rel.get('target_object') or '')
        fields = list(rel.get('ordered_fields') or [])
        if owner not in pointer_spans or target not in pointer_spans or len(fields) < 2:
            continue
        usable = []
        for entry in fields:
            fname = str(entry.get('field') or '')
            finfo = (objects[owner].get('fields') or {}).get(fname) or {}
            if finfo.get('kind') != 'pointer':
                continue
            usable.append((fname, int(finfo.get('offset') or 0)))
            ordered_fields.add((owner, fname))
        if len(usable) >= 2:
            ranked = _sort_cursor_group([{'field': name} for name, _off in usable])
            order = {str(item['field']): pos for pos, item in enumerate(ranked)}
            usable.sort(key=lambda item: order[item[0]])
            order_groups.append({'owner': owner, 'target': target, 'fields': usable})

    function_patches: list[tuple[str, int, str]] = []
    code_word_symbols: list[str] = []
    concrete_pointers: list[tuple[str, int, str, int]] = []
    for oid in selected:
        size = max(1, min(int(objects[oid].get('byte_size') or 1), 4096))
        for fname, finfo in (objects[oid].get('fields') or {}).items():
            if finfo.get('kind') != 'pointer':
                continue
            offset = int(finfo.get('offset') or 0)
            if offset < 0 or offset + 8 > size:
                continue
            pointer_spans[oid].append((offset, 8))
            if (oid, fname) in ordered_fields:
                continue
            ref = finfo.get('ref') or {}
            kind = ref.get('kind')
            if kind == 'function_ptr' and _C_IDENT.match(str(ref.get('symbol') or '')):
                function_patches.append((oid, offset, str(ref['symbol'])))
                if objects[oid].get('code_words') or objects[oid].get('pointer_words'):
                    code_word_symbols.append(str(ref['symbol']))
            elif kind == 'object_ref' and str(ref.get('object_id')) in pointer_spans:
                concrete_pointers.append((oid, offset, str(ref['object_id']), int(ref.get('offset') or 0)))

    images = {
        oid: _object_image(objects[oid], pointer_spans[oid], scalar_spans[oid])
        for oid in selected
    }
    scalar_args = _scalar_parameter_roots(abstract)
    base_slots = len(scalar_writes) + sum((size + 7) // 8 for _oid, size in buffer_writes) + sum(len(group['fields']) for group in order_groups)
    for index, arg in enumerate(scalar_args):
        arg['slot'] = base_slots + index
    nullable_slots: dict[tuple[str, int], int] = {}
    next_slot = base_slots + len(scalar_args)
    for owner, field_off, target, _target_off in concrete_pointers:
        if _nullable_pointee(objects[target]):
            nullable_slots[(owner, field_off)] = next_slot
            next_slot += 1
    nullable_roots: dict[str, int] = {}
    for rname, rinfo in (abstract.get('roots') or {}).items():
        if not _C_IDENT.match(str(rname)) or str(rname).startswith('global:'):
            continue
        ref = (rinfo or {}).get('ref') or {}
        oid = str(ref.get('object_id') or '')
        if ref.get('kind') == 'object_ref' and oid in objects and _nullable_pointee(objects[oid]):
            nullable_roots[str(rname)] = next_slot
            next_slot += 1
    sym_slots = max(1, next_slot)
    lines = [
        'static int __vulgate_snap_sym_ready;',
        'static int __vulgate_snap_w0_ready;',
        'static int __vulgate_snap_w1_ready;',
        f'static uint64_t __vulgate_snap_sym[{sym_slots}];',
    ]
    for arg in scalar_args:
        lines.append(f'static uint64_t {arg["symbol"]};')
    if code_len_slot is not None:
        lines.append('static uint64_t __vulgate_snap_code_len;')
    for oid in selected:
        ident = _c_ident(oid)
        size = len(images[oid])
        lines.append(f'static unsigned char __vulgate_snap_w0_{ident}[{size}];')
        lines.append(f'static unsigned char __vulgate_snap_w1_{ident}[{size}];')
        payload = ', '.join(str(byte) for byte in images[oid])
        lines.append(f'static const unsigned char __vulgate_snap_img_{ident}[{size}] = {{ {payload} }};')

    root_names: list[str] = []
    root_targets: list[tuple[str, str, int]] = []
    global_copies: list[tuple[str, str]] = []
    for rname, rinfo in (abstract.get('roots') or {}).items():
        ref = (rinfo or {}).get('ref') or {}
        if str(rname).startswith('global:'):
            c_name = str(rname).split(':', 1)[1]
            oid = str(ref.get('object_id') or '')
            if _C_IDENT.match(c_name) and ref.get('kind') == 'object_ref' and oid in images:
                global_copies.append((c_name, oid))
            continue
        if not _C_IDENT.match(str(rname)):
            continue
        ref = (rinfo or {}).get('ref') or {}
        if ref.get('kind') != 'object_ref' or str(ref.get('object_id')) not in images:
            continue
        if rname in root_names:
            continue
        root_names.append(str(rname))
        root_targets.append((str(rname), str(ref['object_id']), int(ref.get('offset') or 0)))
        lines.append(f'static void *__vulgate_snap_root_{rname};')

    lines.append('static void __vulgate_snap_symvec(void) {')
    lines.append('    if (__vulgate_snap_sym_ready) return;')
    lines.append('    __vulgate_snap_sym_ready = 1;')
    for index in range(sym_slots):
        lines.append(f'    __vulgate_snap_sym[{index}] = __vulgate_nondet_u64();')
    lines.append('}')

    def base_expr(world_token: str, oid: str) -> str:
        return f'({world_token} ? __vulgate_snap_w1_{_c_ident(oid)} : __vulgate_snap_w0_{_c_ident(oid)})'

    lines.append('static void __vulgate_instantiate_snapshot(int __vulgate_world) {')
    lines.append('    unsigned char *__vulgate_obj;')
    lines.append('    __vulgate_snap_symvec();')
    lines.append('    if (__vulgate_world == 0) {')
    lines.append('        if (__vulgate_snap_w0_ready) goto __vulgate_snap_bind;')
    lines.append('        __vulgate_snap_w0_ready = 1;')
    lines.append('    } else {')
    lines.append('        if (__vulgate_snap_w1_ready) goto __vulgate_snap_bind;')
    lines.append('        __vulgate_snap_w1_ready = 1;')
    lines.append('    }')
    for oid in selected:
        ident = _c_ident(oid)
        lines.append(f'    __vulgate_obj = {base_expr("__vulgate_world", oid)};')
        lines.append(f'    memcpy(__vulgate_obj, __vulgate_snap_img_{ident}, sizeof(__vulgate_snap_img_{ident}));')
    slot = 0
    for oid, offset, width, _ordinal in scalar_writes:
        lines.append(f'    __vulgate_obj = {base_expr("__vulgate_world", oid)};')
        lines.append('    {')
        lines.append(f'        uint64_t __vulgate_tmp = __vulgate_snap_sym[{slot}];')
        lines.append(f'        memcpy(__vulgate_obj + {offset}, &__vulgate_tmp, {width});')
        lines.append('    }')
        slot += 1
    for oid, size in buffer_writes:
        lines.append(f'    __vulgate_obj = {base_expr("__vulgate_world", oid)};')
        for index in range(size):
            packed = slot + (index // 8)
            shift = (index % 8) * 8
            lines.append(f'    __vulgate_obj[{index}] = (uint8_t)(__vulgate_snap_sym[{packed}] >> {shift});')
        slot += (size + 7) // 8
    for owner, field_off, target, target_off in concrete_pointers:
        target_size = len(images[target])
        use_off = min(max(0, target_off), target_size)
        lines.append('    {')
        lines.append(f'        uintptr_t __vulgate_tmp = (uintptr_t)({base_expr("__vulgate_world", target)} + {use_off});')
        null_slot = nullable_slots.get((owner, field_off))
        if null_slot is not None:
            lines.append(f'        if ((__vulgate_snap_sym[{null_slot}] & 1ULL) == 0ULL) __vulgate_tmp = 0;')
        lines.append(f'        memcpy({base_expr("__vulgate_world", owner)} + {field_off}, &__vulgate_tmp, sizeof(__vulgate_tmp));')
        lines.append('    }')
    for group in order_groups:
        target_size = len(images[group['target']])
        offsets = []
        for _fname, _field_off in group['fields']:
            offsets.append(slot)
            slot += 1
        assume_terms = [f'0ULL <= __vulgate_snap_sym[{offsets[0]}]']
        for left, right in zip(offsets, offsets[1:]):
            assume_terms.append(f'__vulgate_snap_sym[{left}] <= __vulgate_snap_sym[{right}]')
        assume_terms.append(f'__vulgate_snap_sym[{offsets[-1]}] <= {target_size}ULL')
        lines.append(f'    __CPROVER_assume({" && ".join(assume_terms)});')
        for (_fname, field_off), sym_index in zip(group['fields'], offsets):
            lines.append('    {')
            lines.append(f'        uintptr_t __vulgate_tmp = (uintptr_t)({base_expr("__vulgate_world", group["target"])} + (size_t)__vulgate_snap_sym[{sym_index}]);')
            lines.append(f'        memcpy({base_expr("__vulgate_world", group["owner"])} + {field_off}, &__vulgate_tmp, sizeof(__vulgate_tmp));')
            lines.append('    }')
    lines.append('__vulgate_snap_bind:')
    for arg in scalar_args:
        lines.append(f'    {arg["symbol"]} = __vulgate_snap_sym[{arg["slot"]}];')
    if code_len_slot is not None:
        lines.append(f'    __vulgate_snap_code_len = __vulgate_snap_sym[{code_len_slot}];')
    for rname, oid, offset in root_targets:
        bound = len(images[oid])
        use_off = offset if 0 <= offset < bound else 0
        lines.append(f'    __vulgate_snap_root_{rname} = (void *)({base_expr("__vulgate_world", oid)} + {use_off});')
        null_slot = nullable_roots.get(rname)
        if null_slot is not None:
            lines.append(f'    if ((__vulgate_snap_sym[{null_slot}] & 1ULL) == 0ULL) __vulgate_snap_root_{rname} = 0;')
    lines.append('    return;')
    lines.append('}')

    prologues = {'0': [], '1': []}
    for world in ('0', '1'):
        prologues[world].append(f'    __vulgate_instantiate_snapshot({world});')
        for oid, offset, symbol in function_patches:
            prologues[world].append('    {')
            prologues[world].append(f'        uintptr_t __vulgate_fp = (uintptr_t)&{symbol};')
            prologues[world].append(f'        memcpy(__vulgate_snap_w{world}_{_c_ident(oid)} + {offset}, &__vulgate_fp, sizeof(__vulgate_fp));')
            prologues[world].append('    }')
        for c_name, oid in global_copies:
            prologues[world].append(
                f'    memcpy(&{c_name}, __vulgate_snap_w{world}_{_c_ident(oid)}, {len(images[oid])});'
            )
    return {
        'code': '\n'.join(lines) + '\n',
        'roots': root_names,
        'world_prologue': {'0': '\n'.join(prologues['0']), '1': '\n'.join(prologues['1'])},
        'globals': [name for name, _oid in global_copies],
        'code_len_symbol': '__vulgate_snap_code_len' if code_len_slot is not None else '',
        'code_word_symbols': code_word_symbols,
    }


def _insert_after_includes(source: str, text: str) -> str:
    lines = source.split('\n')
    last = 0
    started = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#include'):
            started = True
            last = index + 1
        elif started and stripped and not stripped.startswith('#'):
            break
    if last == 0:
        return text + '\n' + source
    head = '\n'.join(lines[:last])
    tail = '\n'.join(lines[last:])
    return head + '\n' + text + '\n' + tail


def _insert_world_prologue(source: str, function_name: str, prologue: str) -> str:
    if not prologue:
        return source
    marker = f'int {function_name}('
    start = source.find(marker)
    if start < 0:
        marker = f'void {function_name}('
        start = source.find(marker)
    if start < 0:
        return source
    brace = source.find('{', start)
    if brace < 0:
        return source
    return source[:brace + 1] + '\n' + prologue + '\n' + source[brace + 1:]


def _paren_depth(source: str, index: int) -> int:
    depth = 0
    for ch in source[:index]:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
    return depth


def _root_local_types(source: str, names: list[str]) -> dict[str, tuple[str, bool]]:
    found: dict[str, tuple[str, bool]] = {}
    for name in names:
        pattern = re.compile(
            rf'(?:^|[;{{])\s*(?:(?:static|extern|const|volatile|register)\s+)*'
            rf'(?P<type>(?:struct|union|enum)\s+[A-Za-z_]\w*|[A-Za-z_]\w*)\s*'
            rf'(?P<stars>\*+)?\s*\b{re.escape(name)}\b',
            re.M,
        )
        match = None
        for candidate in pattern.finditer(source):
            if _paren_depth(source, candidate.start('type')):
                continue
            match = candidate
            break
        if not match:
            continue
        ctype = ' '.join(match.group('type').split())
        stars = match.group('stars') or ''
        if stars:
            found[name] = (f'{ctype} {stars}', True)
        else:
            found[name] = (ctype, False)
    return found


def _statement_assigns_root(statement: str, name: str) -> bool:
    if re.search(rf'\bmemset\s*\(\s*&{re.escape(name)}\b', statement):
        return True
    if re.search(rf'\bmemset\s*\(\s*{re.escape(name)}\b', statement):
        return True
    if re.search(rf'(^|[^<>=!])\b{re.escape(name)}\s*=(?!=)', statement):
        return True
    if re.search(rf'\b{re.escape(name)}\s*(?:\.|->)\s*[A-Za-z_]\w*\s*=(?!=)', statement):
        return True
    if re.search(rf'\(\s*\*\s*{re.escape(name)}\s*\)\s*\.\s*[A-Za-z_]\w*\s*=(?!=)', statement):
        return True
    return False


def _declares_root(statement: str, name: str) -> bool:
    return re.search(
        rf'(?:^|[;{{])\s*(?:(?:static|extern|const|volatile|register)\s+)*'
        rf'(?:(?:struct|union|enum)\s+[A-Za-z_]\w*|[A-Za-z_]\w*)\s*(?:\*+\s*)?{re.escape(name)}\b',
        statement,
    ) is not None


def _strip_root_initializer(statement: str, name: str) -> str:
    return re.sub(
        rf'\b{re.escape(name)}\b\s*=(?!=)\s*[^,;]+',
        name,
        statement,
    )


def _assigned_field_names(statement: str, name: str) -> list[str]:
    return re.findall(
        rf'\b{re.escape(name)}\s*(?:\.|->)\s*([A-Za-z_]\w*)\s*=(?!=)',
        statement,
    )


def _only_kept_field_stores(statement: str, name: str, kept_fields: set[str]) -> bool:
    if not kept_fields:
        return False
    fields = _assigned_field_names(statement, name)
    if not fields or any(field not in kept_fields for field in fields):
        return False
    if re.search(rf'\bmemset\s*\(\s*&{re.escape(name)}\b', statement):
        return False
    if re.search(rf'(^|[^<>=!.>-])\b{re.escape(name)}\s*=(?!=)', statement):
        return False
    return True


def _voidish_type(ctype: str) -> bool:
    text = ctype.strip()
    return text == 'void' or text.startswith('void ') or text.startswith('void*')


def _object_reaches_struct(objects: dict[str, Any], oid: str | None, seen: set[str]) -> bool:
    if not oid or oid in seen:
        return False
    seen.add(oid)
    obj = objects.get(oid) or {}
    ctype = str(obj.get('c_type') or '')
    if ctype and not _voidish_type(ctype) and obj.get('fields'):
        return True
    for finfo in (obj.get('fields') or {}).values():
        if not isinstance(finfo, dict):
            continue
        fref = finfo.get('ref') or {}
        if fref.get('kind') == 'object_ref' and _object_reaches_struct(objects, fref.get('object_id'), seen):
            return True
    return False


def _untyped_root_fields(abstract: dict[str, Any] | None) -> dict[str, set[str]]:
    if not abstract:
        return {}
    roots = abstract.get('roots') or {}
    objects = abstract.get('objects') or {}
    if not isinstance(roots, dict) or not isinstance(objects, dict):
        return {}
    found: dict[str, set[str]] = {}
    for rname, rinfo in roots.items():
        if not isinstance(rinfo, dict):
            continue
        ref = rinfo.get('ref') or {}
        if ref.get('kind') != 'object_ref':
            continue
        obj = objects.get(ref.get('object_id')) or {}
        weak: set[str] = set()
        for fname, finfo in (obj.get('fields') or {}).items():
            if not isinstance(finfo, dict) or finfo.get('kind') != 'pointer':
                continue
            fref = finfo.get('ref') or {}
            if fref.get('kind') != 'object_ref':
                continue
            target = objects.get(fref.get('object_id')) or {}
            ctype = str(target.get('c_type') or '')
            if _voidish_type(ctype) and not _object_reaches_struct(objects, fref.get('object_id'), set()):
                weak.add(str(fname))
        if weak:
            found[str(rname)] = weak
    return found


def _drops_root_setup(statement: str, names: list[str], kept_fields: dict[str, set[str]]) -> bool:
    for name in names:
        if not _statement_assigns_root(statement, name):
            continue
        if _only_kept_field_stores(statement, name, kept_fields.get(name, set())):
            continue
        return True
    return False


def _drop_snapshot_root_setup(source: str, names: list[str], kept_fields: dict[str, set[str]] | None = None) -> str:
    if not names:
        return source
    kept_fields = kept_fields or {}
    rewritten: list[str] = []
    for line in source.split('\n'):
        stripped = line.strip()
        if stripped.startswith('for ') or stripped.startswith('for('):
            rewritten.append(line)
            continue
        if ';' not in line:
            assigns = _drops_root_setup(line, names, kept_fields)
            declares = any(_declares_root(line, name) for name in names)
            if assigns and not declares:
                continue
            rewritten.append(line)
            continue
        indent = re.match(r'\s*', line).group(0)
        pieces = line.split(';')
        kept: list[str] = []
        for piece in pieces:
            if not piece.strip():
                continue
            declared = [name for name in names if _declares_root(piece, name)]
            if declared:
                updated = piece
                for name in declared:
                    updated = _strip_root_initializer(updated, name)
                kept.append(updated.strip())
                continue
            if _drops_root_setup(piece, names, kept_fields):
                continue
            kept.append(piece.strip())
        if not kept:
            continue
        rewritten.append(indent + '; '.join(kept) + ';')
    return '\n'.join(rewritten)


def _rebind_root_locals(source: str, names: list[str]) -> str:
    typed = _root_local_types(source, names)
    for name, (ctype, is_pointer) in typed.items():
        rewritten: list[str] = []
        decl = re.compile(
            rf'(?:^|[;{{])\s*(?:(?:static|extern|const|volatile|register)\s+)*'
            rf'(?:(?:struct|union|enum)\s+[A-Za-z_]\w*|[A-Za-z_]\w*)\s*\*?\s*\b{re.escape(name)}\b'
        )
        for line in source.split('\n'):
            if 'memset' in line or decl.search(line):
                rewritten.append(line)
                continue
            if is_pointer:
                line = re.sub(
                    rf'\b{re.escape(name)}\b',
                    f'(({ctype})__vulgate_snap_root_{name})',
                    line,
                )
            else:
                line = re.sub(
                    rf'\b{re.escape(name)}\s*\.',
                    f'(*(({ctype} *)__vulgate_snap_root_{name})).',
                    line,
                )
            rewritten.append(line)
        source = '\n'.join(rewritten)
    return source


def _split_call_args(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, ch in enumerate(text):
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _typed_pointer_root(info: dict[str, Any], objects: dict[str, Any] | None = None) -> bool:
    if info.get('kind') != 'pointer':
        return False
    ref = info.get('ref') or {}
    obj = {}
    if isinstance(objects, dict) and ref.get('kind') == 'object_ref':
        obj = objects.get(ref.get('object_id')) or {}
    if obj.get('code_words') or obj.get('pointer_words'):
        return True
    if obj.get('byte_buffer') and int(obj.get('byte_size') or 0) > 1:
        return True
    target = str(info.get('target_c_type') or '')
    if not target or target == 'void':
        return False
    return True


_INTEGER_TYPE_NAMES = {
    'size_t', 'ssize_t', 'int', 'unsigned', 'signed', 'long', 'short', 'char',
    'uint64_t', 'uint32_t', 'uint16_t', 'uint8_t', 'int64_t', 'int32_t', 'int16_t', 'int8_t',
    'uintptr_t', 'intptr_t', 'ngx_int_t', 'ngx_uint_t', 'ngx_flag_t',
    'apr_status_t', 'apr_size_t', 'apr_int64_t', 'off_t', 'pid_t', 'time_t',
}


def _cut_parameter_types(source: str, cut: str) -> list[str]:
    pattern = re.compile(rf'\b{re.escape(cut)}\s*\(([^;{{]*)\)\s*(?:;|\{{)')
    for match in pattern.finditer(source):
        types: list[str] = []
        for part in _split_call_args(match.group(1)):
            if '*' in part or part.strip().endswith(']'):
                types.append('pointer')
                continue
            text = re.sub(r'\b(?:const|volatile|register|static)\b', '', part).strip()
            ident = re.search(r'([A-Za-z_]\w*)\s*$', text)
            if not ident:
                types.append('uint64_t')
                continue
            type_text = text[:ident.start()].strip()
            types.append(type_text.split()[-1] if type_text else 'uint64_t')
        if types:
            return types
    return []


def _integer_literal_argument(arg: str) -> bool:
    text = arg.strip()
    while text.startswith('(') and text.endswith(')'):
        text = text[1:-1].strip()
    text = re.sub(r'^\([^)]+\)\s*', '', text).strip()
    return re.fullmatch(r'-?\d+(?:[Uu][Ll]{0,2})?', text) is not None


def _inject_literal_symbols(source: str, symbols: list[tuple[str, str]]) -> str:
    if not symbols:
        return source
    decls = '\n'.join(f'static uint64_t {name};' for name, _ctype in symbols)
    assigns = '\n'.join(f'    {name} = __vulgate_nondet_u64();' for name, _ctype in symbols)
    helper = (
        f'{decls}\n'
        'static void __vulgate_snap_lits(void) {\n'
        '    static int __vulgate_snap_lits_ready;\n'
        '    if (__vulgate_snap_lits_ready) return;\n'
        '    __vulgate_snap_lits_ready = 1;\n'
        f'{assigns}\n'
        '}\n'
    )
    return helper + source


def _rebind_cut_arguments(source: str, abstract: dict[str, Any], param_types: list[str] | None = None,
                         extra_pointers: list[str] | None = None) -> str:
    cut = str(abstract.get('cut_function') or '')
    roots = abstract.get('roots') or {}
    if not cut or not isinstance(roots, dict):
        return source
    names = list(abstract.get('parameter_names') or [
        name for name in roots if not str(name).startswith('global:')
    ])
    flowed = _flowed_scalar_inputs(source, abstract)
    pointer_names = {
        str(name): _c_ident(str(name))
        for name in names
        if isinstance(roots.get(name), dict) and _typed_pointer_root(roots[name], abstract.get('objects') or {})
    }
    if param_types is None:
        param_types = _cut_parameter_types(source, cut)
    for name in extra_pointers or []:
        if _C_IDENT.match(str(name)):
            pointer_names.setdefault(str(name), _c_ident(str(name)))
    if not names:
        return source
    pattern = re.compile(rf'\b{re.escape(cut)}\s*\(')
    pieces: list[str] = []
    cursor = 0
    literal_symbols: dict[str, str] = {}
    for match in pattern.finditer(source):
        index = match.start() - 1
        while index >= 0 and source[index].isspace():
            index -= 1
        if index >= 0 and source[index] == '*':
            continue
        token_start = index
        while token_start >= 0 and (source[token_start].isalnum() or source[token_start] == '_'):
            token_start -= 1
        previous = source[token_start + 1:index + 1]
        if previous == '*' or (previous.isidentifier() and previous not in ('return', 'sizeof')):
            continue
        open_paren = match.end() - 1
        depth = 0
        end = None
        for pos in range(open_paren, len(source)):
            if source[pos] == '(':
                depth += 1
            elif source[pos] == ')':
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end is None:
            continue
        args = _split_call_args(source[open_paren + 1:end])
        if len(args) != len(names):
            continue
        scalar_args = {item['name']: item for item in _scalar_parameter_roots(abstract)}
        rewritten = []
        for index, (arg, pname) in enumerate(zip(args, names)):
            ident = pointer_names.get(str(pname))
            scalar = scalar_args.get(str(pname))
            ptype = param_types[index] if index < len(param_types) else ''
            if ident:
                rewritten.append(f'((void *)__vulgate_snap_root_{ident})')
            elif scalar:
                rewritten.append(f'(({scalar["c_type"]}){scalar["symbol"]})')
            elif ptype in _INTEGER_TYPE_NAMES and _integer_literal_argument(arg):
                symbol = f'__vulgate_snap_lit_{_c_ident(str(pname))}'
                literal_symbols[symbol] = ptype
                rewritten.append(f'(({ptype}){symbol})')
            else:
                rewritten.append(arg)
        pieces.append(source[cursor:open_paren + 1])
        pieces.append(', '.join(rewritten))
        cursor = end
    pieces.append(source[cursor:])
    rewritten_source = _apply_scalar_input_binding(''.join(pieces), flowed)
    return _inject_literal_symbols(rewritten_source, list(literal_symbols.items()))


def _matching_paren(source: str, open_paren: int) -> int | None:
    depth = 0
    for pos in range(open_paren, len(source)):
        if source[pos] == '(':
            depth += 1
        elif source[pos] == ')':
            depth -= 1
            if depth == 0:
                return pos
    return None


def _iter_call_args(source: str, fname: str) -> list[list[str]]:
    found: list[list[str]] = []
    pattern = re.compile(rf'\b{re.escape(fname)}\s*\(')
    for match in pattern.finditer(source):
        index = match.start() - 1
        while index >= 0 and source[index].isspace():
            index -= 1
        if index >= 0 and source[index] == '*':
            continue
        token_start = index
        while token_start >= 0 and (source[token_start].isalnum() or source[token_start] == '_'):
            token_start -= 1
        previous = source[token_start + 1:index + 1]
        if previous == '*' or (previous.isidentifier() and previous not in ('return', 'sizeof')):
            continue
        open_paren = match.end() - 1
        end = _matching_paren(source, open_paren)
        if end is None or source[end + 1:].lstrip().startswith('{'):
            continue
        found.append(_split_call_args(source[open_paren + 1:end]))
    return found


def _function_parameters(source: str) -> dict[str, list[str]]:
    table: dict[str, list[str]] = {}
    pattern = re.compile(r'\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{')
    for match in pattern.finditer(source):
        name = match.group(1)
        if name in ('if', 'while', 'for', 'switch'):
            continue
        params: list[str] = []
        for part in _split_call_args(match.group(2)):
            ident = re.search(r'([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$', part.strip())
            if ident and ident.group(1) not in ('void', 'int', 'char', 'long', 'short', 'unsigned', 'signed'):
                params.append(ident.group(1))
        table[name] = params
    return table


def _flowed_scalar_inputs(source: str, abstract: dict[str, Any]) -> list[tuple[str, str]]:
    cut = str(abstract.get('cut_function') or '')
    names = list(abstract.get('parameter_names') or [])
    by_name = {item['name']: item for item in _scalar_parameter_roots(abstract)}
    if not cut or not names or not by_name:
        return []
    functions = _function_parameters(source)
    pending: list[tuple[str, str]] = []
    for args in _iter_call_args(source, cut):
        if len(args) != len(names):
            continue
        for arg, pname in zip(args, names):
            item = by_name.get(str(pname))
            if not item:
                continue
            for ident in re.findall(r'\b[A-Za-z_]\w*\b', arg):
                if ident in ('size_t', 'uint64_t', 'uintptr_t', 'uint32_t'):
                    continue
                pending.append((ident, item['symbol']))
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    while pending:
        ident, symbol = pending.pop()
        if (ident, symbol) in seen:
            continue
        seen.add((ident, symbol))
        if ident.startswith('__vg_in_'):
            found.append((ident, symbol))
            continue
        for fname, params in functions.items():
            if ident not in params:
                continue
            index = params.index(ident)
            for args in _iter_call_args(source, fname):
                if index >= len(args):
                    continue
                arg = args[index].strip()
                if re.fullmatch(r'[A-Za-z_]\w*', arg):
                    pending.append((arg, symbol))
                else:
                    for token in re.findall(r'__vg_in_\w+', arg):
                        pending.append((token, symbol))
    return found


def _replace_input_token(source: str, token: str, symbol: str) -> str:
    def repl(match: re.Match[str]) -> str:
        line_start = source.rfind('\n', 0, match.start()) + 1
        before = source[line_start:match.start()]
        if re.search(r'\b(?:uint64_t|uint32_t|uint8_t|int|size_t|unsigned|long)\s+$', before):
            return token
        return symbol

    return re.sub(rf'\b{re.escape(token)}\b', repl, source)


def _split_and(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    index = 0
    while index < len(text):
        ch = text[index]
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        if depth == 0 and text.startswith('&&', index):
            parts.append(''.join(buf))
            buf = []
            index += 2
            continue
        buf.append(ch)
        index += 1
    parts.append(''.join(buf))
    return parts


def _apply_scalar_input_binding(source: str, flowed: list[tuple[str, str]]) -> str:
    symbols = {symbol for _token, symbol in flowed}
    for token, symbol in flowed:
        source = _replace_input_token(source, token, symbol)
    if not symbols:
        return source
    lines: list[str] = []
    for line in source.split('\n'):
        stmt = line.strip()
        if stmt.startswith('__CPROVER_assume') and stmt.endswith(';'):
            open_paren = stmt.find('(')
            close_paren = stmt.rfind(')')
            if open_paren >= 0 and close_paren > open_paren:
                conjuncts = _split_and(stmt[open_paren + 1:close_paren])
                kept: list[str] = []
                changed = False
                for conj in conjuncts:
                    mentioned = {symbol for symbol in symbols if re.search(rf'\b{re.escape(symbol)}\b', conj)}
                    other = set(re.findall(r'__vulgate_snap_(?:arg|code)_\w+', conj))
                    literal_only = bool(mentioned) and other <= symbols and bool(re.search(r'\d', conj)) and '__vg_in_' not in conj and '__vulgate_snap_sym[' not in conj
                    if literal_only:
                        changed = True
                        continue
                    kept.append(conj.strip())
                if changed:
                    if kept:
                        indent = line[:len(line) - len(line.lstrip())]
                        lines.append(indent + f'__CPROVER_assume({" && ".join(kept)});')
                    continue
        lines.append(line)
    return '\n'.join(lines)


_LOCAL_NOISE = {
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default', 'return', 'sizeof', 'memset',
    'static', 'const', 'volatile', 'unsigned', 'signed', 'struct', 'union', 'enum', 'extern', 'register',
    'void', 'int', 'char', 'long', 'short', 'float', 'double', '_Bool', 'size_t', 'NULL',
}


def _split_statements(text: str) -> list[tuple[str, bool]]:
    parts: list[tuple[str, bool]] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch in '({[':
            depth += 1
            buf.append(ch)
        elif ch in ')}]':
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ';' and depth == 0:
            parts.append((''.join(buf), True))
            buf = []
        else:
            buf.append(ch)
    tail = ''.join(buf)
    if tail.strip():
        parts.append((tail, False))
    return parts


def _split_commas(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch in '({[':
            depth += 1
        elif ch in ')}]':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            parts.append(''.join(buf))
            buf = []
            continue
        buf.append(ch)
    tail = ''.join(buf)
    if tail.strip():
        parts.append(tail)
    return parts


def _declaration_names(statement: str) -> list[str]:
    text = statement.strip()
    if not text or re.match(r'(if|while|for|return|switch|memset)\b', text):
        return []
    left = text.split('=', 1)[0]
    if '(' in left:
        return []
    parts = _split_commas(left)
    names: list[str] = []
    for index, part in enumerate(parts):
        stripped = part.strip()
        match = re.search(r'(\*+\s*)?([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$', stripped)
        if not match:
            continue
        prefix = stripped[:match.start()]
        if re.search(r'[.>()]', prefix):
            continue
        if index == 0 and not re.search(r'[A-Za-z_]\w*', prefix):
            continue
        names.append(match.group(2))
    return names


def _expand_declarators(statement: str) -> list[str]:
    if '=' in statement or '(' in statement:
        return [statement]
    parts = _split_commas(statement)
    if len(parts) <= 1:
        return [statement]
    first = parts[0]
    stripped_first = first.strip()
    match = re.search(r'(\*+\s*)?([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$', stripped_first)
    if not match:
        return [statement]
    prefix = stripped_first[:match.start()].strip()
    if not prefix or re.search(r'[.>()]', prefix):
        return [statement]
    indent = re.match(r'\s*', statement).group(0)
    expanded = [first.strip()]
    for part in parts[1:]:
        expanded.append(f'{prefix} {part.strip()}')
    return [indent + item if index else item for index, item in enumerate(expanded)]


def _bare_idents(statement: str) -> list[str]:
    scrubbed = re.sub(r'(?:\.|->)\s*[A-Za-z_]\w*', '', statement)
    return re.findall(r'\b[A-Za-z_]\w*\b', scrubbed)


def _statement_mentions(statement: str, declared: set[str]) -> set[str]:
    return set(_bare_idents(statement)) & declared


def _statement_is_anchored(statement: str, declared: set[str]) -> bool:
    names = _declaration_names(statement)
    if names and '(' not in statement.split('=', 1)[0]:
        if '=' not in statement:
            return False
        rhs = statement.split('=', 1)[1]
        return any(ident not in declared and ident not in _LOCAL_NOISE for ident in _bare_idents(rhs))
    calls = set(re.findall(r'\b([A-Za-z_]\w*)\s*\(', statement)) - {'sizeof', 'memset', 'if', 'while', 'for', 'switch', 'return'}
    if calls:
        return True
    for ident in _bare_idents(statement):
        if ident not in declared and ident not in _LOCAL_NOISE:
            return True
    return False


def _drop_unreferenced_locals(source: str) -> str:
    spans: list[tuple[int, int]] = []
    depth = 0
    start = None
    for index, ch in enumerate(source):
        if ch == '{':
            if depth == 0:
                start = index
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                previous = start - 1
                while previous >= 0 and source[previous].isspace():
                    previous -= 1
                if previous >= 0 and source[previous] == ')':
                    spans.append((start, index + 1))
                start = None
    if not spans:
        return source
    pieces: list[str] = []
    cursor = 0
    for body_start, body_end in spans:
        pieces.append(source[cursor:body_start])
        body = source[body_start + 1:body_end - 1]
        statements: list[tuple[str, bool]] = []
        for statement, terminated in _split_statements(body):
            statements.extend((item, terminated) for item in _expand_declarators(statement))
        declared: set[str] = set()
        for statement, _terminated in statements:
            declared.update(_declaration_names(statement))
        live: set[str] = set()
        changed = True
        while changed:
            changed = False
            for statement, _terminated in statements:
                mentioned = _statement_mentions(statement, declared)
                if not mentioned:
                    continue
                if _statement_is_anchored(statement, declared) or (mentioned & live):
                    if not mentioned <= live:
                        live |= mentioned
                        changed = True
        kept: list[str] = []
        for statement, terminated in statements:
            mentioned = _statement_mentions(statement, declared)
            names = _declaration_names(statement)
            if names and all(name not in live for name in names) and not _statement_is_anchored(statement, declared):
                continue
            if mentioned and not (mentioned & live) and not _statement_is_anchored(statement, declared):
                continue
            item = statement.strip()
            if not item:
                continue
            if terminated and not item.endswith(';'):
                item += ';'
            kept.append(item)
        pieces.append('{\n' + '\n'.join(f'    {item}' for item in kept) + '\n}')
        cursor = body_end
    pieces.append(source[cursor:])
    return ''.join(pieces)


def _arm_allocator_coupling(source: str) -> str:
    if not any(token in source for token in ('ngx_palloc(', 'apr_palloc(', '_emalloc(')):
        return source
    source = _insert_world_prologue(source, '__vg_run_world_0', '    __vg_alloc_enter_world(0);')
    patched = '    __vg_alloc_enter_world(1);'
    if '__vg_brigade_last' in source:
        patched += '\n    __vg_brigade_last = 0;'
    source = _insert_world_prologue(source, '__vg_run_world_1', patched)
    return source


def _drop_copied_global_assignments(source: str, names: list[str]) -> str:
    copied = {str(name) for name in names}
    if not copied:
        return source
    name_re = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.|->)')
    kept_lines: list[str] = []
    for line in source.split('\n'):
        content = line.strip()
        if ';' not in content:
            kept_lines.append(line)
            continue
        statements = [part.strip() for part in content.split(';') if part.strip()]
        kept = []
        dropped = False
        for stmt in statements:
            match = name_re.match(stmt)
            left = stmt.split('=', 1)[0].strip()
            if match and match.group(1) in copied and '=' in stmt and name_re.match(left):
                dropped = True
                continue
            kept.append(stmt)
        if not dropped:
            kept_lines.append(line)
            continue
        if kept:
            indent = line[:len(line) - len(line.lstrip())]
            kept_lines.append(indent + '; '.join(kept) + ';')
    return '\n'.join(kept_lines)


def _bind_code_length_symbol(source: str, symbol: str) -> str:
    pending: list[str] = []
    for line in source.split('\n'):
        if '->len' not in line or '=' not in line:
            continue
        rhs = line.split('=', 1)[1]
        for ident in re.findall(r'\b[A-Za-z_]\w*\b', rhs):
            if ident not in ('uintptr_t', 'size_t', 'uint64_t', 'uint32_t'):
                pending.append(ident)
    functions = _function_parameters(source)
    found: list[str] = []
    seen: set[str] = set()
    while pending:
        ident = pending.pop()
        if ident in seen:
            continue
        seen.add(ident)
        if ident.startswith('__vg_in_'):
            found.append(ident)
            continue
        for fname, params in functions.items():
            if ident not in params:
                continue
            index = params.index(ident)
            for args in _iter_call_args(source, fname):
                if index >= len(args):
                    continue
                arg = args[index].strip()
                if re.fullmatch(r'[A-Za-z_]\w*', arg):
                    pending.append(arg)
                else:
                    pending.extend(re.findall(r'__vg_in_\w+', arg))
    if not found:
        return source
    return _apply_scalar_input_binding(source, [(token, symbol) for token in found])


_SETUP_TYPE_WORDS = {
    'void', 'int', 'char', 'long', 'short', 'unsigned', 'signed', 'size_t', 'uintptr_t',
    'uint64_t', 'uint32_t', 'uint8_t', 'u_char', 'ngx_uint_t',
}


def _code_buffer_argument_names(source: str, abstract: dict[str, Any] | None) -> list[str]:
    if not abstract:
        return []
    cut = str(abstract.get('cut_function') or '')
    names = list(abstract.get('parameter_names') or [])
    roots = abstract.get('roots') or {}
    objects = abstract.get('objects') or {}
    if not cut or not names or not isinstance(roots, dict):
        return []
    code_params = set()
    for name in names:
        info = roots.get(name) or {}
        ref = (info or {}).get('ref') or {}
        obj = objects.get(ref.get('object_id')) or {}
        if (obj.get('code_words') or obj.get('byte_buffer') or obj.get('pointer_words')) and _typed_pointer_root(info, objects):
            code_params.add(str(name))
    found: list[str] = []
    for args in _iter_call_args(source, cut):
        if len(args) != len(names):
            continue
        for arg, pname in zip(args, names):
            if str(pname) not in code_params:
                continue
            idents = [item for item in re.findall(r'\b[A-Za-z_]\w*\b', arg) if item not in _SETUP_TYPE_WORDS]
            if len(idents) == 1 and idents[0] not in found:
                found.append(idents[0])
    return found


def _drop_named_setup(source: str, names: list[str]) -> str:
    banned = {str(name) for name in names}
    if not banned:
        return source
    while True:
        fresh: set[str] = set()
        kept_lines: list[str] = []
        for line in source.split('\n'):
            if ';' not in line:
                kept_lines.append(line)
                continue
            kept = []
            for stmt in [part.strip() for part in line.split(';') if part.strip()]:
                if any(re.search(rf'\b{re.escape(name)}\b', stmt) for name in banned):
                    for declared in _declaration_names(stmt):
                        if declared not in banned:
                            fresh.add(declared)
                    continue
                kept.append(stmt)
            if kept:
                indent = line[:len(line) - len(line.lstrip())]
                kept_lines.append(indent + '; '.join(kept) + ';')
        source = '\n'.join(kept_lines)
        if not fresh:
            return source
        banned |= fresh


def _wrapper_for_symbol(source: str, symbol: str) -> str | None:
    pattern = re.compile(r'\b(vg_[A-Za-z0-9_]+)\s*\([^;{}]*\)\s*\{')
    for match in pattern.finditer(source):
        start = match.end() - 1
        depth = 0
        for pos in range(start, len(source)):
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
                if depth == 0:
                    if re.search(rf'\b{re.escape(symbol)}\s*\(', source[start:pos]):
                        return match.group(1)
                    break
    return None


def _retarget_code_wrappers(prologue: str, source: str, symbols: list[str]) -> str:
    for symbol in symbols:
        wrapper = _wrapper_for_symbol(source, symbol)
        if wrapper and wrapper != symbol:
            prologue = prologue.replace(f'&{symbol}', f'&{wrapper}')
    return prologue


def _drop_unbacked_input_bounds(source: str) -> str:
    lines: list[str] = []
    for line in source.split('\n'):
        stmt = line.strip()
        if not (stmt.startswith('__CPROVER_assume(') and '__vg_in_' in stmt and stmt.endswith(';')):
            lines.append(line)
            continue
        open_paren = stmt.find('(')
        close_paren = stmt.rfind(')')
        conjuncts = _split_and(stmt[open_paren + 1:close_paren])
        kept: list[str] = []
        changed = False
        for conj in conjuncts:
            if '__vg_in_' in conj and '__vulgate_snap_' not in conj:
                changed = True
                continue
            kept.append(conj.strip())
        if not changed:
            lines.append(line)
            continue
        if not kept:
            continue
        indent = line[:len(line) - len(line.lstrip())]
        lines.append(indent + f'__CPROVER_assume({" && ".join(kept)});')
    return '\n'.join(lines)


def _drop_snapshot_setup_calls(source: str, root_names: list[str]) -> str:
    if 'vg_setup_' not in source:
        return source
    kept_lines: list[str] = []
    for line in source.split('\n'):
        if ';' not in line or 'vg_setup_' not in line:
            kept_lines.append(line)
            continue
        kept = []
        for stmt in [part.strip() for part in line.split(';') if part.strip()]:
            feeds_snapshot = '__vulgate_snap_root_' in stmt or any(
                re.search(rf'&{re.escape(name)}\b', stmt) for name in root_names
            )
            if re.search(r'\bvg_setup_[A-Za-z0-9_]*\s*\(', stmt) and feeds_snapshot:
                continue
            kept.append(stmt)
        if not kept:
            continue
        indent = line[:len(line) - len(line.lstrip())]
        kept_lines.append(indent + '; '.join(kept) + ';')
    return '\n'.join(kept_lines)


def _prototype_parts(source: str, cut: str) -> list[str]:
    pattern = re.compile(rf'\b{re.escape(cut)}\s*\(([^;{{]*)\)\s*(?:;|\{{)')
    match = pattern.search(source)
    if not match:
        return []
    return _split_call_args(match.group(1))


def _pointer_pointee(part: str) -> str:
    if '*' not in part:
        return ''
    head = part.split('*', 1)[0]
    head = re.sub(r'\b(?:const|volatile|register|static|struct|union|enum)\b', '', head)
    return ' '.join(head.split())


def _unique_pointer_field(abstract: dict[str, Any], name: str) -> tuple[str, int] | None:
    objects = abstract.get('objects') or {}
    if not isinstance(objects, dict):
        return None
    selected = set(_selected_object_ids(abstract))
    hits: list[tuple[str, int]] = []
    for oid, obj in objects.items():
        if oid not in selected or not isinstance(obj, dict):
            continue
        for fname, finfo in (obj.get('fields') or {}).items():
            if str(fname).split('.')[-1] != name or not isinstance(finfo, dict):
                continue
            ref = finfo.get('ref') or {}
            if finfo.get('kind') != 'pointer' or ref.get('kind') != 'object_ref':
                continue
            target_id = str(ref.get('object_id') or '')
            if target_id not in selected:
                continue
            target = objects.get(target_id) or {}
            if (
                str(target.get('c_type') or '') == 'void'
                and int(target.get('byte_size') or 1) <= 1
                and not target.get('code_words')
                and not target.get('byte_buffer')
            ):
                continue
            hits.append((target_id, int(ref.get('offset') or 0)))
    if len(hits) != 1:
        return None
    return hits[0]


def _unrooted_pointer_parameters(source: str, abstract: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not abstract:
        return []
    cut = str(abstract.get('cut_function') or '')
    names = list(abstract.get('parameter_names') or [])
    roots = abstract.get('roots') or {}
    if not cut or not names or not isinstance(roots, dict):
        return []
    parts = _prototype_parts(source, cut)
    found: list[dict[str, Any]] = []
    for index, name in enumerate(names):
        if not _C_IDENT.match(str(name)):
            continue
        info = roots.get(name)
        if isinstance(info, dict) and info.get('kind') == 'pointer':
            continue
        if index >= len(parts):
            continue
        pointee = _pointer_pointee(parts[index])
        if not pointee or pointee == 'void' or '*' in pointee:
            continue
        if not re.fullmatch(r'[A-Za-z_][\w ]*', pointee):
            continue
        field_target = _unique_pointer_field(abstract, str(name))
        if field_target:
            found.append({
                'name': str(name),
                'c_type': pointee,
                'kind': 'field',
                'object_id': field_target[0],
                'offset': field_target[1],
            })
            continue
        found.append({'name': str(name), 'c_type': pointee, 'kind': 'fresh'})
    return found


def _install_unrooted_pointers(rendered: dict[str, Any], params: list[dict[str, Any]]) -> None:
    if not params:
        return
    lines: list[str] = []
    for item in params:
        name = _c_ident(item['name'])
        lines.append(f'static void *__vulgate_snap_root_{name};')
        if item['kind'] == 'fresh':
            lines.append(f'static {item["c_type"]} __vulgate_fresh_w0_{name};')
            lines.append(f'static {item["c_type"]} __vulgate_fresh_w1_{name};')
    rendered['code'] += '\n'.join(lines) + '\n'
    for world in ('0', '1'):
        assigns: list[str] = []
        for item in params:
            name = _c_ident(item['name'])
            if item['kind'] == 'field':
                base = f'__vulgate_snap_w{world}_{_c_ident(item["object_id"])}'
                assigns.append(f'    __vulgate_snap_root_{name} = (void *)({base} + {int(item["offset"])});')
            else:
                assigns.append(f'    __vulgate_snap_root_{name} = &__vulgate_fresh_w{world}_{name};')
        rendered['world_prologue'][world] += '\n' + '\n'.join(assigns)
    rendered['roots'] = list(rendered['roots']) + [item['name'] for item in params]


def apply_snapshot_state(source: str, abstract_snapshot: dict[str, Any] | None) -> str:
    rendered = render_snapshot_state_c(abstract_snapshot)
    if not rendered['code']:
        return _arm_allocator_coupling(source)
    replaced_buffers = _code_buffer_argument_names(source, abstract_snapshot)
    param_types = _cut_parameter_types(source, str((abstract_snapshot or {}).get('cut_function') or ''))
    unrooted = _unrooted_pointer_parameters(source, abstract_snapshot)
    _install_unrooted_pointers(rendered, unrooted)
    source = _drop_copied_global_assignments(source, rendered.get('globals') or [])
    source = _drop_snapshot_root_setup(source, rendered['roots'], _untyped_root_fields(abstract_snapshot))
    source = _rebind_root_locals(source, rendered['roots'])
    source = _rebind_cut_arguments(
        source,
        abstract_snapshot or {},
        param_types,
        [item['name'] for item in unrooted],
    )
    if rendered.get('code_len_symbol'):
        source = _bind_code_length_symbol(source, str(rendered['code_len_symbol']))
    source = _drop_named_setup(source, replaced_buffers)
    source = _drop_snapshot_setup_calls(source, rendered['roots'])
    source = _drop_unbacked_input_bounds(source)
    source = _drop_unreferenced_locals(source)
    for name in rendered['roots']:
        source = '\n'.join(
            line if 'memset' in line else re.sub(
                rf'&{name}\b',
                f'((void *)__vulgate_snap_root_{name})',
                line,
            )
            for line in source.split('\n')
        )
    symbols = list(rendered.get('code_word_symbols') or [])
    source = _insert_world_prologue(source, '__vg_run_world_0', _retarget_code_wrappers(rendered['world_prologue']['0'], source, symbols))
    source = _insert_world_prologue(source, '__vg_run_world_1', _retarget_code_wrappers(rendered['world_prologue']['1'], source, symbols))
    source = _arm_allocator_coupling(_insert_after_includes(source, rendered['code']))
    marker = 'static void __vulgate_instantiate_snapshot(int __vulgate_world) {'
    if '__vulgate_snap_lits(void)' in source and marker in source:
        source = source.replace(marker, marker + '\n    __vulgate_snap_lits();', 1)
    return source
