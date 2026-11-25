import json
import re
from pathlib import Path


def describe_mounts(dsl_path: Path) -> list[dict]:
    from runtime.dsl import parser as dsl_parser

    patch = dsl_parser.load(Path(dsl_path))
    described = []
    for mount in patch.mounts:
        nature = 'read_point' if mount.nature in ('读取点', 'read_point') else 'intercept'
        local_slots = {name: index for index, name in enumerate(mount.local_recipes)}
        sets = []
        reads: dict[tuple[str, int], dict] = {}
        if nature == 'read_point':
            for line in mount.body.splitlines():
                matched = re.match(
                    r'\s*map\["([^"]+)"\]\[arg(\d+)\]\s*=\s*local\("([^"]+)"\)\s*;',
                    line,
                )
                if not matched:
                    continue
                sets.append({
                    'map': matched.group(1),
                    'key_arg': int(matched.group(2)),
                    'value_slot': local_slots.get(matched.group(3), 0),
                })
        else:
            seen: dict[tuple[str, int], dict] = {}
            for kind, map_name, arg in re.findall(
                r'map_(take|get|present)\("([^"]+)",\s*arg(\d+)\)',
                mount.body,
            ):
                key = (map_name, int(arg))
                entry = seen.get(key)
                if entry is None:
                    entry = {'map': map_name, 'key_arg': int(arg), 'consume': False, 'present': False, 'value': False}
                    seen[key] = entry
                if kind == 'present':
                    entry['present'] = True
                else:
                    entry['value'] = True
                    entry['consume'] = entry['consume'] or kind == 'take'
            slot = 0
            for entry in seen.values():
                if entry['value']:
                    entry['slot'] = slot
                    slot += 1
                if entry['present']:
                    entry['present_slot'] = slot
                    slot += 1
                reads[(entry['map'], entry['key_arg'])] = {
                    'map': entry['map'],
                    'key_arg': entry['key_arg'],
                    'consume': entry['consume'],
                    **({'slot': entry['slot']} if 'slot' in entry else {}),
                    **({'present_slot': entry['present_slot']} if 'present_slot' in entry else {}),
                }
        described.append({
            'id': mount.id,
            'nature': nature,
            'sets': sets,
            'reads': list(reads.values()),
        })
    return described


def telemetry_source(bridge: str, mounts: list[dict]) -> str:
    spec = []
    for mount in mounts:
        spec.append({
            'id': mount['id'],
            'target': mount['target'],
            'nature': mount.get('nature') or 'intercept',
            'sets': mount.get('sets') or [],
            'reads': mount.get('reads') or [],
        })
    return r'''
'use strict';
const bridge = Module.load(%s);
const runAddr = bridge.getExportByName('vg_run_with_maps');
const lastReadCount = new NativeFunction(bridge.getExportByName('vg_last_read_count'), 'uint', []);
const copyLastReads = new NativeFunction(bridge.getExportByName('vg_copy_last_reads'), 'uint', ['pointer', 'uint']);
const mounts = %s;
const stack = [];
const pending = [];

function readWords(pointer, count) {
  const words = [];
  for (let index = 0; index < count; index++) {
    try {
      words.push(pointer.add(index * 8).readU64().toString());
    } catch (error) {
      words.push('0');
    }
  }
  return words;
}

function decisionName(code) {
  if (code === 0) return 'PASS';
  if (code === 1) return 'BLOCK';
  if (code === 2) return 'UNKNOWN';
  return 'VM_ERROR';
}

Interceptor.attach(runAddr, {
  onEnter(args) {
    this.stats = args[6];
    this.captured = {
      args: readWords(args[1], 6),
      slots: readWords(args[2], 16),
    };
  },
  onLeave(retval) {
    const decision = retval.toInt32();
    let instructions = '0';
    let safeReads = '0';
    try {
      instructions = this.stats.readU64().toString();
      safeReads = this.stats.add(8).readU64().toString();
    } catch (error) {
    }
    const readCount = lastReadCount();
    const readBuf = Memory.alloc(Math.max(readCount, 1) * 24);
    const copied = copyLastReads(readBuf, readCount);
    const memoryReads = [];
    for (let index = 0; index < copied; index++) {
      const entry = readBuf.add(index * 24);
      memoryReads.push({
        address: entry.readU64().toString(),
        value: entry.add(8).readU64().toString(),
        width: entry.add(16).readU32(),
        rc: entry.add(20).readS32(),
      });
    }
    const record = {
      decision: decision,
      instructions: instructions,
      safe_reads: safeReads,
      args: this.captured.args,
      slots: this.captured.slots,
      memory_reads: memoryReads,
    };
    if (stack.length) stack[stack.length - 1].vm = record;
    else pending.push(record);
  },
});

function emitFrame(spec, frame) {
      const vm = frame.vm || {decision: 0, instructions: '0', safe_reads: '0', args: ['0','0','0','0','0','0'], slots: [], memory_reads: []};
      while (vm.slots.length < 16) vm.slots.push('0');
      while (vm.args.length < 6) vm.args.push('0');
      const code = vm.decision | 0;
      const safeReads = parseInt(vm.safe_reads, 10) || 0;
      const instructions = parseInt(vm.instructions, 10) || 0;
      const memoryReads = vm.memory_reads || [];
      if (frame.nature === 'read_point') {
        const assignment = (spec.sets || [])[0] || null;
        const key = assignment ? vm.args[assignment.key_arg] : '0';
        const value = assignment ? vm.slots[assignment.value_slot] : '0';
        send({
          event: 'observation',
          hook: frame.id,
          id: frame.id,
          map: assignment ? assignment.map : '',
          scope: 0,
          key: key,
          operation: 'set',
          result: assignment ? 0 : 1,
          value: value,
          vm_decision: code,
          decision: decisionName(code),
          instructions: instructions,
          safe_reads: safeReads,
          snapshot: {args: vm.args, slots: vm.slots.slice(0, 16), map_reads: [], memory_reads: memoryReads},
        });
        return;
      }
      const mapReads = (spec.reads || []).map((read) => {
        const present = read.present_slot === undefined ? 1 : (parseInt(vm.slots[read.present_slot], 10) ? 1 : 0);
        return {
          map: read.map,
          scope: 0,
          key: vm.args[read.key_arg],
          slot: read.slot,
          consume: !!read.consume,
          found: present,
          value: present && read.slot !== undefined ? vm.slots[read.slot] : '0',
        };
      });
      send({
        event: 'decision',
        hook: frame.id,
        id: frame.id,
        action: code === 1 ? 'BLOCK' : 'PASS',
        decision: decisionName(code),
        vm_decision: code,
        instructions: instructions,
        safe_reads: safeReads,
        snapshot: {args: vm.args, slots: vm.slots.slice(0, 16), map_reads: mapReads, memory_reads: memoryReads},
      });
}

for (const spec of mounts) {
  Interceptor.attach(ptr(spec.target), {
    onEnter() {
      const frame = {id: spec.id, nature: spec.nature, vm: pending.length ? pending.shift() : null};
      if (spec.nature === 'read_point') {
        emitFrame(spec, frame);
        return;
      }
      stack.push(frame);
    },
    onLeave() {
      if (spec.nature === 'read_point' || !stack.length) return;
      const frame = stack.pop();
      if (frame.id !== spec.id) {
        stack.push(frame);
        return;
      }
      if (!frame.vm && pending.length) frame.vm = pending.shift();
      emitFrame(spec, frame);
    },
  });
}

rpc.exports = {
  install: function () {
    return {attached: mounts.length};
  },
};
''' % (json.dumps(str(bridge)), json.dumps(spec))


def attach_telemetry(session, bridge, mounts, on_message):
    script = session.create_script(telemetry_source(bridge, list(mounts or [])))
    script.on('message', on_message)
    script.load()
    script.exports_sync.install()
    return script
