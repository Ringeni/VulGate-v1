import ctypes
from pathlib import Path


class _VGReadEntry(ctypes.Structure):
    _fields_ = [
        ('address', ctypes.c_uint64),
        ('value', ctypes.c_uint64),
        ('width', ctypes.c_uint32),
        ('rc', ctypes.c_int32),
    ]


def decision_blocked_by_full_map(event: dict) -> bool:
    return event.get('action') == 'BLOCK' and event.get('diagnostic') == 'observation_map_full'


class VMReplay:
    def __init__(self, bridge, rules):
        self.lib = ctypes.CDLL(str(bridge))
        self.lib.vg_program_create.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        self.lib.vg_program_create.restype = ctypes.c_void_p
        self.lib.vg_program_destroy.argtypes = [ctypes.c_void_p]
        self.lib.vg_run.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p]
        self._has_read_replay = hasattr(self.lib, 'vg_set_replay_reads')
        if self._has_read_replay:
            self.lib.vg_set_replay_reads.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            self.lib.vg_set_replay_reads.restype = None
        self.handles = {}
        self.definitions = rules
        self.tables = {}
        for hook, definition in rules.items():
            code = Path(definition['path']).read_bytes()
            buffer = ctypes.create_string_buffer(code)
            handle = self.lib.vg_program_create(buffer, len(code))
            if not handle: raise ValueError('native VM rejected installed rule')
            self.handles[hook] = (handle, definition.get('step_limit', 4096))

    def check(self, events):
        violations, runtime_diagnostics = [], []
        decisions, observations, blocks, diagnostics = 0, 0, 0, 0
        for message in events:
            repeat = max(1, int(message.get('repeat') or 1))
            if message.get('type') == 'error':
                runtime_diagnostics.append({'kind': 'agent_error', 'detail': message.get('description'), 'count': repeat})
                diagnostics += repeat
                continue
            event = message.get('payload', {})
            if event.get('event') == 'diagnostic':
                diagnostics += repeat
                runtime_diagnostics.append({'kind': 'runtime_diagnostic', 'detail': event, 'count': repeat})
            if event.get('event') == 'observation':
                observations += repeat
                key = (event['map'], event['scope'], event['key'])
                if event['operation'] == 'delete': self.tables.pop(key, None)
                elif event['result'] == 0: self.tables[key] = int(event['value'])
            if event.get('event') != 'decision': continue
            decisions += repeat
            blocks += repeat if event['action'] == 'BLOCK' else 0
            diagnostics += repeat if event.get('diagnostic') else 0
            if decision_blocked_by_full_map(event):
                continue
            snapshot = event.get('snapshot')
            if not snapshot:
                violations.append({'kind': 'missing_decision_snapshot', 'hook': event['hook']})
                continue
            reads = snapshot.get('map_reads', [])
            references = self.definitions[event['hook']].get('observations')
            if references is not None and len(reads) != len(references):
                violations.append({'kind': 'missing_map_read', 'hook': event['hook']})
            for index, read in enumerate(reads):
                key = (read['map'], read['scope'], read['key'])
                expected = self.tables.get(key)
                if read['found'] != (expected is not None) or (expected is not None and expected != int(read['value'])):
                    violations.append({'kind': 'observation_replay_mismatch', 'hook': event['hook']})
                if read['consume']: self.tables.pop(key, None)
                if references is not None and index < len(references):
                    reference = references[index]
                    if read['map'] != reference['map'] or read['slot'] != reference['slot'] or bool(read['consume']) != bool(reference.get('consume')):
                        violations.append({'kind': 'observation_binding_mismatch', 'hook': event['hook']})
                    if int(snapshot['slots'][reference['slot']]) != (int(read['value']) if read['found'] else 0):
                        violations.append({'kind': 'observation_slot_mismatch', 'hook': event['hook']})
                    if 'present_slot' in reference and int(snapshot['slots'][reference['present_slot']]) != int(read['found']):
                        violations.append({'kind': 'observation_presence_mismatch', 'hook': event['hook']})
            safe_read_count = int(event['safe_reads'])
            mem_trace = snapshot.get('memory_reads')
            if safe_read_count and (not self._has_read_replay or mem_trace is None):
                violations.append({'kind': 'unreplayable_target_memory_read', 'hook': event['hook']})
                continue
            args = (ctypes.c_uint64 * 6)(*map(int, snapshot['args']))
            slots = (ctypes.c_uint64 * 16)(*map(int, snapshot['slots']))
            stats = (ctypes.c_uint64 * 3)()
            handle, limit = self.handles[event['hook']]
            if safe_read_count:
                arr = (_VGReadEntry * len(mem_trace))(
                    *[_VGReadEntry(int(r['address']), int(r['value']), int(r['width']), int(r['rc'])) for r in mem_trace]
                )
                self.lib.vg_set_replay_reads(arr, len(mem_trace))
            try:
                raw = self.lib.vg_run(handle, args, slots, limit, stats)
            finally:
                if safe_read_count and self._has_read_replay:
                    self.lib.vg_set_replay_reads(None, 0)
            if raw != int(event['vm_decision']) or ('BLOCK' if raw == 1 else 'PASS') != event['action']:
                violations.append({'kind': 'vm_replay_mismatch', 'hook': event['hook']})
            if stats[0] != int(event['instructions']):
                violations.append({'kind': 'vm_instruction_mismatch', 'hook': event['hook']})
            if stats[1] != safe_read_count:
                violations.append({'kind': 'vm_safe_read_count_mismatch', 'hook': event['hook']})
        return {'violations': violations, 'runtime_diagnostics': runtime_diagnostics,
                'decisions': decisions, 'observations': observations,
                'blocks': blocks, 'diagnostics': diagnostics}

    def close(self):
        for handle, _ in self.handles.values(): self.lib.vg_program_destroy(handle)
        self.handles.clear()


def compare(case, baseline, patched, reference, fields):
    failures = []
    for name, expected in case.get('expected', {}).items():
        for world, result in [('baseline', baseline), ('patched', patched), ('reference', reference)]:
            if result is not None and result.get(name) != expected:
                failures.append({'kind': 'contract', 'world': world, 'field': name,
                                 'expected': expected, 'actual': result.get(name)})
    for name in fields:
        if baseline.get(name) != patched.get(name):
            failures.append({'kind': 'functional_difference', 'field': name,
                             'baseline': baseline.get(name), 'patched': patched.get(name)})
        if reference is not None and reference.get(name) != patched.get(name):
            failures.append({'kind': 'reference_difference', 'field': name,
                             'reference': reference.get(name), 'patched': patched.get(name)})
    return failures
