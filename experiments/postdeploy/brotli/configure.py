import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools.postdeploy.binding import bind_callsite
from tools.postdeploy.expressions import compile_guard

GUARD = ('remaining <= 2147483647 and (sample_present == 0 or occupied > capacity or '
         'last_in < next_in or (occupied == 0 and last_in - next_in > capacity) or '
         '(occupied > 0 and occupied == capacity and last_in > next_in and available_in > 0))')
FIELDS = {name: {'source': 'arg', 'index': i} for i, name in
          enumerate(('remaining', 'occupied', 'capacity', 'next_in', 'last_in'))}
FIELDS.update(available_in={'source': 'slot', 'index': 0}, sample_present={'source': 'slot', 'index': 1})


def configure(output, bridge):
    output = output.resolve()
    library = output / 'baseline/libpd_brotli.so'
    layout = json.loads((output / 'layout.json').read_text())
    binding = bind_callsite(library, 'BrotliDecoderDecompressStream', 'WriteRingBuffer', 2426, 'available_in', 's')
    (output / 'binding.json').write_text(json.dumps(binding, indent=2) + '\n')
    rule = compile_guard(GUARD, FIELDS)
    (output / 'policy.bin').write_bytes(rule)
    common = {'module': library.name}
    def field(name, typ): return {'arg': 0, 'reads': [{'offset': layout[name], 'type': typ}]}
    manifest = {'schema': 1, 'bridge': str(bridge.resolve()), 'telemetry': True,
                'maps': {'current_input': {'capacity': 64, 'thread_scoped': True}},
                'observers': [dict(common, id='before_refill', offset=binding['observation_offset'], arg_types=[],
                    map='current_input', operation='set',
                    key={'register': 'rbp', 'reads': [{'offset': binding['key_rbp_offset'], 'type': 'pointer'}]},
                    value={'register': 'rbp', 'reads': [
                        {'offset': binding['parameter_rbp_offset'], 'type': 'pointer'},
                        {'offset': 0, 'type': 'u64'}]})],
                'guards': [dict(common, id='refill_capacity', offset=binding['callee_offset'],
                    return_offsets=[binding['return_offset']], arg_types=['pointer'] * 4 + ['int'],
                    return_type='int', action_id='refill_fatal', rule='policy.bin',
                    vm_args=[field('remaining', 's32'), field('occupied', 'u64'),
                             {'constant': layout['capacity']}, field('next_in', 'pointer'), field('last_in', 'pointer')],
                    observations=[{'map': 'current_input', 'key_arg': 0, 'slot': 0,
                                   'present_slot': 1, 'consume': True}])],
                'artifact_pins': {str(library): hashlib.sha256(library.read_bytes()).hexdigest()}}
    (output / 'patch.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'actions.json').write_text(json.dumps({'schema': 1, 'actions': {
        'refill_fatal': {'kind': 'return_int', 'value': layout['fatal']}}}, indent=2) + '\n')
    (output / 'guard.json').write_text(json.dumps({'expression': GUARD, 'fields': FIELDS,
        'bytecode_sha256': hashlib.sha256(rule).hexdigest()}, indent=2) + '\n')
    print(json.dumps(binding))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--bridge', type=Path, required=True)
    a = p.parse_args()
    configure(a.output, a.bridge)
