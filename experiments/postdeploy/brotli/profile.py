"""Generate the reproducible application profile; no impact region is specified."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def make(folder, cbmc):
    folder = folder.resolve()
    names = [('position', 16), ('remaining', 4), ('occupied', 8),
             ('unread', 8), ('available_in', 2), ('output_capacity', 16)]
    return {
        'schema': 1, 'name': 'brotli-streaming',
        'patch': str(folder / 'patch.json'), 'catalog': str(folder / 'actions.json'),
        'guard': str(folder / 'guard.json'), 'bridge': str(ROOT / 'build/frida-linux/vulgate_frida.so'),
        'workers': {mode: [str(folder / ('reference' if mode == 'reference' else 'baseline') / 'worker')]
                    for mode in ['baseline', 'patched', 'reference']},
        'adapter': 'experiments.postdeploy.brotli.corpus',
        'encoder': str(folder / 'encoder'), 'seed': 20261112, 'fuzz_cases': 24,
        'adaptive_cases': 12,
        'build_records': [str(folder / name) for name in ['build.json', 'binding.json', 'layout.json']] +
                         [str(ROOT / 'build/postdeploy-sources/brotli/source-receipt.json')],
        'progress': [{'field': 'calls', 'min': 1, 'max': 99999}],
        'empty_maps_after_episode': ['current_input'],
        'comparison_fields': ['result', 'error', 'consumed', 'produced', 'total_out', 'output_hex'],
        'symbolic': {
            'scope': 'bounded real WriteRingBuffer entry-state relation; upstream streaming reachability unproved',
            'state_contract': 'independent_local_objects',
            'adapter_source': str(ROOT / 'experiments/postdeploy/brotli/symbolic_adapter.c'),
            'hook_function': 'WriteRingBuffer',
            'operation_roots': ['BrotliDecoderDecompressStream'],
            'hook_parameters': ['s', 'available_out', 'next_out', 'total_out', 'force'],
            'typed_fields': {str(i): {'type': 'BrotliDecoderState', 'member': member} for i, member in
                             [(0, 'meta_block_remaining_len'), (1, 'buffer_length'), (3, 'br.next_in'), (4, 'br.last_in')]},
            'cppflags': ['-I' + str(ROOT / 'build/postdeploy-sources/brotli/baseline/c/include'),
                         '-I' + str(ROOT / 'build/postdeploy-sources/brotli/baseline/c/dec')],
            'cbmc': str(cbmc), 'timeout': 120, 'unwind': 70, 'max_regions': 4,
            'inputs': [{'name': name, 'min': 0, 'max': maximum} for name, maximum in names],
            'outputs': ['return', 'available_out', 'total_out', 'partial_pos_out', 'position',
                        'roundtrips', 'wrap', 'produced'] + ['byte_' + str(i) for i in range(16)],
            'field_expressions': {'remaining': 'remaining', 'occupied': 'occupied', 'capacity': '8',
                                  'next_in': '0', 'last_in': 'unread', 'available_in': 'available_in',
                                  'sample_present': '1'},
            'vm_arg_names': ['remaining', 'occupied', 'capacity', 'next_in', 'last_in'],
            'slot_names': {'0': 'available_in'},
            'snapshot_to_symbolic_exprs': {'unread': 'last_in - next_in'},
        },
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'build/postdeploy-brotli')
    parser.add_argument('--cbmc', type=Path, required=True)
    args = parser.parse_args()
    (args.output / 'profile.json').write_text(json.dumps(make(args.output, args.cbmc), indent=2) + '\n')
