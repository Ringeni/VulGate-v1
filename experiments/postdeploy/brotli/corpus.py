"""Normal functional corpus: mutate plain data and streaming schedules, then encode."""
import hashlib
import random
import subprocess


def cases(profile, directory, analysis, feedback):
    directory.mkdir(parents=True, exist_ok=True)
    rng = random.Random(profile['seed'])
    seeds = [b'', b'A', b'ordinary text\n' * 32,
             b'{"name":"roundtrip","active":true,"count":32}\n' * 16,
             '正常压缩与流式解压\n'.encode() * 32, bytes(range(256)) * 4,
             b'Z' * 4096]
    schedules = [(1, 7, 1), (4096, 4096, 0), (7, 1, 0)]
    samples = [(data, [0, 5, 11][i % 3], *schedule, 'regression')
               for i, data in enumerate(seeds) for schedule in schedules]
    for i in range(profile.get('fuzz_cases', 24)):
        size = rng.choice([0, 1, 7, 8, 9, 31, 128, 257, 1024, 2048])
        data = bytes(rng.randrange(256) for _ in range(size)) if i % 2 else bytes([rng.randrange(32, 127)]) * size
        samples.append((data, rng.choice([0, 3, 5, 9, 11]), rng.choice([1, 2, 7, 8, 9, 64, 4096]),
                        rng.choice([1, 7, 8, 9, 64, 4096]), rng.randrange(2), 'structured_fuzz'))
    # Small input chunks preferentially visit the internal refill path. The
    # baseline corpus remains in the run even if analysis reports no impact.
    if analysis['potential_impact']:
        samples.sort(key=lambda row: row[2])
    total = len(samples) + profile.get('adaptive_cases', 12)
    for index in range(total):
        parent = None
        if index < len(samples):
            data, quality, chunk_in, chunk_out, first_zero, origin = samples[index]
        else:
            # Solver witnesses rank observed states, never become compressed
            # payloads. Mutations retain the encoder's validity contract.
            parents = sorted(feedback, key=lambda f: (
                f['impact_distance'] is None,
                f['impact_distance'] if f['impact_distance'] is not None else float('inf'),
                -f['new_edges']))[:6]
            parent = parents[(index - len(samples)) % len(parents)]['case']
            fields = parent['input']
            data = (directory / ('%03d.plain' % int(parent['id']))).read_bytes()
            chunk_in = max(1, fields['input_chunk'] + rng.choice([-1, 1, 7]))
            chunk_out = max(1, fields['output_chunk'] + rng.choice([-1, 1, 8]))
            quality, first_zero = fields['quality'], 1 - fields['first_output_zero']
            origin = 'impact_and_coverage_guided_fuzz'
        plain, encoded = directory / ('%03d.plain' % index), directory / ('%03d.br' % index)
        plain.write_bytes(data)
        subprocess.run([profile['encoder'], str(plain), str(encoded), str(quality)], check=True)
        yield {'id': str(index), 'origin': origin, 'parent_id': parent['id'] if parent else None,
               'command': f'{index} {encoded} {plain} {chunk_in} {chunk_out} {first_zero}',
               'expected': {'result': 1, 'error': 1, 'produced': len(data), 'total_out': len(data),
                            'consumed': encoded.stat().st_size, 'output_hex': data.hex(), 'matches_expected': True},
               'input': {'size': len(data), 'quality': quality, 'input_chunk': chunk_in,
                         'output_chunk': chunk_out, 'first_output_zero': first_zero,
                         'plain_sha256': hashlib.sha256(data).hexdigest(),
                         'compressed_sha256': hashlib.sha256(encoded.read_bytes()).hexdigest()}}
