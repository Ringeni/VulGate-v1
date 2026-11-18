"""Build the actual upstream decoder and ordinary functional workers on Linux."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def build(sources, output):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    commands = []
    def run(args):
        args = [str(x) for x in args]
        commands.append(args)
        subprocess.run(args, check=True)
    for variant in ('baseline', 'reference'):
        source = sources / variant / 'c'
        folder = output / variant
        folder.mkdir(exist_ok=True)
        library = folder / 'libpd_brotli.so'
        run(['gcc', '-shared', '-fPIC', '-O0', '-g3', '-fno-omit-frame-pointer',
             '-fno-inline', '-fsanitize-coverage=trace-pc', '-I' + str(source / 'include'),
             *sorted((source / 'common').glob('*.c')), *sorted((source / 'dec').glob('*.c')),
             '-Wl,--build-id=sha1', '-o', library])
        run(['gcc', '-O1', '-g', '-I' + str(source / 'include'),
             '-I' + str(ROOT / 'runtime/experiment'), HERE / 'worker.c',
             ROOT / 'runtime/experiment/trace.c', '-L' + str(folder), '-lpd_brotli',
             '-Wl,-rpath,$ORIGIN', '-Wl,--export-dynamic', '-ldl', '-o', folder / 'worker'])
    source = sources / 'reference/c'
    run(['gcc', '-O2', '-I' + str(source / 'include'), HERE / 'encoder.c',
         *sorted((source / 'common').glob('*.c')), *sorted((source / 'enc').glob('*.c')),
         '-lm', '-o', output / 'encoder'])
    source = sources / 'baseline/c'
    run(['gcc', '-O0', '-I' + str(source / 'include'), '-I' + str(source / 'dec'),
         HERE / 'layout.c', '-o', output / 'layout'])
    layout = json.loads(subprocess.check_output([output / 'layout'], text=True))
    (output / 'layout.json').write_text(json.dumps(layout, indent=2) + '\n')
    receipt = {'commands': commands, 'layout': layout,
               'artifacts': {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in output.rglob('*') if p.is_file() and p.suffix not in ('.json',)}}
    (output / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(layout))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--sources', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    build(a.sources.resolve(), a.output)
