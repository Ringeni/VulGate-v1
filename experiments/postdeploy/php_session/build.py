"""Pinned, minimal NTS PHP builds for ordinary upload-progress comparison."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
REVISIONS = {'baseline': 'dd830558ffb1ac8378e812b4db97626e6087de3f',
             'reference': '31c0ea7d7ff1d1fccb6492e52dab544011628065'}


def build(output, scratch):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    receipts = {}
    for mode, revision in REVISIONS.items():
        folder = output / mode
        folder.mkdir(exist_ok=True)
        archive = output / (revision + '.tar.gz')
        url = 'https://codeload.github.com/php/php-src/tar.gz/' + revision
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=120) as response:
                archive.write_bytes(response.read())
        source = scratch / mode
        if not (source / 'main/php.h').exists():
            with tarfile.open(archive) as bundle:
                for item in bundle:
                    relative = Path(*Path(item.name).parts[1:])
                    if relative.is_absolute() or '..' in relative.parts: raise ValueError('archive path')
                    if not item.isfile(): continue
                    path = source / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(bundle.extractfile(item).read())
                    path.chmod(item.mode & 0o777)
        commands = []
        def run(args, name, env=None):
            commands.append(list(map(str, args)))
            print(mode + ': ' + name, flush=True)
            with (folder / (name + '.log')).open('w') as log:
                subprocess.run(list(map(str, args)), cwd=source, stdout=log, stderr=log, check=True, env=env)
        if not (source / 'configure').exists(): run(['./buildconf', '--force'], 'buildconf')
        trace = source / 'pd_trace.o'
        run(['gcc', '-O1', '-g', '-fPIC', '-I' + str(ROOT / 'runtime/experiment'), '-c',
             ROOT / 'runtime/experiment/trace.c', '-o', trace], 'trace-build')
        trace_io = source / 'pd_trace_io.o'
        run(['gcc', '-O1', '-g', '-fPIC', '-I' + str(ROOT / 'runtime/experiment'), '-c',
             HERE / 'trace_io.c', '-o', trace_io], 'trace-io-build')
        # Only session.c receives coverage. The rest of the interpreter retains
        # its normal build, and the trace runtime itself is never instrumented.
        compiler = source / 'pd_cc.py'
        compiler.write_text('#!/usr/bin/python3\nimport os,sys\na=sys.argv[1:]\n'
            'if any(x.endswith("/session.c") for x in a): a += ["-fsanitize-coverage=trace-pc"]\n'
            'os.execv("/usr/bin/gcc", ["gcc"] + a)\n')
        compiler.chmod(0o755)
        import os
        env = dict(os.environ, CC=str(compiler), CFLAGS='-O0 -g -fno-omit-frame-pointer',
                   LIBS=str(trace) + ' ' + str(trace_io) + ' -ldl', LDFLAGS='-Wl,--export-dynamic')
        if not (source / 'Makefile').exists():
            run(['./configure', '--disable-all', '--enable-cli', '--disable-cgi', '--disable-phpdbg',
                 '--enable-session', '--without-pear'], 'configure', env)
        run(['make', '-j4'], 'make', env)
        executable = folder / 'php'
        shutil.copy2(source / 'sapi/cli/php', executable)
        run(['gcc', '-O0', '-I.', '-IZend', '-Imain', '-ITSRM', HERE / 'layout.c', '-o', source / 'pd_layout'], 'layout-build')
        layout = json.loads(subprocess.check_output([source / 'pd_layout'], text=True))
        (folder / 'layout.json').write_text(json.dumps(layout, indent=2) + '\n')
        receipts[mode] = {'revision': revision, 'url': url, 'source': str(source),
            'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            'session_source_sha256': hashlib.sha256((source / 'ext/session/session.c').read_bytes()).hexdigest(),
            'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'version': subprocess.check_output([executable, '-n', '-v'], text=True),
            'commands': commands, 'environment': {k: env[k] for k in ['CC', 'CFLAGS', 'LIBS', 'LDFLAGS']}, 'layout': layout}
        (output / 'build.json').write_text(json.dumps(receipts, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, default=ROOT / 'build/postdeploy-php-session')
    p.add_argument('--scratch', type=Path, default=Path('/tmp/vulgate-php-session-20261112'))
    args = p.parse_args()
    build(args.output, args.scratch)
