"""Build pinned PHP embed libraries for normal multipart functionality tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

REVISIONS = {'baseline': 'dd830558ffb1ac8378e812b4db97626e6087de3f',
             'reference': '31c0ea7d7ff1d1fccb6492e52dab544011628065'}
ROOT = Path(__file__).resolve().parents[3]


def build(output, work):
    output.mkdir(parents=True, exist_ok=True)
    receipt = {'variants': {}, 'commands': []}
    for name, revision in REVISIONS.items():
        archive = output / (revision + '.tar.gz')
        url = 'https://codeload.github.com/php/php-src/tar.gz/' + revision
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=120) as response:
                archive.write_bytes(response.read())
        source = work / name
        if not (source / 'configure.ac').exists():
            source.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as bundle:
                for member in bundle.getmembers():
                    relative = Path(*Path(member.name).parts[1:])
                    if not relative.parts or not member.isfile(): continue
                    if relative.is_absolute() or '..' in relative.parts: raise ValueError('archive path')
                    if 'tests' in relative.parts or relative.suffix == '.phpt': continue
                    target = source / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(bundle.extractfile(member).read())
                    os.chmod(target, member.mode & 0o777)
                    os.utime(target, (member.mtime, member.mtime))
        def run(command, log):
            receipt['commands'].append({'cwd': str(source), 'argv': command})
            with (output / (name + '-' + log)).open('w') as file:
                subprocess.run(command, cwd=source, stdout=file, stderr=file, check=True)
        if not (source / 'configure').exists(): run(['./buildconf', '--force'], 'buildconf.log')
        if not (source / 'Makefile').exists():
            run(['./configure', '--disable-all', '--enable-session', '--enable-embed=shared',
                 '--disable-cli', '--disable-cgi', '--disable-phpdbg', '--without-pear',
                 'CFLAGS=-O0 -g -fno-omit-frame-pointer', 'CXXFLAGS=-O0 -g'], 'configure.log')
        if not (source / 'libs/libphp.so').exists(): run(['make', '-j2'], 'make.log')
        # Instrument only session and multipart implementation, then relink.
        if not (source / '.pd-coverage').exists():
            for path in ['ext/session/session.lo', 'ext/session/.libs/session.o',
                         'main/rfc1867.lo', 'main/.libs/rfc1867.o']:
                (source / path).unlink(missing_ok=True)
            run(['make', '-j2', 'CFLAGS=-O0 -g -fno-omit-frame-pointer -fsanitize-coverage=trace-pc'], 'coverage.log')
            (source / '.pd-coverage').write_text('session.c and rfc1867.c\n')
        folder = output / name
        folder.mkdir(exist_ok=True)
        library = folder / 'libphp.so'
        library.write_bytes((source / 'libs/libphp.so').read_bytes())
        receipt['variants'][name] = {'revision': revision, 'url': url, 'source': str(source),
            'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
            'session_sha256': hashlib.sha256((source / 'ext/session/session.c').read_bytes()).hexdigest()}
        (output / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'variant': name, 'library': str(library)}), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, default=ROOT / 'build/postdeploy-php-progress')
    p.add_argument('--work', type=Path, default=Path('/tmp/vulgate-postdeploy-php-progress'))
    a = p.parse_args()
    build(a.output.resolve(), a.work.resolve())
