"""Check an exact Apache module backport and exercise the patched functions."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
MODULE = 'modules/mappers/mod_vhost_alias.c'
PATCH = HERE / 'httpd-2.4.68-CVE-2026-63292.patch'


def upstream_file(source: Path, release: str) -> bytes:
    return subprocess.check_output(['git', 'show', f'refs/tags/{release}:{MODULE}'], cwd=source)


def verify(source: Path, compiler: str) -> None:
    with tempfile.TemporaryDirectory(prefix='vulgate-63292-') as scratch:
        directory = Path(scratch)
        module = directory / MODULE
        module.parent.mkdir(parents=True)
        module.write_bytes(upstream_file(source, '2.4.68'))
        apply = ['git', '-c', 'core.autocrlf=false', 'apply']
        subprocess.run([*apply, '--check', str(PATCH)], cwd=directory, check=True)
        subprocess.run([*apply, str(PATCH)], cwd=directory, check=True)
        patched = module.read_bytes()
        if patched != upstream_file(source, '2.4.69'):
            raise ValueError('patched module differs from the Apache 2.4.69 release')
        print('Backport applies cleanly and matches the Apache 2.4.69 module.', flush=True)

        text = patched.decode()
        config = text[text.index('typedef enum {'):text.index('static void *mva_create_server_config')]
        guard = text.index('static APR_INLINE int vhost_alias_checkspace')
        interpolate = text.index('static int vhost_alias_interpolate')
        hooks = text.index('static void register_hooks')
        (directory / 'patched_vhost_alias.inc').write_text(
            config + text[guard:interpolate]
            + '#define vhost_alias_checkspace checked_fixture_capacity\n'
            + text[interpolate:hooks], encoding='utf-8',
        )
        fixture = directory / 'verify_cve_2026_63292.c'
        fixture.write_bytes((HERE / fixture.name).read_bytes())
        exe = directory / ('check.exe' if os.name == 'nt' else 'check')
        subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Werror',
                        fixture.name, '-o', exe.name], cwd=directory, check=True)
        subprocess.run([str(exe)], cwd=directory, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='Apache httpd Git checkout with tags 2.4.68 and 2.4.69')
    parser.add_argument('--cc', default=os.environ.get('CC', 'gcc'))
    args = parser.parse_args()
    verify(args.source, args.cc)
