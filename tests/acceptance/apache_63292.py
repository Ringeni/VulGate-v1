"""Rebuild and load the Apache 2.4.68 vhost alias backport on Linux."""

import argparse
import contextlib
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'deploy/backports/httpd-2.4.68-CVE-2026-63292.patch'
HTTPD_COMMIT = '736bb657405eb73fd68a64772c3a908807bdb887'
PATCHED_SOURCE_SHA256 = '753acd5241df00bdc02e1c760ae4a4d31de956bb5ac166fae9b61d1f3d6e9590'
MODULE_SOURCE = Path('modules/mappers/mod_vhost_alias.c')
MODULE_NAME = 'mod_vhost_alias.so'


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_apache(source: Path, work: Path, jobs: int) -> tuple[Path, Path, Path]:
    checkout = work / 'source'
    checkout.mkdir()
    archive = work / 'source.tar'
    subprocess.run(['git', 'archive', '--output', str(archive), HTTPD_COMMIT],
                   cwd=source, check=True)
    subprocess.run(['tar', '-xf', str(archive)], cwd=checkout, check=True)

    prefix = work / 'httpd'
    subprocess.run(['./buildconf', '--with-apr=apr-1-config'], cwd=checkout, check=True)
    subprocess.run([
        './configure', f'--prefix={prefix}', '--with-mpm=prefork',
        '--enable-modules=none', '--enable-mods-static=so unixd authz_core dir mime',
        '--enable-mods-shared=vhost_alias cgi', '--disable-suexec',
    ], cwd=checkout, check=True)
    subprocess.run(['make', f'-j{jobs}'], cwd=checkout, check=True)
    subprocess.run(['make', 'install'], cwd=checkout, check=True)
    baseline = prefix / 'modules' / MODULE_NAME

    subprocess.run(['git', 'apply', '--check', str(PATCH)], cwd=checkout, check=True)
    subprocess.run(['git', 'apply', str(PATCH)], cwd=checkout, check=True)
    if sha256(checkout / MODULE_SOURCE) != PATCHED_SOURCE_SHA256:
        raise RuntimeError('patched module differs from the Apache 2.4.69 source')
    subprocess.run(['make', '-C', 'modules/mappers', '-B', 'mod_vhost_alias.la'],
                   cwd=checkout, check=True)
    patched = work / MODULE_NAME
    shutil.copyfile(checkout / 'modules/mappers/.libs' / MODULE_NAME, patched)
    if sha256(baseline) == sha256(patched):
        raise RuntimeError('the rebuilt module matches the original binary')
    return prefix, baseline, patched


def create_sites(work: Path) -> None:
    contents = {'shop.example.test': 'shop document\n',
                'catalog.example.test': 'catalog document\n'}
    for host, body in contents.items():
        site = work / 'sites' / host
        site.mkdir(parents=True)
        (site / 'index.txt').write_text(body, encoding='utf-8')
        scripts = work / 'cgi' / host
        scripts.mkdir(parents=True)
        script = scripts / 'health.cgi'
        script.write_text('#!/bin/sh\n'
                          "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
                          f"printf '%s CGI %s\\n' '{host}' \"$QUERY_STRING\"\n",
                          encoding='utf-8')
        script.chmod(0o755)
    (work / 'fallback').mkdir()


def request(port: int, host: str, path: str) -> dict:
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        connection.request('GET', path, headers={'Host': host, 'Connection': 'close'})
        response = connection.getresponse()
        return {'status': response.status, 'body': response.read().decode('utf-8')}
    finally:
        connection.close()


def verify_loaded(pid: int, module: Path) -> None:
    for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and Path(fields[5]) == module.resolve():
            return
    raise RuntimeError(f'Apache process {pid} did not map {module}')


@contextlib.contextmanager
def serve(prefix: Path, work: Path, module: Path, mode: str):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    conf = work / f'{mode}.conf'
    error_log = work / f'{mode}-error.log'
    if os.geteuid() == 0:
        nobody = pwd.getpwnam('nobody')
        run_as = f'User {nobody.pw_name}\nGroup {grp.getgrgid(nobody.pw_gid).gr_name}'
    else:
        run_as = ''
    conf.write_text(f'''
ServerRoot "{prefix}"
ServerName localhost
Listen 127.0.0.1:{port}
PidFile "{work / (mode + '.pid')}"
ErrorLog "{error_log}"
LoadModule vhost_alias_module "{module.resolve()}"
LoadModule cgi_module "{prefix / 'modules/mod_cgi.so'}"
{run_as}
StartServers 1
MinSpareServers 1
MaxSpareServers 2
ServerLimit 4
MaxRequestWorkers 4
UseCanonicalName Off
DocumentRoot "{work / 'fallback'}"
VirtualDocumentRoot "{work / 'sites'}/%0"
VirtualScriptAlias "{work / 'cgi'}/%0"
<Directory />
    Require all denied
</Directory>
<Directory "{work / 'sites'}">
    Require all granted
</Directory>
<Directory "{work / 'cgi'}">
    Options +ExecCGI
    Require all granted
</Directory>
''', encoding='utf-8')
    command = [str(prefix / 'bin/httpd'), '-f', str(conf)]
    subprocess.run([*command, '-t'], check=True)
    loaded = subprocess.check_output([*command, '-M'], text=True)
    for expected in ('vhost_alias_module (shared)', 'cgi_module (shared)'):
        if expected not in loaded:
            raise RuntimeError(f'{mode} did not report {expected}')

    with (work / f'{mode}-stderr.log').open('w+') as output:
        process = subprocess.Popen([*command, '-DFOREGROUND'], stdout=output, stderr=output,
                                   start_new_session=True)
        try:
            for _ in range(75):
                if process.poll() is not None:
                    raise RuntimeError(f'{mode} Apache exited with code {process.returncode}')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError(f'{mode} Apache never accepted local connections')
            verify_loaded(process.pid, module)
            yield port
        except Exception:
            output.seek(0)
            print(output.read(), file=sys.stderr)
            if error_log.exists():
                print(error_log.read_text(errors='replace'), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def verify(source: Path, jobs: int) -> dict:
    with tempfile.TemporaryDirectory(prefix='vulgate-httpd-63292-') as directory:
        work = Path(directory)
        # The isolated server runs its workers as nobody when the runner is root.
        work.chmod(0o755)
        prefix, baseline, patched = build_apache(source, work, jobs)
        version = subprocess.check_output([str(prefix / 'bin/httpd'), '-v'], text=True)
        if not re.search(r'Apache/2\.4\.68\b', version):
            raise RuntimeError(f'unexpected Apache binary version: {version}')
        create_sites(work)
        cases = {
            'shop-document': ('shop.example.test', '/index.txt', 'shop document\n'),
            'catalog-document': ('catalog.example.test', '/index.txt', 'catalog document\n'),
            'shop-cgi': ('shop.example.test', '/cgi-bin/health.cgi?name=shop',
                         'shop.example.test CGI name=shop\n'),
            'catalog-cgi': ('catalog.example.test', '/cgi-bin/health.cgi?name=catalog',
                            'catalog.example.test CGI name=catalog\n'),
        }
        results = {}
        for mode, module in [('baseline', baseline), ('patched', patched)]:
            with serve(prefix, work, module, mode) as port:
                results[mode] = {}
                for name, (host, path, body) in cases.items():
                    result = request(port, host, path)
                    if result != {'status': 200, 'body': body}:
                        raise RuntimeError(f'{mode} {name}: unexpected response {result}')
                    results[mode][name] = result
        return {
            'httpd_version': version.splitlines()[0],
            'httpd_commit': HTTPD_COMMIT,
            'httpd_sha256': sha256(prefix / 'bin/httpd'),
            'patched_source_sha256': PATCHED_SOURCE_SHA256,
            'module_sha256': {'baseline': sha256(baseline), 'patched': sha256(patched)},
            'loaded_from_proc_maps': True,
            'normal_requests_match': results['baseline'] == results['patched'],
            'responses': results,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True,
                        help='upstream Apache Git checkout containing release 2.4.68')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('this acceptance requires Linux')
    if args.jobs <= 0:
        parser.error('--jobs must be positive')
    os.umask(0o022)
    evidence = verify(args.source.resolve(), args.jobs)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(evidence, indent=2) + '\n'
    args.report.write_text(text, encoding='utf-8')
    print(text, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
