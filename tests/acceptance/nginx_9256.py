"""Check CVE-2026-9256 repair mounts and ordinary requests on Linux x86-64."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from runtime.dsl import parser  # noqa: E402
from runtime.frida.symbols import build_id  # noqa: E402


PATCH = ROOT / 'runtime/dsl/patches_fine/CVE-2026-9256.vg'
CONFIG = '''
daemon off;
master_process off;
pid nginx.pid;
error_log stderr notice;
events {}
http {
    access_log off;
    client_body_temp_path client_body;
    proxy_temp_path proxy;
    fastcgi_temp_path fastcgi;
    uwsgi_temp_path uwsgi;
    scgi_temp_path scgi;
    server {
        listen 127.0.0.1:PORT;
        server_name localhost;
        absolute_redirect off;
        location = /ready { return 200 "ready\\n"; }
        location /old/ { rewrite ^/old/([a-z]+)$ /target/$1 last; }
        location /target/ { return 200 "rewrite $uri\\n"; }
        location /redirect/ { rewrite ^/redirect/([a-z]+)$ /target/$1 redirect; }
        location /compose/ {
            if ($uri ~ ^/compose/([a-z]+)$) { set $label "$1-$arg_name"; }
            return 200 "complex $label\\n";
        }
        location = /view {
            if ($arg_mode = "brief") { return 200 "brief\\n"; }
            return 200 "full\\n";
        }
    }
}
'''
CASES = (
    ('rewrite', '/old/demo', 200, 'rewrite /target/demo\n', None),
    ('redirect', '/redirect/demo', 302, None, '/target/demo'),
    ('complex', '/compose/report?name=weekly', 200, 'complex report-weekly\n', None),
    ('conditional', '/view?mode=brief', 200, 'brief\n', None),
    ('conditional_fallback', '/view', 200, 'full\n', None),
)


def request(port: int, path: str) -> tuple[int, str | None, str]:
    connection = HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        connection.request('GET', path, headers={'Host': 'localhost', 'Connection': 'close'})
        response = connection.getresponse()
        return response.status, response.getheader('Location'), response.read().decode('utf-8')
    finally:
        connection.close()


@contextmanager
def server_process(command: list[str], log_path: Path, interrupt: signal.Signals):
    with log_path.open('wb') as log:
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            yield process
        except Exception as error:
            output = log_path.read_text(encoding='utf-8', errors='replace')
            raise RuntimeError(f'{error}\n{output}') from error
        finally:
            if process.poll() is None:
                process.send_signal(interrupt)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def check_requests(process: subprocess.Popen, port: int) -> dict:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'nginx launcher exited before readiness with code {process.returncode}')
        try:
            if request(port, '/ready') == (200, None, 'ready\n'):
                break
        except (OSError, HTTPException):
            pass
        time.sleep(0.05)
    else:
        raise RuntimeError('nginx readiness timed out')

    results = {}
    for name, path, status, body, location in CASES:
        observed = request(port, path)
        if observed[:2] != (status, location) or (body is not None and observed[2] != body):
            raise RuntimeError(f'{name} returned {observed!r}')
        results[name] = {'status': observed[0], 'location': observed[1], 'body': observed[2]}
    return results


def pid_at(prefix: Path) -> int:
    return int((prefix / 'nginx.pid').read_text(encoding='utf-8').strip())


def verify_stopped(pid: int) -> None:
    executable = Path(f'/proc/{pid}/exe')
    deadline = time.monotonic() + 2
    while executable.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if executable.exists():
        raise RuntimeError(f'nginx process {pid} remained active after shutdown')


def run_acceptance(nginx: Path) -> dict:
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise RuntimeError('This acceptance check needs Linux x86-64')
    patch = parser.load(PATCH)
    actual_id = build_id(nginx)
    if {mount.build_id for mount in patch.mounts} != {actual_id}:
        raise RuntimeError(f'nginx Build ID does not match {PATCH.name}: {actual_id}')

    with TemporaryDirectory(prefix='vulgate-nginx-9256-') as scratch:
        prefix = Path(scratch)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        configuration = prefix / 'nginx.conf'
        user = 'user nobody nogroup;\n' if os.geteuid() == 0 else ''
        configuration.write_text(user + CONFIG.replace('PORT', str(port)), encoding='utf-8')
        nginx_args = ['-p', str(prefix) + '/', '-c', str(configuration), '-e', 'stderr']
        with server_process([str(nginx), *nginx_args], prefix / 'baseline.log', signal.SIGTERM) as process:
            baseline = check_requests(process, port)
            baseline_pid = pid_at(prefix)
        if process.returncode != 0:
            raise RuntimeError(f'baseline nginx shutdown returned {process.returncode}')
        verify_stopped(baseline_pid)

        report_path = prefix / 'installer.json'
        command = [sys.executable, '-m', 'runtime.dsl.run', '--dsl', str(PATCH),
                   '--spawn', str(nginx), '--duration', '8', '--summary', str(report_path),
                   '--bridge-dir', str(prefix / 'bridge'),
                   *(f'--spawn-arg={arg}' for arg in nginx_args)]
        with server_process(command, prefix / 'patched.log', signal.SIGINT) as process:
            patched = check_requests(process, port)
            patched_pid = pid_at(prefix)
            if process.wait(timeout=20) != 0:
                raise RuntimeError(f'installer exited with code {process.returncode}')
            metadata = json.loads(report_path.read_text(encoding='utf-8'))
        verify_stopped(patched_pid)

    if patched != baseline:
        raise RuntimeError('ordinary HTTP responses differ between baseline and patched nginx')
    telemetry = metadata['final']
    installed = {mount['id'] for mount in telemetry['installed'] if mount['nature'] == 'repair_point'}
    if installed != {mount.id for mount in patch.mounts}:
        raise RuntimeError(f'unexpected repair sites: {telemetry}')
    for site in installed:
        if telemetry['hits'].get(site, 0) == 0 or telemetry['run'].get(site) not in ('repaired', 'repair-unneeded'):
            raise RuntimeError(f'expected a successful hook hit for {site}: {telemetry}')
    return {
        'nginx': subprocess.check_output([str(nginx), '-v'], stderr=subprocess.STDOUT, text=True).strip(),
        'build_id': actual_id,
        'baseline': baseline,
        'patched': patched,
        'repair_sites': telemetry,
    }


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('nginx', type=Path, help='path to the official nginx ELF')
    cli.add_argument('--report', type=Path)
    arguments = cli.parse_args()
    report = json.dumps(run_acceptance(arguments.nginx.resolve()), indent=2)
    if arguments.report is not None:
        arguments.report.write_text(report + '\n', encoding='utf-8')
    print(report)


if __name__ == '__main__':
    main()
