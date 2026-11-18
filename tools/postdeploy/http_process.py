"""Owned localhost HTTP process with pre-request installation and source coverage."""
import http.client
import hashlib
import json
from pathlib import Path
import queue
import socket
import subprocess
import time

from .process import Worker, completion_event_digest, log_cursors, process_tree_fd_count, sanitizer_subprocess_env

CONTROL = r'''
let begin, finish, anchor;
rpc.exports = {
    initialize(spec) {
        const module = Process.getModuleByName(spec.module);
        anchor = module.base.add(spec.anchor_offset);
        const checks = [];
        for (const check of spec.admission || []) {
            const address = module.base.add(check.offset);
            const actual = address.readPointer();
            const expected = check.target_offset === null ? ptr(0) : module.base.add(check.target_offset);
            if (!actual.equals(expected)) throw new Error('admission failed: ' + check.name);
            checks.push({name: check.name, actual: actual.toString(), expected: expected.toString()});
        }
        begin = new NativeFunction(module.getExportByName('vg_trace_begin'), 'void', ['pointer']);
        finish = new NativeFunction(module.getExportByName('vg_trace_finish_file'), 'int', ['pointer']);
        return {module: module.path, checks};
    },
    begin() { begin(anchor); },
    finish(path) { return finish(Memory.allocUtf8String(path)); }
};
'''


def chunked_payload(body: bytes, chunk_size: int) -> bytes:
    size = max(1, int(chunk_size))
    view = body or b''
    parts = []
    offset = 0
    while offset < len(view):
        block = view[offset:offset + size]
        parts.append(f'{len(block):x}\r\n'.encode('ascii'))
        parts.append(block)
        parts.append(b'\r\n')
        offset += len(block)
    parts.append(b'0\r\n\r\n')
    return b''.join(parts)


def transmit_http(connection, method, path, body, headers, chunk_size=None):
    if chunk_size is None:
        connection.request(method, path, body=body, headers=headers or {})
        return
    payload = chunked_payload(body or b'', int(chunk_size))
    connection.putrequest(method, path)
    for key, value in (headers or {}).items():
        if str(key).lower() in ('content-length', 'transfer-encoding', 'host'):
            continue
        connection.putheader(key, value)
    connection.putheader('Transfer-Encoding', 'chunked')
    connection.endheaders(payload)


class HTTPWorker(Worker):
    def __init__(self, command, directory, trace_spec, patch=None, catalog=None, timeout=20, prepare=None,
                 dsl=None, bridge_dir=None, map_names=None):
        import frida
        self.timeout = timeout
        self.dsl = Path(dsl) if dsl else None
        self.bridge_dir = Path(bridge_dir) if bridge_dir else (Path(__file__).resolve().parents[2] / 'build' / 'frida-vm')
        self.map_names = list(map_names or [])
        self.session = self.script = self.control = None
        self.events, self.serial = [], 0
        self.barriers = queue.Queue()
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        command = [str(part).replace('{port}', str(self.port)) for part in command]
        if prepare is not None:
            prepare(self.port)
        self._closed = False
        self.stderr = (self.directory / 'server.log').open('w')
        self.process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=self.stderr, stderr=self.stderr,
            env=sanitizer_subprocess_env(),
        )
        try:
            until = time.monotonic() + timeout
            while True:
                if self.process.poll() is not None: raise RuntimeError('HTTP worker exited before readiness')
                try:
                    with socket.create_connection(('127.0.0.1', self.port), timeout=0.2): break
                except OSError:
                    if time.monotonic() >= until: raise TimeoutError('HTTP worker did not listen')
                    time.sleep(0.02)
            # Threaded HTTP servers may still be completing child/thread startup
            # when the listening socket first accepts. No application request.
            time.sleep(0.2)
            # TCP readiness has not sent an HTTP request. Check admission and
            # install the policy before issuing the first application request.
            self.session = frida.get_local_device().attach(self.process.pid)
            self.control = self.session.create_script(CONTROL)
            self.control.on('message', self._message)
            self.control.load()
            admission = self.control.exports_sync.initialize(trace_spec)
            self._install(command, patch, catalog)
            self.receipt.update(admission=admission, first_request_sent=False, port=self.port)
            (self.directory / 'installation.json').write_text(json.dumps(self.receipt, indent=2) + '\n')
        except BaseException:
            self.close()
            raise

    def execute(self, request):
        start, before = len(self.events), time.monotonic()
        self.serial += 1
        fd_before = process_tree_fd_count(self.process.pid)
        cursors = log_cursors(self.directory)
        try:
            self.control.exports_sync.begin()
            result = self.request(request)
            trace = self.directory / ('trace-%04d.json' % self.serial)
            if self.control.exports_sync.finish(str(trace)) != 0:
                raise RuntimeError('trace save failed')
            result.update(json.loads(trace.read_text()))
            if self.script and not self.dsl:
                self.script.exports_sync.barrier(self.serial)
                if self.barriers.get(timeout=self.timeout) != self.serial:
                    raise RuntimeError('event barrier mismatch')
            status = self.script.exports_sync.status() if self.script else None
            if status is not None and self.map_names:
                try:
                    info = self.script.exports_sync.mapInfo()
                    used = int(info.get('used', 0))
                except Exception:
                    used = 0
                status['map_sizes'] = {name: used for name in self.map_names}
        except Exception as error:
            if type(error).__name__ not in ('InvalidOperationError', 'TransportError'):
                raise
            alive = self.process.poll() is None
            result = {
                'http_status': 0,
                'response_complete': False,
                'transport_error': type(error).__name__,
                'worker_alive': alive,
            }
            status = None
        result['worker_alive'] = self.process.poll() is None
        result['resource_count_delta'] = process_tree_fd_count(self.process.pid) - fd_before
        result['completion_event_digest'] = completion_event_digest(cursors)
        return {'outcome': result, 'events': self.events[start:], 'runtime_status': status,
                'elapsed_seconds': time.monotonic() - before}

    def request(self, request):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=self.timeout)
        status = 0
        try:
            body = Path(request['body_file']).read_bytes() if request.get('body_file') else None
            transmit_http(
                connection,
                request['method'],
                request.get('path', '/'),
                body,
                request.get('headers') or {},
                request.get('chunk_size'),
            )
            response = connection.getresponse()
            status = response.status
            raw = response.read()
            if request.get('response_kind') == 'http':
                result = {'body_sha256': hashlib.sha256(raw).hexdigest(), 'body_length': len(raw),
                          'body_text': raw.decode('utf-8', errors='replace')}
            else:
                result = json.loads(raw)
            result['http_status'] = response.status
            result['response_complete'] = True
            result['response_headers'] = [(key, value) for key, value in response.getheaders()]
        except (OSError, http.client.HTTPException) as error:
            if request.get('response_kind') != 'http': raise
            raw = getattr(error, 'partial', b'')
            result = {'http_status': status, 'response_complete': False,
                      'body_sha256': hashlib.sha256(raw).hexdigest(), 'body_length': len(raw),
                      'body_text': raw.decode('utf-8', errors='replace'), 'transport_error': type(error).__name__,
                      'response_headers': []}
        finally:
            connection.close()
        return result

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try: self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill(); self.process.wait(timeout=3)
        finally:
            if self.session:
                try:
                    self.session.detach()
                except Exception:
                    pass
                self.session = None
            try:
                if self.stderr is not None and not self.stderr.closed:
                    self.stderr.close()
            except OSError:
                pass
