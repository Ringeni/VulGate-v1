from __future__ import annotations

import argparse
import ast
import bisect
from contextlib import ExitStack
import copy
import gzip
import hashlib
import http.server
import json
from pathlib import Path
import random
import re
import socket
import socketserver
import statistics
import subprocess
import threading
import time
from typing import Any
import urllib.parse

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
)

from .case_compiler import (
    compile_case,
    elf_unique_symbols,
    load_spec_file,
    project_snapshot_to_symbols,
    region_branch_distances,
    sha256_file,
    evaluate_snapshot_in_guard_space,
    predicate_distance,
    snapshot_predicate_distances,
)
from .coverage import edges as trace_edges, summarize as summarize_coverage
from .http_process import HTTPWorker
from .monitors import VMReplay
from .obligations import build_and_verify_paired_goto_slice, prescan_static_globals, verify_vm_bytecode_equivalence
from .process import CAPIWorker, CLIStreamWorker, Worker, process_tree_fd_count
from .snapshot_lifter import capture_concrete_snapshot_via_gdb, invocation_selector_from_case

ROOT = Path(__file__).resolve().parents[2]

BACKEND_TEXT = b'ordinary backend response\n'


def grpc_frame(message: bytes) -> bytes:
    if len(message) > 0xFFFFFFFF:
        raise ValueError('grpc message exceeds uint32 length')
    return bytes((0,)) + len(message).to_bytes(4, 'big') + message


def grpc_messages(payload: bytes) -> tuple[list[bytes], bytes]:
    messages: list[bytes] = []
    offset = 0
    view = payload or b''
    while offset + 5 <= len(view):
        length = int.from_bytes(view[offset + 1:offset + 5], 'big')
        end = offset + 5 + length
        if end > len(view):
            break
        messages.append(view[offset + 5:end])
        offset = end
    return messages, view[offset:]


CONTRACT_CONTENT_DIRS = ('dav', 'www', 'html', 'htdocs', 'upload', 'uploads')
VOLATILE_RESPONSE_HEADERS = frozenset({
    'date', 'server', 'connection', 'keep-alive', 'etag', 'last-modified', 'expires', 'age',
})


def _append_backend_traffic(server, record: dict[str, str]) -> int:
    with server.lock:
        server.traffic.append(record)
        return len(server.traffic) - 1


def normalize_response_headers(headers) -> list[tuple[str, str]]:
    normalized: list[tuple[str, str]] = []
    for name, value in headers or []:
        key = str(name).lower()
        if key.startswith(':') or key in VOLATILE_RESPONSE_HEADERS:
            continue
        text = ' '.join(str(value).split())
        if key == 'set-cookie':
            text = text.split('=', 1)[0].strip()
        normalized.append((key, text))
    normalized.sort()
    return normalized


def response_header_digest(headers) -> str:
    blob = '\n'.join(f'{key}:{value}' for key, value in normalize_response_headers(headers)).encode()
    return hashlib.sha256(blob).hexdigest()


def session_store_digest(root: Path) -> list[str]:
    contents: list[str] = []
    base = Path(root)
    if not base.is_dir():
        return contents
    for fp in base.rglob('sess_*'):
        if fp.is_file():
            contents.append(sha256_file(fp))
    contents.sort()
    return contents


CONTRACT_OBSERVATION_FIELDS = (
    'response_header_digest',
    'filesystem_digest',
    'session_digest',
    'backend_digest',
    'database_digest',
    'completion_event_digest',
    'worker_alive',
    'resource_count_delta',
)


def database_store_digest(root: Path) -> list[str]:
    contents: list[str] = []
    base = Path(root)
    if not base.is_dir():
        return contents
    for fp in base.rglob('*'):
        if not fp.is_file():
            continue
        parts = fp.relative_to(base).parts
        in_db_dir = any(part in ('db', 'database') for part in parts[:-1])
        if fp.suffix.lower() not in ('.db', '.sqlite', '.sqlite3') and not in_db_dir:
            continue
        contents.append(sha256_file(fp))
    contents.sort()
    return contents


def _attach_contract_observations(protocol: str, outcomes: dict[str, dict[str, Any]], workers: dict[str, Any]) -> None:
    if protocol not in ('nginx_http', 'httpd_http', 'php_http'):
        return
    for mode, outcome in outcomes.items():
        if 'response_headers' in outcome:
            outcome['response_header_digest'] = response_header_digest(outcome.get('response_headers'))
        worker = workers.get(mode)
        root = getattr(worker, 'directory', None) if worker is not None else None
        if root is None:
            continue
        outcome['filesystem_digest'] = _directory_tree_digest(Path(root), list(CONTRACT_CONTENT_DIRS))
        outcome['session_digest'] = session_store_digest(Path(root))
        outcome['database_digest'] = database_store_digest(Path(root))
BACKEND_HTML = b'<html><body>Hello<!--ordinary comment-->caf\xe9</body></html>'
BACKEND_RANGE = b'0123456789abcdef' * 256


class _UniversalHTTPPeerHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def _note(self, method: str, body: bytes) -> None:
        _append_backend_traffic(self.server, {
            'method': method,
            'path': self.path,
            'body_sha256': hashlib.sha256(body).hexdigest(),
            'content_type': self.headers.get('Content-Type', ''),
            'range': self.headers.get('Range', ''),
        })

    def _respond(self) -> None:
        body = BACKEND_HTML if self.path.startswith('/html') else BACKEND_RANGE if self.path.startswith('/range') else BACKEND_TEXT
        status = 200
        extra_headers = {}
        if self.path.startswith('/range') and self.headers.get('Range', '').startswith('bytes='):
            first, last = self.headers['Range'][6:].split('-')
            start, end = int(first), min(int(last), len(body) - 1)
            extra_headers['Content-Range'] = f'bytes {start}-{end}/{len(body)}'
            body = body[start:end + 1]
            status = 206
        self.send_response(status)
        ctype = 'text/html; charset=ISO-8859-1' if self.path.startswith('/html') else 'text/plain'
        self.send_header('Content-Type', ctype)
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.request_count += 1
        self._note('GET', b'')
        self._respond()

    def do_POST(self):
        self.server.request_count += 1
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length) if length > 0 else b''
        self._note('POST', body)
        self._respond()


class _UniversalPeerConnection(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        try:
            prefix = self.request.recv(24, socket.MSG_PEEK)
            if not prefix:
                return
            if not prefix.startswith(b'PRI * HTTP/2.0'):
                _UniversalHTTPPeerHandler(self.request, self.client_address, self.server)
                return
            self.server.request_count += 1
            streams: dict[int, dict[str, Any]] = {}
            conn = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
            conn.initiate_connection()
            self.request.sendall(conn.data_to_send())
            while True:
                raw = self.request.recv(65535)
                if not raw:
                    break
                for event in conn.receive_data(raw):
                    if isinstance(event, RequestReceived):
                        headers = {str(key): str(value) for key, value in event.headers}
                        streams[event.stream_id] = {
                            'headers': headers,
                            'body': bytearray(),
                            'index': _append_backend_traffic(self.server, {
                                'method': headers.get(':method', 'GET'),
                                'path': headers.get(':path', '/'),
                                'body_sha256': hashlib.sha256(b'').hexdigest(),
                                'content_type': headers.get('content-type', ''),
                                'range': headers.get('range', ''),
                            }),
                        }
                    elif isinstance(event, DataReceived):
                        streams.setdefault(event.stream_id, {'headers': {}, 'body': bytearray(), 'index': None})
                        streams[event.stream_id]['body'].extend(event.data)
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded) and event.stream_id in streams:
                        info = streams.pop(event.stream_id)
                        payload = bytes(info['body'])
                        if info['index'] is not None:
                            with self.server.lock:
                                self.server.traffic[info['index']]['body_sha256'] = hashlib.sha256(payload).hexdigest()
                        headers = info['headers']
                        if str(headers.get('content-type', '')).startswith('application/grpc'):
                            messages, rest = grpc_messages(payload)
                            status_code = '2' if rest else '0'
                            reply = grpc_frame(b''.join(messages))
                            conn.send_headers(event.stream_id, [
                                (':status', '200'),
                                ('content-type', 'application/grpc'),
                            ])
                            conn.send_data(event.stream_id, reply)
                            conn.send_headers(event.stream_id, [('grpc-status', status_code)], end_stream=True)
                        else:
                            conn.send_headers(event.stream_id, [
                                (':status', '200'),
                                ('content-type', 'text/plain'),
                                ('content-length', str(len(BACKEND_TEXT))),
                            ])
                            conn.send_data(event.stream_id, BACKEND_TEXT, end_stream=True)
                self.request.sendall(conn.data_to_send())
        except (OSError, ValueError):
            pass


class UniversalBackendPeer:
    def __enter__(self):
        self.server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _UniversalPeerConnection)
        self.server.daemon_threads = True
        self.server.request_count = 0
        self.server.traffic = []
        self.server.lock = threading.Lock()
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def mark(self) -> int:
        with self.server.lock:
            return len(self.server.traffic)

    def digest_since(self, mark: int) -> str:
        with self.server.lock:
            records = [dict(item) for item in self.server.traffic[mark:]]
        blob = json.dumps(records, sort_keys=True, separators=(',', ':')).encode()
        return hashlib.sha256(blob).hexdigest()

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


def exchange_http2(port: int, spec: dict[str, Any], timeout: float = 5) -> dict[str, Any]:
    raw = b''
    if spec.get('body_file'):
        raw = Path(spec['body_file']).read_bytes()
    elif isinstance(spec.get('body'), (bytes, bytearray)):
        raw = bytes(spec['body'])
    grpc = bool(spec.get('grpc'))
    payload = grpc_frame(raw) if grpc else raw
    seen: set[str] = set()
    extra: list[tuple[str, str]] = []
    for key, value in (spec.get('headers') or {}).items():
        lower = str(key).lower()
        if lower in ('host', 'content-length', 'connection', 'transfer-encoding') or lower.startswith(':'):
            continue
        extra.append((lower, str(value)))
        seen.add(lower)
    if grpc and 'content-type' not in seen:
        extra.append(('content-type', 'application/grpc'))
    if grpc and 'te' not in seen:
        extra.append(('te', 'trailers'))
    headers = [
        (':method', spec.get('method', 'POST' if grpc else 'GET')),
        (':scheme', 'http'),
        (':authority', (spec.get('headers') or {}).get('Host', 'localhost')),
        (':path', spec.get('path', '/')),
        *extra,
    ]
    body = bytearray()
    status = 0
    complete = False
    reason = None
    grpc_status = None
    response_headers: list[tuple[str, str]] = []
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as channel:
            channel.settimeout(timeout)
            conn = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
            conn.initiate_connection()
            conn.send_headers(1, headers, end_stream=not payload)
            if payload:
                conn.send_data(1, payload, end_stream=True)
            channel.sendall(conn.data_to_send())
            while not complete and reason is None:
                data = channel.recv(65535)
                if not data:
                    reason = 'connection_closed'
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        response_headers.extend((str(key), str(value)) for key, value in event.headers)
                        status = int(dict(response_headers).get(':status', status))
                    elif isinstance(event, TrailersReceived):
                        response_headers.extend((str(key), str(value)) for key, value in event.headers)
                        trailer = {str(key): str(value) for key, value in event.headers}
                        if 'grpc-status' in trailer:
                            grpc_status = int(trailer['grpc-status'])
                    elif isinstance(event, DataReceived):
                        body.extend(event.data)
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        complete = True
                    elif isinstance(event, (StreamReset, ConnectionTerminated)):
                        reason = type(event).__name__
                channel.sendall(conn.data_to_send())
    except OSError as error:
        reason = type(error).__name__
    received = bytes(body)
    if grpc:
        messages, rest = grpc_messages(received)
        received = b''.join(messages)
        if rest and reason is None:
            reason = 'truncated_grpc_frame'
            complete = False
    return {
        'http_status': status,
        'response_complete': complete,
        'body_length': len(received),
        'body_text': received.decode('utf-8', errors='replace'),
        'body_sha256': hashlib.sha256(received).hexdigest(),
        'transport_error': reason,
        'response_headers': response_headers,
        'grpc_status': grpc_status,
    }


class UniversalHTTPWorker(HTTPWorker):
    def request(self, spec: dict[str, Any]) -> dict[str, Any]:
        if spec.get('protocol') != 'h2':
            return super().request(spec)
        return exchange_http2(self.port, spec, timeout=5)


def _directory_tree_digest(root: Path, subdirs: list[str]) -> dict[str, str]:
    digests: dict[str, str] = {}
    for sub in subdirs:
        base = root / sub
        if not base.is_dir():
            continue
        for fp in sorted(base.rglob('*')):
            if fp.is_file():
                rel = fp.relative_to(root).as_posix()
                digests[rel] = sha256_file(fp)
    return digests


def _poc_method_paths(case_ir: dict[str, Any]) -> set[tuple[str, str]]:
    poc = ((case_ir.get('seed_traces') or {}).get('poc_reproducer') or {}).get('requests') or []
    keys: set[tuple[str, str]] = set()
    for item in poc:
        if not isinstance(item, dict):
            continue
        method = str(item.get('method', 'GET')).upper()
        raw = str(item.get('uri') or item.get('path') or '/')
        keys.add((method, raw.split('?', 1)[0]))
    return keys


_DAV_EXPECT = {
    'OPTIONS': 200,
    'PROPFIND': 207,
    'PROPPATCH': 207,
    'PUT': 201,
    'MKCOL': 201,
    'COPY': 204,
    'MOVE': 204,
    'DELETE': 204,
}


def _dav_method_names(text: str) -> list[str]:
    match = re.search(r'\bdav_methods\s+([^;]+);', text)
    if not match:
        return []
    found: list[str] = []
    for token in match.group(1).split():
        name = token.upper()
        if name in _DAV_EXPECT and name not in found:
            found.append(name)
    return found


def _httpd_dav_methods(body: str) -> list[str]:
    match = re.search(r'\bDav\s+(\S+)', body)
    if not match or match.group(1).lower() == 'off':
        return []
    return ['OPTIONS', 'PROPFIND', 'PROPPATCH', 'PUT', 'DELETE', 'MKCOL', 'COPY', 'MOVE']


def _uri_under_prefix(prefix: str, files: list[str]) -> str | None:
    pref = prefix if prefix.endswith('/') else prefix + '/'
    for rel in files:
        uri = '/' + rel.lstrip('/')
        rest = uri[len(pref):]
        if uri.startswith(pref) and rest and '/' not in rest:
            return uri
    return None


def _dav_method_templates(prefix: str, methods: list[str], existing: str | None) -> list[dict[str, Any]]:
    copy_path = prefix + 'ordinary-copy.txt'
    move_path = prefix + 'ordinary-move.txt'
    put_path = prefix + 'ordinary-put.txt'
    enabled = [name for name in ('OPTIONS', 'PROPFIND', 'PROPPATCH', 'PUT', 'MKCOL', 'COPY', 'MOVE', 'DELETE') if name in methods]
    items: list[dict[str, Any]] = []
    for name in enabled:
        if name == 'OPTIONS':
            items.append(_http_template('cfg-' + _slug(prefix + name), 'dav_options', 'OPTIONS', prefix, 200))
        elif name == 'PROPFIND':
            items.append(_http_template(
                'cfg-' + _slug(prefix + name), 'dav_propfind', 'PROPFIND', prefix, 207, {'Depth': '0'},
            ))
        elif name == 'PROPPATCH' and existing:
            item = _http_template(
                'cfg-' + _slug(existing + name), 'dav_proppatch', 'PROPPATCH', existing, 207,
                {'Content-Type': 'application/xml'},
            )
            item['body'] = (
                b'<?xml version="1.0"?>'
                b'<D:propertyupdate xmlns:D="DAV:">'
                b'<D:set><D:prop><D:displayname>ordinary</D:displayname></D:prop></D:set>'
                b'</D:propertyupdate>'
            )
            items.append(item)
        elif name == 'PUT':
            item = _http_template(
                'cfg-' + _slug(prefix + name), 'dav_put', 'PUT', put_path, 201, {'Content-Type': 'text/plain'},
            )
            item['body'] = b'ordinary\n'
            items.append(item)
        elif name == 'MKCOL':
            items.append(_http_template(
                'cfg-' + _slug(prefix + name), 'dav_mkcol', 'MKCOL', prefix + 'ordinary-dir/', 201,
            ))
        elif name == 'COPY' and existing:
            items.append(_http_template(
                'cfg-' + _slug(existing + name), 'dav_copy', 'COPY', existing, 204,
                {'Destination': copy_path},
            ))
        elif name == 'MOVE':
            source = copy_path if 'COPY' in methods else existing
            if source:
                items.append(_http_template(
                    'cfg-' + _slug(source + name), 'dav_move', 'MOVE', source, 204,
                    {'Destination': move_path},
                ))
        elif name == 'DELETE':
            if 'MOVE' in methods:
                target = move_path
            elif 'COPY' in methods:
                target = copy_path
            else:
                target = existing
            if target:
                items.append(_http_template('cfg-' + _slug(target + name), 'dav_delete', 'DELETE', target, 204))
    return items


def _http_template(ident: str, group: str, method: str, path: str, status: int,
                   headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        'id': ident,
        'group': group,
        'request': {
            'method': method,
            'path': path,
            'headers': dict(headers or {}),
            'response_kind': 'http',
        },
        'expected_status': status,
    }


def _iter_braced(text: str, keyword: str):
    pattern = re.compile(rf'\b{keyword}\b')
    idx = 0
    while True:
        match = pattern.search(text, idx)
        if not match:
            return
        brace = text.find('{', match.end())
        if brace < 0:
            return
        depth = 0
        end = None
        for pos in range(brace, len(text)):
            if text[pos] == '{':
                depth += 1
            elif text[pos] == '}':
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end is None:
            return
        yield text[match.end():brace], text[brace + 1:end]
        idx = end + 1


_APACHE_REDIRECT_NAMES = {
    'PERMANENT': 301,
    'TEMP': 302,
    'REDIRECT': 302,
    'SEEOTHER': 303,
}


def _nginx_probe_path(mod: str, path: str, body: str) -> str:
    arg = re.search(r'\$arg_([A-Za-z0-9_]+)', body)
    if mod == '=':
        return path + (f'?{arg.group(1)}=ordinary' if arg else '')
    return (path if path.endswith('/') else path + '/') + 'ordinary'


def _nginx_map_variables(cfg: str) -> set[str]:
    found: set[str] = set()
    for header, _body in _iter_braced(cfg, 'map'):
        parts = header.split()
        if len(parts) >= 2 and parts[-1].startswith('$'):
            found.add(parts[-1][1:])
    return found


def _return_uses_mapped_variable(body: str, mapped: set[str]) -> bool:
    match = re.search(r'\breturn\s+\d{3}\s+([^;]*)', body)
    if match is None or not mapped:
        return False
    return any(name in mapped for name in _nginx_named_vars(match.group(1)))


def _nginx_error_page_targets(cfg: str) -> list[tuple[str, int | None]]:
    found: list[tuple[str, int | None]] = []
    seen: set[str] = set()
    for match in re.finditer(r'(?m)^[ \t]*error_page\s+404\s+([^;]+);', cfg):
        parts = match.group(1).split()
        if not parts:
            continue
        target = parts[-1].strip().strip('"').strip("'")
        if not target.startswith('/') or '://' in target:
            continue
        path = target.split('?', 1)[0]
        if path in seen:
            continue
        seen.add(path)
        override = None
        for part in parts[:-1]:
            if re.fullmatch(r'=\d{3}', part):
                override = int(part[1:])
        found.append((path, override))
    return found


def _nginx_return_status(body: str) -> int | None:
    match = re.search(r'\breturn\s+(\d{3})\b', body)
    if match is None:
        return None
    code = int(match.group(1))
    if 100 <= code < 600:
        return code
    return None


def _nginx_rewrite_status(body: str) -> tuple[str, int] | None:
    if re.search(r'\brewrite\b[^;]*\bpermanent\b', body):
        return 'rewrite_permanent', 301
    if re.search(r'\brewrite\b[^;]*\bredirect\b', body):
        return 'rewrite_redirect', 302
    return None


def _rewrite_rule_status(flags: str | None) -> int:
    parts = list(_rewrite_flags(flags))
    bare = False
    for part in parts:
        number = re.fullmatch(r'R=(\d{3})', part)
        if number:
            code = int(number.group(1))
            if 100 <= code < 600:
                return code
            continue
        if part.startswith('R='):
            named = _APACHE_REDIRECT_NAMES.get(part[2:])
            if named is not None:
                return named
        if part in {'R', 'REDIRECT'}:
            bare = True
    return 302 if bare else 200


def _nginx_named_vars(stmt: str) -> list[str]:
    return re.findall(r'\$([A-Za-z_][A-Za-z0-9_]*)', stmt)


def _request_matches_location(uri: str, path: str, mod: str) -> bool:
    if mod == '=':
        return uri == path
    if path.endswith('/'):
        return uri.startswith(path)
    return uri == path or uri.startswith(path + '/')


def _alias_from_uri(path: str, mod: str, target: str, files: list[str]) -> str | None:
    if target.count('$uri') != 1:
        return None
    names = _nginx_named_vars(target)
    if [name for name in names if not name.startswith('arg_')] != ['uri']:
        return None
    if any(name.startswith('arg_') for name in names):
        return None
    head, tail = target.split('$uri', 1)
    for rel in files:
        full = '{root}/' + rel.lstrip('/') if '{root}' in target else rel.lstrip('/')
        if not full.startswith(head):
            continue
        if tail and not full.endswith(tail):
            continue
        end = len(full) - len(tail) if tail else len(full)
        if end < len(head):
            continue
        uri = full[len(head):end]
        if not uri.startswith('/'):
            if not head.endswith('/'):
                continue
            uri = '/' + uri
        if _request_matches_location(uri, path, mod):
            return uri
    return None


def _nginx_location_is_trigger(path: str, body: str) -> bool:
    for kind, stmt in re.findall(r'\b(root|alias)\s+([^;]*);', body):
        for var in _nginx_named_vars(stmt):
            if var.startswith('arg_'):
                continue
            if kind == 'alias' and var == 'uri':
                continue
            return True
    if re.search(r'\balias\b', body) and re.search(r'\brewrite\b', body) and not re.search(r'\b(?:redirect|permanent|last|break)\b', body):
        return True
    if path.rstrip('/') in ('', '/') and re.search(r'\brewrite\b[^;]*\?', body):
        return True
    return False


def _nginx_static_uri(path: str, body: str, files: list[str], mod: str = '') -> str | None:
    alias = re.search(r'\balias\s+([^;]+);', body)
    root = re.search(r'\broot\s+([^;]+);', body)
    prefix = path if path.endswith('/') else path + '/'
    if alias:
        target = alias.group(1).strip().strip('"').strip("'")
        if '$uri' in target:
            return _alias_from_uri(path, mod, target, files)
        suffix = target.split('{root}', 1)[-1].lstrip('/') if '{root}' in target else target.lstrip('/')
        if suffix and not suffix.endswith('/'):
            suffix += '/'
        for rel in files:
            if suffix and rel.startswith(suffix):
                rest = rel[len(suffix):]
                if rest and '/' not in rest:
                    return prefix + rest
        return None
    if not root:
        return None
    target = root.group(1).strip().strip('"').strip("'")
    arg = re.search(r'\$arg_([A-Za-z0-9_]+)', target)
    if arg:
        for rel in files:
            parts = rel.split('/')
            if len(parts) < 2:
                continue
            uri = '/' + '/'.join(parts[1:])
            if uri.startswith(prefix) or uri == path:
                return uri + f'?{arg.group(1)}={parts[0]}'
        return None
    base_dir = target.split('{root}', 1)[-1].strip().strip('/') if '{root}' in target else ''
    for rel in files:
        if base_dir:
            if not rel.startswith(base_dir + '/'):
                continue
            uri = '/' + rel[len(base_dir) + 1:]
        else:
            uri = '/' + rel
        if uri.startswith(prefix):
            return uri
    return None


def _proxy_request_path(prefix: str) -> str:
    if not prefix.startswith('/'):
        prefix = '/' + prefix
    if prefix.endswith('/'):
        return prefix + 'plain'
    return prefix


def _slug(text: str) -> str:
    return re.sub(r'[^A-Za-z0-9]+', '-', text).strip('-') or 'root'


def vhost_alias_docroot(map_text: str, name: str, port: int) -> str:
    maxdots = 19
    dots = [0] * (maxdots + 1)
    ndots = 0
    dots[ndots] = -1
    ndots += 1
    for index, ch in enumerate(name):
        if ch == '.' and ndots < maxdots:
            dots[ndots] = index
            ndots += 1
    dots[ndots] = len(name)
    out: list[str] = []
    cursor = 0
    while cursor < len(map_text):
        if map_text[cursor] != '%':
            out.append(map_text[cursor])
            cursor += 1
            continue
        cursor += 1
        if cursor >= len(map_text):
            break
        if map_text[cursor] == '%':
            out.append('%')
            cursor += 1
            continue
        if map_text[cursor] == 'p':
            out.append(str(port))
            cursor += 1
            continue
        plus_n = plus_m = dash_n = dash_m = 0
        width = 0
        if map_text[cursor] == '-':
            dash_n = 1
            cursor += 1
        if cursor >= len(map_text) or not map_text[cursor].isdigit():
            break
        part = ord(map_text[cursor]) - ord('0')
        cursor += 1
        if cursor < len(map_text) and map_text[cursor] == '+':
            plus_n = 1
            cursor += 1
        if cursor < len(map_text) and map_text[cursor] == '.':
            cursor += 1
            if cursor < len(map_text) and map_text[cursor] == '-':
                dash_m = 1
                cursor += 1
            if cursor >= len(map_text) or not map_text[cursor].isdigit():
                break
            width = ord(map_text[cursor]) - ord('0')
            cursor += 1
            if cursor < len(map_text) and map_text[cursor] == '+':
                plus_m = 1
                cursor += 1
        start = dots[0] + 1
        end = dots[ndots]
        underscore = False
        if part != 0:
            if part > ndots:
                underscore = True
            elif not dash_n:
                start = dots[part - 1] + 1
                if not plus_n:
                    end = dots[part]
            else:
                if not plus_n:
                    start = dots[ndots - part] + 1
                end = dots[ndots - part + 1]
        if underscore:
            segment = '_'
            seg_start = 0
            seg_end = 1
        else:
            segment = name
            seg_start = start
            seg_end = end
        if width != 0:
            if width > seg_end - seg_start:
                segment = '_'
                seg_start = 0
                seg_end = 1
            elif not dash_m:
                seg_start = seg_start + width - 1
                if not plus_m:
                    seg_end = seg_start + 1
            else:
                if not plus_m:
                    seg_start = seg_end - width
                seg_end = seg_end - width + 1
        out.append(segment[seg_start:seg_end].lower())
    rendered = ''.join(out)
    if rendered.endswith('/'):
        rendered = rendered[:-1]
    return rendered


def _vhost_name_candidates(files: list[str]) -> list[str]:
    found = ['localhost', 'www.example.com', 'a.b.c.d.example.com', 'app']
    for rel in files:
        parts = rel.split('/')[:-1]
        for part in parts:
            if part and part not in found:
                found.append(part)
        if len(parts) >= 2:
            dotted = '.'.join(parts[-4:])
            if dotted not in found:
                found.append(dotted)
    return found


def _vhost_request_for_map(directive: str, raw_map: str, files: list[str]) -> tuple[str, str, dict[str, str]] | None:
    if re.search(r'%(?!%)p', raw_map.replace('%%', '')):
        return None
    script = 'Script' in directive
    needs_host = '%' in raw_map.replace('%%', '')
    names = ['127.0.0.1'] if directive.endswith('IP') else _vhost_name_candidates(files)
    for host in names:
        docroot = vhost_alias_docroot(raw_map, host, 80)
        prefix = docroot.split('{root}', 1)[-1].lstrip('/') if '{root}' in docroot else docroot.lstrip('/')
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        for rel in files:
            if prefix and not rel.startswith(prefix):
                continue
            rest = rel[len(prefix):] if prefix else rel
            if not rest:
                continue
            uri = '/cgi-bin/' + rest if script else '/' + rest
            headers = {'Host': host} if needs_host else {}
            return uri, 'virtual_script_alias' if script else 'virtual_document_root', headers
    return None


def _filter_chain_adds(text: str) -> bool:
    for match in re.finditer(r'(?m)^[ \t]*FilterChain\b(.*)$', text):
        for token in match.group(1).split():
            name = token.strip().strip('"').strip("'")
            if name and name[0] not in '!-':
                return True
    return False


_HTTPD_REDIRECT_STATUS = {
    'permanent': 301,
    'temp': 302,
    'temporary': 302,
    'seeother': 303,
    'gone': 410,
}


def _httpd_redirects(text: str) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    seen: set[str] = set()
    for match in re.finditer(r'(?m)^[ \t]*Redirect\s+(.+)$', text):
        parts = match.group(1).split()
        if not parts:
            continue
        status = 302
        token = parts[0].lower()
        if token in _HTTPD_REDIRECT_STATUS:
            parts = parts[1:]
            status = _HTTPD_REDIRECT_STATUS[token]
        elif re.fullmatch(r'\d{3}', parts[0]):
            code = int(parts[0])
            if not 100 <= code < 600:
                continue
            parts = parts[1:]
            status = code
        if not parts or not parts[0].startswith('/'):
            continue
        if status != 410 and len(parts) < 2:
            continue
        path = parts[0]
        if path in seen:
            continue
        seen.add(path)
        found.append((path, status))
    return found


def _error_document_404(text: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r'(?m)^[ \t]*ErrorDocument\s+404\s+(\S+)', text):
        target = match.group(1).strip().strip('"').strip("'")
        if not target.startswith('/') or '://' in target:
            continue
        path = target.split('?', 1)[0]
        if path not in found:
            found.append(path)
    return found


def _httpd_h2c_direct(text: str) -> bool:
    match = re.search(r'(?m)^[ \t]*Protocols\s+(.+)$', text)
    if match is None or not re.search(r'(?<![\w])h2c(?![\w])', match.group(1).lower()):
        return False
    direct = re.search(r'(?m)^[ \t]*H2Direct\s+(on|off)\b', text, re.I)
    return direct is None or direct.group(1).lower() != 'off'


def _httpd_filter_group(text: str) -> str | None:
    output = re.search(
        r'(?m)^[ \t]*(?:SetOutputFilter|AddOutputFilter|AddOutputFilterByType)\b',
        text,
    )
    if output or _filter_chain_adds(text):
        return 'output_filter'
    if re.search(
        r'(?m)^[ \t]*(?:SetInputFilter|AddInputFilter|AddInputFilterByType)\b',
        text,
    ):
        return 'input_filter'
    return None


def _httpd_doc_prefix(cfg: str) -> str:
    match = re.search(r'(?m)^[ \t]*DocumentRoot\s+(\S+)', cfg)
    if not match:
        return ''
    raw = match.group(1).strip().strip('"').strip("'")
    if '{root}' not in raw:
        return ''
    return raw.split('{root}', 1)[-1].strip('/\\')


def _rooted_suffix(raw: str) -> str:
    text = raw.strip().strip('"').strip("'")
    if '{root}' in text:
        text = text.split('{root}', 1)[-1]
    return text.strip('/\\')


def _httpd_doc_uri(rel: str, doc_prefix: str) -> str | None:
    norm = rel.replace('\\', '/').lstrip('/')
    prefix = doc_prefix.strip('/')
    if prefix:
        if norm != prefix and not norm.startswith(prefix + '/'):
            return None
        rest = norm[len(prefix):].lstrip('/')
    else:
        rest = norm
    if not rest or rest.endswith('/'):
        return None
    return '/' + rest


def _without_httpd_blocks(text: str) -> str:
    pattern = re.compile(
        r'(?is)<(Location|Directory|Files|VirtualHost|Proxy|FilesMatch)\b[^>]*>(.*?)</\1>',
    )
    current = text
    while True:
        updated = pattern.sub(' ', current)
        if updated == current:
            return current
        current = updated


_REWRITE_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PROPFIND', 'MKCOL', 'COPY', 'MOVE'}


def _rewrite_flags(text: str | None) -> set[str]:
    if not text:
        return set()
    return {part.strip().upper() for part in text.split(',') if part.strip()}


def _apache_http_header(var: str) -> str | None:
    if not var.startswith('HTTP_') or len(var) <= 5:
        return None
    parts = [part for part in var[5:].split('_') if part]
    if not parts:
        return None
    return '-'.join(part[:1].upper() + part[1:].lower() for part in parts)


def _plain_rewrite_token(raw: str) -> tuple[bool, str] | None:
    text = raw.strip().strip('"').strip("'")
    negated = text.startswith('!')
    if negated:
        text = text[1:]
    if not text or not re.fullmatch(r'[A-Za-z0-9_.:@/+%=-]+', text):
        return None
    return negated, text


def _rule_conditions(cfg: str, start: int, previous: int) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    pattern = re.compile(r'(?m)^[ \t]*RewriteCond\s+%\{([A-Za-z0-9_:]+)\}\s+(\S+)(?:\s+\[([^\]]*)\])?')
    for match in pattern.finditer(cfg):
        if previous <= match.start() < start:
            found.append({
                'var': match.group(1),
                'value': match.group(2),
                'flags': _rewrite_flags(match.group(3)),
            })
    return found


def _apply_rewrite_cond(method: str, path: str, headers: dict[str, str],
                        cond: dict[str, Any]) -> tuple[str, str, dict[str, str]] | None:
    parsed = _plain_rewrite_token(str(cond.get('value') or ''))
    if parsed is None:
        return None
    negated, token = parsed
    updated_headers = dict(headers)
    updated_method = method
    updated_path = path
    name = str(cond.get('var') or '').upper()
    if name.startswith('HTTP_'):
        header = _apache_http_header(name)
        if header is None:
            return None
        current = updated_headers.get(header)
        if negated:
            if current is None or current == token:
                updated_headers[header] = 'other' if token == 'ordinary' else 'ordinary'
        elif current is not None and current != token:
            return None
        else:
            updated_headers[header] = token
        return updated_method, updated_path, updated_headers
    if name == 'REQUEST_METHOD':
        wanted = token.upper()
        if wanted not in _REWRITE_METHODS:
            return None
        if negated:
            if updated_method.upper() == wanted:
                updated_method = 'POST' if wanted == 'GET' else 'GET'
        else:
            updated_method = wanted
        return updated_method, updated_path, updated_headers
    if name == 'QUERY_STRING':
        stem, _, query = path.partition('?')
        if negated:
            if not query or query == token:
                updated_path = stem + ('?vg=2' if token == 'vg=1' else '?vg=1')
        elif query and query != token:
            return None
        else:
            updated_path = stem + '?' + token
        return updated_method, updated_path, updated_headers
    if name == 'HTTPS':
        flag = token.lower()
        if flag not in {'on', 'off'}:
            return None
        if (flag == 'on') != negated:
            return None
        return updated_method, updated_path, updated_headers
    if name == 'REQUEST_URI':
        stem = path.split('?', 1)[0]
        if negated == (stem == token):
            return None
        return updated_method, updated_path, updated_headers
    return None


def _satisfy_rewrite_rule(path: str, conds: list[dict[str, Any]]) -> tuple[str, str, dict[str, str]] | None:
    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for cond in conds:
        current.append(cond)
        if 'OR' not in cond['flags']:
            groups.append(current)
            current = []
    if current:
        groups.append(current)
    method = 'GET'
    headers: dict[str, str] = {}
    for group in groups:
        chosen = None
        for cond in group:
            trial = _apply_rewrite_cond(method, path, headers, cond)
            if trial is not None:
                chosen = trial
                break
        if chosen is None:
            return None
        method, path, headers = chosen
    return method, path, headers


def _fixture_http_templates(case_ir: dict[str, Any]) -> list[dict[str, Any]]:
    cfg = str((case_ir.get('environment_fixture') or {}).get('config_template') or '')
    if not cfg:
        return []
    files = [str(rel) for rel in ((case_ir.get('environment_fixture') or {}).get('files') or {})]
    poc = _poc_method_paths(case_ir)
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(item: dict[str, Any]) -> None:
        request = item['request']
        key = (request['method'], request['path'], str(request.get('protocol') or ''))
        bare = (key[0], key[1].split('?', 1)[0])
        if bare in poc or key in seen:
            return
        seen.add(key)
        found.append(item)

    def prefer_filter(item: dict[str, Any]) -> None:
        key = (item['request']['method'], item['request']['path'])
        bare = (key[0], key[1].split('?', 1)[0])
        if bare in poc:
            return
        if not any(
            existing['request']['method'] == key[0] and existing['request']['path'] == key[1]
            for existing in found
        ):
            add(item)
            return
        for existing in found:
            if (existing['request']['method'], existing['request']['path']) != key:
                continue
            if existing['group'] == 'reverse_proxy' and item['group'] in {'output_filter', 'input_filter'}:
                existing['group'] = item['group']
                existing['id'] = item['id']
            return

    if re.search(r'\blocation\b', cfg):
        mapped = _nginx_map_variables(cfg)
        for header, body in _iter_braced(cfg, 'location'):
            parsed = re.match(r'\s*(=|~\*|\^~|~)?\s*(\S+)\s*$', header)
            if not parsed:
                continue
            mod, path = parsed.group(1) or '', parsed.group(2)
            if mod in ('~', '~*'):
                continue
            if _nginx_location_is_trigger(path, body):
                continue
            ident = 'cfg-' + _slug(path)
            returned = _nginx_return_status(body)
            rewritten = _nginx_rewrite_status(body)
            if returned is not None:
                group = 'map_variable' if _return_uses_mapped_variable(body, mapped) else 'configured_return'
                add(_http_template(ident, group, 'GET', _nginx_probe_path(mod, path, body), returned))
            elif rewritten is not None:
                group, status = rewritten
                add(_http_template(ident, group, 'GET', _nginx_probe_path(mod, path, body), status))
            elif 'grpc_pass' in body:
                grpc = _http_template(ident, 'grpc_pass', 'POST', path, 200, {
                    'content-type': 'application/grpc',
                    'te': 'trailers',
                })
                grpc['body'] = b'ordinary'
                grpc['request']['protocol'] = 'h2'
                grpc['request']['grpc'] = True
                add(grpc)
            elif 'proxy_pass' in body:
                if re.search(r'\bslice\b', body):
                    add(_http_template(ident, 'slice_range_proxy', 'GET', path, 200))
                elif re.search(r'\bproxy_http_version\s+2(?:\.0)?\b', body):
                    upstream = _http_template(ident, 'h2_upstream_proxy', 'GET', path, 200)
                    upstream['request']['protocol'] = 'h2'
                    add(upstream)
                else:
                    add(_http_template(ident, 'reverse_proxy', 'GET', path, 200))
            else:
                uri = _nginx_static_uri(path, body, files, mod)
                if uri:
                    group = 'static_alias_aio' if re.search(r'\baio\s+(?:on|threads)\b', body) else 'configured_file'
                    add(_http_template(ident, group, 'GET', uri, 200))
            methods = _dav_method_names(body)
            if methods and not _nginx_location_is_trigger(path, body):
                prefix = path if path.endswith('/') else path + '/'
                for item in _dav_method_templates(prefix, methods, _nginx_static_uri(path, body, files, mod)):
                    add(item)
        for target, override in _nginx_error_page_targets(cfg):
            status = next(
                (
                    item['expected_status']
                    for item in found
                    if item['request']['path'].split('?', 1)[0] == target
                ),
                None,
            )
            if status is None and override is None:
                continue
            add(_http_template(
                'cfg-error-page-404-' + _slug(target),
                'error_page',
                'GET',
                '/vg-missing-404',
                override if override is not None else status,
            ))
            break
        return found

    for match in re.finditer(r'(?m)^Alias\s+(\S+)\s+(\S+)', cfg):
        prefix, target = match.group(1), match.group(2)
        suffix = target.split('{root}', 1)[-1].lstrip('/') if '{root}' in target else ''
        if suffix and not suffix.endswith('/'):
            suffix += '/'
        for rel in files:
            if not suffix or not rel.startswith(suffix):
                continue
            rest = rel[len(suffix):]
            if not rest or '/' in rest:
                continue
            uri = (prefix if prefix.endswith('/') else prefix + '/') + rest
            add(_http_template('cfg-' + _slug(uri), 'configured_alias', 'GET', uri, 200))
            break
    for match in re.finditer(r'(?m)^ProxyPass\s+(\S+)\s+\S+', cfg):
        path = _proxy_request_path(match.group(1))
        add(_http_template('cfg-' + _slug(path), 'reverse_proxy', 'GET', path, 200))
    rules = list(re.finditer(r'(?m)^[ \t]*RewriteRule\s+(\S+)\s+\S+(?:\s+\[([^\]]*)\])?', cfg))
    previous = 0
    for match in rules:
        path_m = re.fullmatch(r'\^(/[^$]*)\$', match.group(1))
        rule_at = match.start()
        conds = _rule_conditions(cfg, rule_at, previous)
        previous = match.end()
        if not path_m:
            continue
        satisfied = _satisfy_rewrite_rule(path_m.group(1), conds)
        if satisfied is None:
            continue
        method, path, headers = satisfied
        add(_http_template(
            'cfg-' + _slug(path), 'configured_rewrite', method, path,
            _rewrite_rule_status(match.group(2)), headers,
        ))
    for match in re.finditer(r'(?is)<Location\b([^>]*)>(.*?)</Location>', cfg):
        header, body = match.group(1), match.group(2)
        path = header.strip().split()[-1] if header.strip() else ''
        if not path.startswith('/'):
            continue
        dav_methods = _httpd_dav_methods(body)
        if dav_methods:
            prefix = path if path.endswith('/') else path + '/'
            for item in _dav_method_templates(prefix, dav_methods, _uri_under_prefix(prefix, files)):
                add(item)
            continue
        name = path.rsplit('/', 1)[-1]
        filter_group = _httpd_filter_group(body)
        if filter_group:
            prefer_filter(_http_template('cfg-' + _slug(path), filter_group, 'GET', path, 200))
            continue
        if any(rel == name or rel.endswith('/' + name) for rel in files):
            add(_http_template('cfg-' + _slug(path), 'configured_location', 'GET', path, 200))
    doc_prefix = _httpd_doc_prefix(cfg)

    def add_filtered_file(group: str, rel: str) -> bool:
        uri = _httpd_doc_uri(rel, doc_prefix)
        if not uri:
            return False
        before = len(found)
        add(_http_template('cfg-' + _slug(uri + '-' + group), group, 'GET', uri, 200))
        return len(found) != before

    for match in re.finditer(r'(?is)<Directory\b([^>]*)>(.*?)</Directory>', cfg):
        group = _httpd_filter_group(match.group(2))
        if not group:
            continue
        suffix = _rooted_suffix(match.group(1))
        for rel in files:
            norm = rel.replace('\\', '/').lstrip('/')
            if suffix and norm != suffix and not norm.startswith(suffix + '/'):
                continue
            if add_filtered_file(group, norm):
                break
    for match in re.finditer(r'(?is)<Files\b([^>]*)>(.*?)</Files>', cfg):
        group = _httpd_filter_group(match.group(2))
        if not group:
            continue
        name = match.group(1).strip().strip('"').strip("'")
        if not name or any(ch in name for ch in '*?[]'):
            continue
        for rel in files:
            norm = rel.replace('\\', '/').lstrip('/')
            if norm == name or norm.endswith('/' + name):
                if add_filtered_file(group, norm):
                    break
    server_group = _httpd_filter_group(_without_httpd_blocks(cfg))
    if server_group:
        for rel in files:
            if add_filtered_file(server_group, rel):
                break
    for match in re.finditer(
        r'(?m)^(VirtualDocumentRootIP|VirtualDocumentRoot|VirtualScriptAliasIP|VirtualScriptAlias)\s+(\S+)',
        cfg,
    ):
        picked = _vhost_request_for_map(match.group(1), match.group(2).strip().strip('"').strip("'"), files)
        if not picked:
            continue
        uri, group, headers = picked
        add(_http_template('cfg-' + _slug(uri + group), group, 'GET', uri, 200, headers))
    for path, status in _httpd_redirects(cfg):
        add(_http_template('cfg-redirect-' + _slug(path), 'configured_redirect', 'GET', path, status))
    for target in _error_document_404(cfg):
        status = next(
            (
                item['expected_status']
                for item in found
                if item['request']['path'].split('?', 1)[0] == target
            ),
            None,
        )
        if status is None:
            continue
        add(_http_template('cfg-errdoc-404-' + _slug(target), 'error_document', 'GET', '/vg-missing-404', status))
        break
    if _httpd_h2c_direct(cfg):
        for rel in files:
            uri = _httpd_doc_uri(rel, doc_prefix)
            if not uri:
                continue
            direct = _http_template('cfg-h2c-' + _slug(uri), 'http2_direct', 'GET', uri, 200)
            direct['request']['protocol'] = 'h2'
            add(direct)
            break
    return found


def _dav_prefix(config_text: str) -> str | None:
    match = re.search(r'location\s+(?:\^~\s+)?(/[^\s{]*dav[^\s{]*)', config_text, re.IGNORECASE)
    if match is None and 'dav_methods' not in config_text and 'Dav On' not in config_text:
        return None
    prefix = match.group(1) if match is not None else '/dav/'
    if not prefix.endswith('/'):
        prefix += '/'
    return prefix


def _resize_text(text: str, target: int) -> str | None:
    if target < 0 or target > 4096:
        return None
    if len(text) == target:
        return text
    if len(text) > target:
        return text[:target]
    return text + ('a' * (target - len(text)))


def _flip_target(op: ast.cmpop, other: int, want_true: bool) -> int | None:
    if isinstance(op, ast.Lt):
        return other - 1 if want_true else other
    if isinstance(op, ast.LtE):
        return other if want_true else other + 1
    if isinstance(op, ast.Gt):
        return other + 1 if want_true else other
    if isinstance(op, ast.GtE):
        return other if want_true else other - 1
    if isinstance(op, ast.Eq):
        return other if want_true else other + 1
    if isinstance(op, ast.NotEq):
        return other + 1 if want_true else other
    return None


def _integer_text(text: str) -> int | None:
    body = str(text).strip()
    if re.fullmatch(r'[+-]?\d+', body) is None:
        return None
    value = int(body)
    if value < -4096 or value > 4096:
        return None
    return value


def _form_pairs(request: dict[str, Any]) -> list[tuple[str, str]]:
    headers = {str(name).lower(): str(value) for name, value in (request.get('headers') or {}).items()}
    if 'application/x-www-form-urlencoded' not in headers.get('content-type', '').lower():
        return []
    body_file = request.get('body_file')
    if not body_file or not Path(body_file).is_file():
        return []
    text = Path(body_file).read_bytes().decode('ascii', 'ignore')
    pairs: list[tuple[str, str]] = []
    for part in text.split('&'):
        key, sep, raw = part.partition('=')
        if sep and key:
            pairs.append((urllib.parse.unquote_plus(key), urllib.parse.unquote_plus(raw)))
    return pairs


def _request_measures(request: dict[str, Any]) -> list[tuple[Any, ...]]:
    measures: list[tuple[Any, ...]] = []
    path = str(request.get('path') or '/')
    stem, _, query = path.partition('?')
    measures.append(('path', len(stem)))
    if query:
        for part in query.split('&'):
            key, _, raw = part.partition('=')
            if raw:
                decoded = urllib.parse.unquote(raw)
                measures.append(('query', key, len(decoded)))
                number = _integer_text(decoded)
                if number is not None:
                    measures.append(('query_value', key, number))
    for name, value in (request.get('headers') or {}).items():
        text = str(value)
        measures.append(('header', str(name), len(text)))
        number = _integer_text(text)
        if number is not None:
            measures.append(('header_value', str(name), number))
    body_file = request.get('body_file')
    if body_file and Path(body_file).is_file():
        measures.append(('body', len(Path(body_file).read_bytes())))
    for key, raw in _form_pairs(request):
        number = _integer_text(raw)
        if number is not None:
            measures.append(('form_value', key, number))
    if request.get('chunk_size') is not None:
        measures.append(('chunk', int(request['chunk_size'])))
    return measures


def _pick_measure(measures: list[tuple[Any, ...]], value: int) -> tuple[Any, ...] | None:
    rank = {
        'query_value': 0, 'form_value': 1, 'header_value': 2,
        'query': 3, 'path': 4, 'header': 5, 'body': 6, 'chunk': 7,
    }
    hits = [item for item in measures if item[-1] == value]
    if not hits:
        return None
    hits.sort(key=lambda item: rank[str(item[0])])
    return hits[0]


def _pick_affine_measure(measures: list[tuple[Any, ...]], operand: int) -> tuple[tuple[Any, ...], int] | None:
    hits: list[tuple[int, tuple[Any, ...], int]] = []
    for item in measures:
        delta = operand - int(item[-1])
        if delta == 0 or abs(delta) > 64:
            continue
        hits.append((abs(delta), item, delta))
    if not hits:
        return None
    hits.sort(key=lambda row: row[0])
    closest = hits[0][0]
    tied = [row for row in hits if row[0] == closest]
    if len(tied) != 1:
        return None
    return tied[0][1], tied[0][2]


def _apply_measure(request: dict[str, Any], measure: tuple[Any, ...], target: int,
                   corpus_dir: Path, case_id: str) -> bool:
    kind = measure[0]
    if kind == 'path':
        path = str(request.get('path') or '/')
        stem, _, query = path.partition('?')
        resized = _resize_text(stem, target)
        if not resized or not resized.startswith('/'):
            return False
        request['path'] = resized + (f'?{query}' if query else '')
        return request['path'] != path
    if kind == 'query':
        path = str(request.get('path') or '/')
        stem, _, query = path.partition('?')
        key = str(measure[1])
        parts: list[str] = []
        replaced = False
        for part in query.split('&'):
            if not replaced and part.startswith(key + '='):
                parts.append(key + '=' + urllib.parse.quote('a' * target))
                replaced = True
            else:
                parts.append(part)
        if not replaced:
            return False
        request['path'] = stem + '?' + '&'.join(parts)
        return True
    if kind == 'query_value':
        path = str(request.get('path') or '/')
        stem, _, query = path.partition('?')
        key = str(measure[1])
        parts = []
        replaced = False
        for part in query.split('&'):
            if not replaced and part.startswith(key + '='):
                parts.append(key + '=' + urllib.parse.quote(str(target), safe=''))
                replaced = True
            else:
                parts.append(part)
        if not replaced:
            return False
        updated = stem + '?' + '&'.join(parts)
        if updated == path:
            return False
        request['path'] = updated
        return True
    if kind == 'header_value':
        headers = request.setdefault('headers', {})
        name = str(measure[1])
        text = str(target)
        if str(headers.get(name, '')) == text:
            return False
        headers[name] = text
        return True
    if kind == 'form_value':
        source = Path(str(request.get('body_file')))
        key = str(measure[1])
        parts = []
        replaced = False
        for part in source.read_bytes().decode('ascii', 'ignore').split('&'):
            name, sep, _raw = part.partition('=')
            if sep and urllib.parse.unquote_plus(name) == key and not replaced:
                parts.append(urllib.parse.urlencode({key: str(target)}))
                replaced = True
            else:
                parts.append(part)
        if not replaced:
            return False
        corpus_dir.mkdir(parents=True, exist_ok=True)
        dest = corpus_dir / f'{_slug(case_id)}-form.txt'
        dest.write_text('&'.join(parts), encoding='ascii')
        request['body_file'] = str(dest)
        return True
    if kind == 'header':
        headers = request.setdefault('headers', {})
        name = str(measure[1])
        resized = _resize_text(str(headers.get(name, '')), target)
        if resized is None or resized == str(headers.get(name, '')):
            return False
        headers[name] = resized
        return True
    if kind == 'body':
        source = Path(str(request.get('body_file')))
        data = source.read_bytes()
        resized = data[:target] if target <= len(data) else data + (b'a' * (target - len(data)))
        if resized == data:
            return False
        corpus_dir.mkdir(parents=True, exist_ok=True)
        dest = corpus_dir / f'{_slug(case_id)}-body.bin'
        dest.write_bytes(resized)
        request['body_file'] = str(dest)
        return True
    if kind == 'chunk':
        if target < 1:
            return False
        request['chunk_size'] = target
        return int(measure[1]) != target
    return False


def branch_flip_case(case: dict[str, Any], dist: dict[str, Any], corpus_dir: Path) -> dict[str, Any] | None:
    request = case.get('request')
    if not isinstance(request, dict):
        return None
    try:
        node = ast.parse(str(dist.get('predicate') or ''), mode='eval').body
    except SyntaxError:
        return None
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = int(dist['lhs'])
    right = int(dist['rhs'])
    measures = _request_measures(request)
    offset = 0
    chosen = _pick_measure(measures, left)
    control_left = chosen is not None
    if chosen is None:
        chosen = _pick_measure(measures, right)
    if chosen is None:
        affine = _pick_affine_measure(measures, left)
        if affine is not None:
            chosen, offset = affine
            control_left = True
        else:
            affine = _pick_affine_measure(measures, right)
            if affine is None:
                return None
            chosen, offset = affine
            control_left = False
    op = node.ops[0]
    other = right if control_left else left
    if not control_left:
        swapped = {
            ast.Lt: ast.Gt(),
            ast.LtE: ast.GtE(),
            ast.Gt: ast.Lt(),
            ast.GtE: ast.LtE(),
            ast.Eq: ast.Eq(),
            ast.NotEq: ast.NotEq(),
        }.get(type(op))
        if swapped is None:
            return None
        op = swapped
    target = _flip_target(op, other, not bool(dist.get('truth')))
    if target is None:
        return None
    target -= offset
    if target < 0 or target > 4096 or target == int(chosen[-1]):
        return None
    flipped = copy.deepcopy(case)
    flipped.pop('prelude_request', None)
    if not _apply_measure(flipped['request'], chosen, target, Path(corpus_dir), str(flipped.get('id') or 'flip')):
        return None
    predicate = str(dist.get('predicate') or '')
    flipped['id'] = f'{case.get("id", "case")}-flip-{_slug(predicate)}'
    flipped['group'] = 'branch_flip'
    flipped['stream_kind'] = 'guided_fuzz'
    flipped['target_predicate'] = predicate
    flipped['schedule_distance'] = float(dist.get('normalized_distance') or 0.0)
    return flipped


def enqueue_unseen_branch_flips(case: dict[str, Any],
                                guard: dict[str, Any],
                                snapshot: dict[str, Any],
                                predicate_distances: dict[str, dict[str, Any]],
                                pending: list[dict[str, Any]],
                                seen: set[str],
                                corpus_dir: Path) -> None:
    existing = {str(item.get('id')) for item in pending}
    for dist in snapshot_predicate_distances(guard, snapshot):
        key = f'{guard.get("id")}:{dist["predicate"]}'
        record = predicate_distances.get(key) or {}
        if record.get('seen_true') and record.get('seen_false'):
            continue
        if key in seen or len(pending) >= 256:
            continue
        flipped = branch_flip_case(case, dist, corpus_dir)
        if flipped is None:
            continue
        if flipped['id'] in existing:
            seen.add(key)
            continue
        seen.add(key)
        existing.add(flipped['id'])
        pending.append(flipped)


def _snapshot_alias_values(guard: dict[str, Any],
                           snapshot: dict[str, Any],
                           field_map: dict[str, Any] | None) -> dict[str, int]:
    values = dict(evaluate_snapshot_in_guard_space(guard, snapshot))
    for field, expr in (field_map or {}).items():
        if field in values and isinstance(expr, str) and expr.isidentifier():
            values.setdefault(expr, values[field])
    return values


def enqueue_caller_condition_flips(case: dict[str, Any],
                                   guard: dict[str, Any],
                                   snapshot: dict[str, Any],
                                   conditions: list[dict[str, Any]],
                                   pending: list[dict[str, Any]],
                                   seen: set[str],
                                   corpus_dir: Path,
                                   field_map: dict[str, Any] | None = None) -> None:
    values = _snapshot_alias_values(guard, snapshot, field_map)
    function = str(guard.get('function') or '')
    guard_id = str(guard.get('id') or '')
    existing = {str(item.get('id')) for item in pending}
    for cond in conditions or []:
        target = str(cond.get('guard') or '')
        if target not in {function, guard_id}:
            continue
        caller = str(cond.get('caller') or '')
        for pred in cond.get('input_predicates') or []:
            key = f'{caller}:{pred}'
            if key in seen or len(pending) >= 256:
                continue
            dist = predicate_distance(str(pred), values)
            if dist is None:
                continue
            flipped = branch_flip_case(case, dist, corpus_dir)
            if flipped is None:
                continue
            flipped['id'] = f'{case.get("id", "case")}-caller-{_slug(caller)}-{_slug(str(pred))}'
            flipped['group'] = 'caller_condition_flip'
            flipped['schedule_class'] = 'caller_condition'
            flipped['target_caller'] = caller
            flipped['target_predicate'] = str(pred)
            if flipped['id'] in existing:
                seen.add(key)
                continue
            seen.add(key)
            existing.add(flipped['id'])
            pending.append(flipped)


def protocol_preserving_mutations(base: dict[str, Any], config_text: str, corpus_dir: Path) -> list[dict[str, Any]]:
    request = base['request']
    path = str(request.get('path', '/'))
    stem, query = (path.split('?', 1) + [''])[:2]
    if stem.endswith('/'):
        directory, leaf = stem, 'index'
    else:
        slash = stem.rfind('/')
        directory, leaf = stem[:slash + 1], stem[slash + 1:] or 'index'
    variants: list[dict[str, Any]] = []

    def emit(suffix: str, method: str, new_path: str, headers: dict[str, str] | None = None,
             body: bytes | None = None, chunk_size: int | None = None, prelude: dict[str, Any] | None = None) -> None:
        item = copy.deepcopy(base)
        item['id'] = f'{base["id"]}-{suffix}'
        item['stream_kind'] = 'guided_fuzz'
        item['group'] = 'protocol_' + suffix.split('-')[0]
        req = item['request']
        req['method'] = method
        req['path'] = new_path
        req['headers'] = dict(headers if headers is not None else request.get('headers') or {})
        if body is not None:
            body_path = Path(corpus_dir) / f'{item["id"]}.body'
            body_path.write_bytes(body)
            req['body_file'] = str(body_path)
        if chunk_size is not None:
            req['chunk_size'] = int(chunk_size)
        if prelude is not None:
            item['prelude_request'] = prelude
        variants.append(item)
        return item

    query_suffix = f'?{query}' if query else ''
    emit('seg-len', request.get('method', 'GET'), f'{directory}{leaf}{"a" * 48}{query_suffix}')
    dotted_leaf = f'{leaf}.a.b' if '.' not in leaf else f'a.b.c.{leaf}'
    emit('seg-dots', request.get('method', 'GET'), f'{directory}{dotted_leaf}{query_suffix}')
    joined = f'{query}&vgk=a.b' if query else 'vgk=a.b'
    emit('query', request.get('method', 'GET'), f'{stem}?{joined}')
    headers = dict(request.get('headers') or {})
    headers['Accept'] = 'text/plain, application/octet-stream'
    headers['Accept-Language'] = 'en, zh'
    emit('headers', request.get('method', 'GET'), path, headers=headers)
    form = urllib.parse.urlencode({'vg_field': 'ordinary', 'vg_note': 'a.b'}).encode('ascii')
    form_headers = dict(request.get('headers') or {})
    form_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    emit('form', 'POST', stem, headers=form_headers, body=form)
    chunk_body = b'ordinary-chunk-body'
    for size in (1, 8, 64):
        emit(f'chunk-{size}', 'POST', stem,
             headers=dict(request.get('headers') or {}), body=chunk_body, chunk_size=size)
    dav = _dav_prefix(config_text)
    if dav is not None:
        target = dav + 'file.txt'
        copy_req = {
            'method': 'COPY',
            'path': target,
            'headers': {'Destination': dav + 'file-moved.txt'},
            'response_kind': request.get('response_kind', 'http'),
        }
        emit('dav-seq', 'MOVE', target, headers={'Destination': dav + 'file-final.txt'}, prelude=copy_req)
    for path in _grpc_location_paths(config_text):
        item = emit(
            'grpc-' + _slug(path),
            'POST',
            path,
            headers={'content-type': 'application/grpc', 'te': 'trailers'},
            body=b'ordinary',
        )
        item['request']['protocol'] = 'h2'
        item['request']['grpc'] = True
        item['group'] = 'protocol_grpc'
    return variants


def _grpc_location_paths(config_text: str) -> list[str]:
    if 'grpc_pass' not in config_text:
        return []
    found: list[str] = []
    for header, body in _iter_braced(config_text, 'location'):
        if 'grpc_pass' not in body:
            continue
        parsed = re.match(r'\s*(=|~\*|\^~|~)?\s*(\S+)\s*$', header)
        if not parsed or parsed.group(1) in ('~', '~*'):
            continue
        path = parsed.group(2)
        if path.startswith('/') and path not in found:
            found.append(path)
    return found


def _cli_payloads(case_ir: dict[str, Any]) -> list[bytes]:
    payloads: list[bytes] = []
    for seed in (case_ir.get('seed_traces') or {}).get('benign_seeds') or []:
        if not isinstance(seed, dict):
            continue
        if isinstance(seed.get('body_hex'), str):
            payloads.append(bytes.fromhex(seed['body_hex']))
        elif isinstance(seed.get('body'), str):
            payloads.append(seed['body'].encode())
    for content in ((case_ir.get('environment_fixture') or {}).get('files') or {}).values():
        if isinstance(content, str):
            payloads.append(content.encode())
        elif isinstance(content, (bytes, bytearray)):
            payloads.append(bytes(content))
    if not payloads:
        payloads.append(b'ordinary\n')
    return payloads


def _cli_stream_cases(case_ir: dict[str, Any],
                      corpus_dir: Path,
                      symbolic_result: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    payloads = _cli_payloads(case_ir)
    chunks = [int(item) for item in (case_ir['app_profile'].get('stream_chunk_sizes') or [0, 1, 8, 64])]
    fixed_cases: list[dict[str, Any]] = []
    for index, payload in enumerate(payloads):
        for chunk in chunks:
            path = corpus_dir / f'cli-{index:03d}-c{chunk}.bin'
            path.write_bytes(payload)
            fixed_cases.append({
                'id': f'cli-{index:03d}-c{chunk}',
                'group': 'cli_stream',
                'stream_kind': 'fixed_eval',
                'invocation': {'body_file': str(path), 'chunk_size': chunk},
                'expected': {'exit_code': 0, 'bytes_in': len(payload)},
            })
    guided_cases: list[dict[str, Any]] = []
    for index, payload in enumerate(payloads):
        mutated = [
            ('chunk1', payload, 1),
            ('chunk8', payload, 8),
            ('chunk64', payload, 64),
            ('longer', payload + (b'A' * 48), 8),
            ('dot', (payload[:1] + b'.' + payload[1:]) if payload else b'.', 8),
        ]
        for name, body, chunk in mutated:
            path = corpus_dir / f'cli-fuzz-{index:03d}-{name}.bin'
            path.write_bytes(body)
            guided_cases.append({
                'id': f'cli-fuzz-{index:03d}-{name}',
                'group': 'cli_stream_mutation',
                'stream_kind': 'guided_fuzz',
                'invocation': {'body_file': str(path), 'chunk_size': chunk},
                'expected': {'exit_code': 0, 'bytes_in': len(body)},
            })
    return fixed_cases, _schedule_guided_cases(case_ir, guided_cases, symbolic_result)


def _c_api_u64_words(spec: dict[str, Any]) -> list[int]:
    words = [int(item) for item in (spec.get('u64') or [0, 0, 0, 0])]
    if len(words) > 4:
        raise ValueError('u64_4 accepts four words')
    return words + [0] * (4 - len(words))


def _c_api_command(convention: str, symbol: str, words: list[int] | None = None,
                   body_file: str | None = None, out_cap: int | None = None) -> str:
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', symbol):
        raise ValueError('c api symbol must be an identifier')
    if convention == 'u64_4':
        a, b, c, d = words or [0, 0, 0, 0]
        return f'u64_4 {symbol} {a} {b} {c} {d}'
    if convention == 'buf_in_out':
        return f'buf_in_out {symbol} {body_file} {int(out_cap or 0)}'
    raise ValueError('c api convention must be u64_4 or buf_in_out')


def _c_api_cases(case_ir: dict[str, Any],
                 corpus_dir: Path,
                 symbolic_result: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    fixed_cases: list[dict[str, Any]] = []
    guided_cases: list[dict[str, Any]] = []
    calls = list(case_ir['app_profile'].get('c_api_calls') or [])
    for index, spec in enumerate(calls):
        convention = str(spec.get('convention') or '')
        symbol = str(spec.get('symbol') or '')
        expected = {'call_ok': True}
        if convention == 'u64_4':
            words = _c_api_u64_words(spec)
            command = _c_api_command(convention, symbol, words=words)
            if 'expected_return' in spec:
                expected['return_u64'] = int(spec['expected_return'])
            fixed_cases.append({
                'id': f'capi-{index:03d}',
                'group': 'c_api_u64',
                'stream_kind': 'fixed_eval',
                'invocation': command,
                'expected': expected,
            })
            mutations = [words[0] + 1, 0, 4294967295]
            for name, value in zip(('plus', 'zero', 'wide'), mutations):
                changed = [value, *words[1:]]
                guided_cases.append({
                    'id': f'capi-fuzz-{index:03d}-{name}',
                    'group': 'c_api_u64_mutation',
                    'stream_kind': 'guided_fuzz',
                    'invocation': _c_api_command(convention, symbol, words=changed),
                    'expected': {'call_ok': True},
                })
        elif convention == 'buf_in_out':
            body = bytes.fromhex(spec['body_hex']) if spec.get('body_hex') else str(spec.get('body') or '').encode()
            out_cap = int(spec.get('out_cap') or max(len(body), 1))
            path = corpus_dir / f'capi-{index:03d}.bin'
            path.write_bytes(body)
            if 'expected_return' in spec:
                expected['return_u64'] = int(spec['expected_return'])
            fixed_cases.append({
                'id': f'capi-{index:03d}',
                'group': 'c_api_buffer',
                'stream_kind': 'fixed_eval',
                'invocation': _c_api_command(convention, symbol, body_file=str(path), out_cap=out_cap),
                'expected': expected,
            })
            variants = [
                ('longer', body + (b'A' * 48)),
                ('dot', (body[:1] + b'.' + body[1:]) if body else b'.'),
                ('len1', body[:1] if body else b'A'),
                ('len8', (body + b'B' * 8)[:8]),
                ('len64', (body + b'C' * 64)[:64]),
            ]
            for name, mutated in variants:
                mutated_path = corpus_dir / f'capi-fuzz-{index:03d}-{name}.bin'
                mutated_path.write_bytes(mutated)
                guided_cases.append({
                    'id': f'capi-fuzz-{index:03d}-{name}',
                    'group': 'c_api_buffer_mutation',
                    'stream_kind': 'guided_fuzz',
                    'invocation': _c_api_command(
                        convention, symbol, body_file=str(mutated_path), out_cap=max(out_cap, len(mutated)),
                    ),
                    'expected': {'call_ok': True},
                })
        else:
            raise ValueError('c api convention must be u64_4 or buf_in_out')
    return fixed_cases, _schedule_guided_cases(case_ir, guided_cases, symbolic_result)


def operation_payload(protocol: str, case: dict[str, Any]) -> Any:
    if protocol == 'brotli_stream_rpc':
        return case['command']
    if protocol in ('cli_stream', 'c_api_rpc'):
        return case['invocation']
    return case['request']


_PHP_DEFAULT_DIRECTIVES = {
    'session.upload_progress.enabled': '1',
    'session.upload_progress.cleanup': '0',
    'session.upload_progress.freq': '1',
    'session.upload_progress.min_freq': '0',
    'session.upload_progress.name': 'PHP_SESSION_UPLOAD_PROGRESS',
    'session.upload_progress.prefix': 'upload_progress_',
    'file_uploads': '1',
    'display_errors': '0',
    'log_errors': '1',
    'session.use_strict_mode': '0',
}


def _php_ini_text(line: str) -> str:
    out: list[str] = []
    quote = ''
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            out.append(char)
            if char == '\\' and index + 1 < len(line):
                out.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = ''
            index += 1
            continue
        if char in '"\'':
            quote = char
            out.append(char)
            index += 1
            continue
        if char in ';#':
            break
        out.append(char)
        index += 1
    return ''.join(out).strip()


def _php_unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in '"\'':
        body = text[1:-1]
        if text[0] == '"':
            body = body.replace('\\\\', '\x00').replace('\\"', '"').replace('\x00', '\\')
        return body
    return text


def parse_php_ini(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for raw in str(text or '').splitlines():
        line = _php_ini_text(raw)
        if not line or line.startswith('['):
            continue
        if '=' not in line:
            continue
        name, value = line.split('=', 1)
        name = name.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', name):
            continue
        found[name] = _php_unquote(value)
    return found


def _php_enabled(value: str, default: bool) -> bool:
    token = str(value).strip().lower()
    mapped = {
        '1': True, 'on': True, 'true': True, 'yes': True,
        '0': False, 'off': False, 'false': False, 'no': False,
    }
    return mapped.get(token, default)


def php_runtime_settings(case_ir: dict[str, Any]) -> dict[str, str]:
    fixture = case_ir.get('environment_fixture') or {}
    settings = dict(_PHP_DEFAULT_DIRECTIVES)
    settings.update(parse_php_ini(str(fixture.get('config_template') or '')))
    extra = fixture.get('php_ini')
    if isinstance(extra, str):
        settings.update(parse_php_ini(extra))
    elif isinstance(extra, dict):
        for key, value in extra.items():
            name = str(key).strip()
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', name):
                settings[name] = str(value)
    return settings


def php_upload_plan(case_ir: dict[str, Any]) -> dict[str, Any]:
    settings = php_runtime_settings(case_ir)
    uploads = _php_enabled(settings.get('file_uploads', '1'), True)
    progress_on = _php_enabled(settings.get('session.upload_progress.enabled', '1'), True)
    cleanup = _php_enabled(settings.get('session.upload_progress.cleanup', '0'), False)
    name = settings.get('session.upload_progress.name') or 'PHP_SESSION_UPLOAD_PROGRESS'
    prefix = settings.get('session.upload_progress.prefix')
    if prefix is None:
        prefix = 'upload_progress_'
    progress = bool(
        uploads and progress_on and not cleanup and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name)
    )
    return {
        'settings': settings,
        'file_uploads': uploads,
        'progress': progress,
        'progress_name': name,
        'progress_prefix': prefix,
    }


def php_ini_arguments(case_ir: dict[str, Any], save_path: Path | None = None) -> list[str]:
    settings = php_runtime_settings(case_ir)
    args: list[str] = []
    if save_path is not None:
        args.extend(['-d', f'session.save_path={save_path}'])
    keys = list(_PHP_DEFAULT_DIRECTIVES)
    keys.extend(sorted(key for key in settings if key not in _PHP_DEFAULT_DIRECTIVES and key != 'session.save_path'))
    for key in keys:
        if key == 'session.save_path':
            continue
        value = settings.get(key)
        if value is None:
            continue
        args.extend(['-d', f'{key}={value}'])
    return args


def synthesize_corpus_from_fixture_and_profile(case_ir: dict[str, Any],
                                               corpus_dir: Path,
                                               symbolic_result: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    corpus_dir = Path(corpus_dir).resolve()
    corpus_dir.mkdir(parents=True, exist_ok=True)
    protocol = case_ir['app_profile']['protocol']
    fixture = case_ir.get('environment_fixture', {})
    seeds = case_ir.get('seed_traces', {})
    rng = random.Random(20261113)

    if protocol == 'brotli_stream_rpc':
        encoder = Path(case_ir['app_profile']['encoder_binary']).resolve()
        fixed_cases: list[dict[str, Any]] = []
        plain_seeds = [
            b'', b'A', b'ordinary text\n' * 32,
            b'{"name":"roundtrip","active":true,"count":32}\n' * 16,
            '正常压缩与流式解压\n'.encode('utf-8') * 32,
            bytes(range(256)) * 4,
            b'Z' * 4096,
        ]
        schedules = [(1, 7, 1), (4096, 4096, 0), (7, 1, 0)]
        idx = 0
        for s_i, data in enumerate(plain_seeds):
            for chunk_in, chunk_out, first_zero in schedules:
                qual = [0, 5, 11][s_i % 3]
                plain_f = corpus_dir / f'{idx:03d}.plain'
                enc_f = corpus_dir / f'{idx:03d}.br'
                plain_f.write_bytes(data)
                subprocess.run([str(encoder), str(plain_f), str(enc_f), str(qual)], check=True)
                fixed_cases.append({
                    'id': f'fixed-{idx:03d}',
                    'group': f'stream_q{qual}_in{chunk_in}',
                    'stream_kind': 'fixed_eval',
                    'command': f'{idx} {enc_f} {plain_f} {chunk_in} {chunk_out} {first_zero}',
                    'expected': {
                        'result': 1, 'error': 1, 'produced': len(data),
                        'total_out': len(data), 'consumed': enc_f.stat().st_size,
                        'output_hex': data.hex(), 'matches_expected': True,
                    },
                    'params': {'size': len(data), 'quality': qual, 'chunk_in': chunk_in, 'chunk_out': chunk_out, 'first_zero': first_zero},
                })
                idx += 1

        guided_cases: list[dict[str, Any]] = []
        for g_i in range(24):
            sz = rng.choice([0, 1, 7, 8, 9, 31, 128, 257, 1024, 2048])
            data = bytes(rng.randrange(256) for _ in range(sz)) if g_i % 2 else bytes([rng.randrange(32, 127)]) * sz
            qual = rng.choice([0, 3, 5, 9, 11])
            chunk_in = rng.choice([1, 2, 7, 8, 9, 64, 4096])
            chunk_out = rng.choice([1, 7, 8, 9, 64, 4096])
            first_zero = rng.randrange(2)
            plain_f = corpus_dir / f'{idx:03d}.plain'
            enc_f = corpus_dir / f'{idx:03d}.br'
            plain_f.write_bytes(data)
            subprocess.run([str(encoder), str(plain_f), str(enc_f), str(qual)], check=True)
            guided_cases.append({
                'id': f'fuzz-{g_i:03d}',
                'group': 'guided_stream_fuzz',
                'stream_kind': 'guided_fuzz',
                'command': f'{idx} {enc_f} {plain_f} {chunk_in} {chunk_out} {first_zero}',
                'expected': {
                    'result': 1, 'error': 1, 'produced': len(data),
                    'total_out': len(data), 'consumed': enc_f.stat().st_size,
                    'output_hex': data.hex(), 'matches_expected': True,
                },
                'params': {'size': len(data), 'quality': qual, 'chunk_in': chunk_in, 'chunk_out': chunk_out, 'first_zero': first_zero},
            })
            idx += 1
        return fixed_cases, _schedule_guided_cases(case_ir, guided_cases, symbolic_result)

    if protocol == 'cli_stream':
        return _cli_stream_cases(case_ir, corpus_dir, symbolic_result)

    if protocol == 'c_api_rpc':
        return _c_api_cases(case_ir, corpus_dir, symbolic_result)

    if protocol == 'php_http':
        fixed_cases = []
        guided_cases = []
        upload_plan = php_upload_plan(case_ir)
        progress_name = str(upload_plan['progress_name'])
        sizes = [0, 1, 32, 256, 4096, 32768]
        groups = ['form']
        if upload_plan['file_uploads']:
            groups.append('plain_upload')
        if upload_plan['progress']:
            groups.append('progress_upload')
        idx = 0
        for group in groups:
            for sz in sizes:
                msg = f'ordinary-{idx}'
                headers = {'Cookie': f'PHPSESSID=vgtest{idx:04d}'}
                expected: dict[str, Any] = {
                    'http_status': 200,
                    'message': msg,
                    'files': [],
                    'progress_present': group == 'progress_upload',
                    'progress_done': True if group == 'progress_upload' else None,
                    'progress_file_count': 1 if group == 'progress_upload' else 0,
                }
                if group == 'form':
                    body = urllib.parse.urlencode({'message': msg}).encode('utf-8')
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                else:
                    boundary = 'VulGateUniversalBoundary20261113'
                    parts = [
                        f'--{boundary}\r\nContent-Disposition: form-data; name="message"\r\n\r\n{msg}\r\n'.encode('utf-8')
                    ]
                    if group == 'progress_upload':
                        parts.append(
                            f'--{boundary}\r\nContent-Disposition: form-data; name="{progress_name}"\r\n\r\njob\r\n'.encode('utf-8')
                        )
                    data = (b'Ordinary upload data.\n' * ((sz + 20) // 21))[:sz]
                    parts.extend([
                        f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="note.txt"\r\nContent-Type: text/plain\r\n\r\n'.encode('utf-8'),
                        data,
                        b'\r\n',
                        f'--{boundary}--\r\n'.encode('utf-8'),
                    ])
                    body = b''.join(parts)
                    headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
                    expected['files'] = [{
                        'field': 'document', 'name': 'note.txt', 'size': sz, 'error': 0,
                        'sha256': hashlib.sha256(data).hexdigest(),
                    }]
                bpath = corpus_dir / f'php-{idx:03d}.body'
                bpath.write_bytes(body)
                fixed_cases.append({
                    'id': f'php-{idx:03d}',
                    'group': group,
                    'stream_kind': 'fixed_eval',
                    'request': {'method': 'POST', 'path': '/', 'body_file': str(bpath), 'headers': headers},
                    'expected': expected,
                })
                idx += 1
        for g_i in range(6):
            sz = rng.choice([7, 64, 513, 8192])
            msg = f'guided-{g_i}-{rng.randrange(1000)}'
            boundary = f'VulGateFuzzBoundary{g_i:02d}'
            use_prog = bool(upload_plan['progress'] and g_i % 2 == 1)
            data = bytes(rng.randrange(65, 91) for _ in range(sz))
            if not upload_plan['file_uploads']:
                body = urllib.parse.urlencode({'message': msg}).encode('utf-8')
                headers = {
                    'Cookie': f'PHPSESSID=vgfuzz{g_i:04d}',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
                expected = {
                    'http_status': 200,
                    'message': msg,
                    'files': [],
                    'progress_present': False,
                    'progress_done': None,
                    'progress_file_count': 0,
                }
                group = 'form'
            else:
                parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="message"\r\n\r\n{msg}\r\n'.encode('utf-8')]
                if use_prog:
                    parts.append(
                        f'--{boundary}\r\nContent-Disposition: form-data; name="{progress_name}"\r\n\r\nfuzzjob\r\n'.encode('utf-8')
                    )
                parts.extend([
                    f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="fuzz.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode('utf-8'),
                    data, b'\r\n', f'--{boundary}--\r\n'.encode('utf-8'),
                ])
                body = b''.join(parts)
                headers = {
                    'Cookie': f'PHPSESSID=vgfuzz{g_i:04d}',
                    'Content-Type': 'multipart/form-data; boundary=' + boundary,
                }
                expected = {
                    'http_status': 200,
                    'message': msg,
                    'files': [{'field': 'document', 'name': 'fuzz.bin', 'size': sz, 'error': 0, 'sha256': hashlib.sha256(data).hexdigest()}],
                    'progress_present': use_prog,
                    'progress_done': True if use_prog else None,
                    'progress_file_count': 1 if use_prog else 0,
                }
                group = 'progress_upload' if use_prog else 'plain_upload'
            bpath = corpus_dir / f'php-fuzz-{g_i:03d}.body'
            bpath.write_bytes(body)
            guided_cases.append({
                'id': f'php-fuzz-{g_i:03d}',
                'group': group,
                'stream_kind': 'guided_fuzz',
                'request': {
                    'method': 'POST', 'path': '/', 'body_file': str(bpath),
                    'headers': headers,
                },
                'expected': expected,
            })
        for size in (1, 8, 64):
            if not guided_cases:
                break
            chunked = copy.deepcopy(guided_cases[0])
            chunked['id'] = f'{chunked["id"]}-chunk-{size}'
            chunked['request']['chunk_size'] = size
            guided_cases.append(chunked)
        return fixed_cases, _schedule_guided_cases(case_ir, guided_cases, symbolic_result)

    cfg_text = fixture.get('config_template', '')
    base_templates: list[dict[str, Any]] = []

    explicit_seeds = seeds.get('benign_seeds', [])
    for s_idx, item in enumerate(explicit_seeds):
        req = {
            'method': item.get('method', 'GET'),
            'path': item['path'],
            'headers': dict(item.get('headers', {})),
            'response_kind': 'http',
        }
        if item.get('protocol'):
            req['protocol'] = item['protocol']
        if 'body' in item and item['body'] is not None:
            raw_b = item['body'].encode('utf-8') if isinstance(item['body'], str) else bytes(item['body'])
            bf = corpus_dir / f'seed-{s_idx:03d}.body'
            bf.write_bytes(raw_b)
            req['body_file'] = str(bf)
        base_templates.append({
            'id': item.get('id', f'seed-{s_idx:02d}'),
            'group': item.get('group', 'declared_seed'),
            'request': req,
            'expected_status': int(item.get('expected_status', 200)),
        })

    seen_requests = {
        (item['request']['method'], item['request']['path'], str(item['request'].get('protocol') or ''))
        for item in base_templates
    }
    for item in _fixture_http_templates(case_ir):
        key = (item['request']['method'], item['request']['path'], str(item['request'].get('protocol') or ''))
        if key in seen_requests:
            continue
        seen_requests.add(key)
        base_templates.append(item)

    if not base_templates:
        if 'location = /plain' in cfg_text:
            base_templates.append({'id': 'plain', 'group': 'static_http', 'request': {'method': 'GET', 'path': '/plain', 'headers': {}, 'response_kind': 'http'}, 'expected_status': 200})
        if 'location = /value' in cfg_text:
            base_templates.append({'id': 'value', 'group': 'script_variable', 'request': {'method': 'GET', 'path': '/value?name=ordinary', 'headers': {}, 'response_kind': 'http'}, 'expected_status': 200})
        if 'location /files/' in cfg_text:
            base_templates.append({'id': 'file', 'group': 'static_alias_aio', 'request': {'method': 'GET', 'path': '/files/file.txt', 'headers': {}, 'response_kind': 'http'}, 'expected_status': 200})
        if 'Plain.txt' in cfg_text or 'plain.txt' in cfg_text:
            base_templates.append({'id': 'plain_txt', 'group': 'static_http', 'request': {'method': 'GET', 'path': '/plain.txt', 'headers': {}, 'response_kind': 'http'}, 'expected_status': 200})
        if 'ProxyPass /proxy/' in cfg_text:
            base_templates.append({'id': 'proxy', 'group': 'reverse_proxy', 'request': {'method': 'GET', 'path': '/proxy/plain', 'headers': {}, 'response_kind': 'http'}, 'expected_status': 200})

    for item in base_templates:
        raw = item.pop('body', None)
        if raw is not None and 'body_file' not in item['request']:
            payload = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode('utf-8')
            body_path = corpus_dir / f'{_slug(str(item["id"]))}.body'
            body_path.write_bytes(bytes(payload))
            item['request']['body_file'] = str(body_path)

    fixed_cases = []
    for item in base_templates:
        base_copy = copy.deepcopy(item)
        base_copy['stream_kind'] = 'fixed_eval'
        fixed_cases.append(base_copy)
        for v_idx, tlen in enumerate([1, 17, 129]):
            derived = copy.deepcopy(item)
            derived['id'] = f'{item["id"]}-ord-{v_idx}'
            derived['stream_kind'] = 'fixed_eval'
            tok = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(tlen))
            derived['request']['headers']['X-Ordinary-Token'] = tok
            p = derived['request']['path']
            if item['id'] == 'value':
                derived['request']['path'] = '/value?name=' + urllib.parse.quote(tok)
            else:
                derived['request']['path'] = p + ('&' if '?' in p else '?') + 'sample=' + tok
            fixed_cases.append(derived)

    guided_cases = []
    host_variants = ['localhost', 'sub.example.org', 'a.b.c.d.example.com', 'deep.v1.v2.v3.service.local']
    for g_idx, item in enumerate(base_templates):
        mut = copy.deepcopy(item)
        mut['id'] = f'guided-{item["id"]}-{g_idx}'
        mut['stream_kind'] = 'guided_fuzz'
        mut['request']['headers']['Host'] = host_variants[g_idx % len(host_variants)]
        mut['request']['headers']['Accept-Encoding'] = 'identity'
        guided_cases.append(mut)
    for item in base_templates:
        guided_cases.extend(protocol_preserving_mutations(item, cfg_text, corpus_dir))

    return fixed_cases, _schedule_guided_cases(case_ir, guided_cases, symbolic_result)


def _cleanup_targets(symbolic_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    plan = (symbolic_result or {}).get('boundary_plan') or {}
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cont in plan.get('continuations') or []:
        for row in cont.get('direct_callers') or []:
            caller = str(row.get('caller') or '')
            resources: list[str] = []
            releases: list[str] = []
            for item in row.get('held_resources') or []:
                if isinstance(item, dict):
                    if item.get('symbol'):
                        resources.append(str(item['symbol']))
                    if item.get('release'):
                        releases.append(str(item['release']))
                elif item:
                    resources.append(str(item))
            resources.extend(str(item) for item in (row.get('open_resource_symbols') or []) if item)
            if not caller or caller in seen or not resources:
                continue
            seen.add(caller)
            found.append({
                'caller': caller,
                'resources': sorted(set(resources)),
                'releases': sorted(set(releases)),
            })
    return found


def _block_witness_query(symbolic_result: dict[str, Any] | None) -> str:
    regions = (symbolic_result or {}).get('impact_regions', {}).get('regions') or []
    for reg in regions:
        if reg.get('classification') != 'CHANGED_BY_BLOCK':
            continue
        witness = reg.get('witness') or {}
        if not isinstance(witness, dict) or not witness:
            continue
        return '&'.join(f'{key}={val}' for key, val in sorted(witness.items()))
    return ''


def _schedule_guided_cases(case_ir: dict[str, Any],
                           guided_cases: list[dict[str, Any]],
                           symbolic_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    predicates: list[str] = []
    for guard in case_ir.get('guards', []):
        for pred in guard.get('extracted_predicates', []):
            predicates.append(f'{guard["id"]}:{pred}')
    for idx, case in enumerate(guided_cases):
        if predicates and 'target_predicate' not in case:
            case['target_predicate'] = predicates[idx % len(predicates)]
        case.setdefault('schedule_distance', 1.0)
    if not guided_cases:
        return guided_cases
    regions = (symbolic_result or {}).get('impact_regions', {}).get('regions') or []
    template = guided_cases[0]
    block_index = None
    for index, reg in enumerate(regions):
        if (
            block_index is None
            and reg.get('classification') == 'CHANGED_BY_BLOCK'
            and isinstance(reg.get('witness'), dict)
            and reg.get('witness')
        ):
            block_index = index
        if reg.get('classification') in ('UNREACHABLE', None):
            continue
        witness = reg.get('witness') or {}
        if not witness:
            continue
        cloned = copy.deepcopy(template)
        cloned['id'] = f'guided-region-{len(guided_cases)}'
        cloned['group'] = 'region_distance'
        cloned['stream_kind'] = 'guided_fuzz'
        cloned['schedule_distance'] = 0.0
        cloned['target_region'] = reg.get('region')
        if reg.get('hook_parameter_snapshot'):
            cloned['hook_parameter_snapshot'] = reg['hook_parameter_snapshot']
        if 'request' in cloned:
            query = '&'.join(f'{key}={val}' for key, val in sorted(witness.items()))
            path = cloned['request'].get('path', '/')
            cloned['request']['path'] = path + ('&' if '?' in path else '?') + query
        if isinstance(cloned.get('params'), dict):
            for key, val in witness.items():
                if key in cloned['params']:
                    cloned['params'][key] = val
        cloned['target_region_index'] = index
        cloned['target_region_classification'] = reg.get('classification')
        guided_cases.append(cloned)
    if guided_cases and not any(item.get('schedule_class') == 'cleanup_after_block' for item in guided_cases):
        for target in _cleanup_targets(symbolic_result) or [None]:
            cleanup = copy.deepcopy(guided_cases[0])
            caller = '' if target is None else str(target['caller'])
            cleanup['id'] = 'guided-cleanup-after-block' if not caller else f'guided-cleanup-{_slug(caller)}'
            cleanup['group'] = 'caller_cleanup'
            cleanup['schedule_class'] = 'cleanup_after_block'
            cleanup['schedule_distance'] = 0.5
            cleanup.pop('target_region', None)
            cleanup.pop('target_region_index', None)
            cleanup.pop('target_region_classification', None)
            cleanup.pop('target_predicate', None)
            cleanup.pop('target_hook', None)
            cleanup.pop('hook_parameter_snapshot', None)
            if target is not None:
                cleanup['target_cleanup_caller'] = caller
                cleanup['target_cleanup_resources'] = list(target['resources'])
                cleanup['target_release'] = list(target['releases'])
            if block_index is not None:
                cleanup['cleanup_region_index'] = block_index
            prelude = copy.deepcopy(cleanup.get('request') or {})
            if 'path' in prelude:
                path = str(prelude['path'])
                query = _block_witness_query(symbolic_result) or 'vg_block_probe=1'
                prelude['path'] = path + ('&' if '?' in path else '?') + query
            cleanup['prelude_request'] = prelude
            guided_cases.append(cleanup)
    guard_ids = [str(guard['id']) for guard in case_ir.get('guards') or [] if guard.get('id')]
    open_cases = [item for item in guided_cases if item.get('schedule_class') != 'cleanup_after_block']
    if guard_ids and open_cases:
        for index, item in enumerate(open_cases):
            item.setdefault('target_hook', guard_ids[index % len(guard_ids)])
        covered = {item.get('target_hook') for item in open_cases}
        for gid in guard_ids:
            if gid in covered:
                continue
            cloned = copy.deepcopy(open_cases[0])
            cloned['id'] = f'guided-hook-{_slug(gid)}'
            cloned['group'] = 'unhit_hook'
            cloned['stream_kind'] = 'guided_fuzz'
            cloned['target_hook'] = gid
            cloned['schedule_distance'] = 0.25
            cloned.pop('target_region', None)
            cloned.pop('target_region_index', None)
            cloned.pop('target_region_classification', None)
            cloned.pop('hook_parameter_snapshot', None)
            cloned.pop('prelude_request', None)
            guided_cases.append(cloned)
    guided_cases.sort(key=lambda item: float(item.get('schedule_distance', 1.0)))
    return guided_cases


def absorb_decision_snapshot(guard: dict[str, Any],
                             snapshot: dict[str, Any],
                             regions: list[dict[str, Any]],
                             symbolic_names: set[str],
                             formulas: dict[str, Any],
                             predicate_distances: dict[str, dict[str, Any]],
                             visited: set[int],
                             guided_visited: set[int],
                             fixed_visited: set[int],
                             stream_kind: str,
                             pending: list[dict[str, Any]]) -> tuple[list[int], float | None]:
    for dist_info in snapshot_predicate_distances(guard, snapshot):
        pkey = f'{guard["id"]}:{dist_info["predicate"]}'
        rec = predicate_distances.setdefault(pkey, {'seen_true': False, 'seen_false': False, 'min_gap': float('inf')})
        if dist_info['truth']:
            rec['seen_true'] = True
        else:
            rec['seen_false'] = True
        rec['min_gap'] = min(rec['min_gap'], float(dist_info['normalized_distance']))
    if not regions:
        return [], None
    sym_vals = project_snapshot_to_symbols(guard, snapshot, symbolic_names, formulas)
    hits, distances = region_branch_distances(regions, sym_vals)
    for r_idx in hits:
        visited.add(r_idx)
        if stream_kind == 'guided_fuzz':
            guided_visited.add(r_idx)
        else:
            fixed_visited.add(r_idx)
    apply_unhit_region_distances(pending, distances, visited)
    open_distances = [dist for index, dist in distances.items() if index not in visited]
    return hits, (min(open_distances) if open_distances else None)


def apply_unhit_region_distances(pending: list[dict[str, Any]],
                                 distances: dict[int, float],
                                 visited: set[int]) -> None:
    for item in pending:
        if item.get('schedule_class') == 'cleanup_after_block':
            index = item.get('cleanup_region_index')
            if index is None:
                continue
            index = int(index)
            if index in visited or index not in distances:
                continue
            item['schedule_distance'] = distances[index]
            continue
        index = item.get('target_region_index')
        if index is None:
            continue
        index = int(index)
        if index in visited or index not in distances:
            continue
        if item.get('target_region_classification') not in ('CHANGED_BY_BLOCK', 'CHANGED_ON_PASS', 'MIXED', 'UNRESOLVED'):
            continue
        item['schedule_distance'] = distances[index]


def guided_case_rank(item: dict[str, Any],
                     triggered_hooks: set[str],
                     predicate_distances: dict[str, dict[str, Any]],
                     visited_regions: set[int]) -> tuple[int, float]:
    distance = float(item.get('schedule_distance', 1.0))
    hook = item.get('target_hook')
    if hook and hook not in triggered_hooks:
        return (0, distance)
    key = item.get('target_predicate')
    rec = predicate_distances.get(key) if key else None
    if key and (rec is None or not (rec.get('seen_true') and rec.get('seen_false'))):
        gap = distance if rec is None else float(rec.get('min_gap', distance))
        return (1, gap)
    region_index = item.get('target_region_index')
    if (
        region_index is not None
        and item.get('target_region_classification') in ('CHANGED_BY_BLOCK', 'CHANGED_ON_PASS', 'MIXED', 'UNRESOLVED')
        and int(region_index) not in visited_regions
    ):
        return (2, distance)
    if item.get('schedule_class') == 'cleanup_after_block':
        return (3, distance)
    return (4, distance)


def pcs_to_dynamic_trace(pcs: list[int], symbol_offsets: dict[str, int]) -> dict[str, Any]:
    ordered = sorted((off, name) for name, off in symbol_offsets.items())
    offsets = [off for off, _name in ordered]
    sequence: list[str] = []
    for pc in pcs:
        idx = bisect.bisect_right(offsets, int(pc)) - 1
        if idx < 0:
            continue
        name = ordered[idx][1]
        if not sequence or sequence[-1] != name:
            sequence.append(name)
    edges: list[list[str]] = []
    seen: set[tuple[str, str]] = set()
    for left, right in zip(sequence, sequence[1:]):
        key = (left, right)
        if key in seen:
            continue
        seen.add(key)
        edges.append([left, right])
        if len(edges) >= 256:
            break
    return {
        'call_edges': edges,
        'call_stacks': [sequence[:48]] if sequence else [],
    }


def ensure_poc_alias_files(case_ir: dict[str, Any]) -> None:
    fixture = case_ir.setdefault('environment_fixture', {})
    files = fixture.setdefault('files', {})
    config = str(fixture.get('config_template') or '')
    requests = ((case_ir.get('seed_traces') or {}).get('poc_reproducer') or {}).get('requests') or []
    for alias in re.finditer(r'alias\s+\{root\}/([^;\s]+)', config):
        locs = list(re.finditer(r'location\s+(\S+)\s*\{', config[:alias.start()]))
        if not locs:
            continue
        prefix = locs[-1].group(1)
        if not prefix.endswith('/'):
            prefix += '/'
        dest_root = alias.group(1).strip('/')
        for item in requests:
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or item.get('uri') or '')
            if not path.startswith(prefix):
                continue
            leaf = path[len(prefix):].split('?', 1)[0]
            if not leaf or leaf.startswith('/') or '..' in leaf.split('/'):
                continue
            files.setdefault(f'{dest_root}/{leaf}', 'ordinary DAV file\n')


class _RestartableWorker:
    def __init__(self, factory):
        self.factory = factory
        self.worker = factory()

    def restart(self):
        self.worker.close()
        self.worker = self.factory()

    def close(self):
        if self.worker is not None:
            self.worker.close()
            self.worker = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def request_boundaries_hold(baseline: dict[str, int], current: dict[str, int]) -> bool:
    for mode, started in baseline.items():
        if mode not in current or int(current[mode]) > int(started):
            return False
    return True


def restore_fixture_files(case_ir: dict[str, Any], directory: Path) -> None:
    directory = Path(directory).resolve()
    files = (case_ir.get('environment_fixture') or {}).get('files') or {}
    declared: set[Path] = set()
    parents: set[Path] = set()
    for rel in files:
        dest = (directory / rel).resolve()
        declared.add(dest)
        parents.add(dest.parent)
    kept_names = {'server.conf', 'error.log', 'server.log', 'stderr.log', 'installation.json'}
    for parent in parents:
        if not parent.is_dir():
            continue
        try:
            parent.relative_to(directory)
        except ValueError:
            continue
        paths = sorted(parent.rglob('*'), key=lambda item: len(item.parts), reverse=True)
        for path in paths:
            if path.is_file():
                if path.resolve() in declared or path.name in kept_names or path.name.startswith('trace-'):
                    continue
                path.unlink()
            elif path.is_dir() and path != parent and not any(path.iterdir()):
                path.rmdir()
    _write_fixture_files(case_ir, directory)


def _write_fixture_files(case_ir: dict[str, Any], output_dir: Path) -> None:
    fixture = case_ir.get('environment_fixture', {})
    for rel_path, content in fixture.get('files', {}).items():
        dest = output_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            dest.write_text(content, encoding='utf-8')
        else:
            dest.write_bytes(bytes(content))


def _baseline_http_launch(case_ir: dict[str, Any], output_dir: Path) -> tuple[Path, dict[str, int], list[str], dict[str, Any], Any]:
    protocol = case_ir['app_profile']['protocol']
    binfo = (case_ir['app_profile'].get('builds') or {}).get('baseline') or {}
    exe = Path(str(binfo.get('executable', '')))
    uniq, _ambiguous = elf_unique_symbols(exe) if exe.is_file() else ({}, {})

    def prepare(port: int) -> None:
        template = case_ir.get('environment_fixture', {}).get('config_template')
        if not template:
            return
        module_loads = _render_httpd_module_loads(binfo) if protocol == 'httpd_http' else ''
        with socket.socket() as backend_sock:
            backend_sock.bind(('127.0.0.1', 0))
            backend_port = backend_sock.getsockname()[1]
        rendered = template.format(
            root=str(output_dir),
            port=port,
            backend=backend_port,
            source_dir=binfo.get('source_dir', ''),
            module_loads=module_loads,
        )
        (output_dir / 'server.conf').write_text(rendered, encoding='utf-8')

    if protocol == 'nginx_http':
        cmd = [str(exe), '-p', str(output_dir) + '/', '-c', str(output_dir / 'server.conf')]
        trace_spec = {'module': exe.name, 'anchor_offset': uniq.get('main', 0)}
        prepare_fn = prepare
    elif protocol == 'httpd_http':
        cmd = [str(exe), '-X', '-f', str(output_dir / 'server.conf')]
        trace_spec = {'module': exe.name, 'anchor_offset': uniq.get('main', 0)}
        prepare_fn = prepare
    else:
        router = Path(case_ir['app_profile']['router_script']).resolve()
        sess_dir = output_dir / 'sessions'
        sess_dir.mkdir(parents=True, exist_ok=True)
        anchor_sym = case_ir['app_profile'].get('trace_anchor_symbol', 'php_session_rfc1867_callback')
        cmd = [
            str(exe), '-n',
            *php_ini_arguments(case_ir, sess_dir),
            '-S', '127.0.0.1:{port}',
            str(router),
        ]
        trace_spec = {'module': exe.name, 'anchor_offset': uniq[anchor_sym], 'admission': []}
        prepare_fn = None
    return exe, uniq, cmd, trace_spec, prepare_fn


def _http_world_launch(case_ir: dict[str, Any], output_dir: Path, build_key: str, backend_port: int):
    protocol = case_ir['app_profile']['protocol']
    binfo = case_ir['app_profile']['builds'][build_key]
    exe = Path(binfo['executable']).resolve()
    uniq, _ambiguous = elf_unique_symbols(exe)

    def prepare(port: int) -> None:
        template = str(case_ir.get('environment_fixture', {}).get('config_template') or '')
        module_loads = _render_httpd_module_loads(binfo) if protocol == 'httpd_http' else ''
        rendered = template.format(
            root=str(output_dir),
            port=port,
            backend=backend_port,
            source_dir=binfo.get('source_dir', ''),
            module_loads=module_loads,
        )
        (output_dir / 'server.conf').write_text(rendered, encoding='utf-8')

    if protocol == 'nginx_http':
        cmd = [str(exe), '-p', str(output_dir) + '/', '-c', str(output_dir / 'server.conf')]
    elif protocol == 'httpd_http':
        cmd = [str(exe), '-X', '-f', str(output_dir / 'server.conf')]
    else:
        raise ValueError(f'isolated poc launch does not cover {protocol}')
    trace_spec = {'module': exe.name, 'anchor_offset': uniq['main']}
    return cmd, trace_spec, prepare


def execute_isolated_poc(case_ir: dict[str, Any], workers: dict[str, Any], health_request: dict[str, Any]) -> dict[str, Any]:
    poc_spec = (case_ir.get('seed_traces') or {}).get('poc_reproducer') or {}
    poc_res: dict[str, Any] = {'executed': True, 'worlds': {}}
    for mode, worker in workers.items():
        log_mark = worker_log_mark(worker.directory)
        mode_steps = []
        for item in poc_spec.get('requests') or []:
            request = _normalized_http_request(item) if isinstance(item, dict) else item
            result = worker.execute(request)
            mode_steps.append({
                'http_status': result['outcome'].get('http_status'),
                'response_complete': result['outcome'].get('response_complete'),
                'decisions': len([msg for msg in result['events'] if msg.get('payload', {}).get('event') == 'decision']),
                'blocks': len([msg for msg in result['events'] if msg.get('payload', {}).get('action') == 'BLOCK']),
            })
        health = worker.execute(health_request)
        log_suffix = worker_log_suffix(worker.directory, log_mark)
        world_row = {
            'poc_steps': mode_steps,
            'post_poc_worker_alive': worker.process.poll() is None,
            'post_poc_health_status': health['outcome'].get('http_status', health['outcome'].get('result')),
            'path_mismatch': logged_path_mismatch(log_suffix, poc_spec.get('requests') or []),
        }
        _annotate_poc_world(world_row, log_suffix, str((case_ir.get('safety_oracle') or {}).get('kind') or ''))
        poc_res['worlds'][mode] = world_row
    poc_res['verdict'] = judge_isolated_poc(poc_res['worlds'])
    return poc_res


def run_isolated_poc_check(vuln_spec_or_path: dict[str, Any] | Path,
                           patch_spec_or_path: dict[str, Any] | Path,
                           app_profile_or_path: dict[str, Any] | Path,
                           output_dir: Path) -> dict[str, Any]:
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    vuln_spec = load_spec_file(vuln_spec_or_path) if isinstance(vuln_spec_or_path, (Path, str)) else vuln_spec_or_path
    patch_spec = load_spec_file(patch_spec_or_path) if isinstance(patch_spec_or_path, (Path, str)) else patch_spec_or_path
    app_profile = load_spec_file(app_profile_or_path) if isinstance(app_profile_or_path, (Path, str)) else app_profile_or_path
    case_ir = compile_case(vuln_spec, patch_spec, app_profile, output_dir)
    ensure_poc_alias_files(case_ir)
    seeds = (case_ir.get('seed_traces') or {}).get('benign_seeds') or []
    health_request = _normalized_http_request(seeds[0]) if seeds else {
        'method': 'GET', 'path': '/plain', 'headers': {}, 'response_kind': 'http',
    }
    patch_manifest = Path(case_ir['deployment']['patch_manifest'])
    actions_catalog = Path(case_ir['deployment']['actions_catalog'])
    modes = ['patched', 'baseline']
    reference = (app_profile.get('builds') or {}).get('reference') or {}
    if Path(str(reference.get('executable') or '')).is_file():
        modes.append('reference')
    with ExitStack() as stack:
        peer = stack.enter_context(UniversalBackendPeer()) if app_profile['protocol'] in ('nginx_http', 'httpd_http') else None
        workers: dict[str, Any] = {}
        for mode in modes:
            build_key = 'reference' if mode == 'reference' else 'baseline'
            world_dir = output_dir / 'runtime' / mode
            _write_fixture_files(case_ir, world_dir)
            cmd, trace_spec, prepare = _http_world_launch(case_ir, world_dir, build_key, peer.port if peer else 0)
            try:
                workers[mode] = stack.enter_context(UniversalHTTPWorker(
                    cmd, world_dir, trace_spec,
                    patch=patch_manifest if mode == 'patched' else None,
                    catalog=actions_catalog,
                    prepare=prepare,
                    timeout=20,
                ))
            except Exception:
                if mode != 'reference':
                    raise
                continue
        poc = execute_isolated_poc(case_ir, workers, health_request)
    report = {
        'case_id': case_ir['case_id'],
        'verdict': poc['verdict'],
        **isolated_poc_report_fields(poc, False),
        'worlds': poc['worlds'],
    }
    (output_dir / 'isolated-poc.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def _normalized_http_request(item: dict[str, Any]) -> dict[str, Any]:
    request = {
        'method': item.get('method', 'GET'),
        'path': item.get('path') or item.get('uri') or '/',
        'headers': dict(item.get('headers') or {}),
        'response_kind': item.get('response_kind', 'http'),
    }
    if item.get('body_file'):
        request['body_file'] = item['body_file']
    return request


def replay_anchor_cases(case_ir: dict[str, Any], fixed_cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    poc = ((case_ir.get('seed_traces') or {}).get('poc_reproducer') or {}).get('requests') or []
    anchored = [
        {'id': f'poc-{idx}', 'request': _normalized_http_request(item)}
        for idx, item in enumerate(poc)
        if isinstance(item, dict)
    ]
    seen_paths: set[str] = set()
    ranked: list[dict[str, Any]] = []
    for case in fixed_cases:
        if not case.get('request'):
            continue
        if '-ord-' in str(case.get('id', '')):
            continue
        path = str(case['request'].get('path') or '/')
        base = path.split('?', 1)[0]
        if base in seen_paths:
            continue
        seen_paths.add(base)
        ranked.append(case)
    ranked.sort(key=lambda case: (str(case['request'].get('path') or '/').split('?', 1)[0] in ('/plain', '/plain.txt', '/'), str(case.get('id', ''))))
    benign = ranked[:2]
    samples = [*anchored, *benign]
    if not samples:
        samples = [{'request': {'method': 'GET', 'path': '/', 'headers': {}, 'response_kind': 'http'}}]
    return samples


_ORACLE_LOG_RULES = (
    ('physical_memory_safety', (
        'heap-buffer-overflow', 'stack-buffer-overflow', 'global-buffer-overflow',
        'stack-buffer-underflow', 'dynamic-stack-buffer-overflow', 'container-overflow',
        'negative-size-param', 'allocation-size-too-big', 'memcpy-param-overlap',
        'AddressSanitizer: SEGV', 'stack-overflow', 'stack smashing detected',
        'free(): invalid next size', 'malloc(): corrupted', 'pointer-overflow',
        'Segmentation fault',
    )),
    ('temporal_object_validity', (
        'heap-use-after-free', 'stack-use-after-return', 'stack-use-after-scope',
        'double-free', 'alloc-dealloc-mismatch', 'double free or corruption',
        'invalid free',
    )),
    ('initialized_read_safety', (
        'use-of-uninitialized-value', 'MemorySanitizer',
    )),
    ('arithmetic_domain_safety', (
        'signed-integer-overflow', 'unsigned-integer-overflow',
        'implicit-unsigned-integer-truncation', 'implicit-signed-integer-truncation',
        'division by zero', 'float-divide-by-zero', 'shift exponent', 'shift base',
        'negation of', 'float-cast-overflow',
    )),
)


def runtime_oracle_kinds(text: str) -> list[str]:
    found: list[str] = []
    for kind, markers in _ORACLE_LOG_RULES:
        if any(marker in text for marker in markers):
            found.append(kind)
    return found


def process_log_has_fatal(text: str) -> bool:
    return bool(runtime_oracle_kinds(text) or 'Aborted' in text)


def _annotate_poc_world(row: dict[str, Any], log_suffix: str, oracle_kind: str) -> None:
    row['process_fatal'] = process_log_has_fatal(log_suffix)
    row['oracle_runtime_kinds'] = runtime_oracle_kinds(log_suffix)
    row['safety_oracle_kind'] = oracle_kind


def logged_path_mismatch(text: str, requests: list[Any]) -> bool:
    leaves: list[tuple[str, str]] = []
    for item in requests or []:
        if not isinstance(item, dict):
            continue
        raw = str(item.get('path') or item.get('uri') or '')
        request_path = raw.split('?', 1)[0]
        leaf = request_path.rstrip('/').rsplit('/', 1)[-1]
        if leaf and leaf not in ('.', '..'):
            leaves.append((request_path, leaf))
    for line in text.splitlines():
        match = re.search(r'(?:lstat|stat|open)\(\)\s+"([^"]+)"', line)
        if not match:
            continue
        logged = match.group(1)
        for request_path, leaf in leaves:
            if request_path not in line:
                continue
            if leaf not in logged:
                return True
    return False


def worker_log_mark(directory: Path) -> dict[str, int]:
    marks: dict[str, int] = {}
    for name in ('error.log', 'server.log', 'stderr.log'):
        path = Path(directory) / name
        marks[name] = path.stat().st_size if path.exists() else 0
    return marks


def worker_log_suffix(directory: Path, marks: dict[str, int]) -> str:
    parts: list[str] = []
    for name, mark in marks.items():
        path = Path(directory) / name
        if not path.exists():
            continue
        parts.append(path.read_bytes()[max(0, int(mark)):].decode('utf-8', 'replace'))
    return '\n'.join(parts)


def _sanitizer_matches_oracle(baseline: dict[str, Any]) -> bool | None:
    kinds = baseline.get('oracle_runtime_kinds')
    wanted = str(baseline.get('safety_oracle_kind') or '')
    if not isinstance(kinds, list) or not wanted:
        return None
    if wanted in kinds:
        return True
    if kinds:
        return False
    return None


def _poc_baseline_fault(baseline: dict[str, Any]) -> bool:
    steps = baseline.get('poc_steps') or []
    protocol_fault = bool(baseline.get('path_mismatch')) or any(
        (not step.get('response_complete', True)) or int(step.get('http_status') or 0) >= 500
        for step in steps
    )
    matched = _sanitizer_matches_oracle(baseline)
    if matched is True:
        return True
    if matched is False:
        return protocol_fault
    return (
        (not baseline.get('post_poc_worker_alive', True))
        or bool(baseline.get('process_fatal'))
        or protocol_fault
    )


def _poc_patched_outcome(patched: dict[str, Any]) -> tuple[bool, bool, bool]:
    steps = patched.get('poc_steps') or []
    blocked = any(int(step.get('blocks') or 0) > 0 for step in steps)
    alive = bool(patched.get('post_poc_worker_alive')) and not patched.get('process_fatal')
    health = patched.get('post_poc_health_status')
    health_ok = health in (200, 'ok', 0) or (isinstance(health, int) and 200 <= health < 400)
    return blocked, alive, health_ok


def judge_isolated_poc(worlds: dict[str, Any]) -> str:
    baseline = worlds.get('baseline') or {}
    patched = worlds.get('patched') or {}
    blocked, alive, health_ok = _poc_patched_outcome(patched)
    if _poc_baseline_fault(baseline) and blocked and alive and health_ok:
        return 'CONFIRMED'
    return 'NOT_CONFIRMED'


def isolated_poc_report_fields(poc: dict[str, Any] | None, model_reproduced: bool) -> dict[str, Any]:
    if not poc or not poc.get('executed'):
        return {
            'poc_nonvacuity_on_baseline': 'NOT_PROVIDED',
            'poc_blocked_on_patched': None,
            'post_poc_worker_healthy': None,
        }
    worlds = poc.get('worlds') or {}
    baseline = worlds.get('baseline') or {}
    patched = worlds.get('patched') or {}
    p0_fault = _poc_baseline_fault(baseline)
    p1_block, p1_alive, health_ok = _poc_patched_outcome(patched)
    if p0_fault and model_reproduced:
        nonvacuity = 'REPRODUCED_IN_MODEL_AND_CONTAINER'
    elif p0_fault:
        nonvacuity = 'REPRODUCED_IN_CONTAINER'
    elif model_reproduced:
        nonvacuity = 'REPRODUCED_IN_MODEL'
    else:
        nonvacuity = 'NOT_REPRODUCED'
    return {
        'poc_nonvacuity_on_baseline': nonvacuity,
        'poc_blocked_on_patched': bool(p1_block and p1_alive),
        'post_poc_worker_healthy': bool(p1_alive and health_ok),
    }


def _attributed_field_change(episode: dict[str, Any]) -> bool:
    if not episode.get('changed_fields'):
        return False
    return episode.get('replay_attribution') != 'outside_footprint'


def touched_hook_ids(events: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for message in events:
        payload = message.get('payload') if isinstance(message, dict) else None
        if not isinstance(payload, dict):
            continue
        if payload.get('event') not in ('observation', 'decision'):
            continue
        hook = payload.get('hook')
        if hook and str(hook) not in found:
            found.append(str(hook))
    return found


def attribute_tri_replay(footprint: dict[str, Any] | None, episode: dict[str, Any]) -> str:
    footprint = footprint or {}
    changed = list(episode.get('changed_fields') or [])
    replay = list(episode.get('replay_violations') or [])
    blocks = int(episode.get('blocks') or 0)
    reference_ok = bool(episode.get('reference_consistent', True))
    baseline_fault = bool(episode.get('baseline_fault'))
    patched_fault = bool(episode.get('patched_fault'))
    recorded = 'touched_hooks' in episode or 'touched_functions' in episode
    hooks = {str(item) for item in (episode.get('touched_hooks') or [])}
    functions = {str(item) for item in (episode.get('touched_functions') or [])}
    hook_ids = {str(item) for item in (footprint.get('hook_ids') or [])}
    named = {
        str(item)
        for item in (
            list(footprint.get('guard_functions') or [])
            + list(footprint.get('observer_functions') or [])
            + list(footprint.get('skipped_callee_writes') or [])
        )
    }
    hook_hit = bool(hooks) and (not hook_ids or bool(hooks & hook_ids))
    function_hit = bool(functions & named)
    if recorded:
        touched = hook_hit or function_hit or blocks > 0
    else:
        touched = True
    fields_differ = bool(changed) or bool(replay)
    if baseline_fault and patched_fault and not fields_differ:
        return 'preexisting'
    if not fields_differ and reference_ok:
        if baseline_fault and not patched_fault:
            return 'eliminated_on_patch' if touched else 'outside_footprint'
        if patched_fault and not baseline_fault:
            return 'patch_introduced' if touched else 'outside_footprint'
        if blocks:
            return 'patch_intercepted' if touched else 'outside_footprint'
        return 'unchanged'
    if not fields_differ and not reference_ok:
        return 'reference_disagrees'
    if baseline_fault and patched_fault and not changed and not replay:
        return 'preexisting'
    if baseline_fault and not patched_fault:
        return 'eliminated_on_patch' if touched else 'outside_footprint'
    if baseline_fault and patched_fault:
        return 'patch_introduced' if touched else 'preexisting'
    return 'patch_introduced' if touched else 'outside_footprint'


def guided_fuzz_report_fields(episodes: list[dict[str, Any]],
                              fixed_regions: set[int],
                              guided_regions: set[int],
                              footprint: dict[str, Any] | None = None) -> dict[str, Any]:
    unexpected = 0
    introduced = 0
    outside = 0
    preexisting = 0
    eliminated = 0
    reference_only = 0
    intercepted = 0
    changed_cases = 0
    for episode in episodes:
        label = attribute_tri_replay(footprint, episode)
        replay = episode.get('replay_violations') or []
        benign = bool(episode.get('eligible_benign'))
        passed_but_changed = benign and not episode.get('blocks') and bool(episode.get('changed_fields'))
        reference_broke = benign and not episode.get('reference_consistent', True)
        anomaly = bool(replay) or passed_but_changed or reference_broke
        if episode.get('changed_fields') and label != 'outside_footprint':
            changed_cases += 1
        if label == 'outside_footprint':
            outside += 1
        elif label == 'preexisting':
            preexisting += 1
        elif label == 'eliminated_on_patch':
            eliminated += 1
        elif label == 'reference_disagrees':
            reference_only += 1
        elif label == 'patch_intercepted':
            intercepted += 1
        elif anomaly and label == 'patch_introduced':
            unexpected += 1
            introduced += 1
        elif label == 'patch_introduced':
            introduced += 1
    return {
        'executed_cases': len(episodes),
        'changed_cases': changed_cases,
        'blocked_cases': sum(1 for episode in episodes if episode.get('blocks')),
        'newly_triggered_regions': len(guided_regions - fixed_regions),
        'unexpected_contract_failures': unexpected,
        'patch_introduced_anomalies': introduced,
        'outside_footprint_anomalies': outside,
        'preexisting_anomalies': preexisting,
        'eliminated_on_patch': eliminated,
        'reference_disagreements': reference_only,
        'patch_intercepted_cases': intercepted,
    }


def verification_task_rows(symbolic_report: dict[str, Any]) -> list[dict[str, Any]]:
    tasks = ((symbolic_report.get('boundary_plan') or {}).get('tasks') or [])
    covered: set[str] = set()
    for task in tasks:
        if task.get('role') not in (None, 'covering_cut'):
            continue
        if task.get('cut_function'):
            covered.add(task['cut_function'])
        covered.update(task.get('subtree_functions') or [])
    rows = []
    for task in tasks:
        function = task.get('cut_function')
        inside_covering_query = function in covered
        local_status = str((task.get('local_obligation') or {}).get('status') or '')
        if task.get('role') in (None, 'covering_cut') or inside_covering_query:
            proof_entry = 'paired_query'
        elif local_status in ('PROVED_IN_BOUNDED_DOMAIN', 'VIOLATED'):
            proof_entry = 'local_query'
        else:
            proof_entry = 'recorded_not_discharged'
        rows.append({
            'cut_function': function,
            'role': task.get('role'),
            'seed_activated': bool(task.get('seed_activated')),
            'episode_length': task.get('episode_length', 1),
            'state_lifetime': task.get('state_lifetime'),
            'proof_entry': proof_entry,
        })
    return rows


def collect_baseline_dynamic_traces(case_ir: dict[str, Any],
                                    fixed_cases: list[dict[str, Any]],
                                    output_dir: Path) -> list[dict[str, Any]]:
    protocol = case_ir['app_profile']['protocol']
    if protocol not in ('nginx_http', 'httpd_http', 'php_http'):
        return []
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_fixture_files(case_ir, output_dir)
    exe, uniq, cmd, trace_spec, prepare_fn = _baseline_http_launch(case_ir, output_dir)
    if not exe.is_file():
        return []
    worker = UniversalHTTPWorker(cmd, output_dir, trace_spec, timeout=20, prepare=prepare_fn)
    traces: list[dict[str, Any]] = []
    try:
        samples = replay_anchor_cases(case_ir, fixed_cases)
        for sample in samples:
            outcome = worker.execute(sample['request'])
            pcs = outcome['outcome'].get('trace') or []
            if pcs:
                traces.append(pcs_to_dynamic_trace(list(pcs), uniq))
    finally:
        worker.close()
    return traces


def capture_baseline_cut_snapshot(case_ir: dict[str, Any],
                                  fixed_cases: list[dict[str, Any]],
                                  output_dir: Path,
                                  globals_to_read: list[str] | None = None) -> dict[str, Any]:
    protocol = case_ir['app_profile']['protocol']
    empty = {'captured': False, 'invocations': 0, 'call_stacks': [], 'call_edges': [], 'snapshot': None}
    if protocol not in ('nginx_http', 'httpd_http', 'php_http'):
        return empty
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_fixture_files(case_ir, output_dir)
    exe, _uniq, cmd, _trace_spec, prepare_fn = _baseline_http_launch(case_ir, output_dir)
    if not exe.is_file():
        return empty
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    if prepare_fn is not None:
        prepare_fn(port)
    command = [part.replace('{port}', str(port)) for part in cmd]
    samples = replay_anchor_cases(case_ir, fixed_cases)
    http_requests = []
    for sample in samples:
        req = sample['request']
        body = ''
        if req.get('body_file'):
            body = Path(req['body_file']).read_text(encoding='utf-8', errors='replace')
        http_requests.append({
            'host': '127.0.0.1',
            'port': port,
            'method': req.get('method', 'GET'),
            'path': req.get('path', '/'),
            'headers': dict(req.get('headers') or {}),
            'body': body,
            'wait_sec': 12,
        })
    root_fn = ((case_ir.get('defect_anchors') or {}).get('root_cause_site') or {}).get('function')
    cut_function = root_fn or case_ir['guards'][0]['function']
    try:
        return capture_concrete_snapshot_via_gdb(
            exe,
            command[1:],
            cut_function,
            output_dir,
            http_requests=http_requests,
            stop_on_first=False,
            invocation_selector=invocation_selector_from_case(case_ir),
            max_depth=3,
            globals_to_read=globals_to_read,
            pointer_arrays=list(case_ir['app_profile'].get('pointer_arrays') or []),
            timeout=40,
        )
    except (OSError, subprocess.TimeoutExpired):
        return empty


def outcome_is_error(outcome: dict[str, Any]) -> bool:
    status = outcome.get('http_status')
    if isinstance(status, int) and status >= 500:
        return True
    if outcome.get('response_complete') is False:
        return True
    result = str(outcome.get('result') or '')
    return bool(result) and result not in ('ok', 'success')


def mark_error_fallback(baseline: dict[str, Any], patched: dict[str, Any], patched_blocks: int) -> None:
    if (outcome_is_error(patched) or int(patched_blocks or 0) > 0) and not outcome_is_error(baseline):
        patched['error_fallback'] = True


def render_evaluation_summary(report: dict[str, Any]) -> str:
    installation = report.get('installation') or {}
    bound = installation.get('hooks_bound') or {}
    correct = report.get('correctness_and_safety') or {}
    metrics = report.get('path_and_functional_metrics') or {}
    hooks = metrics.get('hook_triggering') or {}
    regions = metrics.get('symbolic_impact_regions') or {}
    fixed = metrics.get('functional_impact_fixed_eval') or {}
    guided = metrics.get('functional_impact_guided_fuzz') or {}
    coverage = metrics.get('paired_coverage') or {}
    performance = metrics.get('performance_overhead') or {}
    vm = correct.get('vm_bytecode_equivalence') or {}
    continuation = correct.get('action_and_caller_continuation') or {}
    target = correct.get('target_vulnerability_elimination') or {}
    pass_path = correct.get('pass_path_noninterference') or {}
    pass_status = pass_path.get('status') if isinstance(pass_path, dict) else pass_path
    constraints = (continuation.get('scope') or {}).get('symbolization_constraints') or {}
    pinned = ','.join(str(item) for item in (constraints.get('pin_concrete') or [])) or '-'
    forced = ','.join(str(item) for item in (constraints.get('force_symbolic') or [])) or '-'
    lines = [
        f"case {report.get('case_id')}",
        f"installation {installation.get('status')} hooks {bound.get('installed')}/{bound.get('required')} quiescent {installation.get('quiescent_attach_verified')}",
        f"vm {vm.get('status')} properties {vm.get('checked_properties')} max_instructions {vm.get('max_instructions')}",
        f"continuation {continuation.get('status')} scope {(continuation.get('scope') or {}).get('kind')} pin {pinned} force {forced}",
        f"target {target.get('status')} cut_local {target.get('cut_local_status')} poc {target.get('poc_nonvacuity_on_baseline')} blocked {target.get('poc_blocked_on_patched')} healthy {target.get('post_poc_worker_healthy')}",
        f"pass_path {pass_status}",
        f"hooks triggered {hooks.get('triggered_hooks')}/{hooks.get('installed_hooks')} observations {hooks.get('total_observations', hooks.get('observations'))} decisions {hooks.get('total_vm_decisions', hooks.get('decisions'))} blocks {hooks.get('block_decisions')} replay {hooks.get('vm_replay_mismatches', hooks.get('replay_violations'))} map_leaks {hooks.get('map_retention_leaks')} reset_violations {hooks.get('request_reset_violations', 0)}",
        f"regions unchanged {regions.get('unchanged_regions')} changed_by_block {regions.get('changed_by_block_regions')} changed_on_pass {regions.get('changed_on_pass_regions')} unresolved {regions.get('unresolved_regions')} visited {regions.get('dynamically_visited_impact_regions')}",
        f"fixed {fixed.get('changed_cases')}/{fixed.get('denominator_valid_benign_cases')} blocked {fixed.get('blocked_benign_cases')} pass_changed {fixed.get('pass_but_output_changed_cases')}",
        _guided_summary_line(guided),
        f"coverage retained {coverage.get('retained_edge_ratio')} lost {coverage.get('lost_edges_union')} error_edges {coverage.get('gained_error_edges_union')} mcnemar {coverage.get('statistically_significant_lost_edges_q005')}",
        f"latency baseline {performance.get('median_latency_ms_baseline')} patched {performance.get('median_latency_ms_patched')} overhead {performance.get('relative_overhead_ratio')}",
    ]
    bypasses = target.get('bypass_paths') or []
    if bypasses:
        lines.append('bypass ' + '; '.join(' -> '.join(str(step) for step in path) for path in bypasses))
    return '\n'.join(lines) + '\n'


def _guided_summary_line(guided: dict[str, Any]) -> str:
    line = f"guided executed {guided.get('executed_cases')} new_regions {guided.get('newly_triggered_regions')} contract_failures {guided.get('unexpected_contract_failures')}"
    if 'outside_footprint_anomalies' in guided:
        line += (
            f" introduced {guided.get('patch_introduced_anomalies')}"
            f" outside_footprint {guided.get('outside_footprint_anomalies')}"
            f" preexisting {guided.get('preexisting_anomalies')}"
            f" eliminated {guided.get('eliminated_on_patch')}"
        )
    return line


def transient_map_names(case_ir: dict[str, Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for name in (case_ir.get('environment_fixture') or {}).get('transient_maps') or []:
        text = str(name)
        if text not in seen:
            seen.add(text)
            names.append(text)
    consume_flags: dict[str, list[bool]] = {}
    for guard in case_ir.get('guards') or []:
        for read in guard.get('map_reads') or []:
            consume_flags.setdefault(str(read.get('map')), []).append(bool(read.get('consume')))
    for name, flags in consume_flags.items():
        if name not in seen and flags and all(flags):
            seen.add(name)
            names.append(name)
    return names


def count_transient_map_leaks(names: list[str],
                              replay_tables: dict[Any, Any],
                              runtime_status: dict[str, Any] | None) -> int:
    sizes = ((runtime_status or {}).get('map_sizes') or {})
    leaks = 0
    for name in names:
        runtime_left = int(sizes.get(name) or 0)
        replay_left = sum(1 for key in replay_tables if isinstance(key, tuple) and key and key[0] == name)
        if runtime_left > 0 or replay_left > 0:
            leaks += 1
    return leaks


def installation_report_fields(case_ir: dict[str, Any],
                               receipt: dict[str, Any],
                               required_hooks: int,
                               installed_hooks: int,
                               receipt_path: str) -> dict[str, Any]:
    identities = case_ir.get('identities') or {}
    profile = case_ir.get('app_profile') or {}
    baseline = ((profile.get('builds') or {}).get('baseline') or {})
    executable = str(baseline.get('executable') or '')
    pins = identities.get('artifact_pins') or {}
    target_sha = pins.get(executable) or pins.get(str(Path(executable))) or ''
    build_ids = identities.get('gnu_build_ids') or {}
    gnu_build_id = build_ids.get(Path(executable).name) if executable else None
    if not gnu_build_id:
        gnu_build_id = next((value for value in build_ids.values() if value), '')
    bytecode = {
        str(guard['id']): guard['bytecode_sha256']
        for guard in case_ir.get('guards') or []
        if guard.get('id') and guard.get('bytecode_sha256')
    }
    addresses = [item.get('address') for item in receipt.get('bindings') or [] if item.get('address')]
    ambiguous = sum(addresses.count(addr) - 1 for addr in set(addresses) if addresses.count(addr) > 1)
    phase = str((case_ir.get('deployment') or {}).get('quiescent_phase') or 'pre_first_request')
    quiescent = bool(receipt.get('installed')) and phase == 'pre_first_request' and receipt.get('first_request_sent') is not True
    status = 'INSTALLED_AND_VERIFIED' if receipt.get('installed') and installed_hooks == required_hooks and ambiguous == 0 else 'FAILED'
    return {
        'status': status,
        'target_elf_sha256': target_sha,
        'gnu_build_id': gnu_build_id or '',
        'hooks_bound': {'required': required_hooks, 'installed': installed_hooks, 'ambiguous': ambiguous},
        'bytecode_sha256': bytecode,
        'quiescent_attach_verified': quiescent,
        'receipt_path': receipt_path,
    }


def evaluate_case(vuln_spec_or_path: dict[str, Any] | Path,
                  patch_spec_or_path: dict[str, Any] | Path,
                  app_profile_or_path: dict[str, Any] | Path,
                  output_dir: Path,
                  cbmc_bin: Path | None = None) -> dict[str, Any]:
    import os

    started = time.monotonic()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)

    vuln_spec = load_spec_file(vuln_spec_or_path) if isinstance(vuln_spec_or_path, (Path, str)) else vuln_spec_or_path
    patch_spec = load_spec_file(patch_spec_or_path) if isinstance(patch_spec_or_path, (Path, str)) else patch_spec_or_path
    app_profile = load_spec_file(app_profile_or_path) if isinstance(app_profile_or_path, (Path, str)) else app_profile_or_path

    if cbmc_bin is None:
        env_cbmc = os.environ.get('VULGATE_CBMC')
        if env_cbmc:
            cbmc_bin = Path(env_cbmc)
        elif Path('/home/vita/vulgate-full-typed-cold-backend-20261105-v1/toolchain-bin/cbmc').exists():
            cbmc_bin = Path('/home/vita/vulgate-full-typed-cold-backend-20261105-v1/toolchain-bin/cbmc')
        else:
            cbmc_bin = Path('/mnt/d/Codex/2026-11-03/goal-042fb9fb-01ec-4a00-960b-c95a63665f9e/work/general-implementation/reproducible-toolchain-v3/cbmc/usr/bin/cbmc')

    case_ir = compile_case(vuln_spec, patch_spec, app_profile, output_dir)
    ensure_poc_alias_files(case_ir)

    vm_proofs: dict[str, dict[str, Any]] = {}
    for g in case_ir['guards']:
        vm_proofs[g['id']] = verify_vm_bytecode_equivalence(
            g, cbmc_bin, output_dir / 'symbolic' / f'vm_{g["id"]}',
            timeout=case_ir['budgets']['solver_timeout_sec'],
        )

    if app_profile['protocol'] in ('nginx_http', 'httpd_http', 'php_http'):
        fixed_preview: list[dict[str, Any]] = []
        try:
            fixed_preview, _guided_preview = synthesize_corpus_from_fixture_and_profile(
                case_ir, output_dir / 'corpus-anchor', None,
            )
        except Exception as exc:
            case_ir['anchor_corpus_error'] = f'{type(exc).__name__}: {exc}'[-500:]
        try:
            case_ir['dynamic_traces'] = collect_baseline_dynamic_traces(
                case_ir, fixed_preview, output_dir / 'trace-anchor',
            )
        except Exception as exc:
            case_ir['dynamic_traces'] = []
            case_ir['anchor_trace_error'] = f'{type(exc).__name__}: {exc}'[-500:]
        try:
            globals_needed = prescan_static_globals(
                case_ir, cbmc_bin, output_dir / 'symbolic' / 'prescan',
            )
        except Exception:
            globals_needed = []
        try:
            snapshot = capture_baseline_cut_snapshot(
                case_ir, fixed_preview, output_dir / 'snapshot-anchor',
                globals_to_read=globals_needed,
            )
            if snapshot.get('captured'):
                case_ir.setdefault('symbolization_scope', {})['concrete_snapshot'] = snapshot
                if snapshot.get('call_edges'):
                    case_ir['dynamic_traces'].append({
                        'call_edges': snapshot['call_edges'],
                        'call_stacks': snapshot.get('call_stacks') or [],
                    })
            else:
                case_ir['anchor_snapshot_error'] = 'not_captured'
        except Exception as exc:
            case_ir['anchor_snapshot_error'] = f'{type(exc).__name__}: {exc}'[-500:]
    symbolic_report = build_and_verify_paired_goto_slice(
        case_ir, vm_proofs, cbmc_bin, output_dir / 'symbolic' / 'paired_goto',
    )
    from .planner import extract_patch_footprint
    boundary_plan = symbolic_report.get('boundary_plan') or {}
    footprint = boundary_plan.get('patch_footprint') or extract_patch_footprint(
        case_ir, boundary_plan.get('continuations'),
    )

    fixed_cases, guided_cases = synthesize_corpus_from_fixture_and_profile(
        case_ir, output_dir / 'corpus', symbolic_report,
    )
    all_cases = [*fixed_cases, *guided_cases]

    protocol = app_profile['protocol']
    patch_manifest_path = Path(case_ir['deployment']['patch_manifest'])
    actions_catalog_path = Path(case_ir['deployment']['actions_catalog'])
    bridge_path = Path(case_ir['deployment']['bridge'])

    rules_for_replay = {
        g['id']: {
            'path': Path(g['rule_path']),
            'step_limit': g['step_limit'],
            'observations': g.get('map_reads', []),
        }
        for g in case_ir['guards']
    }

    episode_records: list[dict[str, Any]] = []
    coverage_pairs: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    latencies_ms: dict[str, list[float]] = {'baseline': [], 'patched': []}
    hook_totals = {
        'observations': 0,
        'decisions': 0,
        'pass_decisions': 0,
        'block_decisions': 0,
        'diagnostics': 0,
        'replay_violations': 0,
        'map_retention_leaks': 0,
        'request_reset_violations': 0,
    }
    triggered_hook_ids: set[str] = set()
    visited_region_indices: set[int] = set()
    fixed_visited_regions: set[int] = set()
    guided_visited_regions: set[int] = set()
    best_predicate_distances: dict[str, dict[str, float]] = {}
    poc_runtime_verification: dict[str, Any] | None = None

    dsl_path = ROOT / 'runtime' / 'dsl' / 'patches' / (str(case_ir['case_id']) + '.vg')
    if not dsl_path.is_file():
        dsl_path = None
    with ExitStack() as stack:
        peer = stack.enter_context(UniversalBackendPeer()) if protocol in ('nginx_http', 'httpd_http') else None
        workers: dict[str, Any] = {}
        holders: dict[str, _RestartableWorker] = {}
        installation_receipt: dict[str, Any] = {}

        def _track(mode: str, factory) -> None:
            holder = stack.enter_context(_RestartableWorker(factory))
            holders[mode] = holder
            workers[mode] = holder.worker

        for mode in ('patched', 'baseline', 'reference'):
            build_key = 'reference' if mode == 'reference' else 'baseline'
            if build_key not in app_profile['builds']:
                continue
            binfo = app_profile['builds'][build_key]
            wdir = output_dir / 'runtime' / mode
            wdir.mkdir(parents=True, exist_ok=True)

            if protocol == 'brotli_stream_rpc':
                cmd = [str(Path(binfo['executable']).resolve())]
                def launch_brotli(command=list(cmd), directory=wdir, patched=mode == 'patched'):
                    return Worker(
                        command, directory,
                        patch=patch_manifest_path if patched else None,
                        catalog=actions_catalog_path,
                        dsl=dsl_path if patched else None,
                        bridge_dir=ROOT / 'build' / 'frida-vm',
                        map_names=case_ir.get('empty_maps_after_episode'),
                    )
                _track(mode, launch_brotli)
            elif protocol == 'cli_stream':
                def launch_cli(command=[str(Path(binfo['executable']).resolve()), *list(binfo.get('argv') or [])], directory=wdir, patched=mode == 'patched'):
                    return CLIStreamWorker(
                        command, directory,
                        patch=patch_manifest_path if patched else None,
                        catalog=actions_catalog_path,
                    )
                _track(mode, launch_cli)
            elif protocol == 'c_api_rpc':
                def launch_capi(command=[str(Path(app_profile['c_api_host']).resolve()), str(Path(binfo['library']).resolve())], directory=wdir, patched=mode == 'patched'):
                    return CAPIWorker(
                        command, directory,
                        patch=patch_manifest_path if patched else None,
                        catalog=actions_catalog_path,
                    )
                _track(mode, launch_capi)
            elif protocol == 'php_http':
                sess_dir = wdir / 'sessions'
                sess_dir.mkdir(parents=True, exist_ok=True)
                exe_p = Path(binfo['executable']).resolve()
                uniq_syms, _ = elf_unique_symbols(exe_p)
                anchor_sym = app_profile.get('trace_anchor_symbol', 'php_session_rfc1867_callback')
                trace_spec: dict[str, Any] = {
                    'module': exe_p.name,
                    'anchor_offset': uniq_syms[anchor_sym],
                    'admission': [],
                }
                for adm in case_ir.get('environment_fixture', {}).get('admission_checks', []):
                    off = uniq_syms[adm['symbol']] + int(adm.get('add_offset', 0))
                    tgt = None if adm.get('expected_symbol') is None else uniq_syms[adm['expected_symbol']]
                    trace_spec['admission'].append({'name': adm['name'], 'offset': off, 'target_offset': tgt})
                router_p = Path(app_profile['router_script']).resolve()
                cmd = [
                    str(exe_p), '-n',
                    *php_ini_arguments(case_ir, sess_dir),
                    '-S', '127.0.0.1:{port}',
                    str(router_p),
                ]
                def launch_php(command=list(cmd), directory=wdir, spec=dict(trace_spec), patched=mode == 'patched'):
                    restore_fixture_files(case_ir, directory)
                    return UniversalHTTPWorker(
                        command, directory, spec,
                        patch=patch_manifest_path if patched else None,
                        catalog=actions_catalog_path,
                        dsl=dsl_path if patched else None,
                        bridge_dir=ROOT / 'build' / 'frida-vm',
                        map_names=case_ir.get('empty_maps_after_episode'),
                    )
                _track(mode, launch_php)
            else:
                exe_p = Path(binfo['executable']).resolve()
                uniq_syms, _ = elf_unique_symbols(exe_p)
                fixture = case_ir.get('environment_fixture', {})

                def _prepare_cfg(port: int, d: Path = wdir, b_info: dict[str, Any] = binfo) -> None:
                    tpl = fixture['config_template']
                    rendered = tpl.format(
                        root=str(d),
                        port=port,
                        backend=peer.port if peer else 0,
                        source_dir=b_info.get('source_dir', ''),
                        module_loads=_render_httpd_module_loads(b_info) if protocol == 'httpd_http' else '',
                    )
                    (d / 'server.conf').write_text(rendered, encoding='utf-8')

                if protocol == 'nginx_http':
                    cmd = [str(exe_p), '-p', str(wdir) + '/', '-c', str(wdir / 'server.conf')]
                else:
                    cmd = [str(exe_p), '-X', '-f', str(wdir / 'server.conf')]

                trace_spec = {'module': exe_p.name, 'anchor_offset': uniq_syms['main']}
                def launch_http(command=list(cmd), directory=wdir, spec=dict(trace_spec), prep=_prepare_cfg, patched=mode == 'patched'):
                    restore_fixture_files(case_ir, directory)
                    return UniversalHTTPWorker(
                        command, directory, spec,
                        patch=patch_manifest_path if patched else None,
                        catalog=actions_catalog_path,
                        prepare=prep,
                        timeout=15,
                        dsl=dsl_path if patched else None,
                        bridge_dir=ROOT / 'build' / 'frida-vm',
                        map_names=case_ir.get('empty_maps_after_episode'),
                    )
                _track(mode, launch_http)

            if mode == 'patched':
                installation_receipt = dict(workers['patched'].receipt)

        vm_replayer = VMReplay(bridge_path, rules_for_replay)
        stack.callback(vm_replayer.close)

        guards_by_id = {g['id']: g for g in case_ir['guards']}
        sym_regions = symbolic_report.get('impact_regions', {}).get('regions', [])
        sym_input_names = {x['name'] for x in case_ir.get('symbolization_scope', {}).get('symbolic_inputs', [])}
        inv_map = case_ir.get('symbolization_scope', {}).get('snapshot_to_symbolic_exprs', {})

        pending_fixed = [case for case in all_cases if case.get('stream_kind') != 'guided_fuzz']
        pending_guided = [case for case in all_cases if case.get('stream_kind') == 'guided_fuzz']
        flipped_predicates: set[str] = set()
        caller_conditions = list(symbolic_report.get('caller_return_conditions') or [])
        if not caller_conditions:
            caller_conditions = list(
                ((symbolic_report.get('impact_regions') or {}).get('entry_predicates') or {}).get('caller_return_conditions') or []
            )
        caller_field_map = case_ir.get('symbolization_scope', {}).get('field_to_input_map') or {}
        reset_mode = str(((app_profile.get('lifecycle_hooks') or {}).get('request_reset')) or '')
        baseline_fds = {
            mode: process_tree_fd_count(worker.process.pid)
            for mode, worker in workers.items()
            if getattr(worker, 'process', None) is not None and worker.process.poll() is None
        }
        cases_started = 0
        while True:
            if pending_fixed:
                case = pending_fixed.pop(0)
            elif pending_guided:
                pending_guided.sort(key=lambda item: guided_case_rank(
                    item, triggered_hook_ids, best_predicate_distances, visited_region_indices,
                ))
                case = pending_guided.pop(0)
            else:
                break
            reset_held = True
            if cases_started and reset_mode == 'process_restart':
                for mode, holder in holders.items():
                    holder.restart()
                    workers[mode] = holder.worker
            elif cases_started and reset_mode == 'request_cleanup_then_snapshot':
                current_fds = {
                    mode: process_tree_fd_count(worker.process.pid)
                    for mode, worker in workers.items()
                    if getattr(worker, 'process', None) is not None and worker.process.poll() is None
                }
                reset_held = request_boundaries_hold(baseline_fds, current_fds)
                if not reset_held:
                    hook_totals['request_reset_violations'] += 1
            cases_started += 1
            if case.get('prelude_request') and protocol != 'brotli_stream_rpc':
                pre_execs = {mode: w.execute(case['prelude_request']) for mode, w in workers.items()}
                pre_replay = vm_replayer.check(pre_execs['patched']['events'])
                hook_totals['observations'] += pre_replay['observations']
                hook_totals['decisions'] += pre_replay['decisions']
                hook_totals['block_decisions'] += pre_replay['blocks']
                hook_totals['pass_decisions'] += (pre_replay['decisions'] - pre_replay['blocks'])
                hook_totals['diagnostics'] += pre_replay['diagnostics']
                hook_totals['replay_violations'] += len(pre_replay['violations'])
                hook_totals['map_retention_leaks'] += count_transient_map_leaks(
                    transient_map_names(case_ir), vm_replayer.tables, pre_execs['patched'].get('runtime_status'),
                )
                if reset_mode == 'request_cleanup_then_snapshot':
                    current_fds = {
                        mode: process_tree_fd_count(worker.process.pid)
                        for mode, worker in workers.items()
                        if getattr(worker, 'process', None) is not None and worker.process.poll() is None
                    }
                    if not request_boundaries_hold(baseline_fds, current_fds):
                        reset_held = False
                        hook_totals['request_reset_violations'] += 1
                for msg in pre_execs['patched']['events']:
                    ev = msg.get('payload', {})
                    if ev.get('event') in ('observation', 'decision') and ev.get('hook'):
                        triggered_hook_ids.add(ev['hook'])
                    if ev.get('event') == 'decision' and ev.get('snapshot') and ev.get('hook') in guards_by_id:
                        absorb_decision_snapshot(
                            guards_by_id[ev['hook']], ev['snapshot'], sym_regions, sym_input_names, inv_map,
                            best_predicate_distances, visited_region_indices, guided_visited_regions,
                            fixed_visited_regions, case.get('stream_kind') or '', pending_guided,
                        )
                        enqueue_unseen_branch_flips(
                            case, guards_by_id[ev['hook']], ev['snapshot'], best_predicate_distances,
                            pending_guided, flipped_predicates, output_dir / 'corpus',
                        )
                        enqueue_caller_condition_flips(
                            case, guards_by_id[ev['hook']], ev['snapshot'], caller_conditions,
                            pending_guided, flipped_predicates, output_dir / 'corpus', caller_field_map,
                        )
            op_payload = operation_payload(protocol, case)
            execs = {}
            for mode, worker in workers.items():
                mark = peer.mark() if peer is not None else None
                execs[mode] = worker.execute(op_payload)
                if mark is not None:
                    execs[mode]['outcome']['backend_digest'] = peer.digest_since(mark)
            outcomes = {mode: record['outcome'] for mode, record in execs.items()}
            _attach_contract_observations(protocol, outcomes, workers)

            latencies_ms['baseline'].append(execs['baseline']['elapsed_seconds'] * 1000.0)
            latencies_ms['patched'].append(execs['patched']['elapsed_seconds'] * 1000.0)

            replay = vm_replayer.check(execs['patched']['events'])
            hook_totals['observations'] += replay['observations']
            hook_totals['decisions'] += replay['decisions']
            hook_totals['block_decisions'] += replay['blocks']
            hook_totals['pass_decisions'] += (replay['decisions'] - replay['blocks'])
            hook_totals['diagnostics'] += replay['diagnostics']
            hook_totals['replay_violations'] += len(replay['violations'])

            hook_totals['map_retention_leaks'] += count_transient_map_leaks(
                transient_map_names(case_ir), vm_replayer.tables, execs['patched'].get('runtime_status'),
            )

            episode_hits: list[int] = []
            episode_unhit_distance: float | None = None
            for msg in execs['patched']['events']:
                ev = msg.get('payload', {})
                if ev.get('event') in ('observation', 'decision') and ev.get('hook'):
                    triggered_hook_ids.add(ev['hook'])
                if ev.get('event') == 'decision' and ev.get('snapshot') and ev.get('hook') in guards_by_id:
                    hits, nearest = absorb_decision_snapshot(
                        guards_by_id[ev['hook']], ev['snapshot'], sym_regions, sym_input_names, inv_map,
                        best_predicate_distances, visited_region_indices, guided_visited_regions,
                        fixed_visited_regions, case.get('stream_kind') or '', pending_guided,
                    )
                    enqueue_unseen_branch_flips(
                        case, guards_by_id[ev['hook']], ev['snapshot'], best_predicate_distances,
                        pending_guided, flipped_predicates, output_dir / 'corpus',
                    )
                    enqueue_caller_condition_flips(
                        case, guards_by_id[ev['hook']], ev['snapshot'], caller_conditions,
                        pending_guided, flipped_predicates, output_dir / 'corpus', caller_field_map,
                    )
                    for r_idx in hits:
                        if r_idx not in episode_hits:
                            episode_hits.append(r_idx)
                    if nearest is not None:
                        episode_unhit_distance = nearest if episode_unhit_distance is None else min(episode_unhit_distance, nearest)

            eligible_benign, changed_fields, ref_diff = _compare_world_outcomes(
                protocol, case, outcomes['baseline'], outcomes['patched'], outcomes.get('reference'), [],
            )

            mark_error_fallback(outcomes['baseline'], outcomes['patched'], replay['blocks'])
            coverage_pairs.append((case['id'], outcomes['baseline'], outcomes['patched']))
            with gzip.open(output_dir / 'runtime' / f'episode-{case["id"]}.json.gz', 'wt', encoding='utf-8') as gz:
                json.dump({
                    'case': case,
                    'outcomes': {k: {fk: fv for fk, fv in v.items() if fk != 'trace'} for k, v in outcomes.items()},
                    'replay': replay,
                    'changed_fields': changed_fields,
                }, gz)

            episode_record = {
                'id': case['id'],
                'group': case.get('group', 'default'),
                'stream_kind': case['stream_kind'],
                'eligible_benign': eligible_benign,
                'reference_consistent': len(ref_diff) == 0,
                'changed_fields': changed_fields,
                'decisions': replay['decisions'],
                'blocks': replay['blocks'],
                'replay_violations': replay['violations'],
                'region_hits': episode_hits,
                'nearest_unhit_region_distance': episode_unhit_distance,
                'baseline_fault': outcome_is_error(outcomes['baseline']),
                'patched_fault': outcome_is_error(outcomes['patched']),
                'touched_hooks': touched_hook_ids(execs['patched']['events']),
                'request_reset_held': reset_held,
            }
            episode_record['replay_attribution'] = attribute_tri_replay(footprint, episode_record)
            episode_records.append(episode_record)

        poc_spec = case_ir.get('seed_traces', {}).get('poc_reproducer')
        if poc_spec and poc_spec.get('requests'):
            poc_res: dict[str, Any] = {'executed': True, 'worlds': {}}
            health_case = fixed_cases[0]
            health_op = operation_payload(protocol, health_case)
            for mode, w in workers.items():
                log_mark = worker_log_mark(w.directory)
                mode_steps = []
                mode_hooks: list[str] = []
                for r_item in poc_spec['requests']:
                    r_exec = w.execute(_normalized_http_request(r_item) if isinstance(r_item, dict) else r_item)
                    mode_steps.append({
                        'http_status': r_exec['outcome'].get('http_status'),
                        'response_complete': r_exec['outcome'].get('response_complete'),
                        'decisions': len([m for m in r_exec['events'] if m.get('payload', {}).get('event') == 'decision']),
                        'blocks': len([m for m in r_exec['events'] if m.get('payload', {}).get('action') == 'BLOCK']),
                    })
                    if mode == 'patched':
                        for hook in touched_hook_ids(r_exec['events']):
                            if hook not in mode_hooks:
                                mode_hooks.append(hook)
                h_exec = w.execute(health_op)
                log_suffix = worker_log_suffix(w.directory, log_mark)
                world_row = {
                    'poc_steps': mode_steps,
                    'post_poc_worker_alive': w.process.poll() is None,
                    'post_poc_health_status': h_exec['outcome'].get('http_status', h_exec['outcome'].get('result')),
                    'path_mismatch': logged_path_mismatch(log_suffix, poc_spec.get('requests') or []),
                }
                _annotate_poc_world(
                    world_row, log_suffix, str((case_ir.get('safety_oracle') or {}).get('kind') or ''),
                )
                if mode == 'patched':
                    world_row['touched_hooks'] = mode_hooks
                poc_res['worlds'][mode] = world_row
            poc_res['verdict'] = judge_isolated_poc(poc_res['worlds'])
            baseline_world = poc_res['worlds'].get('baseline') or {}
            patched_world = poc_res['worlds'].get('patched') or {}
            reference_world = poc_res['worlds'].get('reference')
            baseline_fault = _poc_baseline_fault(baseline_world)
            _blocked, alive, health_ok = _poc_patched_outcome(patched_world)
            patched_steps = patched_world.get('poc_steps') or []
            patched_fault = (not alive) or (not health_ok) or any(
                (not step.get('response_complete', True)) or int(step.get('http_status') or 0) >= 500
                for step in patched_steps
            )
            reference_fault = _poc_baseline_fault(reference_world) if reference_world else baseline_fault
            poc_res['replay_attribution'] = attribute_tri_replay(footprint, {
                'baseline_fault': baseline_fault,
                'patched_fault': patched_fault,
                'changed_fields': ['poc_outcome'] if baseline_fault != patched_fault else [],
                'blocks': sum(int(step.get('blocks') or 0) for step in patched_steps),
                'replay_violations': [],
                'reference_consistent': reference_fault == baseline_fault,
                'touched_hooks': list(patched_world.get('touched_hooks') or []),
            })
            poc_runtime_verification = poc_res

    cov_summary = summarize_coverage(coverage_pairs)
    (output_dir / 'coverage.json').write_text(json.dumps(cov_summary, indent=2) + '\n', encoding='utf-8')

    fixed_valid = [
        e for e in episode_records
        if e['stream_kind'] == 'fixed_eval' and e['eligible_benign'] and e['reference_consistent']
    ]
    fixed_changed = [e for e in fixed_valid if _attributed_field_change(e)]
    fixed_blocked = [e for e in fixed_valid if e['blocks'] > 0]
    fixed_pass_changed = [e for e in fixed_valid if e['blocks'] == 0 and _attributed_field_change(e)]

    groups_breakdown: dict[str, dict[str, int]] = {}
    for e in fixed_valid:
        grp = groups_breakdown.setdefault(e['group'], {'passed': 0, 'changed': 0, 'total': 0})
        grp['total'] += 1
        if _attributed_field_change(e):
            grp['changed'] += 1
        else:
            grp['passed'] += 1

    guided_eps = [e for e in episode_records if e['stream_kind'] == 'guided_fuzz']
    sig_lost_edges = sum(
        1 for t in cov_summary.get('edge_tests', [])
        if t.get('lost', 0) > t.get('gained', 0) and t.get('q_bh', 1.0) < 0.05
    )

    sym_regs = symbolic_report.get('impact_regions', {}).get('regions', [])
    nonempty_regs = [i for i, r in enumerate(sym_regs) if r.get('classification') != 'UNREACHABLE']
    impact_regs = [i for i, r in enumerate(sym_regs) if r.get('classification') in ('CHANGED_BY_BLOCK', 'CHANGED_ON_PASS', 'MIXED')]

    total_required_hooks = len(case_ir['guards']) + len(case_ir['observers'])
    installed_hooks_count = int(installation_receipt.get('guards', 0)) + int(installation_receipt.get('observers', 0))
    (output_dir / 'installation-receipt.json').write_text(
        json.dumps(installation_receipt, indent=2, ensure_ascii=False) + '\n',
        encoding='utf-8',
    )
    installation_fields = installation_report_fields(
        case_ir, installation_receipt, total_required_hooks, installed_hooks_count, 'installation-receipt.json',
    )
    vm_checked = sum(int(item.get('checked_properties') or 0) for item in vm_proofs.values())
    vm_instructions = [int(item.get('bytecode_instructions') or 0) for item in vm_proofs.values()]

    med_base = statistics.median(latencies_ms['baseline']) if latencies_ms['baseline'] else 0.0
    med_patch = statistics.median(latencies_ms['patched']) if latencies_ms['patched'] else 0.0

    final_report = {
        'schema': 'vulgate.evaluation_report/v2',
        'case_id': case_ir['case_id'],
        'application': case_ir['application_name'],
        'elapsed_seconds': time.monotonic() - started,
        'identities': case_ir['identities'],
        'installation': {
            **installation_fields,
            'required_hooks': total_required_hooks,
            'installed_hooks': installed_hooks_count,
            'hook_installation_coverage': (installed_hooks_count / total_required_hooks) if total_required_hooks else 1.0,
            'receipt': installation_receipt,
        },
        'correctness_and_safety': {
            'vm_bytecode_equivalence': {
                'status': 'PROVED' if vm_proofs and all(v['status'] == 'PROVED' for v in vm_proofs.values()) else 'UNRESOLVED',
                'checked_properties': vm_checked,
                'max_instructions': max(vm_instructions) if vm_instructions else 0,
                'guards': vm_proofs,
            },
            'action_and_caller_continuation': {
                **symbolic_report.get('action_and_caller_continuation', {'status': 'UNRESOLVED'}),
                'verification_tasks': verification_task_rows(symbolic_report),
            },
            'target_vulnerability_elimination': {
                **symbolic_report.get('target_vulnerability_elimination', {'status': 'UNRESOLVED'}),
                **isolated_poc_report_fields(
                    poc_runtime_verification,
                    bool((symbolic_report.get('target_vulnerability_elimination') or {}).get('baseline_vulnerability_reproduced_in_model')),
                ),
            },
            'pass_path_noninterference': symbolic_report.get('pass_path_noninterference', {'status': 'UNRESOLVED'}),
            'replay_attribution': {
                'patch_footprint': footprint,
                'isolated_poc': None if poc_runtime_verification is None else poc_runtime_verification.get('replay_attribution'),
            },
            'isolated_poc_runtime_check': poc_runtime_verification,
        },
        'path_and_functional_metrics': {
            'hook_triggering': {
                'installed_hooks': installed_hooks_count,
                'triggered_hooks': len(triggered_hook_ids),
                'hook_trigger_ratio': (len(triggered_hook_ids) / installed_hooks_count) if installed_hooks_count else 0.0,
                'triggered_hook_ids': sorted(triggered_hook_ids),
                **hook_totals,
                'total_observations': hook_totals['observations'],
                'total_vm_decisions': hook_totals['decisions'],
                'vm_replay_mismatches': hook_totals['replay_violations'],
                'predicate_branch_coverage': best_predicate_distances,
            },
            'symbolic_impact_regions': {
                'total_partitioned_regions': len(sym_regs),
                'total_regions': len(sym_regs),
                'nonempty_reachable_regions': len(nonempty_regs),
                'unchanged_regions': sum(1 for r in sym_regs if r.get('classification') == 'UNCHANGED'),
                'changed_by_block_regions': sum(1 for r in sym_regs if r.get('classification') == 'CHANGED_BY_BLOCK'),
                'changed_on_pass_regions': sum(1 for r in sym_regs if r.get('classification') == 'CHANGED_ON_PASS'),
                'unresolved_regions': sum(1 for r in sym_regs if r.get('classification') == 'UNRESOLVED'),
                'mixed_or_unresolved_regions': sum(1 for r in sym_regs if r.get('classification') in ('MIXED', 'UNRESOLVED')),
                'dynamically_visited_nonempty_regions': len(visited_region_indices & set(nonempty_regs)),
                'dynamically_visited_impact_regions': len(visited_region_indices & set(impact_regs)),
                'region_details': sym_regs,
            },
            'functional_impact_fixed_eval': {
                'denominator_valid_benign_cases': len(fixed_valid),
                'changed_cases': len(fixed_changed),
                'changed_fraction': (len(fixed_changed) / len(fixed_valid)) if fixed_valid else 0.0,
                'changed_rate': (len(fixed_changed) / len(fixed_valid)) if fixed_valid else 0.0,
                'blocked_benign_cases': len(fixed_blocked),
                'normal_rejection_fraction': (len(fixed_blocked) / len(fixed_valid)) if fixed_valid else 0.0,
                'false_block_rate_on_corpus': (len(fixed_blocked) / len(fixed_valid)) if fixed_valid else 0.0,
                'pass_but_output_changed_cases': len(fixed_pass_changed),
                'pass_path_changed_cases': len(fixed_pass_changed),
                'pass_path_changed_fraction': (len(fixed_pass_changed) / max(1, len(fixed_valid) - len(fixed_blocked))) if fixed_valid else 0.0,
                'sampling_basis': 'declared_fixed_functional_corpus',
                'by_functional_group': groups_breakdown,
            },
            'functional_impact_guided_fuzz': guided_fuzz_report_fields(
                guided_eps, fixed_visited_regions, guided_visited_regions, footprint,
            ),
            'paired_coverage': {
                'complete_paired_episodes': cov_summary['complete_episodes'],
                'incomplete_episodes': cov_summary['incomplete_episodes'],
                'baseline_unique_edges': cov_summary['baseline_edges'],
                'patched_unique_edges': cov_summary['patched_edges'],
                'retained_edge_fraction': cov_summary['retained_fraction'],
                'retained_edge_ratio': cov_summary['retained_fraction'],
                'lost_edge_union': cov_summary['lost_edge_union'],
                'lost_edges_union': cov_summary['lost_edge_union'],
                'gained_edge_union': cov_summary['gained_edge_union'],
                'gained_error_edges_union': cov_summary['gained_error_edges_union'],
                'changed_sequence_episodes': cov_summary['changed_sequences'],
                'changed_trace_episodes': cov_summary['changed_sequences'],
                'significant_lost_edges_bh_q005': sig_lost_edges,
                'statistically_significant_lost_edges_q005': sig_lost_edges,
            },
            'performance_overhead': {
                'median_latency_ms_baseline': round(med_base, 4),
                'median_latency_ms_patched': round(med_patch, 4),
                'relative_latency_delta': round((med_patch - med_base) / med_base, 4) if med_base > 0 else 0.0,
                'relative_overhead_ratio': round((med_patch - med_base) / med_base, 4) if med_base > 0 else 0.0,
            },
        },
        'episodes': episode_records,
    }

    (output_dir / 'evaluation-report.json').write_text(json.dumps(final_report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    (output_dir / 'evaluation-summary.txt').write_text(render_evaluation_summary(final_report), encoding='utf-8')
    return final_report


def _render_httpd_module_loads(build_info: dict[str, Any]) -> str:
    src_dir = Path(build_info['source_dir'])
    required = [
        'authn_core', 'authn_file', 'authz_core', 'authz_host', 'authz_user', 'auth_basic',
        'unixd', 'log_config', 'mime', 'dir', 'alias', 'headers', 'filter', 'proxy',
        'proxy_http', 'xml2enc', 'proxy_html', 'charset_lite', 'rewrite', 'session',
        'session_cookie', 'dav', 'dav_fs', 'vhost_alias', 'http2',
    ]
    lines = []
    for mod in required:
        cands = list(src_dir.glob(f'modules/**/.libs/mod_{mod}.so'))
        if not cands:
            if mod in ('unixd', 'log_config'):
                continue
            raise ValueError(f'missing httpd module {mod} under {src_dir}')
        lines.append(f'LoadModule {mod}_module {cands[0]}')
    return '\n'.join(lines)


def _compare_world_outcomes(protocol: str,
                            case: dict[str, Any],
                            baseline: dict[str, Any],
                            patched: dict[str, Any],
                            reference: dict[str, Any] | None,
                            extra_diffs: list[str]) -> tuple[bool, list[str], list[str]]:
    if protocol == 'brotli_stream_rpc':
        fields = ['result', 'error', 'consumed', 'produced', 'total_out', 'output_hex',
                  'database_digest', 'completion_event_digest', 'worker_alive', 'resource_count_delta']
        exp = case.get('expected', {})
        eligible = all(baseline.get(k) == v for k, v in exp.items()) and (
            reference is None or all(reference.get(k) == v for k, v in exp.items())
        )
        changed = [f for f in fields if baseline.get(f) != patched.get(f)] + list(extra_diffs)
        ref_diff = [f for f in fields if reference is not None and baseline.get(f) != reference.get(f)]
        return eligible, changed, ref_diff

    if protocol == 'cli_stream':
        fields = ['exit_code', 'stdout_sha256', 'bytes_in', 'bytes_out', 'chunk_size',
                  'database_digest', 'completion_event_digest', 'worker_alive', 'resource_count_delta']
        exp = case.get('expected', {})
        eligible = all(baseline.get(k) == v for k, v in exp.items()) and (
            reference is None or all(reference.get(k) == v for k, v in exp.items())
        )
        changed = [f for f in fields if baseline.get(f) != patched.get(f)] + list(extra_diffs)
        ref_diff = [f for f in fields if reference is not None and baseline.get(f) != reference.get(f)]
        return eligible, changed, ref_diff

    if protocol == 'c_api_rpc':
        fields = ['call_ok', 'return_u64', 'output_sha256', 'bytes_out',
                  'database_digest', 'completion_event_digest', 'worker_alive', 'resource_count_delta']
        exp = case.get('expected', {})
        eligible = all(baseline.get(k) == v for k, v in exp.items()) and (
            reference is None or all(reference.get(k) == v for k, v in exp.items())
        )
        changed = [f for f in fields if baseline.get(f) != patched.get(f)] + list(extra_diffs)
        ref_diff = [f for f in fields if reference is not None and baseline.get(f) != reference.get(f)]
        return eligible, changed, ref_diff

    if protocol == 'php_http':
        exp = case.get('expected', {})
        fields = list(dict.fromkeys([*exp.keys(), 'progress_bytes', 'body_sha256', *CONTRACT_OBSERVATION_FIELDS]))
        eligible = all(baseline.get(k) == v for k, v in exp.items()) and (
            reference is None or all(reference.get(k) == v for k, v in exp.items())
        )
        changed = [f for f in fields if baseline.get(f) != patched.get(f)] + list(extra_diffs)
        ref_diff = [f for f in fields if reference is not None and baseline.get(f) != reference.get(f)]
        return eligible, changed, ref_diff

    exp_status = int(case.get('expected_status', 200))
    eligible = (
        baseline.get('http_status') == exp_status and bool(baseline.get('response_complete')) and
        (reference is None or (reference.get('http_status') == exp_status and bool(reference.get('response_complete'))))
    )
    fields = ['http_status', 'response_complete', 'body_sha256', *CONTRACT_OBSERVATION_FIELDS]
    changed = [f for f in fields if baseline.get(f) != patched.get(f)] + list(extra_diffs)
    ref_diff = [f for f in fields if reference is not None and baseline.get(f) != reference.get(f)]
    return eligible, changed, ref_diff


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--vuln', type=Path, required=True)
    parser.add_argument('--patch', type=Path, required=True)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cbmc', type=Path, default=None)
    args = parser.parse_args()
    report = evaluate_case(args.vuln, args.patch, args.app, args.out, args.cbmc)
    print(json.dumps({
        'case_id': report['case_id'],
        'installation': report['installation']['status'],
        'vm': report['correctness_and_safety']['vm_bytecode_equivalence']['status'],
        'continuation': report['correctness_and_safety']['action_and_caller_continuation']['status'],
        'target': report['correctness_and_safety']['target_vulnerability_elimination']['status'],
        'fixed_changed': f"{report['path_and_functional_metrics']['functional_impact_fixed_eval']['changed_cases']}/{report['path_and_functional_metrics']['functional_impact_fixed_eval']['denominator_valid_benign_cases']}",
    }, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
