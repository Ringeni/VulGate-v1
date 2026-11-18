"""A resettable JSON-line worker and real Frida installation for paired runs."""
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time

try:
    from runtime.frida.run import load_bundle
except ImportError:
    load_bundle = None

ROOT = Path(__file__).resolve().parents[2]
_LOG_SKIP = {'server.log', 'stderr.log'}


def _install_dsl(pid: int, dsl_path: Path, bridge_dir: Path, session=None):
    """Install a .vg patch through the current DSL -> VM -> Frida chain."""
    import frida
    from runtime.dsl import parser as dsl_parser
    from runtime.dsl import resolve as dsl_resolve
    from runtime.dsl import vm as dsl_vm
    from runtime.dsl import vm_run

    patch = dsl_parser.load(dsl_path)
    dsl_resolve.resolve_patch(patch, pid=pid, executable=None)
    globals_ = {}
    for name in vm_run._global_names(patch):
        _, address = dsl_resolve.resolve_global(name, pid, None, None)
        globals_[name] = address
    compiled = dsl_vm.compile_patch(patch, globals_)
    targets = [vm_run._target_address(pid, mount, None) for mount in patch.mounts]
    bridge = vm_run._bridge(bridge_dir)
    if session is None:
        session = frida.get_local_device().attach(pid)
    script = session.create_script(vm_run._script(patch, compiled, targets, bridge))
    script.load()
    result = script.exports_sync.install()
    return session, script, result, bridge


def process_tree_fd_count(pid: int) -> int:
    if pid <= 0:
        return 0
    seen: set[int] = set()
    stack = [int(pid)]
    total = 0
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        fd_dir = Path(f'/proc/{current}/fd')
        if fd_dir.is_dir():
            total += sum(1 for _ in fd_dir.iterdir())
        child_file = Path(f'/proc/{current}/task/{current}/children')
        if not child_file.is_file():
            continue
        try:
            text = child_file.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for part in text.split():
            if part.isdigit():
                stack.append(int(part))
    return total


def log_cursors(root: Path) -> dict[str, int]:
    cursors: dict[str, int] = {}
    base = Path(root)
    if not base.is_dir():
        return cursors
    for fp in base.rglob('*.log'):
        if not fp.is_file() or fp.name in _LOG_SKIP:
            continue
        cursors[str(fp.resolve())] = fp.stat().st_size
    return cursors


def normalize_completion_line(raw: bytes) -> str:
    text = raw.decode('utf-8', errors='replace')
    text = re.sub(r'\b0x[0-9a-fA-F]+\b', '', text)
    text = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b', '', text)
    text = re.sub(r'\b\d{4}[/-]\d{2}[/-]\d{2}\b', '', text)
    text = re.sub(r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b', '', text)
    text = re.sub(r'\[[A-Za-z]{3} [A-Za-z]{3} [^\]]+\]', '', text)
    text = re.sub(r'\bpid[: ]+\d+\b', 'pid', text, flags=re.IGNORECASE)
    text = re.sub(r'\b\d+#\d+:?', '', text)
    return ' '.join(text.split())


def completion_event_digest(cursors: dict[str, int]) -> list[str]:
    digests: list[str] = []
    for name, start in cursors.items():
        fp = Path(name)
        if not fp.is_file():
            continue
        data = fp.read_bytes()
        chunk = data[start:] if 0 <= start <= len(data) else data
        for line in chunk.splitlines():
            text = normalize_completion_line(line)
            if text:
                digests.append(hashlib.sha256(text.encode()).hexdigest())
    digests.sort()
    return digests


def sanitizer_subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault('ASAN_OPTIONS', 'halt_on_error=1:abort_on_error=1:detect_leaks=0')
    env.setdefault('UBSAN_OPTIONS', 'halt_on_error=1:abort_on_error=1:print_stacktrace=1')
    env.setdefault('MSAN_OPTIONS', 'halt_on_error=1:abort_on_error=1')
    return env


class Worker:
    def __init__(self, command, directory, patch=None, catalog=None, dsl=None,
                 bridge_dir=None, map_names=None, timeout=20):
        self.timeout = timeout
        self.dsl = Path(dsl) if dsl else None
        self.bridge_dir = Path(bridge_dir) if bridge_dir else ROOT / 'build' / 'frida-vm'
        self.map_names = list(map_names or [])
        self.session = self.script = None
        self.events = []
        self.lines = queue.Queue()
        self.barriers = queue.Queue()
        self.serial = 0
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.stderr = (self.directory / 'stderr.log').open('w')
        self.process = subprocess.Popen([str(x) for x in command], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.stderr, text=True, bufsize=1,
            env=sanitizer_subprocess_env())
        def read():
            for line in self.process.stdout:
                self.lines.put(line)
            self.lines.put(None)
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            ready = self.lines.get(timeout=timeout)
            if ready is None or json.loads(ready) != {'ready': True}:
                raise RuntimeError('worker did not become ready: ' + str(ready))
            self._install(command, patch, catalog)
            (self.directory / 'installation.json').write_text(json.dumps(self.receipt, indent=2) + '\n')
        except BaseException:
            self.close()
            raise

    def _install(self, command, patch, catalog):
        self.receipt = {'pid': self.process.pid, 'command': list(map(str, command)), 'installed': False}
        if self.dsl:
            self.session, self.script, result, bridge = _install_dsl(
                self.process.pid, self.dsl, self.bridge_dir, self.session)
            hooks = result.get('installed') or []
            self.receipt.update(result, backend='dsl-vm-frida',
                                installed=bool(hooks),
                                guards=sum(1 for h in hooks if h.get('nature') == 'intercept'),
                                observers=sum(1 for h in hooks if h.get('nature') == 'read_point'),
                                dsl=str(self.dsl), bridge=str(bridge),
                                hashes={str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in (self.dsl, bridge, Path(command[0]))})
            return
        if patch:
            import frida
            config, actions = load_bundle(Path(patch), Path(catalog))
            if self.session is None:
                self.session = frida.get_local_device().attach(self.process.pid)
            source = ROOT / 'runtime/frida/agent.js'
            self.script = self.session.create_script(source.read_text())
            self.script.on('message', self._message)
            self.script.load()
            result = self.script.exports_sync.install(config, actions)
            pins = [source, Path(patch), Path(catalog), Path(config['bridge']), Path(command[0])]
            pins += [(Path(patch).parent / g['rule']).resolve() for g in config['guards']]
            self.receipt.update(result, frida=frida.__version__, hashes={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in pins})

    def _message(self, message, data):
        if message.get('payload', {}).get('event') == 'barrier':
            self.barriers.put(message['payload']['token'])
        else:
            self.events.append(message)

    def _record_request_resources(self, outcome: dict, fd_before: int, cursors: dict[str, int]) -> None:
        outcome['worker_alive'] = self.process.poll() is None
        outcome['resource_count_delta'] = process_tree_fd_count(self.process.pid) - fd_before
        outcome['completion_event_digest'] = completion_event_digest(cursors)

    def execute(self, command):
        start = len(self.events)
        self.serial += 1
        before = time.monotonic()
        fd_before = process_tree_fd_count(self.process.pid)
        cursors = log_cursors(self.directory)
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        line = self.lines.get(timeout=self.timeout)
        if line is None: raise RuntimeError('worker exited: ' + str(self.process.poll()))
        reply = json.loads(line)
        self._record_request_resources(reply, fd_before, cursors)
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
        return {'outcome': reply, 'events': self.events[start:],
                'runtime_status': status,
                'elapsed_seconds': time.monotonic() - before}

    def close(self):
        if getattr(self, '_closed', False):
            return
        self._closed = True
        try:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write('exit\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    self.process.kill()
                    self.process.wait(timeout=3)
        finally:
            if self.session:
                try:
                    self.session.detach()
                except Exception:
                    pass
                self.session = None
            self.reader.join(timeout=1)
            try: self.process.stdin.close()
            except (BrokenPipeError, OSError): pass
            try: self.process.stdout.close()
            except OSError: pass
            try:
                if self.stderr is not None and not self.stderr.closed:
                    self.stderr.close()
            except OSError:
                pass

    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class CAPIWorker(Worker):
    def execute(self, command):
        result = super().execute(command)
        outcome = result['outcome']
        hex_text = outcome.pop('output_hex', None)
        raw = b'' if hex_text is None else bytes.fromhex(hex_text)
        outcome['output_sha256'] = hashlib.sha256(raw).hexdigest()
        outcome['bytes_out'] = len(raw)
        return result


class CLIStreamWorker:
    def __init__(self, command, directory, patch=None, catalog=None, timeout=20):
        self.command = [str(item) for item in command]
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.patch = Path(patch) if patch else None
        self.catalog = Path(catalog) if catalog else None
        self.timeout = timeout
        self.events = []
        self.barriers = queue.Queue()
        self.serial = 0
        self.session = None
        self.script = None
        self.process = None
        self.stderr = None
        self.receipt = {'command': list(self.command), 'installed': False}
        self._spawn()
        (self.directory / 'installation.json').write_text(json.dumps(self.receipt, indent=2) + '\n')

    def _spawn(self):
        self._release_process()
        self.stderr = (self.directory / 'stderr.log').open('ab')
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
        )
        self.receipt['pid'] = self.process.pid
        if self.patch is not None:
            self._install()

    def _install(self):
        import frida
        config, actions = load_bundle(self.patch, self.catalog)
        self.session = frida.get_local_device().attach(self.process.pid)
        source = ROOT / 'runtime/frida/agent.js'
        self.script = self.session.create_script(source.read_text())
        self.script.on('message', self._message)
        self.script.load()
        result = self.script.exports_sync.install(config, actions)
        pins = [source, self.patch, self.catalog, Path(config['bridge']), Path(self.command[0])]
        pins += [(self.patch.parent / g['rule']).resolve() for g in config['guards']]
        self.receipt.update(
            result,
            frida=frida.__version__,
            hashes={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in pins},
        )

    def _message(self, message, data):
        del data
        if message.get('payload', {}).get('event') == 'barrier':
            self.barriers.put(message['payload']['token'])
        else:
            self.events.append(message)

    def _write_body(self, body: bytes, chunk: int) -> None:
        if not body:
            return
        if chunk <= 0 or chunk >= len(body):
            self.process.stdin.write(body)
            self.process.stdin.flush()
            return
        for offset in range(0, len(body), chunk):
            self.process.stdin.write(body[offset:offset + chunk])
            self.process.stdin.flush()

    def execute(self, spec):
        if self.process is None or self.process.poll() is not None:
            self._spawn()
        if isinstance(spec, dict) and spec.get('argv'):
            self.command = [str(item) for item in spec['argv']]
            self._spawn()
        body = b''
        chunk = 0
        if isinstance(spec, dict):
            if spec.get('body_file'):
                body = Path(spec['body_file']).read_bytes()
            elif spec.get('body_hex'):
                body = bytes.fromhex(spec['body_hex'])
            elif isinstance(spec.get('body'), str):
                body = spec['body'].encode()
            chunk = int(spec.get('chunk_size') or 0)
        elif isinstance(spec, str):
            body = spec.encode()
        start = len(self.events)
        self.serial += 1
        before = time.monotonic()
        fd_before = process_tree_fd_count(self.process.pid)
        cursors = log_cursors(self.directory)
        captured: list[bytes] = []

        def read_stdout():
            captured.append(self.process.stdout.read())

        reader = threading.Thread(target=read_stdout, daemon=True)
        reader.start()
        try:
            self._write_body(body, chunk)
        except BrokenPipeError:
            pass
        still_running = self.process.poll() is None
        fd_after = process_tree_fd_count(self.process.pid) if still_running else 0
        try:
            self.process.stdin.close()
        except OSError:
            pass
        reader.join(self.timeout)
        if reader.is_alive():
            self.process.kill()
            reader.join(1)
        try:
            self.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        output = captured[0] if captured else b''
        exit_code = self.process.returncode if self.process.returncode is not None else -1
        outcome = {
            'exit_code': exit_code,
            'stdout_sha256': hashlib.sha256(output).hexdigest(),
            'bytes_in': len(body),
            'bytes_out': len(output),
            'chunk_size': chunk if chunk > 0 else len(body),
            'worker_alive': still_running and exit_code == 0,
            'resource_count_delta': fd_after - fd_before,
            'completion_event_digest': completion_event_digest(cursors),
        }
        status = None
        if self.script is not None and self.process.poll() is None:
            self.script.exports_sync.barrier(self.serial)
            if self.barriers.get(timeout=self.timeout) != self.serial:
                raise RuntimeError('event barrier mismatch')
            status = self.script.exports_sync.status()
        self._release_process()
        return {
            'outcome': outcome,
            'events': self.events[start:],
            'runtime_status': status,
            'elapsed_seconds': time.monotonic() - before,
        }

    def _release_process(self):
        if self.session is not None:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None
            self.script = None
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if self.stderr is not None and not self.stderr.closed:
            self.stderr.close()
        self.stderr = None
        self.process = None

    def close(self):
        self._release_process()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
