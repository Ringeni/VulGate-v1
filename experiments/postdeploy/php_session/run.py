"""Replay the original sixth policy on ordinary PHP uploads and session progress."""
from contextlib import ExitStack
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time
import argparse
import subprocess
import urllib.parse

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from elftools.elf.elffile import ELFFile
from tools.postdeploy.coverage import summarize
from tools.postdeploy.expressions import compile_guard
from tools.postdeploy.http_process import HTTPWorker
from tools.postdeploy.monitors import VMReplay, compare
from tools.postdeploy.symbolic import prove_vm_summary


def binding(executable, layout):
    names = ['php_session_rfc1867_callback', 'php_session_rfc1867_orig_callback', 'php_rfc1867_callback', 'ps_globals']
    with executable.open('rb') as file:
        elf = ELFFile(file)
        base = min(p['p_vaddr'] for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD')
    # nm reads the large PHP ELF in bulk; avoid per-symbol file seeks on WSL mounts.
    entries = subprocess.check_output(['nm', '-an', '--defined-only', str(executable)], text=True).splitlines()
    offsets = {}
    for name in names:
        matches = [line.split() for line in entries if line.split()[-1:] == [name]]
        if len(matches) != 1: raise ValueError('symbol is not unique: ' + name)
        offsets[name] = int(matches[0][0], 16) - base
    if layout['zts'] != 0: raise ValueError('this experiment requires an NTS build')
    return {'module': executable.name, 'anchor_offset': offsets[names[0]], 'offsets': offsets,
        'admission': [
            {'name': 'original callback chain empty', 'offset': offsets[names[1]], 'target_offset': None},
            {'name': 'registered callback is session callback', 'offset': offsets[names[2]], 'target_offset': offsets[names[0]]},
            {'name': 'no preexisting progress state', 'offset': offsets['ps_globals'] + layout['progress_offset'], 'target_offset': None}]}


def corpus(directory):
    directory.mkdir()
    sizes = [0, 1, 32, 256, 4096, 32768]
    index = 0
    for group in ['form', 'plain_upload', 'progress_upload']:
        for size in sizes:
            message = 'ordinary-' + str(index)
            headers = {'Cookie': 'PHPSESSID=vgtest%04d' % index}
            expected = {'http_status': 200, 'message': message, 'files': [],
                        'progress_present': group == 'progress_upload',
                        'progress_done': True if group == 'progress_upload' else None,
                        'progress_file_count': 1 if group == 'progress_upload' else 0}
            if group == 'form':
                body = urllib.parse.urlencode({'message': message}).encode()
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                boundary = 'VulGateOrdinaryBoundary20261112'
                parts = []
                def field(name, value):
                    parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n').encode())
                field('message', message)
                if group == 'progress_upload': field('PHP_SESSION_UPLOAD_PROGRESS', 'job')
                data = (b'Ordinary upload data.\n' * ((size + 20) // 21))[:size]
                parts += [(f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="note.txt"\r\n'
                           'Content-Type: text/plain\r\n\r\n').encode(), data, b'\r\n', (f'--{boundary}--\r\n').encode()]
                body = b''.join(parts)
                headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
                expected['files'] = [{'field': 'document', 'name': 'note.txt', 'size': size, 'error': 0,
                                      'sha256': hashlib.sha256(data).hexdigest()}]
            path = directory / ('%02d.body' % index)
            path.write_bytes(body)
            yield {'id': str(index), 'group': group, 'size': size, 'expected': expected,
                   'request': {'method': 'POST', 'body_file': str(path), 'headers': headers}}
            index += 1


def run(folder, output, cbmc):
    output.mkdir(parents=True, exist_ok=False)
    build = json.loads((folder / 'build.json').read_text())
    bindings = {mode: binding(folder / mode / 'php', build[mode]['layout']) for mode in ['baseline', 'reference']}
    (output / 'binding.json').write_text(json.dumps(bindings, indent=2) + '\n')
    (output / 'build.json').write_text(json.dumps(build, indent=2) + '\n')
    code = output / 'policy.bin'
    # Exactly the policy from 06_php_session.bpf.cpp: every callback is BLOCK,
    # and the trusted action returns PHP SUCCESS. The upload parser continues.
    code.write_bytes(compile_guard('True', {}))
    guard = {'id': 'session_progress_off', 'module': 'php', 'offset': bindings['baseline']['anchor_offset'],
             'arg_types': ['uint', 'pointer', 'pointer'], 'return_type': 'int',
             'vm_args': [{'constant': 0}], 'rule': str(code), 'action_id': 'PHP_SESSION_SUCCESS'}
    manifest = {'schema': 1, 'bridge': str(ROOT / 'build/frida-linux/vulgate_frida.so'), 'telemetry': True,
                'maps': {}, 'observers': [], 'guards': [guard],
                'artifact_pins': {str(folder / 'baseline/php'): build['baseline']['executable_sha256']}}
    patch, catalog = output / 'patch.json', output / 'actions.json'
    patch.write_text(json.dumps(manifest, indent=2) + '\n')
    catalog.write_text(json.dumps({'schema': 1, 'actions': {'PHP_SESSION_SUCCESS': {'kind': 'return_int', 'value': 0}}}, indent=2) + '\n')
    results, pairs, totals = [], [], {'decisions': 0, 'blocks': 0, 'diagnostics': 0}
    begin = time.monotonic()
    with ExitStack() as stack:
        workers = {}
        for mode in ['patched', 'baseline', 'reference']:
            source_mode = 'reference' if mode == 'reference' else 'baseline'
            state = output / mode / 'sessions'
            state.mkdir(parents=True)
            command = [str(folder / source_mode / 'php'), '-n',
                '-d', 'session.save_path=' + str(state), '-d', 'session.upload_progress.enabled=1',
                '-d', 'session.upload_progress.cleanup=0', '-d', 'session.upload_progress.freq=1',
                '-d', 'session.upload_progress.min_freq=0', '-d', 'display_errors=0',
                '-d', 'log_errors=1', '-d', 'session.use_strict_mode=0',
                '-S', '127.0.0.1:{port}', str(HERE / 'router.php')]
            workers[mode] = stack.enter_context(HTTPWorker(command, output / mode, bindings[source_mode],
                patch=patch if mode == 'patched' else None, catalog=catalog))
        vm = VMReplay(manifest['bridge'], {guard['id']: {'path': code, 'observations': []}})
        stack.callback(vm.close)
        vm_proof = prove_vm_summary({'expression': 'True', 'fields': {}}, dict(guard, rule_path=str(code)),
            {'cbmc': str(cbmc), 'timeout': 60, 'unwind': 10}, output / 'vm-summary')
        for case in corpus(output / 'corpus'):
            executions = {mode: worker.execute(case['request']) for mode, worker in workers.items()}
            outcomes = {mode: result['outcome'] for mode, result in executions.items()}
            replay = vm.check(executions['patched']['events'])
            fields = list(case['expected']) + ['progress_bytes']
            failures = compare(case, outcomes['baseline'], outcomes['patched'], outcomes['reference'], fields)
            base_or_reference = [f for f in failures if f.get('world') in ('baseline', 'reference')]
            if base_or_reference: raise AssertionError('normal baseline/reference contract failed: ' + json.dumps(base_or_reference))
            if replay['violations']: raise AssertionError(replay['violations'])
            for key in totals: totals[key] += replay[key]
            pairs.append((case['id'], outcomes['baseline'], outcomes['patched']))
            with gzip.open(output / ('case-%s.json.gz' % case['id']), 'wt') as file:
                json.dump({'case': case, 'executions': executions, 'replay': replay, 'failures': failures}, file)
            changed = [field for field in fields if outcomes['baseline'][field] != outcomes['patched'][field]]
            results.append({'case_id': case['id'], 'group': case['group'], 'size': case['size'],
                            'changed_fields': changed, 'failures': failures, 'blocks': replay['blocks'],
                            'outcomes': {mode: {k: v for k, v in result.items() if k != 'trace'} for mode, result in outcomes.items()}})
            print(json.dumps({'case': case['id'], 'group': case['group'], 'changed_fields': changed, 'blocks': replay['blocks']}), flush=True)
    coverage = summarize(pairs)
    (output / 'coverage.json').write_text(json.dumps(coverage, indent=2) + '\n')
    groups = {name: {'cases': sum(r['group'] == name for r in results),
                     'affected': sum(r['group'] == name and bool(r['changed_fields']) for r in results)}
              for name in ['form', 'plain_upload', 'progress_upload']}
    report = {'case': 'sixth existing PHP session upload-progress policy', 'seconds': time.monotonic() - begin,
        'groups': groups, 'monitor': totals, 'vm_summary': vm_proof,
        'source_scope': 'real PHP NTS built-in HTTP server; actual multipart/session callbacks',
        'symbolic_scope': 'installed VM bytecode summary only; PHP request-state differential symbolic execution not claimed',
        'coverage_scope': 'instrumented real ext/session/session.c in identical baseline/patched ELF',
        'coverage': {k: v for k, v in coverage.items() if k not in ('paths', 'edge_tests')},
        'cases': results, 'false_positive_detected': groups['progress_upload']['affected'] > 0,
        'upload_integrity_preserved': all(r['outcomes']['baseline']['files'] == r['outcomes']['patched']['files'] for r in results),
        'status_only_oracle_would_pass': all(r['outcomes']['patched']['http_status'] == 200 for r in results)}
    report['coverage_by_group'] = {name: {k: v for k, v in summarize([
        pair for pair, result in zip(pairs, results) if result['group'] == name]).items()
        if k not in ('paths', 'edge_tests')} for name in groups}
    paths = [HERE / 'run.py', HERE / 'router.php', HERE / 'build.py', HERE / 'trace_io.c',
             ROOT / 'tools/postdeploy/http_process.py', ROOT / 'tools/postdeploy/process.py',
             ROOT / 'tools/postdeploy/monitors.py', ROOT / 'tools/postdeploy/coverage.py',
             ROOT / 'runtime/frida/agent.js', code, patch, catalog]
    report['input_hashes'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert vm_proof['status'] == 'unsat'
    assert groups == {'form': {'cases': 6, 'affected': 0}, 'plain_upload': {'cases': 6, 'affected': 0},
                      'progress_upload': {'cases': 6, 'affected': 6}}, groups
    assert report['upload_integrity_preserved'] and report['status_only_oracle_would_pass']
    print(json.dumps({k: report[k] for k in ['groups', 'monitor', 'coverage', 'false_positive_detected']}, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, default=ROOT / 'build/postdeploy-php-session')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--cbmc', type=Path, required=True)
    args = p.parse_args()
    run(args.build.resolve(), args.output.resolve(), args.cbmc)
