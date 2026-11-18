"""Capture actual GCC/Clang build invocations without interpreting shell recipes.

``python -m tools.build_capture --output capture --cwd project --compiler gcc
-- make -j4 CC={cc}`` runs the build with a private compiler wrapper. The output
database records completed C compilations. It is build evidence, not a claim
that the verification backend supports each command or the whole application.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
from uuid import uuid4

from tools.verification.build import expand_responses


SEMANTIC_ENV = ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH',
                'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH', 'DEPENDENCIES_OUTPUT',
                'SUNPRO_DEPENDENCIES', 'SDKROOT')


def checksum(path):
    with Path(path).open('rb') as stream:
        digest = sha256()
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(data)
    return digest.hexdigest()


def save(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    os.replace(temporary, path)


def describe(arguments, directory):
    responses = {}
    args = expand_responses(arguments, directory, responses)
    sources, output, index = [], None, 0
    operands = {'-o', '-I', '-isystem', '-iquote', '-idirafter', '-include', '-imacros',
                '--sysroot', '-isysroot', '-D', '-U', '-x', '-MF', '-MT', '-MQ', '-MJ',
                '-B', '-Xassembler', '-Xpreprocessor', '-Xlinker', '-aux-info'}
    language = None
    while index < len(args):
        arg = args[index]
        index += 1
        if arg in operands:
            if index == len(args):
                raise ValueError('missing operand: ' + arg)
            value = args[index]
            index += 1
            if arg == '-o':
                output = str((directory / value).resolve())
            elif arg == '-x':
                language = value
        elif arg.startswith('-o') and len(arg) > 2:
            output = str((directory / arg[2:]).resolve())
        elif not arg.startswith('-') and (Path(arg).suffix in ('.c', '.i') or language == 'c'):
            sources.append(str((directory / arg).resolve()))
    kind = 'compile-c' if '-c' in args and sources else 'other'
    if kind == 'compile-c' and (len(sources) != 1 or '-E' in args or '-S' in args):
        raise ValueError('captured C compilation must have one source and produce an object')
    if kind == 'compile-c' and output is None:
        output = str(directory / (Path(sources[0]).stem + '.o'))
    return {'kind': kind, 'sources': sources, 'output': output, 'response_files': responses}


def invoke(configuration, arguments):
    config = json.loads(Path(configuration).read_text(encoding='utf-8'))
    directory = Path.cwd().resolve()
    record = {'schema': 1, 'directory': str(directory),
              'arguments': [config['compiler'], *arguments], 'started_ns': time.time_ns(),
              'environment': {name: os.environ[name] for name in SEMANTIC_ENV if os.environ.get(name)}}
    destination = Path(config['records']) / (uuid4().hex + '.json')
    try:
        record.update(describe(arguments, directory))
        record['compiler_sha256'] = checksum(config['compiler'])
        record['sources_before'] = {name: checksum(name) for name in record['sources']}
        record['state'] = 'STARTED'
        save(destination, record)
        process = subprocess.run(record['arguments'])
        record['returncode'] = process.returncode
        record['sources_after'] = {name: checksum(name) for name in record['sources']}
        record['output_sha256'] = (checksum(record['output']) if process.returncode == 0 and
                                  record['output'] and Path(record['output']).is_file() else None)
        record['completed_ns'] = time.time_ns()
        record['state'] = 'COMPLETE'
        save(destination, record)
        return process.returncode if process.returncode >= 0 else 128 - process.returncode
    except (OSError, ValueError) as exc:
        record.update(state='CAPTURE_FAILED', reason=str(exc))
        save(destination, record)
        print('build capture: ' + str(exc), file=sys.stderr)
        return 125


def collect(output, build_returncode):
    output = Path(output)
    records = [json.loads(path.read_text(encoding='utf-8')) for path in sorted((output / 'records').glob('*.json'))]
    failures, entries, destinations = [], [], set()
    if build_returncode != 0:
        failures.append('build command failed: ' + str(build_returncode))
    if not records:
        failures.append('no compiler invocations were captured; perform a fresh configured build')
    for record in records:
        if record.get('state') != 'COMPLETE' or record.get('returncode') != 0:
            failures.append('compiler invocation did not complete successfully')
            continue
        if record['environment']:
            failures.append('compiler environment must be expressed as explicit arguments: ' +
                            ', '.join(record['environment']))
        expected = {record['arguments'][0]: record['compiler_sha256'], **record['response_files'],
                    **record['sources_before']}
        if record['sources_before'] != record['sources_after']:
            failures.append('source changed during compilation')
        if record['output'] and record['output_sha256']:
            expected[record['output']] = record['output_sha256']
        for path, pin in expected.items():
            if not Path(path).is_file() or checksum(path) != pin:
                failures.append('captured input/output changed: ' + path)
        if record['kind'] != 'compile-c':
            continue
        if not record['output_sha256']:
            failures.append('C compilation did not produce a regular output file')
        if record['output'] in destinations:
            failures.append('object was compiled more than once: ' + record['output'])
        destinations.add(record['output'])
        entries.append({'directory': record['directory'], 'file': record['sources'][0],
                        'output': record['output'], 'arguments': record['arguments']})
    if not entries:
        failures.append('no C object compilation was captured')
    entries.sort(key=lambda row: (row['file'], row['output']))
    if not failures:
        save(output / 'compile_commands.json', entries)
    elif (output / 'compile_commands.json').exists():
        (output / 'compile_commands.json').unlink()
    report = {'schema': 1, 'kind': 'vulgate-build-capture',
              'status': 'CAPTURED' if not failures else 'INCOMPLETE',
              'build_returncode': build_returncode, 'invocations': len(records),
              'c_compilations': len(entries), 'reasons': sorted(set(failures)),
              'verification_qualified': False,
              'scope': 'Completed build command and captured compiler arguments; header/configuration and proof binding require verification preprocessing.',
              'assets': {p.relative_to(output).as_posix(): checksum(p)
                         for p in output.rglob('*') if p.is_file() and p.name != 'manifest.json'}}
    save(output / 'manifest.json', report)
    return report


def capture(output, directory, compiler, command):
    if os.name != 'posix':
        raise ValueError('run build capture on Linux, including inside WSL')
    output, directory = Path(output).resolve(), Path(directory).resolve()
    if output.exists():
        raise ValueError('capture output must be a new directory')
    if not directory.is_dir() or not command or not any('{cc}' in arg for arg in command):
        raise ValueError('provide a build directory and argv containing the {cc} compiler placeholder')
    resolved = shutil.which(compiler)
    if resolved is None:
        raise ValueError('compiler not found: ' + compiler)
    # Keep the driver's spelling; symlink names can select compiler behavior.
    compiler = os.path.abspath(resolved)
    output.mkdir(parents=True)
    (output / 'records').mkdir()
    config = output / 'wrapper.json'
    save(config, {'compiler': compiler, 'records': str(output / 'records')})
    wrapper = output / 'cc'
    repository = str(Path(__file__).resolve().parents[1])
    # A shell launcher permits Python/repository paths with spaces. It invokes
    # a fixed script; compiler arguments are forwarded literally via "$@".
    driver = output / 'driver.py'
    driver.write_text('import sys\nsys.path.insert(0, ' + repr(repository) + ')\n'
                      'from tools.build_capture import invoke\n'
                      'raise SystemExit(invoke(' + repr(str(config)) + ', sys.argv[1:]))\n', encoding='utf-8')
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' +
                       shlex.quote(str(driver)) + ' "$@"\n', encoding='utf-8')
    wrapper.chmod(0o755)
    argv = [arg.replace('{cc}', str(wrapper)) for arg in command]
    save(output / 'build.json', {'directory': str(directory), 'arguments': argv,
                               'capture_source_sha256': checksum(__file__)})
    with (output / 'build.log').open('wb') as stream:
        process = subprocess.run(argv, cwd=directory, stdout=stream, stderr=subprocess.STDOUT)
    return collect(output, process.returncode)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cwd', required=True, type=Path)
    parser.add_argument('--compiler', default='gcc')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        report = capture(args.output, args.cwd, args.compiler, command)
        print(json.dumps({k: v for k, v in report.items() if k != 'assets'}, indent=2))
        return 0 if report['status'] == 'CAPTURED' else 1
    except (OSError, ValueError) as exc:
        print(json.dumps({'status': 'INCOMPLETE', 'reason': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
