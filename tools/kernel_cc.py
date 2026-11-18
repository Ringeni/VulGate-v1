"""Kbuild compiler interposer; substitute pinned objects before Kbuild postprocessing."""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4


def checksum(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def selected_source(arguments, replacements, directory):
    if '-c' not in arguments or '-E' in arguments or '-S' in arguments:
        return None
    matches = [str((directory / a).resolve()) for a in arguments if a.endswith('.c') and not a.startswith('-')]
    matches = [s for s in matches if s in replacements]
    if len(matches) > 1:
        raise ValueError('ambiguous kernel compilation input')
    return matches[0] if matches else None


def checked_run(command, **kwargs):
    return subprocess.run(command, check=True, timeout=180, **kwargs)


def main(config_path, arguments):
    config = json.loads(Path(config_path).read_text())
    compiler = config['compiler']
    compiler_argv0 = config.get('compiler_argv0', compiler)
    source = selected_source(arguments, config['replacements'], Path.cwd())
    if source is None:
        os.execv(compiler, [compiler_argv0, *arguments])
    # Import only for selected units: Kbuild also invokes CC for feature probes.
    sys.path.insert(0, config['repository'])
    from tools.verification.build import parse_unit
    from tools.verification.source import sha256 as digest
    replacement = config['replacements'][source]
    unit = parse_unit(Path(source), Path.cwd(), [compiler, *arguments], {})
    expected = replacement['snapshot']
    if (list(unit.preprocess_flags) != expected['build']['preprocess_flags'] or
            list(unit.native_flags) != expected['build']['native_flags'] or
            unit.source_argument != expected['build']['source_argument']):
        raise ValueError('Kbuild compilation options differ from verified recipe: ' + source)
    if checksum(compiler) != expected['build']['compiler']['sha256']:
        raise ValueError('native compiler changed')
    preprocessed = checked_run([config['goto_cc'], '--native-compiler', compiler, '-E',
                               *unit.preprocess_flags, unit.source_argument], capture_output=True).stdout
    if digest(preprocessed.decode('utf-8', errors='replace').encode('utf-8')) != expected['sha256']:
        raise ValueError('staged kernel preprocessing differs from verified bytes: ' + source)
    if arguments.count('-o') != 1:
        raise ValueError('Kbuild must use one separate -o argument')
    destination = (Path.cwd() / arguments[arguments.index('-o') + 1]).resolve()
    if not destination.is_relative_to(Path(config['build'])) or destination.suffix != '.o':
        raise ValueError('Kbuild object destination escapes the staged build')
    inputs = replacement['inputs']
    for path, pin in inputs.items():
        if checksum(path) != pin:
            raise ValueError('pinned replacement object changed: ' + path)
    # Generate the normal dependency file and retain native diagnostics. Kbuild
    # performs fixdep, objtool and its remaining rule after this process returns.
    checked_run([compiler_argv0, *arguments], executable=compiler)
    if len(inputs) == 1:
        shutil.copyfile(next(iter(inputs)), destination)
    else:
        checked_run([config['ld'], '-r', '-o', str(destination), *inputs])
    for path, pin in inputs.items():
        if checksum(path) != pin:
            raise ValueError('replacement object changed during injection')
    event = {'source': source, 'directory': str(Path.cwd()), 'arguments': arguments,
             'preprocessed_sha256': expected['sha256'], 'inputs': inputs,
             'object': str(destination), 'before_kbuild_postprocessing_sha256': checksum(destination)}
    event_path = Path(config['events']) / (uuid4().hex + '.json')
    event_path.write_text(json.dumps(event, indent=2) + '\n')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2:])
