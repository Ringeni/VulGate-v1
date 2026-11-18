"""Replay a pinned GCC object/library link with verified object substitutions."""
import json
import os
from pathlib import Path
import re

from tools.verification.build import expand_responses
from tools.verification.source import sha256
from tools.verification.spec import SpecificationError


def captured_recipe(manifest_path, pin, captured_output, runtime, selected, objects, compiler, link_mode):
    from tools.application_binding import check_assets, pinned_json

    if os.name != 'posix':
        raise SpecificationError('captured application linking runs on the original Linux build host')
    path = Path(manifest_path).resolve()
    manifest = pinned_json(path, pin, 'vulgate-build-capture')
    if manifest.get('status') != 'CAPTURED' or manifest.get('build_returncode') != 0:
        raise SpecificationError('captured build is incomplete')
    check_assets(path.parent, manifest['assets'])
    records = [json.loads((path.parent / name).read_text()) for name in manifest['assets']
               if name.startswith('records/') and name.endswith('.json')]
    output = str(Path(captured_output).resolve())
    links = [r for r in records if r.get('kind') == 'other' and r.get('output') == output]
    if len(links) != 1:
        raise SpecificationError('select exactly one captured executable link output')
    record = links[0]
    expected = {}
    for row in records:
        if row.get('state') != 'COMPLETE' or row.get('returncode') != 0 or row.get('environment'):
            raise SpecificationError('captured invocation is incomplete or uses an implicit environment')
        pins = {row['arguments'][0]: row['compiler_sha256'], **row['response_files'], **row['sources_before']}
        if row['sources_before'] != row['sources_after']:
            raise SpecificationError('source changed during captured build')
        if row.get('output_sha256'):
            pins[row['output']] = row['output_sha256']
        for name, checksum in pins.items():
            if name in expected and expected[name] != checksum:
                raise SpecificationError('conflicting captured input identities')
            expected[name] = checksum
    if any(not Path(name).is_file() or sha256(Path(name).read_bytes()) != checksum
           for name, checksum in expected.items()):
        raise SpecificationError('captured build input or output changed')
    if Path(record['arguments'][0]).resolve() != Path(compiler).resolve():
        raise SpecificationError('captured linker driver differs from runtime compiler')
    database = path.parent / 'compile_commands.json'
    replacements = {}
    snapshots = {Path(row['source']).resolve(): row for row in runtime['dependencies']['preprocessed']}
    for source, replacement in zip(selected, objects):
        provenance = snapshots[source]['build']['provenance']
        if (provenance.get('database') != str(database) or
                provenance.get('database_sha256') != sha256(database.read_bytes())):
            raise SpecificationError('selected runtime source does not use the pinned captured compilation database')
        rows = [r for r in records if r.get('kind') == 'compile-c' and r.get('sources') == [str(source)]
                and r.get('output') == provenance['record'].get('output')]
        if len(rows) != 1 or rows[0]['arguments'] != provenance['record']['arguments']:
            raise SpecificationError('selected runtime compilation recipe differs from captured build')
        replacements[rows[0]['output']] = str(replacement)
    directory = Path(record['directory'])
    response_pins = {}
    arguments = expand_responses(record['arguments'][1:], directory, response_pins)
    if response_pins != record['response_files']:
        raise SpecificationError('captured link response files changed')
    rewritten, seen, index, outputs = [], set(), 0, 0
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        if argument == '-o' or argument.startswith('-o'):
            if argument == '-o':
                if index == len(arguments):
                    raise SpecificationError('missing captured output')
                value = arguments[index]
                index += 1
            else:
                value = argument[2:]
            if str((directory / value).resolve()) != output:
                raise SpecificationError('captured output argument disagrees with its record')
            outputs += 1
        elif argument in ('-pie', '-no-pie'):
            if argument != ('-pie' if link_mode == 'pie' else '-no-pie'):
                raise SpecificationError('captured link mode disagrees with requested link mode')
        elif argument == '-L' or argument.startswith('-L'):
            if argument == '-L':
                if index == len(arguments):
                    raise SpecificationError('missing library directory')
                value = arguments[index]
                index += 1
            else:
                value = argument[2:]
            rewritten.extend(['-L', str((directory / value).resolve())])
        elif re.fullmatch(r'-l[A-Za-z0-9_+.-]+', argument) or argument in ('-pthread', '-rdynamic', '-Wl,-E'):
            rewritten.append(argument)
        elif not argument.startswith('-') and Path(argument).suffix == '.o':
            original = str((directory / argument).resolve())
            if original not in expected:
                raise SpecificationError('link object was not recorded in the completed build')
            if original in replacements:
                if original in seen:
                    raise SpecificationError('selected object appears more than once in captured link')
                seen.add(original)
            rewritten.append(replacements.get(original, original))
        else:
            raise SpecificationError('unsupported captured linker argument: ' + argument)
    if outputs != 1 or seen != set(replacements):
        raise SpecificationError('captured link omits a selected object or has ambiguous outputs')
    # Helpers precede libraries so ordinary left-to-right symbol resolution is
    # preserved. Other object and library arguments retain their original order.
    rewritten[0:0] = [str(p) for p in objects[len(selected):]]
    evidence = {'manifest': str(path), 'manifest_sha256': pin, 'captured_output': output,
                'link_record': record, 'replacements': replacements, 'arguments': rewritten,
                'captured_inputs': expected,
                'scope': 'Captured object bytes and compiler recipes; historical header contents are not attested.'}
    return rewritten, evidence
