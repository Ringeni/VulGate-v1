"""CBMC backend. Raw solver facts are retained independently of release gates."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from .source import sha256
from .spec import SpecificationError
from .typed_transport import (FULL, LEGACY, TransportError, canonical, check_mode, compare_models,
                              inspection_model, strict_loads, transport_view)


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


class BackendError(RuntimeError):
    pass


def configure_object_encoding(functions, symbols, object_bits):
    """Keep CBMC's allocation bound consistent before shadow instrumentation.

    CBMC regenerates __CPROVER_initialize when its max_malloc_size symbol does
    not match the requested pointer encoding. Doing that after our transform
    discards global write tracking. Update both representations of this one
    backend-owned constant first; use the compiled architecture, not host sizes.
    """
    from .spec import SpecificationError
    try:
        pointer = symbols['__CPROVER_architecture_pointer_width']['value']
        while pointer['id'] == 'typecast':
            pointer = pointer['sub'][0]
        if pointer['id'] != 'constant' or pointer['namedSub']['type']['id'] not in ('signedbv', 'unsignedbv'):
            raise ValueError('unsupported pointer-width constant')
        pointer_width = int(pointer['namedSub']['value']['id'], 16)
        if type(object_bits) is not int or not 1 <= object_bits <= 32 or object_bits >= pointer_width:
            raise SpecificationError('object_bits must be in 1..32 and smaller than the compiled pointer width')
        bound = 1 << (pointer_width - object_bits - 1)
        symbol = symbols['__CPROVER_max_malloc_size']
        if (symbol['type']['id'] != 'unsignedbv' or
                bound >= 1 << int(symbol['type']['namedSub']['width']['id'])):
            raise ValueError('unsupported allocation-bound type')
        initialize = next(f for f in functions if f['name'] == '__CPROVER_initialize')
        assignments = [i for i in initialize['instructions'] if i['instructionId'] == 'ASSIGN' and
                       i['code']['sub'][0].get('namedSub', {}).get('identifier', {}).get('id') == '__CPROVER_max_malloc_size']
        if len(assignments) != 1:
            raise ValueError('expected exactly one allocation-bound initialization')
        value = {'id': 'constant', 'namedSub': {'type': deepcopy(symbol['type']),
                 'value': {'id': format(bound, 'X')}, '#C_no_nondet_initialization': {'id': '1'}}}
        symbol['value'] = value
        assignments[0]['code']['sub'][1] = deepcopy(value)
        return {'object_bits': object_bits, 'pointer_width': pointer_width, 'max_malloc_size': bound}
    except (KeyError, IndexError, TypeError, ValueError, StopIteration) as exc:
        raise SpecificationError(f'cannot configure backend pointer encoding: {exc}') from exc


def decode_messages(process):
    if process.timed_out:
        raise BackendError("backend timeout")
    try:
        payload = strict_loads(process.stdout)
    except (ValueError, TypeError) as exc:
        raise BackendError("backend did not produce complete JSON") from exc
    if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
        raise BackendError("unsupported backend JSON envelope")
    return payload


def output_diagnostics(stdout):
    """Read complete message objects from an array prefix, never proof results.

    Stop at the first damaged element instead of searching for later/nested
    objects. A closed JSON envelope describes output syntax, not proof completion.
    Phase text records the last observation, not the phase at process termination.
    """
    diagnostics = {"output_complete": False, "last_observed_phase": None,
                   "backend_warnings": [], "backend_errors": [], "last_message": None,
                   "initialization_backend_warnings": []}
    if not isinstance(stdout, str):
        return diagnostics
    text = stdout.lstrip(" \t\r\n")
    if not text.startswith("["):
        return diagnostics

    def invalid_constant(value):
        raise ValueError("non-JSON constant: " + value)

    decoder = json.JSONDecoder(parse_constant=invalid_constant)
    index = 1
    phases = ("Starting Bounded Model Checking", "Starting symbolic execution",
              "Runtime Symex:", "size of program expression:", "converting SSA",
              "Passing problem to ", "Runtime decision procedure:")
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    if text[index:index + 1] == "]":
        diagnostics["output_complete"] = not text[index + 1:].strip(" \t\r\n")
        return diagnostics
    while text[index:index + 1] == "{":
        try:
            item, index = decoder.raw_decode(text, index)
        except (ValueError, RecursionError):
            break
        # Only direct, complete message objects contribute diagnostics. A result
        # object or a nested message cannot supply properties or solver status.
        message, kind = item.get("messageText"), item.get("messageType")
        if isinstance(message, str) and isinstance(kind, str):
            diagnostics["last_message"] = {"messageType": kind, "messageText": message}
            if kind in ("WARNING", "ERROR"):
                diagnostics["backend_warnings" if kind == "WARNING" else "backend_errors"].append(message)
            if kind == "WARNING" and "Shadow memory:" in message and "mux size" not in message:
                diagnostics["initialization_backend_warnings"].append(message)
            if kind == "STATUS-MESSAGE" and message.startswith(phases):
                diagnostics["last_observed_phase"] = message
        while index < len(text) and text[index] in " \t\r\n":
            index += 1
        if text[index:index + 1] == "]":
            diagnostics["output_complete"] = not text[index + 1:].strip(" \t\r\n")
            break
        if text[index:index + 1] != ",":
            break
        index += 1
        while index < len(text) and text[index] in " \t\r\n":
            index += 1
    return diagnostics


def classify(process, target_descriptions, initialization_evidence=None):
    """Do not interpret exit 0, empty results or incomplete proofs as success."""
    report = {"status": "UNKNOWN", "properties": [], "target": "UNKNOWN",
              "contracts_and_runtime_checks": "UNKNOWN", "completeness": "UNKNOWN",
              "initialization": "UNKNOWN", "reasons": [], "reachability": {},
              **output_diagnostics(process.stdout)}
    if process.timed_out:
        report["reasons"].append("solver timeout")
        return report
    if process.returncode not in (0, 10):
        report["reasons"].append(f"backend exit {process.returncode}")
        return report
    if not report["output_complete"]:
        report["reasons"].append("backend did not produce complete JSON")
        return report
    try:
        messages = decode_messages(process)
    except BackendError as exc:
        report["reasons"].append(str(exc))
        return report
    results = [r for item in messages for r in item.get("result", [])]
    if not results or not any(item.get("cProverStatus") in ("success", "failure") for item in messages):
        report["reasons"].append("missing properties or final solver status")
        return report
    errors = [item.get("messageText", "backend error") for item in messages if item.get("messageType") == "ERROR"]
    if errors:
        report["reasons"].extend(errors)
        return report
    report["properties"] = results
    incomplete, targets, contracts, initialization, guarded_unsupported = [], [], [], [], []
    found_targets = set()
    for item in results:
        description, name, status = item.get("description", ""), item.get("property", ""), item.get("status")
        if status not in ("SUCCESS", "FAILURE"):
            incomplete.append(f"property {name}: {status}")
        if ".unwind." in name or ".recursion." in name or name.endswith(".recursion") or ".no-body." in name:
            if status != "SUCCESS":
                incomplete.append(f"incomplete execution semantics: {name}")
        elif description.startswith("__VG_UNMODELED_INIT:"):
            guarded_unsupported.append(item)
        elif ".uninitialized_local." in name or description == "vulgate.initialized_read":
            initialization.append(item)
        elif description.startswith("__VG_REACH_"):
            current = {"FAILURE": "REACHABLE", "SUCCESS": "UNREACHABLE"}.get(status, "UNKNOWN")
            previous = report['reachability'].get(description, 'UNREACHABLE')
            report['reachability'][description] = ('REACHABLE' if 'REACHABLE' in (previous, current) else
                                                   'UNKNOWN' if 'UNKNOWN' in (previous, current) else 'UNREACHABLE')
        elif description in target_descriptions:
            found_targets.add(description)
            targets.append(item)
        else:
            contracts.append(item)
    missing = set(target_descriptions) - found_targets
    if missing:
        incomplete.append("missing target descriptions: " + ", ".join(sorted(missing)))
    report["completeness"] = "UNKNOWN" if incomplete else "COMPLETE_FOR_HARNESS"
    if incomplete:
        report["reachability"] = {name: "UNKNOWN" if value == "UNREACHABLE" else value
                                  for name, value in report["reachability"].items()}
    report["reasons"].extend(incomplete)
    for key, properties in (("target", targets), ("contracts_and_runtime_checks", contracts)):
        report[key] = ("REFUTED" if any(p.get("status") == "FAILURE" for p in properties)
                       else "UNKNOWN" if incomplete else "PROVED_FOR_HARNESS")
    report["initialization_diagnostics"] = initialization
    shadow_warnings = report["initialization_backend_warnings"]
    report["initialization_evidence"] = initialization_evidence
    report["initialization_backend_warnings"] = shadow_warnings
    expected_unsupported = {p["property"] for p in (initialization_evidence or {}).get("guarded_unsupported", [])}
    unsupported_statuses = {}
    for prop in guarded_unsupported:
        unsupported_statuses.setdefault(prop["description"], []).append(prop["status"])
    # Static loop expansion can give one marker several property IDs. Every
    # copy must be unreachable; one successful copy cannot hide a reachable one.
    proved_unreachable = {description for description, statuses in unsupported_statuses.items()
                          if all(status == "SUCCESS" for status in statuses)}
    unresolved_effects = expected_unsupported - proved_unreachable
    unexpected_effects = set(unsupported_statuses) - expected_unsupported
    report["initialization_unsupported_effects"] = guarded_unsupported
    report["initialization_unrecorded_effects"] = sorted(unexpected_effects)
    if unexpected_effects:
        report['reasons'].append('unsupported initialization markers are absent from instrumentation evidence')
    marker = (initialization_evidence or {}).get('global_initialization_marker')
    marker_present = marker is None or any(p.get('description') == marker and p.get('status') == 'SUCCESS' for p in results)
    if not marker_present:
        report['reasons'].append('global initialization instrumentation was not preserved by the backend')
    if initialization_evidence is None or initialization_evidence.get("unsupported") or incomplete or shadow_warnings or unresolved_effects or unexpected_effects or not marker_present:
        report["initialization"] = "UNKNOWN"
        report["reasons"].append("initialization evidence is incomplete")
    else:
        report["initialization"] = ("REFUTED" if any(p["status"] == "FAILURE" for p in initialization)
                                     else "PROVED_FOR_HARNESS")
    deferred_writes = (initialization_evidence or {}).get('deferred_bit_field_writes', [])
    imprecise_writes = [item for item in deferred_writes
                       if report['reachability'].get(item['marker']) != 'UNREACHABLE']
    if deferred_writes:
        report['initialization_precision'] = {
            'method': 'under-approximate initialized storage after nonvolatile bit-field writes',
            'deferred_writes': len(deferred_writes), 'not_proved_unreachable': len(imprecise_writes),
            'may_under_approximate_initialized_storage': bool(imprecise_writes)}
    if report['initialization'] == 'REFUTED' and imprecise_writes:
        report['initialization'] = 'UNKNOWN'
        report['reasons'].append('failed initialization reads may depend on deferred bit-field writes')
    statuses = [report[key] for key in ("target", "contracts_and_runtime_checks", "initialization")]
    report["status"] = ("REFUTED" if "REFUTED" in statuses else
                        "UNKNOWN" if "UNKNOWN" in statuses else "PROVED_FOR_HARNESS")
    return report


class CBMC:
    def __init__(self, toolchain, task, output, *, transport_mode=FULL):
        self.toolchain, self.task, self.output = toolchain, task, Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        # Repeated policy checks may reuse their output/cache directory. Keep
        # command records and complete byte sidecars from earlier invocations,
        # including orphaned sidecars left before a command record was saved.
        self.log_index = max((int(match.group(1))
            for path in self.output.glob('command-*')
            if (match := re.fullmatch(r'command-([0-9]+)(?:\.json|\.stdout\.json|\.stderr\.log)', path.name))),
            default=0)
        self.build_semantic_options = []
        self.compiler_queries = []
        self.environment_evidence = []
        check_mode(transport_mode)
        self.transport_mode = transport_mode
        self.transport_tools = None
        self.inspection_evidence = []
        self.transport_roundtrips = []

    def command(self, tool, args, *, cwd=None, external=False):
        method = self.toolchain.run_external if external else self.toolchain.run
        result = method(tool, args, self.task.timeout, **({"cwd": cwd} if cwd is not None else {}))
        self.log_index += 1
        save_json(self.output / f"command-{self.log_index:03}.json",
                  {**result.to_dict(), "working_directory": str(cwd) if cwd is not None else None})
        return result

    def require(self, tool, args, **options):
        result = self.command(tool, args, **options)
        if result.timed_out or result.returncode != 0:
            raise BackendError(f"{tool} failed: {result.stdout[-3000:]} {result.stderr[-1000:]}")
        return result

    def preprocess(self):
        if self.task.compilation_database is not None or self.task.units:
            return self.preprocess_build()
        result = []
        for index, source in enumerate(self.task.sources):
            flags = ["-I" + self.toolchain.path(p) for p in self.task.include_dirs]
            flags += ["-D" + d for d in self.task.defines]
            process = self.require("goto-cc", ["-E", *flags, source])
            data = process.stdout.encode("utf-8")
            if not data.strip():
                raise BackendError("preprocessor emitted empty translation unit")
            destination = self.output / f"unit-{index:03}.i"
            destination.write_bytes(data)
            result.append({"source": source, "path": destination, "sha256": sha256(data)})
        return result

    def preprocess_build(self):
        from .build import load_units
        from .build_options import call_profile
        from .build_semantics import CONTEXT_OPTIONS
        result, compilers = [], {}
        for index, unit in enumerate(load_units(self.task)):
            if (self.toolchain.wsl_distribution and unit.provenance.get("database") and
                    unit.provenance.get("command_syntax") == "windows"):
                raise BackendError("a Windows compilation database requires a native Windows backend; provide the WSL build database")
            compiler_key = (unit.compiler, unit.directory)
            if compiler_key not in compilers:
                compilers[compiler_key] = self.toolchain.native_compiler(unit.compiler, unit.directory)
            compiler = compilers[compiler_key]
            flags = list(unit.preprocess_flags)
            flags.extend("-I" + self.toolchain.path(p) for p in self.task.include_dirs)
            flags.extend("-D" + d for d in self.task.defines)
            source_argument = unit.source_argument
            if (not unit.provenance.get("database") and self.toolchain.wsl_distribution and
                    (":" in source_argument or "\\" in source_argument)):
                source_argument = self.toolchain.path(unit.source)
            process = self.require("goto-cc", ["--native-compiler", compiler["executable"], "-E", *flags, source_argument],
                                   cwd=unit.directory)
            data = process.stdout.encode("utf-8")
            if not data.strip():
                raise BackendError("preprocessor emitted empty translation unit")
            destination = self.output / f"unit-{index:03}.i"
            destination.write_bytes(data)
            abi = self.check_native_abi(unit, compiler, index)
            build = {"directory": str(unit.directory), "source_argument": source_argument,
                     "compiler": compiler, "preprocess_flags": flags, "frontend_flags": list(unit.frontend_flags),
                     "native_flags": list(unit.native_flags), "native_call_profile": call_profile(unit.native_flags),
                     "semantic_options": [flag for flag in flags if flag in CONTEXT_OPTIONS],
                     "abi": abi, "abi_scope": "fundamental types and representative aggregate layout, not machine-code correspondence",
                     "provenance": unit.provenance}
            result.append({"source": unit.source, "path": destination, "sha256": sha256(data), "build": build})
        if any(s["build"]["abi"] != result[0]["build"]["abi"] for s in result[1:]):
            raise BackendError("translation units have incompatible ABI configurations for the shared GOTO model")
        if any(s['build']['native_call_profile'] != result[0]['build']['native_call_profile'] for s in result[1:]):
            raise BackendError('translation units have incompatible native stack calling conventions')
        save_json(self.output / "build.json", [{"source": str(s["source"]), **s["build"]} for s in result])
        return result

    def check_native_abi(self, unit, compiler, index):
        from .build_options import X86_64_OPTIONS
        types = {"pointer": "void *", "bool": "_Bool", "char": "char", "short": "short", "int": "int",
                 "long": "long", "long_long": "long long", "float": "float", "double": "double", "long_double": "long double"}
        expressions = {f"{key}_{measure}": f"{operator}({value})" for key, value in types.items()
                       for measure, operator in (("size", "sizeof"), ("alignment", "__alignof__"))}
        structures = [f"struct __vulgate_layout_{key} {{ char prefix; {value} value; }};" for key, value in types.items()]
        for key in types:
            expressions[f"{key}_member_offset"] = f"__builtin_offsetof(struct __vulgate_layout_{key}, value)"
            expressions[f"{key}_struct_size"] = f"sizeof(struct __vulgate_layout_{key})"
        probe = self.output / f"abi-{index:03}.i"
        probe.write_text("\n".join([*structures, *[f"const unsigned __vulgate_abi_{key} = {expression};"
                                                  for key, expression in expressions.items()]]), encoding="utf-8")
        binary = probe.with_suffix(".goto")
        self.require("goto-cc", ["--native-compiler", compiler["executable"], *unit.frontend_flags, "-c", probe, "-o", binary], cwd=unit.directory)
        messages = decode_messages(self.require("goto-instrument", ["--show-symbol-table", "--json-ui", binary]))
        symbols = next((item["symbolTable"] for item in messages if "symbolTable" in item), {})

        def integer(symbol):
            value = symbols.get(symbol, {}).get("value", {})
            while value.get("id") == "typecast" and len(value.get("sub", [])) == 1:
                value = value["sub"][0]
            if value.get("id") != "constant":
                raise BackendError(f"ABI probe did not yield a constant for {symbol}")
            return int(value["namedSub"]["value"]["id"], 16)

        abi = {key: integer("__vulgate_abi_" + key) for key in expressions}
        for name in ("char_width", "char_is_unsigned", "wchar_t_width", "wchar_t_is_unsigned", "endianness"):
            abi[name] = integer("__CPROVER_architecture_" + name)
        native = [*structures, *[f"typedef char __vulgate_check_{key}[({expression}) == {abi[key]} ? 1 : -1];"
                                for key, expression in expressions.items()]]
        native.extend([
            f"typedef char __vulgate_check_char_bits[__CHAR_BIT__ == {abi['char_width']} ? 1 : -1];",
            f"typedef char __vulgate_check_char_sign[((char)-1 > 0) == {abi['char_is_unsigned']} ? 1 : -1];",
            f"typedef char __vulgate_check_wchar[sizeof(__WCHAR_TYPE__) * __CHAR_BIT__ == {abi['wchar_t_width']} ? 1 : -1];",
            f"typedef char __vulgate_check_wchar_sign[((__WCHAR_TYPE__)-1 > 0) == {abi['wchar_t_is_unsigned']} ? 1 : -1];",
        ])
        endian = {1: "__ORDER_LITTLE_ENDIAN__", 2: "__ORDER_BIG_ENDIAN__"}.get(abi["endianness"])
        if endian is None:
            raise BackendError("unsupported GOTO target endianness")
        native.append(f"#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != {endian}\n#error ABI endianness mismatch\n#endif")
        if any(flag in X86_64_OPTIONS for flag in unit.native_flags):
            native.append('#if !defined(__x86_64__) || defined(__ILP32__)\n#error x86-64 LP64 code-generation profile required\n#endif')
        check_file = self.output / f"abi-{index:03}-native.c"
        check_file.write_text("\n".join(native) + "\n", encoding="utf-8")
        # Probe the compiler's type model without application headers/macros.
        # Those have already been applied to the actual source snapshot.
        checked = self.command(compiler["executable"], [*unit.native_flags, "-fsyntax-only", "-x", "c", check_file], cwd=unit.directory, external=True)
        if checked.returncode != 0 or checked.timed_out:
            raise BackendError(f"native/GOTO ABI qualification failed: {checked.stderr[-3000:]}")
        return abi

    def compile(self, files, name="program", *, units=None):
        from .compiler_queries import QUERIES, guard_compiler_queries, source_references
        binary = self.output / (name + ".goto")
        self.compiler_queries = []
        sources = [file.read_bytes() for file in files]
        references = source_references(sources, self.task.entry) if any(
            query in source for source in sources for query in QUERIES) else None
        guarded = []
        for index, (file, original) in enumerate(zip(files, sources)):
            data, sites = guard_compiler_queries(original, str(file))
            self.compiler_queries.extend({**site, 'source': str(file),
                'source_reference_reachable': None if references is None else site['function'] in references} for site in sites)
            if data != original:
                transformed = self.output / f'{name}-native-query-{index:03}.i'
                transformed.write_bytes(data)
                guarded.append(transformed)
            else:
                guarded.append(file)
        files = guarded
        save_json(self.output / (name + '.compiler-queries.json'), self.compiler_queries)
        self.build_semantic_options = sorted({option for unit in (units or [])
                                              for option in unit.get('build', {}).get('semantic_options', [])})
        configured = units and all("build" in unit for unit in units)
        if configured:
            objects = []
            for index, file in enumerate(files):
                build = units[index if index < len(units) else 0]["build"]
                compiler, flags = build["compiler"]["executable"], build["frontend_flags"]
                if index >= len(units):
                    helper = self.output / "verification-instrumentation.i"
                    helper.write_bytes(file.read_bytes())
                    file = helper
                obj = self.output / f"{name}-{index:03}.goto"
                self.require("goto-cc", ["--native-compiler", compiler, *flags, "-c", file, "-o", obj], cwd=Path(build["directory"]))
                objects.append(obj)
            first = units[0]["build"]
            self.require("goto-cc", ["--native-compiler", first["compiler"]["executable"], *first["frontend_flags"],
                                     *objects, "--function", self.task.entry, "-o", binary])
        else:
            self.require("goto-cc", [*files, "--function", self.task.entry, "-o", binary])
        return binary

    def bind_transport_tools(self):
        versions = self.toolchain.versions()
        identities = {name: versions.get(name, {}) for name in ('goto-instrument', 'symtab2gb')}
        for name, identity in identities.items():
            digest = identity.get('sha256', '')
            if (not isinstance(digest, str) or len(digest) != 64 or
                    any(c not in '0123456789abcdef' for c in digest) or
                    not isinstance(identity.get('executable'), str) or not identity['executable']):
                raise BackendError('cannot bind typed transport executable: ' + name)
        if self.transport_tools is not None and canonical(identities) != canonical(self.transport_tools):
            raise BackendError('typed transport executable identity changed during preparation')
        self.transport_tools = deepcopy(identities)
        return identities

    def inspect(self, binary):
        evidence = {'binary': str(binary), 'mode': self.transport_mode, 'status': 'FAILED',
                    'first_command': self.log_index + 1}
        try:
            evidence['tools'] = self.bind_transport_tools()
            evidence['binary_sha256_before'] = file_sha256(binary)
            # Ordinary show modes run instrumentation, including property
            # relabeling and failed-symbol insertion. Full transport must see
            # the binary exactly as imported, before either transformation.
            suffix = '-raw' if self.transport_mode == FULL else ''
            if self.transport_mode == FULL:
                from .typed_json_stream import stream_functions
                function_file = self.export_to_file(binary, '--show-goto-functions-raw')
                functions = []
                bodies = list(stream_functions(function_file, messages=functions))
                for group in functions:
                    if 'functions' in group:
                        group['functions'] = bodies
                symbol_file = self.export_to_file(binary, '--show-symbol-table-raw')
                symbols = strict_loads(symbol_file.read_text(encoding='utf-8'))
            else:
                functions = decode_messages(self.require("goto-instrument", ["--show-goto-functions" + suffix, "--json-ui", binary]))
                symbols = decode_messages(self.require("goto-instrument", ["--show-symbol-table" + suffix, "--json-ui", binary]))
            self.bind_transport_tools()
            evidence['binary_sha256_after'] = file_sha256(binary)
            if evidence['binary_sha256_before'] != evidence['binary_sha256_after']:
                raise BackendError('inspected model binary changed during export')
            functions, symbols, metadata = inspection_model(functions, symbols, mode=self.transport_mode)
            evidence.update(metadata, status='VALIDATED')
            return functions, symbols
        except (BackendError, SpecificationError, OSError, ValueError, RecursionError) as exc:
            evidence['reason'] = str(exc)
            raise BackendError('typed model inspection failed: ' + str(exc)) from exc
        finally:
            evidence['last_command'] = self.log_index
            self.inspection_evidence.append(evidence)
            save_json(self.output / f'inspection-{len(self.inspection_evidence):03}.json', evidence)

    def export_to_file(self, binary, option):
        self.log_index += 1
        prefix = self.output / f'command-{self.log_index:03}'
        stdout, stderr = Path(str(prefix) + '.stdout.json'), Path(str(prefix) + '.stderr.log')
        process = self.toolchain.run_to_files('goto-instrument', [option, '--json-ui', binary],
                                             stdout, stderr, self.task.timeout)
        record = {**process.to_dict(), 'working_directory': None,
                  'stdout_sha256': file_sha256(stdout), 'stderr_sha256': file_sha256(stderr),
                  'stdout_bytes': stdout.stat().st_size, 'stderr_bytes': stderr.stat().st_size,
                  'output_storage': 'COMPLETE_BYTE_SIDECARS'}
        save_json(Path(str(prefix) + '.json'), record)
        if process.timed_out or process.returncode != 0:
            raise BackendError(f'file-backed model export failed: {option}; see {prefix}.json')
        return stdout

    def import_model(self, functions, symbols, binary, *, name):
        """Both import sites require actual re-export equality and native model validation."""
        functions_file = self.output / (name + '.functions.json')
        symbols_file = self.output / (name + '.symbols.json')
        evidence = {'status': 'FAILED', 'mode': self.transport_mode,
                    'full_typed': self.transport_mode == FULL, 'binary': str(binary),
                    'functions_file': str(functions_file), 'symbols_file': str(symbols_file),
                    'first_command': self.log_index + 1}
        def verify_transport_files(stage):
            for key, path in (('functions', functions_file), ('symbols', symbols_file)):
                observed = file_sha256(path)
                evidence[key + '_sha256_' + stage] = observed
                if observed != evidence[key + '_sha256']:
                    raise BackendError('transport payload changed during import/export: ' + key)
        try:
            function_payload, symbol_payload = transport_view(functions, symbols, mode=self.transport_mode)
            save_json(functions_file, function_payload)
            save_json(symbols_file, symbol_payload)
            # Do not retain a second complete transformed model while loading
            # the actual imported model. Both serialized views are already on
            # disk and are revalidated by their byte hashes below.
            del function_payload, symbol_payload
            evidence['functions_sha256'] = file_sha256(functions_file)
            evidence['symbols_sha256'] = file_sha256(symbols_file)
            evidence['tools'] = self.bind_transport_tools()
            self.require('symtab2gb', [symbols_file, '--goto-functions', functions_file, '--out', binary])
            verify_transport_files('after_import')
            # inspect re-exports the actual imported binary. It is not a second
            # copy of the intended Python objects or an IREP-only round trip.
            actual_functions, actual_symbols = self.inspect(binary)
            verify_transport_files('after_export')
            evidence['inspection'] = len(self.inspection_evidence)
            evidence['binary_sha256'] = self.inspection_evidence[-1]['binary_sha256_after']
            evidence.update(compare_models(functions, symbols, actual_functions, actual_symbols,
                                           mode=self.transport_mode))
            if evidence['status'] != 'MATCH':
                raise BackendError('whole-model import/export mismatch at ' + evidence['first_difference']['path'])
            evidence['roundtrip_status'] = 'MATCH'
            # Serialization equality alone also preserves a malformed model.
            # This native validation-only option checks types and GOTO structure
            # immediately after loading, without rewriting or saving the input.
            evidence['model_validation'] = {'status': 'FAILED', 'command': self.log_index + 1,
                                            'option': '--validate-goto-binary'}
            self.require('goto-instrument', [binary, '--validate-goto-binary', '--json-ui'])
            evidence['binary_sha256_after_validation'] = file_sha256(binary)
            if evidence['binary_sha256_after_validation'] != evidence['binary_sha256']:
                raise BackendError('imported binary changed during native model validation')
            self.bind_transport_tools()
            evidence['model_validation']['status'] = 'VALID'
        except (BackendError, SpecificationError, OSError, ValueError, RecursionError) as exc:
            if evidence['status'] == 'MATCH':
                evidence['status'] = 'FAILED'
            evidence['reason'] = str(exc)
            raise BackendError('typed transport preparation failed: ' + str(exc)) from exc
        finally:
            evidence['last_command'] = self.log_index
            self.transport_roundtrips.append(evidence)
            save_json(self.output / (name + '.roundtrip.json'), evidence)
        return binary

    def check(self, binary, name="verification"):
        from .environment import environment_report
        from .shadow import transform
        from .build_semantics import qualify_result
        from .compiler_queries import bind_query_entries, remove_query_bindings
        from .indirect_calls import has_indirect_calls, mark_target_checks, qualify_targets
        if self.task.environment and not self.environment_evidence:
            raise BackendError('environment summaries must be frozen and applied before a backend query')
        linked = self.output / (name + ".library.goto")
        self.require("goto-instrument", ["--add-library", binary, linked])
        functions, symbols = self.inspect(linked)
        functions = bind_query_entries(functions, symbols, self.compiler_queries, transport_mode=self.transport_mode)
        functions, symbols = remove_query_bindings(functions, symbols, self.compiler_queries)
        save_json(self.output / (name + '.query-bindings.json'), self.compiler_queries)
        encoding = configure_object_encoding(functions, symbols, self.task.object_bits)
        functions, symbols, initialization = transform(functions, symbols, self.task.targets,
            implicit_zero_init='-ftrivial-auto-var-init=zero' in self.build_semantic_options,
            strict_flexible_arrays='-fstrict-flex-arrays=3' in self.build_semantic_options,
            transport_mode=self.transport_mode)
        initialization['pointer_encoding'] = encoding
        save_json(self.output / (name + ".initialization.json"), initialization)
        instrumented = self.output / (name + ".initialized.goto")
        self.import_model(functions, symbols, instrumented, name=name)
        indirect_evidence = []
        if has_indirect_calls(functions):
            # Shadow checks and original correspondence markers precede this
            # standard compiler transformation, just as they precede CBMC's
            # default broad function-pointer removal. Only the target proposal
            # changes; every generated target-set assertion must be discharged.
            refined = self.output / (name + '.indirect.goto')
            self.require('goto-instrument', ['--value-set-fi-fp-removal', instrumented, refined])
            refined_functions, refined_symbols = self.inspect(refined)
            indirect_evidence = mark_target_checks(refined_functions, transport_mode=self.transport_mode)
            instrumented = self.output / (name + '.indirect.checked.goto')
            self.import_model(refined_functions, refined_symbols, instrumented, name=name + '.indirect')
        save_json(self.output / (name + '.indirect-targets.json'), indirect_evidence)
        args = [instrumented, "--json-ui", "--trace", "--unwind", str(self.task.unwind),
                "--object-bits", str(self.task.object_bits),
                "--unwinding-assertions", "--bounds-check", "--pointer-check",
                "--pointer-overflow-check", "--signed-overflow-check", "--undefined-shift-check",
                "--div-by-zero-check"]
        if self.task.memory_cleanup:
            args.extend(["--memory-leak-check", "--memory-cleanup-check"])
        process = self.command("cbmc", args)
        report = classify(process, self.task.targets, initialization)
        report = qualify_targets(report, indirect_evidence)
        report = qualify_result(report, self.build_semantic_options, self.compiler_queries)
        report.update(environment_report(self.environment_evidence))
        report['typed_transport'] = {'mode': self.transport_mode, 'tools': self.transport_tools,
                                     'roundtrips': self.transport_roundtrips}
        if self.transport_mode == LEGACY:
            keys = ('status', 'target', 'contracts_and_runtime_checks', 'initialization', 'completeness')
            report['typed_transport']['legacy_model_statuses'] = {key: report.get(key) for key in keys}
            report.update({key: 'UNKNOWN' for key in keys})
            report['reachability'] = {key: 'UNKNOWN' for key in report.get('reachability', {})}
            report.setdefault('reasons', []).append('explicit legacy transport cannot establish full typed preservation')
        save_json(self.output / (name + ".json"), report)
        return report
