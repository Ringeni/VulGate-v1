"""Compilation-database recipes without executing build-command strings.

Only compiler invocations and options whose role is understood are accepted.
Preprocessing uses the recorded native compiler; GOTO front-end options are
kept separately. Response files, argument order and working directories are
part of the build evidence.
"""
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shlex

from .spec import SpecificationError
from .build_semantics import CONTEXT_OPTIONS
from .build_options import codegen_option


def local_path(value, directory):
    if not isinstance(value, str) or not value or "\0" in value:
        raise SpecificationError("build path must be a nonempty string")
    if os.name == "nt" and (match := re.match(r"^/mnt/([a-zA-Z])/(.*)$", value)):
        value = match[1] + ":/" + match[2]
    if os.name == "nt" and value.startswith("/"):
        raise SpecificationError(f"build path is not accessible from the Windows host: {value}")
    return (directory / value).resolve()


def windows_arguments(command):
    """MS C-runtime quote/backslash rules, without cmd.exe expansion."""
    args, index = [], 0
    while index < len(command):
        while index < len(command) and command[index].isspace():
            index += 1
        if index == len(command):
            break
        value, quoted = [], False
        while index < len(command) and (quoted or not command[index].isspace()):
            slash = 0
            while index < len(command) and command[index] == "\\":
                slash += 1
                index += 1
            if index < len(command) and command[index] == '"':
                value.append("\\" * (slash // 2))
                if slash % 2:
                    value.append('"')
                elif quoted and index + 1 < len(command) and command[index + 1] == '"':
                    value.append('"')
                    index += 1
                else:
                    quoted = not quoted
                index += 1
            else:
                value.append("\\" * slash)
                if index < len(command) and (quoted or not command[index].isspace()):
                    value.append(command[index])
                    index += 1
        if quoted:
            raise SpecificationError("unclosed quote in Windows compilation command")
        args.append("".join(value))
    return args


def command_arguments(command, syntax):
    if not isinstance(command, str):
        raise SpecificationError("compilation command must be a string")
    # A compilation database's command form is shell-escaped. Shell expansion
    # cannot be reconstructed from a frozen argv; prefer the arguments form.
    if syntax == "windows":
        if any(character in command for character in ("%", "!", "^", "&", "|", "<", ">")):
            raise SpecificationError("shell expansion/redirection requires compilation database arguments form")
        return windows_arguments(command)
    if any(character in command for character in ("$", "`", "\n", "\r")):
        raise SpecificationError("shell expansion requires compilation database arguments form")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split, lexer.commenters = True, ""
    try:
        args = list(lexer)
    except ValueError as exc:
        raise SpecificationError(f"invalid quoted compilation command: {exc}") from exc
    if any(argument and all(c in ";&|<>" for c in argument) for argument in args):
        raise SpecificationError("compound shell commands are not compilation recipes")
    return args


def response_arguments(value):
    """GNU driver response syntax: backslashes escape even inside single quotes."""
    if "\0" in value:
        raise SpecificationError("NUL in compiler response file")
    result, word, quote, started, escaped = [], [], None, False, False
    for character in value:
        if escaped:
            word.append(character)
            escaped = False
        elif character == "\\":
            escaped, started = True, True
        elif quote is not None:
            if character == quote:
                quote = None
            else:
                word.append(character)
        elif character in ("'", '"'):
            quote, started = character, True
        elif character in " \t\n\r\v\f":
            if started:
                result.append("".join(word))
                word, started = [], False
        else:
            word.append(character)
            started = True
    if quote is not None or escaped:
        raise SpecificationError("unterminated quote or escape in compiler response file")
    if started:
        result.append("".join(word))
    return result


@dataclass(frozen=True)
class Unit:
    source: Path
    directory: Path
    compiler: str
    source_argument: str
    preprocess_flags: tuple[str, ...]
    frontend_flags: tuple[str, ...]
    native_flags: tuple[str, ...]
    provenance: dict = field(default_factory=dict)


def expand_responses(arguments, directory, dependencies, active=()):
    if len(active) > 16:
        raise SpecificationError("response file nesting limit exceeded")
    result = []
    for argument in arguments:
        if argument.startswith("@"):
            path = local_path(argument[1:], directory)
            if path in active:
                raise SpecificationError("cyclic compiler response files")
            data = path.read_bytes()
            dependencies[str(path)] = sha256(data).hexdigest()
            try:
                nested = response_arguments(data.decode("utf-8-sig"))
            except ValueError as exc:
                raise SpecificationError(f"invalid response file {path}: {exc}") from exc
            result.extend(expand_responses(nested, directory, dependencies, (*active, path)))
        else:
            result.append(argument)
        if len(result) > 10000:
            raise SpecificationError("compiler argument expansion limit exceeded")
    return result


def parse_unit(source, directory, arguments, provenance, *, explicit_flags=False, compiler="gcc"):
    if not isinstance(arguments, list) or any(not isinstance(a, str) or "\0" in a for a in arguments):
        raise SpecificationError("compiler arguments must be strings")
    responses = {}
    args = expand_responses(arguments, directory, responses)
    if not explicit_flags:
        if not args:
            raise SpecificationError("empty compilation command")
        compiler, args = args[0], args[1:]
        if Path(compiler.replace("\\", "/")).name in ("ccache", "sccache"):
            if not args:
                raise SpecificationError("compiler wrapper has no compiler")
            compiler, args = args[0], args[1:]
    name = compiler.replace("\\", "/").rsplit("/", 1)[-1]
    if not re.fullmatch(r"(?:(?:[A-Za-z0-9_]+-)+)?(?:gcc|clang|cc)(?:-\d+(?:\.\d+)*)?(?:\.exe)?", name):
        raise SpecificationError(f"unsupported native C compiler: {compiler}")
    if "/" in compiler or "\\" in compiler:
        # POSIX absolute compiler paths belong to the backend host. Native
        # Windows compiler paths remain native and require a native backend.
        if not compiler.startswith("/"):
            compiler = str(local_path(compiler, directory))
    pre, frontend, native, discarded, inputs = [], [], [], [], []
    index = 0
    with_value = {"-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "--sysroot", "-isysroot", "-D", "-U"}
    frontend_exact = {"-m32", "-m64", "-funsigned-char", "-fsigned-char", "-fshort-wchar"}
    standards = {"c89", "gnu89", "c99", "gnu99", "c11", "gnu11", "c17", "gnu17", "c18", "gnu18", "c23", "gnu23", "c2x", "gnu2x"}
    while index < len(args):
        arg = args[index]
        index += 1

        def operand():
            nonlocal index
            if index == len(args):
                raise SpecificationError(f"missing argument to {arg}")
            value = args[index]
            index += 1
            return value

        if arg in ("-o", "-MF", "-MT", "-MQ", "-MJ"):
            discarded.extend([arg, operand()])
        elif arg in ("-c", "-MD", "-MMD", "-MP", "-pipe"):
            # -pipe selects communication between compiler stages. It changes
            # neither preprocessing/C semantics nor the target ABI.
            discarded.append(arg)
        elif re.fullmatch(r'-Wp,-M(?:M)?D,[^,\r\n]+', arg):
            # This exact GNU form only writes dependency output. Do not accept
            # extra comma-separated preprocessor options or a missing path.
            discarded.append(arg)
        elif any(arg.startswith(prefix) and arg != prefix for prefix in ("-o", "-MF", "-MT", "-MQ", "-MJ")):
            discarded.append(arg)
        elif arg in with_value:
            pre.extend([arg, operand()])
        elif any(arg.startswith(prefix) and arg != prefix for prefix in ("-I", "-D", "-U")) or arg.startswith("--sysroot="):
            pre.append(arg)
        elif arg.startswith('-fmacro-prefix-map=') and '=' in arg[len('-fmacro-prefix-map='):]:
            # __FILE__/__BASE_FILE__ are resolved by the native preprocessor;
            # their exact bytes are retained in the frozen translation unit.
            pre.append(arg)
        elif arg == "-x":
            if inputs:
                raise SpecificationError("language selection after the source is not a qualified C recipe")
            if operand() != "c":
                raise SpecificationError("only C compilation units are supported")
            pre.extend(["-x", "c"])
        elif arg == "-ansi" or arg.startswith("-std="):
            standard = "c89" if arg == "-ansi" else {"c90": "c89", "gnu90": "gnu89"}.get(arg[5:], arg[5:])
            if standard not in standards:
                raise SpecificationError(f"unsupported C language standard: {arg}")
            pre.append(arg)
            frontend.append("-std=" + standard)
            native.append(arg)
        elif arg in frontend_exact:
            pre.append(arg)
            frontend.append(arg)
            native.append(arg)
        elif arg in CONTEXT_OPTIONS or codegen_option(arg):
            # Native compilation retains the option. Every symbolic query
            # separately qualifies its stronger defined-execution obligations.
            pre.append(arg)
            native.append(arg)
        elif arg in ("-nostdinc", "-undef", "-fPIC", "-fpic", "-fPIE", "-fpie", "-fno-pic", "-fno-pie", "-fno-PIC", "-fno-PIE") or re.fullmatch(r"-O(?:[0-3sgz]|fast)?", arg):
            if arg == "-Ofast":
                raise SpecificationError("-Ofast changes arithmetic semantics and is not qualified")
            pre.append(arg)
            if arg not in ('-nostdinc', '-undef'):
                native.append(arg)
        elif re.fullmatch(r"-g(?:[0-3]|gdb[0-3]?)?", arg) or arg in ("-w", "-pedantic", "-pedantic-errors") or arg.startswith("-W") and not arg.startswith(("-Wl,", "-Wa,", "-Wp,")):
            pre.append(arg)
            native.append(arg)
        elif not arg.startswith("-") and not explicit_flags and local_path(arg, directory) == source:
            inputs.append(arg)
        else:
            raise SpecificationError(f"unsupported compilation option or input: {arg}")
    if not explicit_flags and len(inputs) != 1:
        raise SpecificationError("compilation command must contain its source exactly once")
    # gcc_mode handles both flags independently rather than respecting their
    # last occurrence. Normalize mutually exclusive options before replay.
    effective = {}
    for option in frontend:
        key = ("standard" if option.startswith("-std=") else "word_size" if option in ("-m32", "-m64") else
               "char_sign" if option in ("-funsigned-char", "-fsigned-char") else option)
        effective[key] = option
    return Unit(source, directory, compiler, inputs[0] if inputs else str(source), tuple(pre), tuple(effective.values()), tuple(native),
                {**provenance, "arguments": arguments, "response_files": responses, "discarded_build_outputs": discarded})


def load_units(task):
    """Resolve recipes anew for every run, so changed build metadata invalidates evidence."""
    database, database_digest = [], None
    if task.compilation_database is not None:
        data = task.compilation_database.read_bytes()
        database_digest = sha256(data).hexdigest()
        database = json.loads(data.decode("utf-8-sig"))
        if not isinstance(database, list) or any(not isinstance(record, dict) for record in database):
            raise SpecificationError("compilation database must be an array of command objects")
    options = {local_path(item["source"], task.path.parent): item for item in task.units}
    if len(options) != len(task.units) or any(source not in task.sources for source in options):
        raise SpecificationError("unit options must refer to distinct task sources")
    result = []
    for source in task.sources:
        option = options.get(source, {})
        matches = []
        for number, record in enumerate(database):
            if not isinstance(record.get("directory"), str) or not isinstance(record.get("file"), str):
                raise SpecificationError("compilation database entry requires directory and file")
            directory = local_path(record["directory"], task.compilation_database.parent)
            if local_path(record["file"], directory) == source:
                matches.append((number, record, directory))
        if "output" in option:
            selected_output = local_path(option["output"], task.path.parent)
            matches = [(n, r, d) for n, r, d in matches if isinstance(r.get("output"), str) and
                       local_path(r["output"], d) == selected_output]
            if not matches:
                raise SpecificationError(f"no compilation command matches selected output for {source}")
        if len(matches) > 1:
            raise SpecificationError(f"ambiguous compilation commands for {source}; select an output")
        if matches:
            if set(option) - {"source", "output"}:
                raise SpecificationError("database command options must not be silently overridden by unit flags")
            number, record, directory = matches[0]
            syntax = task.command_syntax
            if syntax == "auto":
                syntax = "windows" if re.match(r"^[A-Za-z]:[/\\]|^\\\\", record["directory"]) else "posix"
            arguments = record.get("arguments")
            if arguments is None:
                arguments = command_arguments(record.get("command"), syntax)
            result.append(parse_unit(source, directory, arguments,
                {"database": str(task.compilation_database), "database_sha256": database_digest,
                 "record_index": number, "record": record, "command_syntax": syntax}))
        else:
            if task.compilation_database is not None and "flags" not in option:
                raise SpecificationError(f"no compilation command for {source}; provide explicit unit flags for the harness")
            directory = local_path(option.get("directory", str(task.path.parent)), task.path.parent)
            result.append(parse_unit(source, directory, option.get("flags", []), {"explicit_unit": option},
                                     explicit_flags=True, compiler=option.get("compiler", "gcc")))
        if not result[-1].directory.is_dir():
            raise SpecificationError(f"missing compilation working directory: {result[-1].directory}")
    return result
