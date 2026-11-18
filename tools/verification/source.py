"""Instrument compiler-preprocessed C at parsed function entry boundaries."""
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_c

from .expression import compile_expression
from .spec import FamilyPolicy, SpecificationError, TablePolicy


LINE_MARKER = re.compile(rb'(?m)^[ \t]*#[ \t]*(?:line[ \t]+)?(?P<line>[0-9]+)[ \t]+(?P<file>"(?:[^"\\\r\n]|\\.)*")(?:[ \t]+[1-4])*[ \t]*(?=\r?$)')


@dataclass(frozen=True)
class Function:
    name: str
    body_start: int
    start: int
    end: int


def syntax_tree(source: bytes):
    # GCC may insert line markers *inside* an expression after expanding a
    # system-header macro. They carry location data, not C syntax. Hide only
    # canonical line markers from tree-sitter, preserving every byte offset;
    # instrumentation and both compilers still receive the original bytes.
    syntax = LINE_MARKER.sub(lambda match: b' ' * len(match[0]), source)
    # GNU permits attributes between a pointer return type and its function
    # declarator; tree-sitter-c does not recognize all such placements. They
    # carry compiler semantics, not brace/name locations. Mask complete token-
    # balanced attribute groups only in the syntax view. Never match inside
    # comments/string literals; original bytes still go to both compilers.
    tokens = list(re.finditer(rb'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[A-Za-z_][A-Za-z_0-9]*|\.\.\.|[^\s]', syntax))
    masked = bytearray(syntax)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (token[0] in (b'typeof', b'__typeof', b'__typeof__', b'__builtin_types_compatible_p', b'__builtin_offsetof')
                and index + 1 < len(tokens) and tokens[index + 1][0] == b'('):
            # GNU type operands (including typeof(_Generic(...))) are not
            # fully represented by tree-sitter-c. This view locates function
            # boundaries only; the original type/expression goes to compilers.
            depth, end = 0, index + 1
            while end < len(tokens):
                depth += (tokens[end][0] == b'(') - (tokens[end][0] == b')')
                if depth == 0:
                    break
                end += 1
            if end < len(tokens):
                for offset in range(token.start(), tokens[end].end()):
                    if masked[offset] not in (10, 13):
                        masked[offset] = 32
                replacement = b'0' if token[0].startswith(b'__builtin_') else b'int'
                masked[token.start():token.start() + len(replacement)] = replacement
                index = end
        elif token[0] in (b'asm', b'__asm', b'__asm__'):
            end = index + 1
            qualifiers = (b'inline', b'__inline', b'__inline__', b'volatile', b'__volatile', b'__volatile__', b'goto')
            while end < len(tokens) and tokens[end][0] in qualifiers:
                if tokens[end][0] in (b'inline', b'__inline', b'__inline__'):
                    masked[tokens[end].start():tokens[end].end()] = b' ' * len(tokens[end][0])
                end += 1
        elif token[0] == b'case':
            depth, end, ellipsis = 0, index + 1, None
            while end < len(tokens):
                value = tokens[end][0]
                depth += (value in (b'(', b'[')) - (value in (b')', b']'))
                if depth == 0 and value in (b':', b';', b'{', b'}'):
                    break
                if depth == 0 and value == b'...':
                    ellipsis = end
                end += 1
            if ellipsis is not None and end < len(tokens) and tokens[end][0] == b':':
                for offset in range(tokens[ellipsis].start(), tokens[end].start()):
                    if masked[offset] not in (10, 13):
                        masked[offset] = 32
        elif token[0] in (b'struct', b'union') and index + 1 < len(tokens) and tokens[index + 1][0] == b'{':
            # Anonymous aggregate definitions can contain unnamed bit-fields,
            # another grammar gap. Their type is compiler-owned; the locator
            # only needs the surrounding declarator and function boundary.
            depth, end = 0, index + 1
            while end < len(tokens):
                depth += (tokens[end][0] == b'{') - (tokens[end][0] == b'}')
                if depth == 0:
                    break
                end += 1
            if end < len(tokens):
                for offset in range(token.start(), tokens[end].end()):
                    if masked[offset] not in (10, 13):
                        masked[offset] = 32
                masked[token.start():token.start() + 3] = b'int'
                index = end
        elif token[0].startswith(b'"') and index + 1 < len(tokens) and tokens[index + 1][0].startswith(b'"'):
            # GNU asm constraint operands accept concatenated literals where
            # the locator grammar expects one string. Preserve the first and
            # hide only adjacent literals, retaining offsets and line breaks.
            end = index + 1
            while end < len(tokens) and tokens[end][0].startswith(b'"'):
                for offset in range(tokens[end].start(), tokens[end].end()):
                    if masked[offset] not in (10, 13):
                        masked[offset] = 32
                end += 1
            index = end - 1
        elif (token[0] in (b'__attribute__', b'__attribute') and index + 2 < len(tokens)
                and tokens[index + 1][0] == tokens[index + 2][0] == b'('):
            depth, end = 0, index + 1
            while end < len(tokens):
                depth += (tokens[end][0] == b'(') - (tokens[end][0] == b')')
                if depth == 0:
                    break
                end += 1
            if end < len(tokens):
                for offset in range(token.start(), tokens[end].end()):
                    if masked[offset] not in (10, 13):
                        masked[offset] = 32
                index = end
        elif token[0] == b'__builtin_va_arg' and index + 1 < len(tokens) and tokens[index + 1][0] == b'(':
            # GCC's second va_arg operand is a type. The C grammar treats this
            # builtin as an ordinary call, so give only that operand a harmless
            # expression in the syntax view. All body syntax stays checked.
            depth, comma, end = 0, None, index + 1
            while end < len(tokens):
                value = tokens[end][0]
                depth += (value == b'(') - (value == b')')
                if value == b',' and depth == 1:
                    comma = end
                if depth == 0:
                    break
                end += 1
            if comma is not None and comma + 1 < end < len(tokens):
                for offset in range(tokens[comma + 1].start(), tokens[end].start()):
                    if masked[offset] not in (10, 13):
                        masked[offset] = 32
                masked[tokens[comma + 1].start()] = ord('0')
                index = end
        index += 1
    syntax = bytes(masked)
    return Parser(Language(tree_sitter_c.language())).parse(syntax)


def file_scope_declarations(source: bytes):
    """Lexical visibility only; the compiler supplies object identity and type."""
    declarations = []
    for node in syntax_tree(source).root_node.named_children:
        if node.type != 'declaration' or node.has_error:
            continue
        for declarator in node.children_by_field_name('declarator'):
            while declarator is not None and declarator.type != 'identifier':
                declarator = declarator.child_by_field_name('declarator')
            if declarator is not None:
                declarations.append((source[declarator.start_byte:declarator.end_byte].decode('utf-8'), node.end_byte))
    return declarations


def function_locations(source, definitions):
    """Map definition signatures to logical locations retained by preprocessing."""
    definitions = sorted(definitions, key=lambda f: f.start)
    result = {f.name: set() for f in definitions}
    offset, position, line_number, filename = 0, 0, 1, None
    for line in source.splitlines(keepends=True):
        marker = LINE_MARKER.fullmatch(line.rstrip(b'\r\n'))
        if marker:
            try:
                filename = json.loads(marker['file'].decode('utf-8'))
            except (ValueError, UnicodeError):
                filename = None
            line_number = int(marker['line'])
        else:
            while position < len(definitions) and offset >= definitions[position].body_start:
                position += 1
            for definition_index in range(position, len(definitions)):
                function = definitions[definition_index]
                if function.start >= offset + len(line):
                    break
                if filename is not None and offset < function.body_start:
                    result[function.name].add((filename, line_number))
            line_number += 1
        offset += len(line)
    return result


def functions(source: bytes):
    tree = syntax_tree(source)
    found = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type != "function_definition":
            pending.extend(reversed(node.named_children))
            continue
        declarator = node.child_by_field_name("declarator")
        while declarator is not None and declarator.type != "identifier":
            declarator = declarator.child_by_field_name("declarator")
        body = node.child_by_field_name("body")
        if declarator is None or body is None or body.type != "compound_statement" or node.has_error:
            raise SpecificationError("unsupported function syntax in preprocessed C")
        found.append(Function(source[declarator.start_byte:declarator.end_byte].decode("utf-8"),
                              body.start_byte + 1, node.start_byte, node.end_byte))
    return found


def table_selection(decisions, region, bit=0):
    if len(set(decisions)) == 1:
        return str(decisions[0]) + "u"
    return (f"(({region} & {1 << bit}u) ? {table_selection(decisions[1::2], region, bit + 1)}"
            f" : {table_selection(decisions[::2], region, bit + 1)})")


def domain_selection(domain, sample):
    result = str(domain[-1]) + "u"
    for index, choice in reversed(list(enumerate(domain[:-1]))):
        result = f"(({sample} % {len(domain)}u) == {index}u ? {choice}u : {result})"
    return result


def family_state(policies):
    fixed = [p for p in policies if isinstance(p, FamilyPolicy) and p.selection == "fixed_table"]
    if not fixed:
        return ""
    declarations = [f"unsigned __vulgate_choices_{p.name}[{len(p.domains)}];" for p in fixed]
    body = ["if (__vulgate_family_initialized) return;", "__vulgate_family_initialized = 1;"]
    for policy in fixed:
        for region, domain in enumerate(policy.domains):
            sample = f"__vulgate_sample_{policy.name}_{region}"
            if len(domain) > 1:
                body.extend([f"unsigned {sample} = 0u;", f"__CPROVER_havoc_object(&{sample});"])
            body.append(f"__vulgate_choices_{policy.name}[{region}] = {domain_selection(domain, sample)};")
    return ("\n".join(declarations) + "\n_Bool __vulgate_family_initialized = 0;\n"
            "void __vulgate_family_initialize(void) {\n" + "\n".join(body) + "\n}\n")


def instrument(source, policies, entry, add_root_marker, nondeterministic_actions=False, pass_only=False,
               initialize_family=False):
    if b"__vulgate_" in source or b"__VG_" in source:
        raise SpecificationError("source uses reserved verification instrumentation namespace")
    if re.search(rb"(?m)^\s*#\s*pragma\s+CPROVER\s+check\s+disable\b", source):
        raise SpecificationError("source disables backend checks through a CPROVER pragma")
    definitions = functions(source)
    edits, bindings = [], []
    for policy in policies:
        matches = [f for f in definitions if f.name == policy.function]
        if len(matches) != 1:
            raise SpecificationError(f"expected one definition of {policy.function} in its translation unit")
        hook = f'\n__CPROVER_assert(0, "__VG_REACH_POLICY:{policy.name}");\n'
        if isinstance(policy, (TablePolicy, FamilyPolicy)):
            if nondeterministic_actions:
                raise SpecificationError("action-family queries require one return action")
            region = f"__vulgate_region_{policy.name}"
            guard_name = f"__vulgate_decision_{policy.name}"
            hook += f"unsigned {region} = 0u;\n"
            observations = set()
            for bit, predicate in enumerate(policy.predicates):
                expression, names = compile_expression(predicate)
                observations.update(names)
                hook += f"{region} |= ((unsigned)!!({expression})) << {bit}u;\n"

            if isinstance(policy, FamilyPolicy):
                if policy.selection == "fixed_table":
                    expression = f"__vulgate_choices_{policy.name}[{region}]"
                else:
                    sample = f"__vulgate_sample_{policy.name}"
                    hook += f"unsigned {sample} = 0u;\n__CPROVER_havoc_object(&{sample});\n"
                    choices = [domain_selection(d, sample) for d in policy.domains]
                    expression = choices[-1]
                    for index, choice in reversed(list(enumerate(choices[:-1]))):
                        expression = f"({region} == {index}u ? {choice} : {expression})"
            else:
                expression = table_selection(policy.decisions, region)
            hook += f"unsigned {guard_name} = {expression};\n"
            observations = sorted(observations)
        else:
            expression, observations = compile_expression(policy.guard)
            if nondeterministic_actions:
                expression = f"({expression}) && __vulgate_choose()"
            guard_name = f"__vulgate_guard_{policy.name}"
            hook += f'_Bool {guard_name} = ({expression});\n'
        hook += f'__CPROVER_assert(0, "__VG_REACH_EVALUATED:{policy.name}");\n'
        if isinstance(policy, (TablePolicy, FamilyPolicy)):
            for index in range(2**len(policy.predicates)):
                hook += (f'if ({region} == {index}u) '
                         f'__CPROVER_assert(0, "__VG_REACH_REGION:{policy.name}:{index}");\n')
                if isinstance(policy, FamilyPolicy):
                    for choice in policy.domains[index]:
                        hook += (f'if ({region} == {index}u && {guard_name} == {choice}u) '
                                 f'__CPROVER_assert(0, "__VG_REACH_ACTION:{policy.name}:{index}:{choice}");\n')
        if pass_only:
            hook += f'__CPROVER_assume(!{guard_name});\n'
        else:
            for choice, value in enumerate(policy.return_actions, 1):
                action = "return;" if value is None else f"return {compile_expression({'const': value})[0]};"
                hook += f'if ({guard_name} == {choice}) {{ __vulgate_blocked = 1; {action} }}\n'
        edits.append((matches[0].body_start, hook.encode()))
        bindings.append({**policy.to_dict(), "emitted_guard": expression, "observations": observations,
                         "mode": "pass_only" if pass_only else "protected"})
    roots = [f for f in definitions if f.name == entry] if add_root_marker else []
    if len(roots) > 1:
        raise SpecificationError("ambiguous root definition")
    if roots:
        addition = b'\n__CPROVER_assert(0, "__VG_REACH_ROOT");\n'
        if initialize_family:
            addition += b'__vulgate_family_initialize();\n'
        edits.append((roots[0].body_start, addition))
    for offset, addition in sorted(edits, key=lambda item: item[0], reverse=True):
        source = source[:offset] + addition + source[offset:]
    prefix = (b'extern _Bool __vulgate_blocked;\nextern _Bool __vulgate_choose(void);\n'
              b'extern void __CPROVER_assert(_Bool, const char *);\n'
              b'extern void __CPROVER_assume(_Bool);\n')
    if any(isinstance(p, FamilyPolicy) for p in policies) or initialize_family:
        prefix += b'extern void __CPROVER_havoc_object(void *);\nextern void __vulgate_family_initialize(void);\n'
    for policy in policies:
        if isinstance(policy, FamilyPolicy) and policy.selection == "fixed_table":
            prefix += f"extern unsigned __vulgate_choices_{policy.name}[{len(policy.domains)}];\n".encode()
    return prefix + source, bindings, bool(roots)


def sha256(data):
    return hashlib.sha256(data).hexdigest()
