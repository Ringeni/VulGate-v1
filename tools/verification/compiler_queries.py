"""Guard native compiler queries that the symbolic frontend folds differently.

Until their optimization-specific semantics are modeled, a query-containing
function must be unreachable. Native source bytes are never rewritten by this
module. Analysis copies receive entry assertions and private typed bindings;
the linked compiler model retains an entry obligation for every source site.
"""
import re

from .source import LINE_MARKER, functions, sha256, syntax_tree
from .spec import SpecificationError
from .typed_transport import FULL, copy_location


QUERIES = {b'__builtin_object_size', b'__builtin_dynamic_object_size', b'__builtin_constant_p'}
BINDING_PREFIX = '__vulgate_query_binding_'
TOKENS = re.compile(rb'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|[A-Za-z_][A-Za-z_0-9]*|[^\s]')


def source_references(sources, entry):
    """Conservative references, including function addresses and global initializers.

    Diagnostic context only: source-name absence cannot discharge a missing
    compiler assertion, especially in the presence of asm redirections.
    Duplicate static names add edges conservatively.
    """
    edges, globals_ = {}, set()
    for source in sources:
        lexical = LINE_MARKER.sub(lambda m: b' ' * len(m[0]), source)
        for function in functions(source):
            edges.setdefault(function.name, set()).update(
                m[0].decode() for m in TOKENS.finditer(lexical[function.body_start:function.end])
                if re.fullmatch(rb'[A-Za-z_][A-Za-z_0-9]*', m[0]))
        pending = list(syntax_tree(source).root_node.named_children)
        while pending:
            node = pending.pop()
            if node.type == 'function_definition':
                continue
            if node.type == 'init_declarator':
                value = node.child_by_field_name('value')
                if value is not None:
                    globals_.update(m[0].decode() for m in TOKENS.finditer(lexical[value.start_byte:value.end_byte])
                                    if re.fullmatch(rb'[A-Za-z_][A-Za-z_0-9]*', m[0]))
            pending.extend(node.named_children)
    if entry not in edges:
        return None
    reachable, queue = {entry, *globals_}, [entry, *globals_]
    for name in queue:
        for child in edges.get(name, set()) & edges.keys():
            if child not in reachable:
                reachable.add(child)
                queue.append(child)
    return reachable


def guard_compiler_queries(source, unit_id=''):
    # Check every translation unit, including ones without a native query.
    if BINDING_PREFIX.encode() in source:
        raise SpecificationError('source uses the reserved compiler-query binding namespace')
    if not any(query in source for query in QUERIES):
        return source, []
    lexical = LINE_MARKER.sub(lambda m: b' ' * len(m[0]), source)
    tokens = list(TOKENS.finditer(lexical))
    # Parenthesized callees are valid C, e.g. (__builtin_constant_p)(value).
    # Qualify every code-token use; none of these optimization-dependent
    # builtins can be admitted merely by spelling its callee differently.
    calls = [(token.start(), token[0].decode()) for token in tokens if token[0] in QUERIES]
    if not calls:
        return source, []
    definitions = functions(source)
    grouped, sites = {}, []
    for offset, kind in calls:
        owner = next((f for f in definitions if f.body_start <= offset < f.end), None)
        if owner is None:
            sites.append({'function': None, 'offset': offset, 'query': kind, 'marker': None,
                          'reason': 'compiler-dependent query outside a function body'})
        else:
            grouped.setdefault(owner, []).append({'offset': offset, 'query': kind})
    edits, bindings = [], []
    for function, queries in grouped.items():
        identity = sha256(source + b'\0' + str(function.body_start).encode() + b'\0' + unit_id.encode())
        marker = '__VG_REACH_COMPILER_QUERY:' + identity
        binding = BINDING_PREFIX + identity
        sites.append({'function': function.name, 'queries': queries, 'marker': marker,
                      'binding_function': binding,
                      'reason': 'compiler-dependent query requires native optimization semantics'})
        edits.append((function.body_start, f'\n__CPROVER_assert(0, "{marker}");\n'.encode()))
        # The compiler resolves asm redirections and TU-local function names.
        # A never-called function returns that exact typed function pointer.
        # Its reference also preserves otherwise discarded GNU inline bodies.
        bindings.append(f'__typeof__(&{function.name}) {binding}(void) {{ return &{function.name}; }}')
    for offset, addition in sorted(edits, reverse=True):
        source = source[:offset] + addition + source[offset:]
    if edits:
        source = (b'extern void __CPROVER_assert(_Bool, const char *);\n' + source +
                  ('\n' + '\n'.join(bindings) + '\n').encode())
    return source, sites


def bind_query_entries(functions_, symbols, sites, *, transport_mode=FULL):
    """Reattach every source-site obligation to its compiler-resolved entry.

    The linker can keep just one inline body and its one entry marker. Each
    private typed binding survives independently, so all coalesced obligations
    can be restored without guessing names or equating different definitions.
    Original function instructions, branches and call targets stay intact.
    """
    by_name = {f['name']: f for f in functions_}
    additions = {}
    for site in sites:
        probe = by_name.get(site.get('binding_function'), {})
        returns = [i.get('code', {}).get('sub', []) for i in probe.get('instructions', [])
                   if i.get('instructionId') == 'SET_RETURN_VALUE']
        site['binding_status'] = 'UNRESOLVED'
        if len(returns) != 1 or len(returns[0]) != 1:
            continue
        pointer = returns[0][0]
        if pointer.get('id') != 'address_of' or len(pointer.get('sub', [])) != 1:
            continue
        reference = pointer['sub'][0]
        if reference.get('id') != 'symbol':
            continue
        name = reference.get('namedSub', {}).get('identifier', {}).get('id')
        if symbols.get(name, {}).get('type', {}).get('id') != 'code':
            continue
        site['compiler_symbol'] = name
        target = by_name.get(name, {})
        instructions = target.get('instructions', [])
        if not instructions:
            site['binding_status'] = 'NO_COMPILED_BODY'
            continue
        site['binding_status'] = 'BOUND_TO_COMPILED_ENTRY'
        present = any(i.get('instructionId') == 'ASSERT' and
                      i.get('sourceLocation', {}).get('comment') == site['marker'] for i in instructions)
        site['entry_marker_restored'] = not present
        if present:
            continue
        assertion = {
            'instructionId': 'ASSERT',
            'guard': {'id': 'constant', 'namedSub': {'type': {'id': 'bool'}, 'value': {'id': 'false'}}}}
        copy_location(assertion, symbols[name], mode=transport_mode, donor_kind='symbol',
                      updates={'function': name, 'comment': site['marker'], 'propertyClass': 'assertion'},
                      remove=('propertyId',), create_from_nil=True)
        additions.setdefault(name, []).append(assertion)
    for name, prefixes in additions.items():
        original = by_name[name]['instructions']
        numbers = {i['locationNumber']: index + len(prefixes) for index, i in enumerate(original)}
        for instruction in original:
            if 'targets' in instruction:
                instruction['targets'] = [numbers[n] for n in instruction['targets']]
        combined = prefixes + original
        for number, instruction in enumerate(combined):
            instruction['locationNumber'] = number
            instruction.pop('instruction', None)
        by_name[name]['instructions'] = combined
    return functions_


def true_guard(guard):
    # Match the literal's semantic fields, without deleting retained annotations.
    # Unknown non-comment members are not admitted as an inert binding shape.
    def annotated_leaf(value, identifier):
        return (value.get('id') == identifier and not value.get('sub') and
                all(k.startswith('#') for k in value.get('namedSub', {})))
    fields = guard.get('namedSub', {})
    return (guard.get('id') == 'constant' and not guard.get('sub') and
            all(k in ('type', 'value') or k.startswith('#') for k in fields) and
            annotated_leaf(fields.get('type', {}), 'bool') and
            annotated_leaf(fields.get('value', {}), 'true'))


def remove_query_bindings(functions_, symbols, sites):
    """Consume private symbol-resolution metadata before pointer analysis.

    CBMC collects address-taken functions from *all* function bodies and symbol
    values before reachability pruning. Leaving these never-called helpers in
    the model therefore introduces spurious indirect-call targets. Remove only
    exact recorded helpers after checking their shape, restored obligations and
    absence of references from the retained model. Original callees stay intact.
    """
    bindings = {s['binding_function']: s for s in sites if s.get('binding_function')}
    by_name = {f['name']: f for f in functions_}
    reserved = {n for n in (*by_name, *symbols) if n.startswith(BINDING_PREFIX)}
    if reserved != bindings.keys():
        raise SpecificationError('compiler-query binding namespace contains missing or unrecorded symbols')
    for name, site in bindings.items():
        body = by_name.get(name, {}).get('instructions', [])
        symbol = symbols.get(name, {})
        if (site.get('binding_status') != 'BOUND_TO_COMPILED_ENTRY' or
                symbol.get('type', {}).get('id') != 'code' or
                symbol.get('value', {}).get('id') != 'compiled' or
                [i.get('instructionId') for i in body] != ['SET_RETURN_VALUE', 'GOTO', 'END_FUNCTION']):
            raise SpecificationError('compiler-query binding is unresolved or has an unexpected body: ' + name)
        returned = body[0].get('code', {}).get('sub', [])
        jump = body[1]
        if (len(returned) != 1 or returned[0].get('id') != 'address_of' or
                len(returned[0].get('sub', [])) != 1 or
                returned[0]['sub'][0].get('id') != 'symbol' or
                returned[0]['sub'][0].get('namedSub', {}).get('identifier', {}).get('id') != site['compiler_symbol'] or
                not true_guard(jump.get('guard', {})) or
                jump.get('targets') != [body[-1].get('locationNumber')]):
            raise SpecificationError('compiler-query binding is not an inert typed address return: ' + name)
        if not any(i.get('instructionId') == 'ASSERT' and
                   i.get('sourceLocation', {}).get('comment') == site['marker']
                   for i in by_name.get(site['compiler_symbol'], {}).get('instructions', [])):
            raise SpecificationError('compiler-query entry obligation is missing: ' + name)

    retained_functions = [f for f in functions_ if f['name'] not in bindings]
    retained_symbols = {n: s for n, s in symbols.items() if n not in bindings}
    pending = [retained_functions, retained_symbols]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            if node.get('id') == 'symbol':
                identifier = node.get('namedSub', {}).get('identifier', {}).get('id', '')
                if identifier.startswith(BINDING_PREFIX):
                    raise SpecificationError('retained model references a compiler-query binding: ' + identifier)
            pending.extend(node.values())
    for site in bindings.values():
        site['binding_metadata_removed'] = True
    return retained_functions, retained_symbols
