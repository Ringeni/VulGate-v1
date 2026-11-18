"""Entry-visible objects and bounded GOTO condition translation.

This is proposal construction, not a proof engine. Each path gets its own
entry-expression environment. Calls/indirect writes invalidate mutable reads;
back edges, recursion and exhausted budgets are reported as omissions.
"""
from copy import deepcopy

from .shadow import symbol_name, typ
from .spec import SpecificationError, identifier


def visible_globals(declarations, entry_start, module, parameters, symbols):
    names = {name for name, end in declarations if end <= entry_start} - set(parameters.values())
    result, excluded = {}, []
    for name in sorted(names):
        try:
            identifier(name)
        except SpecificationError:
            continue
        if name.startswith(('__CPROVER', '__vulgate_')):
            continue
        objects = [(key, value) for key, value in symbols.items()
                   if value.get('baseName') == name and value.get('isStaticLifetime')
                   and not value.get('isType') and not value.get('isMacro') and not value.get('isAuxiliary')
                   and not value.get('location', {}).get('function') and value.get('type', {}).get('id') != 'code']
        local = [(key, value) for key, value in objects if value.get('isFileLocal') and value.get('module') == module]
        choices = local or [(key, value) for key, value in objects if not value.get('isFileLocal')]
        if len(choices) != 1:
            if choices:
                excluded.append({'name': name, 'reason': 'ambiguous compiler object identity'})
            continue
        key, value = choices[0]
        if value.get('isThreadLocal') or value.get('isVolatile'):
            excluded.append({'name': name, 'symbol': key, 'reason': 'thread-local or volatile object'})
            continue
        result[key] = {'name': name, 'type': value['type'], 'module': value.get('module'),
                       'location': value.get('location', {}), 'file_local': value.get('isFileLocal', False)}
    return result, excluded


def walk(value):
    yield value
    for child in value.get('sub', []):
        yield from walk(child)


def is_global(value):
    return value.get('isStaticLifetime') and not value.get('isType') and not value.get('isAuxiliary')


def symbol_expression(name, value_type):
    return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}, 'type': deepcopy(value_type)}}


def entry_conditions(entry, compiled, symbols, bindings, options, harness):
    """Substitute typed values along bounded, acyclic execution prefixes.

Environments contain frozen expressions over entry symbols. A snapshot taken
before a memory write remains expressible, but a new read after such a write is
not confused with an entry read. Unknown writes kill all address-escaped locals
and global mappings. Callee return values are deliberately not summarized.
"""
    functions = {f['name']: f for f in compiled}
    conditions, omitted = [], []
    spent = 0
    escaped = set()
    for function in compiled:
        for instruction in function.get('instructions', []):
            for key in ('guard', 'code'):
                for node in walk(instruction.get(key, {})):
                    if node.get('id') == 'address_of':
                        escaped.update(symbol_name(s) for s in walk(node) if s.get('id') == 'symbol')
    global_ids = {name for name, value in symbols.items() if is_global(value)}

    def note(function, instruction, reason):
        item = {'function': function, 'location': instruction.get('sourceLocation', {}), 'reason': reason}
        if item not in omitted:
            omitted.append(item)

    def expand(expression, environment, memory_stable):
        if expression.get('id') == 'symbol':
            return deepcopy(environment.get(symbol_name(expression)))
        # These are fresh memory reads at the current instruction, rather than
        # previously captured entry values substituted from the environment.
        if expression.get('id') in ('dereference', 'member', 'index') and not memory_stable:
            return None
        if expression.get('id') in ('side_effect', 'address_of'):
            return None
        children = [expand(child, environment, memory_stable) for child in expression.get('sub', [])]
        if any(child is None for child in children):
            return None
        result = deepcopy(expression)
        if 'sub' in result:
            result['sub'] = children
        # Keep the expression grammar budget bounded before it reaches emission.
        if sum(1 for _ in walk(result)) > 512:
            return None
        return result

    def invalidate(environment):
        return {name: value for name, value in environment.items() if name not in global_ids | escaped}

    def visit(name, environment, memory_stable, stack, calls):
        nonlocal spent
        function = functions.get(name)
        if function is None or not function.get('isBodyAvailable'):
            note(name, {}, 'callee body unavailable')
            return
        instructions = function.get('instructions', [])
        positions = {item['locationNumber']: index for index, item in enumerate(instructions)}
        pending = [(0, environment, memory_stable, frozenset())]
        while pending:
            index, environment, memory_stable, visited = pending.pop()
            if index >= len(instructions):
                continue
            item = instructions[index]
            if spent >= options.flow_steps:
                note(name, item, 'condition translation step budget exhausted')
                return
            spent += 1
            if index in visited:
                note(name, item, 'loop back edge not expanded')
                continue
            visited = visited | {index}
            kind = item['instructionId']
            code = item.get('code', {}).get('sub', [])
            environment = dict(environment)
            if kind in ('ASSERT', 'ASSUME', 'GOTO') and not item.get('sourceLocation', {}).get('comment', '').startswith('__VG_'):
                expression = expand(item.get('guard', {}), environment, memory_stable)
                if expression is not None:
                    conditions.append({'expression': expression, 'location': item.get('sourceLocation', {}),
                                       'function': name, 'calls': calls, 'instruction': item['locationNumber']})
                else:
                    note(name, item, 'condition lacks a stable entry expression')
            if kind == 'ASSIGN' and len(code) == 2:
                left, right = code
                value = expand(right, environment, memory_stable)
                target = symbol_name(left) if left.get('id') == 'symbol' else None
                if target is None or target in global_ids or target in escaped:
                    environment = invalidate(environment)
                    memory_stable = False
                    note(name, item, 'memory write invalidates later unresolved reads')
                if target is not None:
                    environment.pop(target, None)
                    if value is not None:
                        environment[target] = value
            elif kind == 'DECL' and code:
                environment.pop(symbol_name(code[0]), None)
            elif kind == 'DEAD' and code:
                environment.pop(symbol_name(code[0]), None)
            elif kind == 'FUNCTION_CALL':
                callee = symbol_name(code[1]) if len(code) >= 3 and code[1].get('id') == 'symbol' else ''
                actual = code[2].get('sub', []) if len(code) >= 3 else []
                if callee and callee != harness and callee not in stack and len(calls) < options.call_depth:
                    parameters = functions.get(callee, {}).get('parameterIdentifiers', [])
                    child = {key: value for key, value in environment.items() if key in global_ids}
                    if len(parameters) == len(actual):
                        for formal, argument in zip(parameters, actual):
                            value = expand(argument, environment, memory_stable)
                            if value is not None:
                                child[formal] = value
                        visit(callee, child, memory_stable, (*stack, callee),
                              [*calls, {'caller': name, 'callee': callee, 'location': item.get('sourceLocation', {})}])
                    else:
                        note(name, item, 'call parameter binding is incomplete or variadic')
                else:
                    note(name, item, 'indirect, recursive, harness or depth-limited call not expanded')
                # No function-effect or return summary is assumed here.
                environment = invalidate(environment)
                memory_stable = False
                if code and code[0].get('id') == 'symbol':
                    environment.pop(symbol_name(code[0]), None)
            elif kind not in ('ASSIGN', 'DECL', 'DEAD', 'ASSERT', 'ASSUME', 'GOTO', 'SKIP',
                              'LOCATION', 'END_FUNCTION', 'SET_RETURN_VALUE'):
                note(name, item, 'unmodeled instruction ends this translation prefix')
                continue
            if kind in ('END_FUNCTION', 'SET_RETURN_VALUE'):
                continue
            if kind == 'GOTO':
                guard = item.get('guard', {})
                truth = guard.get('namedSub', {}).get('value', {}).get('id') if guard.get('id') == 'constant' else None
                if truth not in ('false', '0'):
                    for target in item.get('targets', []):
                        if target in positions:
                            pending.append((positions[target], environment, memory_stable, visited))
                        else:
                            note(name, item, 'unresolved control-flow target')
                if truth in ('true', '1'):
                    continue
            pending.append((index + 1, environment, memory_stable, visited))

    initial = {name: symbol_expression(name, symbols[name]['type']) for name in bindings if name in symbols}
    visit(entry, initial, True, (entry,), [])
    return conditions, omitted
