"""Recover C lvalue qualifiers that GOTO expression types may omit."""
from copy import deepcopy


def storage_type(expression, symbols):
    declared = expression.get('namedSub', {}).get('type', {})
    kind, children = expression.get('id'), expression.get('sub', [])
    if kind == 'symbol':
        name = expression.get('namedSub', {}).get('identifier', {}).get('id')
        return symbols.get(name, {}).get('type', declared)
    if kind not in ('dereference', 'member', 'index') or not children:
        return declared
    base = storage_type(children[0], symbols)
    if kind in ('dereference', 'index') and base.get('id') in ('pointer', 'array'):
        selected = (base.get('sub') or [declared])[0]
    elif kind == 'member':
        if base.get('id') in ('struct_tag', 'union_tag'):
            tag = base.get('namedSub', {}).get('identifier', {}).get('id')
            aggregate = symbols.get(tag, {}).get('type', {})
        else:
            aggregate = base
        component = expression.get('namedSub', {}).get('component_name', {}).get('id')
        selected = next((item.get('namedSub', {}).get('type', {}) for item in
                         aggregate.get('namedSub', {}).get('components', {}).get('sub', [])
                         if item.get('namedSub', {}).get('name', {}).get('id') == component), declared)
    else:
        return declared
    # Qualifiers on an aggregate apply to its members. A volatile pointer is
    # different: only reading the pointer itself is volatile, not its pointee.
    if base.get('id') != 'pointer':
        selected = deepcopy(selected)
        for qualifier in ('#volatile', '#atomic'):
            if base.get('namedSub', {}).get(qualifier, {}).get('id') == '1':
                selected.setdefault('namedSub', {})[qualifier] = {'id': '1'}
    return selected
