"""Contextual qualification for native options with stronger model obligations.

These options are replayed in native compilation. The symbolic model requires
defined pointer/arithmetic operations and explicit initialization before reads;
it does not silently claim to model wrapping arithmetic or implicit zero stores.
"""
from copy import deepcopy
from .storage_types import storage_type


CONTEXT_OPTIONS = {
    '-fno-strict-overflow': 'No reached signed or pointer arithmetic overflow in the checked context.',
    '-fno-delete-null-pointer-checks': 'No reached invalid pointer access in the checked context.',
    '-ftrivial-auto-var-init=zero': 'No read depends on implicit initialization; no observable implicit stores.',
    '-fno-strict-aliasing': 'Use the object/byte pointer model without type-based native alias optimizations.',
    '-fno-allow-store-data-races': 'Sequential checked context; no reached concurrent or atomic operation.',
    '-fstrict-flex-arrays=3': 'No reached access or address escape of fixed trailing array members; compiler queries separately qualified.',
}


def qualify_result(report, options, compiler_queries=()):
    options = sorted(set(options))
    if not options and not compiler_queries:
        return report
    report = deepcopy(report)
    reasons = []
    for key, expected in (('completeness', 'COMPLETE_FOR_HARNESS'),
                          ('contracts_and_runtime_checks', 'PROVED_FOR_HARNESS'),
                          ('initialization', 'PROVED_FOR_HARNESS')):
        if report.get(key) != expected:
            reasons.append(key + ' does not discharge the stronger model obligation')
    sites = (report.get('initialization_evidence') or {}).get('correspondence_sites', [])
    for site in sites:
        # This comparison changes initial values/optimization premises, not
        # object identity or layout in the C model. Layout-sensitive operations
        # remain a separate structural PASS obligation; they are not evidence
        # of dependence on an implicit initialization value.
        if (site['instruction'] in ('START_THREAD', 'END_THREAD', 'ATOMIC_BEGIN', 'ATOMIC_END') and
                report.get('reachability', {}).get(site['marker']) != 'UNREACHABLE'):
            reasons.append(site['reason'] + ' in ' + site['function'])
    query_evidence = []
    for site in compiler_queries:
        status = report.get('reachability', {}).get(site['marker'], 'UNKNOWN') if site['marker'] else 'UNKNOWN'
        query_evidence.append({**site, 'status': status})
        if status != 'UNREACHABLE':
            reasons.append(site['reason'] + (' in ' + site['function'] if site['function'] else ''))
    report['build_semantics'] = {
        'status': 'UNKNOWN' if reasons else 'PROVED_FOR_HARNESS',
        'options': {option: CONTEXT_OPTIONS[option] for option in options},
        'method': 'Native option replay with context-specific stronger defined-execution obligations.',
        'reasons': reasons,
        'compiler_queries': query_evidence,
    }
    if reasons:
        # A counterexample to the stronger model need not be a native-program
        # counterexample (e.g. a local that GCC implicitly zeroes). Keep raw
        # properties, but do not learn refutations or native reachability from it.
        keys = ('status', 'target', 'contracts_and_runtime_checks', 'initialization')
        report['abstract_model_statuses'] = {key: report.get(key) for key in keys}
        report.update({key: 'UNKNOWN' for key in keys})
        report['reachability'] = {key: 'UNKNOWN' for key in report.get('reachability', {})}
        report.setdefault('reasons', []).append('native compilation-option correspondence is incomplete')
    return report


def contains_observable_storage(type_, symbols, active=()):
    """Implicit initialization must not introduce volatile/atomic stores."""
    named = type_.get('namedSub', {})
    if any(named.get(q, {}).get('id') == '1' for q in ('#volatile', '#atomic')):
        return True
    kind = type_.get('id')
    if kind in ('struct_tag', 'union_tag', 'c_enum_tag'):
        tag = named.get('identifier', {}).get('id')
        if tag in active:
            return True
        return contains_observable_storage(symbols.get(tag, {}).get('type', {}), symbols, (*active, tag))
    if kind in ('struct', 'union'):
        return any(contains_observable_storage(c.get('namedSub', {}).get('type', {}), symbols, active)
                   for c in named.get('components', {}).get('sub', []))
    if kind in ('array', 'c_bit_field', 'c_enum'):
        return any(contains_observable_storage(t, symbols, active) for t in type_.get('sub', []))
    # Initializing a pointer does not initialize its pointee.
    return False


def fixed_trailing_array_member(expression, symbols):
    """The backend uses allocation bounds for some trailing-member accesses.

    Until subobject provenance is modeled, do not claim the strict native
    fixed-array semantics for an access/decay whose bounds could differ.
    An actual C flexible member is distinguished by the compiler's type flag.
    """
    if expression.get('id') != 'member' or not expression.get('sub'):
        return False
    base = storage_type(expression['sub'][0], symbols)
    if base.get('id') == 'struct_tag':
        name = base.get('namedSub', {}).get('identifier', {}).get('id')
        base = symbols.get(name, {}).get('type', {})
    if base.get('id') != 'struct':
        return False
    members = [c.get('namedSub', {}) for c in base.get('namedSub', {}).get('components', {}).get('sub', [])
               if c.get('namedSub', {}).get('#is_padding', {}).get('id') != '1']
    if not members or members[-1].get('name') != expression.get('namedSub', {}).get('component_name'):
        return False
    type_ = members[-1].get('type', {})
    return type_.get('id') == 'array' and type_.get('namedSub', {}).get('#flexible_array_member', {}).get('id') != '1'
