"""Explicit, conditional source summaries for named environment boundaries.

Summary files contain a complete C compound statement, without preprocessing
directives. The body is compiled in the original function's parameter/type
scope. Its behavior is an assumption, not a proved implementation equivalence.
The original snapshots are never overwritten and remain the native input.
"""
from dataclasses import dataclass
import re

from .source import LINE_MARKER, function_locations, functions, sha256, syntax_tree
from .spec import EnvironmentSummary, SpecificationError, identifier


_TOKENS = re.compile(rb'/\*[\s\S]*?\*/|//[^\r\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|[^\s]')
_FORBIDDEN = {b'_Pragma', b'__pragma', b'asm', b'__asm', b'__asm__',
              b'__builtin_unreachable', b'__builtin_trap', b'abort', b'exit',
              b'_Exit', b'quick_exit', b'longjmp', b'_longjmp', b'siglongjmp'}


def _code_tokens(body):
    return [token for token in _TOKENS.findall(body)
            if not token.startswith((b'/*', b'//', b'"', b"'"))]


def _reserved(token):
    return token.startswith((b'__CPROVER', b'__vulgate', b'vulgate_'))


def _qualify_body(body, *, original=False):
    try:
        body.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise SpecificationError('environment bodies must be UTF-8 C source') from exc
    # Translation-phase tricks must not turn an inspected token into another
    # identifier or a compiler directive when the .i file is compiled.
    inspected = LINE_MARKER.sub(b'', body) if original else body
    if b'\x00' in inspected or b'??' in inspected or re.search(rb'\\\r?\n', inspected):
        raise SpecificationError('environment body contains unsupported token encoding')
    tokens = _code_tokens(inspected)
    forbidden = [token for token in tokens if _reserved(token) or b'assert' in token.lower()
                 or b'assume' in token.lower() or token in _FORBIDDEN or token == b'#']
    if forbidden:
        kind = 'original environment function' if original else 'environment summary'
        raise SpecificationError(f'{kind} contains assertions, assumptions, reserved instrumentation or unsupported control: '
                                 + forbidden[0].decode('utf-8'))
    if not original:
        stripped = body.strip()
        if not stripped.startswith(b'{') or not stripped.endswith(b'}'):
            raise SpecificationError('environment summary must be one complete C compound statement')
        probe = b'void environment_body_probe(void) ' + stripped
        tree = syntax_tree(probe)
        children = [node for node in tree.root_node.named_children if node.type != 'comment']
        if (tree.root_node.has_error or len(children) != 1 or children[0].type != 'function_definition'
                or children[0].end_byte != len(probe)):
            raise SpecificationError('environment summary must contain only one function body')
        pending = list(children[0].named_children)
        while pending:
            node = pending.pop()
            if node.type == 'function_definition':
                raise SpecificationError('nested environment function definitions are unsupported')
            pending.extend(node.named_children)


@dataclass(frozen=True)
class FrozenSummary:
    specification: EnvironmentSummary
    start: int
    end: int
    original: bytes
    summary: bytes
    evidence: dict


def freeze_environment(task, snapshots, policies=()):
    """Freeze once on the original snapshots; later calls also check freshness."""
    requested = task.environment
    if any(not isinstance(item, EnvironmentSummary) for item in requested):
        raise SpecificationError('environment must contain typed function summary specifications')
    keys = [(item.translation_unit, item.function) for item in requested]
    if len(keys) != len(set(keys)):
        raise SpecificationError('duplicate environment function summary')
    policy_entries = {(policy.translation_unit, policy.function) for policy in policies}
    for item in requested:
        identifier(item.function)
        if (item.translation_unit not in task.sources or item.function == task.entry
                or _reserved(item.function.encode()) or (item.translation_unit, item.function) in policy_entries):
            raise SpecificationError('environment summary cannot replace a root, policy entry or reserved function')
        if not isinstance(item.assumption, str) or not item.assumption.strip():
            raise SpecificationError('environment summary requires an explicit nonempty assumption')
        if sum(snapshot['source'] == item.translation_unit for snapshot in snapshots) != 1:
            raise SpecificationError('environment function must bind exactly one task translation unit')
    evidence = []
    for snapshot in snapshots:
        selected = tuple(item for item in requested if item.translation_unit == snapshot['source'])
        existing = snapshot.get('_environment_summaries')
        if existing is not None and tuple(binding.specification for binding in existing) != selected:
            raise SpecificationError('environment configuration changed after freezing its source snapshot')
        if not selected and existing is None:
            continue
        source = snapshot['path'].read_bytes()
        if sha256(source) != snapshot['sha256']:
            raise SpecificationError('preprocessed source snapshot changed during environment qualification')
        if existing is None:
            definitions = functions(source)
            locations = function_locations(source, definitions)
            bindings = []
            for item in selected:
                matches = [function for function in definitions if function.name == item.function]
                if len(matches) != 1:
                    raise SpecificationError(f'environment requires exactly one definition of {item.function} in its translation unit')
                function = matches[0]
                start, end = function.body_start - 1, function.end
                original = source[start:end]
                summary = item.body_file.read_bytes()
                _qualify_body(original, original=True)
                _qualify_body(summary)
                signature = source[function.start:start]
                record = {**item.to_dict(), 'original_preprocessed_sha256': snapshot['sha256'],
                          'original_body': original.decode('utf-8'), 'original_body_sha256': sha256(original),
                          'summary_body': summary.decode('utf-8'), 'summary_body_sha256': sha256(summary),
                          'original_signature': signature.decode('utf-8'), 'signature_sha256': sha256(signature),
                          'function_sha256': sha256(source[function.start:end]),
                          'location': [{'file': filename, 'line': line} for filename, line in sorted(locations[item.function])],
                          'body_byte_range': [start, end],
                          'binding': 'original declaration, parameter scope and linkage retained; summary body compiled in place',
                          'equivalence': 'ASSUMED_NOT_PROVED'}
                bindings.append(FrozenSummary(item, start, end, original, summary, record))
            existing = tuple(bindings)
            snapshot['_environment_summaries'] = existing
        for binding in existing:
            if binding.specification.body_file.read_bytes() != binding.summary:
                raise SpecificationError('environment summary changed after its bytes were frozen')
            if source[binding.start:binding.end] != binding.original:
                raise SpecificationError('original environment function changed after qualification')
            evidence.append(binding.evidence)
    return evidence


def apply_environment(snapshot, source):
    """Replace only the previously qualified body spans in a frozen snapshot."""
    if sha256(source) != snapshot['sha256']:
        raise SpecificationError('environment replacement requires the original frozen source')
    for binding in sorted(snapshot.get('_environment_summaries', ()), key=lambda item: item.start, reverse=True):
        if binding.specification.body_file.read_bytes() != binding.summary:
            raise SpecificationError('environment summary changed before source replacement')
        if source[binding.start:binding.end] != binding.original:
            raise SpecificationError('environment source body no longer matches its qualified span')
        source = source[:binding.start] + binding.summary + source[binding.end:]
    return source


def environment_report(evidence):
    return {'conditional_on_environment': bool(evidence), 'environment': evidence,
            'environment_scope': ('All symbolic obligations use these assumed bodies. Original environment implementations '
                                  'and equivalence to them have not been proved.' if evidence else 'No supplied environment summaries.')}
