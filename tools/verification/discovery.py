"""Compiler-derived entry, observation and return-action proposals.

Discovery proposes a finite search space; it never certifies a policy. All
expressions and actions are compiled and checked again by whole-policy synthesis.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass
import json
from itertools import islice
from pathlib import Path
import re
from uuid import uuid4

from .backend import BackendError, CBMC, save_json
from .engine import compiler_call_graph, dependency_manifest, digest, prepare_variant
from .expression import compile_expression
from .entry_context import entry_conditions, visible_globals
from .shadow import symbol_name, typ
from .source import file_scope_declarations, function_locations, functions as source_functions
from .spec import SpecificationError, identifier


@dataclass(frozen=True)
class DiscoveryOptions:
    max_distance: int = 3
    max_entries: int = 8
    max_predicates: int = 8
    max_actions: int = 8
    field_depth: int = 2
    array_elements: int = 4
    max_leaves: int = 64
    max_globals: int = 32
    call_depth: int = 2
    flow_steps: int = 512

    def __post_init__(self):
        for name, limit in (("max_distance", 64), ("max_entries", 16), ("max_predicates", 8),
                            ("max_actions", 16), ("field_depth", 4), ("array_elements", 32),
                            ("max_leaves", 512), ("max_globals", 1024), ("call_depth", 8), ("flow_steps", 100000)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= limit:
                raise SpecificationError(f"discovery {name} must be in 1..{limit}")

    @classmethod
    def load(cls, path=None):
        if path is None:
            return cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) - {"schema", *cls.__dataclass_fields__} or data.get("schema") != 1:
            raise SpecificationError("expected discovery options schema 1")
        return cls(**{k: v for k, v in data.items() if k != "schema"})


def resolve_type(value, symbols):
    seen = set()
    while value.get("id") in ("struct_tag", "union_tag", "c_enum_tag"):
        name = value.get("namedSub", {}).get("identifier", {}).get("id")
        if name in seen or name not in symbols:
            return {}
        seen.add(name)
        value = symbols[name].get("type", {})
    return value


def integer_domain(value):
    kind = value.get("id")
    if kind in ("bool", "c_bool"):
        return 0, 1
    if kind not in ("signedbv", "unsignedbv"):
        return None
    try:
        width = int(value["namedSub"]["width"]["id"])
    except (KeyError, ValueError):
        return None
    if not 1 <= width <= 64:
        return None
    return (-(2**(width-1)), 2**(width-1)-1) if kind == "signedbv" else (0, 2**width-1)


def constant_value(node):
    """Interpret typed IR integer literals, including constant casts/negation."""
    kind, operands = node.get("id"), node.get("sub", [])
    if kind in ("unary-", "typecast") and len(operands) == 1:
        value = constant_value(operands[0])
        if value is None:
            return None
        if kind == "unary-":
            value = -value
        domain = integer_domain(typ(node))
        if domain is None:
            return None
        if typ(node).get("id") in ("bool", "c_bool"):
            return int(bool(value))
        lower, upper = domain
        return (value - lower) % (upper-lower+1) + lower
    if kind != "constant":
        return None
    value = node.get("namedSub", {}).get("value", {}).get("id")
    domain = integer_domain(typ(node))
    if domain is None or not isinstance(value, str):
        return None
    if typ(node).get("id") == "bool":
        return {"true": 1, "false": 0, "1": 1, "0": 0}.get(value)
    try:
        base = int(node.get("namedSub", {}).get("#base", {}).get("id", "16"))
    except ValueError:
        return None
    if base not in (2, 8, 10, 16):
        return None
    try:
        raw = int(value, base)
    except ValueError:
        return None
    lower, upper = domain
    return (raw - lower) % (upper-lower+1) + lower


def walk(expression):
    yield expression
    for operand in expression.get("sub", []):
        yield from walk(operand)


def pure_type(value, symbols):
    resolved = resolve_type(value, symbols)
    return bool(resolved) and not any(t.get("namedSub", {}).get(q, {}).get("id") == "1"
                                     for t in (value, resolved) for q in ("#volatile", "#atomic"))


def op(name, *args):
    return {"op": name, "args": list(args)}


def guarded(expression, prerequisites):
    for requirement in reversed(list({digest(p): p for p in prerequisites}.values())):
        expression = op("&&", requirement, expression)
    return expression


def translate(expression, parameters, symbols):
    """Translate entry-visible IR reads; preserve only lossless numeric casts."""
    kind, operands = expression.get("id"), expression.get("sub", [])
    value_type = typ(expression)
    if not pure_type(value_type, symbols):
        return None
    constant = constant_value(expression)
    if constant is not None:
        return ({"const": constant}, []) if -(2**63) <= constant < 2**63 else None
    if kind == "symbol" and symbol_name(expression) in parameters:
        return {"var": parameters[symbol_name(expression)]}, []
    if kind == "typecast" and len(operands) == 1:
        child = translate(operands[0], parameters, symbols)
        if child is None:
            return None
        if value_type.get("id") in ("bool", "c_bool"):
            return op("!", op("!", child[0])), child[1]
        source, destination = integer_domain(typ(operands[0])), integer_domain(value_type)
        if source and destination and destination[0] <= source[0] <= source[1] <= destination[1]:
            return child
        return None
    children = [translate(child, parameters, symbols) for child in operands]
    if any(child is None for child in children):
        return None
    requirements = [p for child in children for p in child[1]]
    values = [child[0] for child in children]
    if kind == "dereference" and len(values) == 1:
        return op("*", values[0]), [*requirements, op("!=", values[0], {"const": 0})]
    if kind == "member" and len(values) == 1:
        field = expression.get("namedSub", {}).get("component_name", {}).get("id")
        try:
            identifier(field)
        except SpecificationError:
            return None
        return {"base": values[0], "field": field, "pointer": False}, requirements
    if kind == "index" and len(values) == 2:
        array = resolve_type(typ(operands[0]), symbols)
        extent = constant_value(array.get('namedSub', {}).get('size', {})) if array.get('id') == 'array' else None
        if extent is None or not 0 < extent < 2**63:
            return None
        bounds = [op('>=', values[1], {'const': 0}), op('<', values[1], {'const': extent})]
        return {"base": values[0], "index": values[1]}, [*requirements, *bounds]
    mapping = {"=": "==", "notequal": "!=", "and": "&&", "or": "||", "not": "!", "unary-": "-",
               "bitnot": "~", "mod": "%", "bitand": "&", "bitor": "|", "bitxor": "^",
               "shl": "<<", "lshr": ">>", "ashr": ">>"}
    operator = mapping.get(kind, kind)
    if operator in ("!", "~", "-") and len(values) == 1:
        return op(operator, *values), requirements
    if operator in ("==", "!=", "<", "<=", ">", ">=", "&&", "||", "+", "-", "*", "/", "%",
                    "&", "|", "^", "<<", ">>") and len(values) >= 2:
        result = values[0]
        for value in values[1:]:
            result = op(operator, result, value)
        return result, requirements
    return None


def parameter_leaves(expression, value_type, symbols, depth, prerequisites=(), array_elements=4):
    if not pure_type(value_type, symbols):
        return
    value_type = resolve_type(value_type, symbols)
    if integer_domain(value_type) is not None or value_type.get("id") == "pointer":
        yield expression, value_type, list(prerequisites)
    if depth == 0:
        return
    if value_type.get("id") == "pointer" and value_type.get("sub"):
        target = value_type["sub"][0]
        if resolve_type(target, symbols).get("id") in ("struct", "array"):
            yield from parameter_leaves(op("*", expression), target, symbols, depth-1,
                                        (*prerequisites, op("!=", expression, {"const": 0})), array_elements)
    elif value_type.get("id") == "struct":
        for component in value_type.get("namedSub", {}).get("components", {}).get("sub", []):
            named = component.get("namedSub", {})
            name = named.get("name", {}).get("id")
            try:
                identifier(name)
            except SpecificationError:
                continue
            field = {"base": expression, "field": name, "pointer": False}
            yield from parameter_leaves(field, named.get("type", {}), symbols, depth-1, prerequisites, array_elements)
    elif value_type.get('id') == 'array' and value_type.get('sub'):
        extent = constant_value(value_type.get('namedSub', {}).get('size', {}))
        if extent is not None and extent > 0:
            for index in range(min(extent, array_elements)):
                yield from parameter_leaves({'base': expression, 'index': {'const': index}}, value_type['sub'][0],
                                            symbols, depth-1, prerequisites, array_elements)


def catalog(task, snapshots, compiled, symbols, options):
    owners = {f["name"] for f in compiled for i in f.get("instructions", [])
              if i["instructionId"] == "ASSERT" and i.get("sourceLocation", {}).get("comment") in task.targets}
    if not owners:
        raise SpecificationError("no compiled target assertion sites for discovery")
    graph = compiler_call_graph(compiled, symbols, sorted(owners), options.max_distance)
    by_name = {f["name"]: f for f in compiled}
    definitions, locations, declarations, context = {}, {}, {}, []
    for index, snapshot in enumerate(snapshots):
        source = snapshot["path"].read_bytes()
        declarations[index] = file_scope_declarations(source)
        parsed = source_functions(source)
        locations[index] = function_locations(source, parsed)
        for function in parsed:
            definitions[index, function.name] = function
    expressions = [i.get(key, {}) for f in compiled if not f["name"].startswith(("__CPROVER", "__vulgate_"))
                   for i in f.get("instructions", []) for key in ("guard", "code")]
    constants = sorted({value for e in expressions for n in walk(e) if (value := constant_value(n)) is not None
                        and -(2**63) <= value < 2**63}, key=lambda n: (abs(n), n))
    candidates, excluded, truncations = [], [], []
    for candidate in sorted(graph["candidates"], key=lambda c: (c["distance"], c["symbol"])):
        name, symbol = candidate["name"], candidate["symbol"]
        reason = None
        module = re.fullmatch(r"unit-(\d+)", candidate.get("module") or "")
        location = candidate.get('location', {})
        point = (location.get('file'), int(location.get('line', '-1')))
        possible = [i for i in range(len(snapshots)) if point in locations[i].get(name, set())]
        # A linked external symbol may keep its first declaration's module.
        # File-local functions still need the module to distinguish identical
        # header definitions in different translation units.
        if symbols.get(symbol, {}).get('isFileLocal'):
            possible = [i for i in possible if module and i == int(module[1])]
        index = possible[0] if len(possible) == 1 else -1
        if index < 0:
            reason = "compiled function cannot be bound unambiguously to an input translation unit"
        elif name == task.entry:
            reason = "root harness is an environment specification, not an automatic gate candidate"
        returned = resolve_type(candidate.get("type", {}).get("namedSub", {}).get("return_type", {}), symbols)
        domain = integer_domain(returned)
        if not reason and domain is None and returned.get("id") not in ("empty", "pointer"):
            reason = "return type is outside automatic integer/void/null-pointer action discovery"
        if reason:
            excluded.append({"symbol": symbol, "reason": reason})
            continue
        parameters, types = {}, {}
        for parameter in candidate["type"].get("namedSub", {}).get("parameters", {}).get("sub", []):
            named = parameter.get("namedSub", {})
            parameter_name = named.get("#base_name", {}).get("id")
            try:
                identifier(parameter_name)
            except SpecificationError:
                continue
            parameters[named.get("#identifier", {}).get("id")] = parameter_name
            types[parameter_name] = named.get("type", {})
        globals_found, globals_excluded = visible_globals(declarations[index], definitions[index, name].start,
                                                         f'unit-{index:03}', parameters, symbols)
        globals_excluded.extend({'name': value['name'], 'symbol': key, 'reason': 'qualified or unsupported observation type'}
                                for key, value in globals_found.items() if not pure_type(value['type'], symbols))
        globals_found = {key: value for key, value in globals_found.items() if pure_type(value['type'], symbols)}
        relevant_functions, frontier = {symbol}, {symbol}
        for _ in range(options.call_depth):
            frontier = {edge['callee'] for edge in graph['edges'] if edge['caller'] in frontier} - relevant_functions
            relevant_functions.update(frontier)
        referenced = {symbol_name(node) for owner in relevant_functions
                      for item in by_name.get(owner, {}).get('instructions', [])
                      for key in ('guard', 'code') for node in walk(item.get(key, {})) if node.get('id') == 'symbol'}
        globals_found = dict(sorted(globals_found.items(), key=lambda pair: (pair[0] not in referenced, pair[1]['name'])))
        if len(globals_found) > options.max_globals:
            truncations.append({'symbol': symbol, 'globals_proposed': len(globals_found), 'globals_selected': options.max_globals})
        globals_found = dict(list(globals_found.items())[:options.max_globals])
        bindings = {**parameters, **{key: value['name'] for key, value in globals_found.items()}}
        predicates, seen = [], set()

        def propose(expression, origin):
            try:
                _, names = compile_expression(expression)
            except SpecificationError:
                return
            # A predicate and its negation induce the same observation partition.
            partition = expression
            while partition.get("op") == "!" and len(partition.get("args", [])) == 1:
                partition = partition["args"][0]
            if (partition.get("op") in ("==", "!=") and len(partition.get("args", [])) == 2 and
                    partition["args"][1] == {"const": 0}):
                partition = partition["args"][0]
            key = digest(partition)
            if names and key not in seen:
                predicates.append({"expression": expression, "origin": origin})
                seen.add(key)

        instructions = by_name[symbol].get("instructions", [])
        conditions, flow_omissions = entry_conditions(symbol, compiled, symbols, bindings, options, task.entry)
        ordered = sorted(conditions, key=lambda item: item['location'].get('comment') not in task.targets)
        for condition in ordered:
            for expression in walk(condition['expression']):
                if expression.get("id") not in ("=", "notequal", "<", "<=", ">", ">=", "and", "or", "not"):
                    continue
                translated = translate(expression, bindings, symbols)
                if translated is not None:
                    propose(guarded(*translated), {"kind": "interprocedural_condition" if condition['calls'] else "compiled_condition",
                            'location': condition['location'], 'function': condition['function'], 'calls': condition['calls']})
        visible_types = {**types, **{value['name']: value['type'] for value in globals_found.values()}}
        leaves = list(islice((leaf for variable, value_type in visible_types.items()
                             for leaf in parameter_leaves({'var': variable}, value_type, symbols, options.field_depth,
                                                          array_elements=options.array_elements)), options.max_leaves + 1))
        if len(leaves) > options.max_leaves:
            truncations.append({'symbol': symbol, 'reason': 'observable leaf budget exhausted', 'leaves_selected': options.max_leaves})
            leaves = leaves[:options.max_leaves]
        # Observe different inputs before spending the finite basis on thresholds
        # of the first parameter alone.
        for leaf, leaf_type, requirements in leaves:
            propose(guarded(op("!=", leaf, {"const": 0}), requirements), {"kind": "entry_value_truth"})
        for value in constants[:16]:
            for leaf, leaf_type, requirements in leaves:
                if leaf_type.get("id") != "pointer":
                    for relation in ("==", ">"):
                        propose(guarded(op(relation, leaf, {"const": value}), requirements), {"kind": "entry_value_constant", "value": value})
        own_returns = [constant_value(i.get("code", {}).get("sub", [{}])[0]) for i in instructions
                       if i["instructionId"] == "SET_RETURN_VALUE" and i.get("code", {}).get("sub")]
        if returned.get("id") == "pointer":
            actions = [0]
        elif domain is None:
            actions = [None]
        else:
            choices = [*sorted({x for x in own_returns if x is not None and x < 0}), -1,
                       *own_returns, 0, 1, *constants]
            actions = list(dict.fromkeys(v for v in choices if v is not None and
                                         domain[0] <= v <= domain[1] and -(2**63) <= v < 2**63))
        if len(predicates) > options.max_predicates or len(actions) > options.max_actions:
            truncations.append({"symbol": symbol, "predicates_proposed": len(predicates), "actions_proposed": len(actions)})
        candidates.append({**candidate, "id": f"entry_{index}_{name}", "translation_unit": str(snapshots[index]["source"]),
                           'definition_module': f'unit-{index:03}',
                           "parameters": types, "predicates": predicates[:options.max_predicates],
                           'globals': globals_found, 'global_exclusions': globals_excluded, 'flow_omissions': flow_omissions,
                           "returns": actions[:options.max_actions], "qualification": "UNVERIFIED_PROPOSALS"})
    if len(candidates) > options.max_entries:
        truncations.append({"entries_proposed": len(candidates), "entries_selected": options.max_entries})
    candidates = candidates[:options.max_entries]
    # Excerpts support generators; compiled snapshots, not these excerpts, are proof inputs.
    remaining = 512 * 1024
    selected = {(c["translation_unit"], c["name"]) for c in candidates}
    for index, snapshot in enumerate(snapshots):
        source = snapshot["path"].read_bytes()
        for (unit, name), function in definitions.items():
            if unit != index or ((str(snapshot["source"]), name) not in selected and name != task.entry):
                continue
            body = source[function.start:function.end]
            excerpt = body[:min(65536, remaining)]
            remaining -= len(excerpt)
            context.append({"translation_unit": str(snapshot["source"]), "function": name,
                            "source": excerpt.decode("utf-8", errors="replace"), "truncated": len(excerpt) != len(body)})
    return {"candidates": candidates, "excluded": excluded, "truncations": truncations, "graph": graph, "context": context}


def discover(task, toolchain, output, options=None):
    task = deepcopy(task)
    options = options or DiscoveryOptions()
    output = Path(output).resolve()
    run = output / "runs" / uuid4().hex
    run.mkdir(parents=True)
    save_json(output / "status.json", {"status": "STARTED", "run": str(run)})
    report = {"schema": 1, "status": "UNKNOWN", "discovery_status": "UNKNOWN", "deployment_ready": False,
              "conditional_on_environment": bool(task.environment),
              "run": str(run), "options": asdict(options), "reasons": []}
    try:
        if task.environment:
            raise SpecificationError("environment summaries require separate induction/discovery qualification")
        versions = toolchain.versions()
        snapshots = CBMC(toolchain, task, run / "preprocessed").preprocess()
        dependencies = dependency_manifest(task, versions, snapshots)
        save_json(run / "dependencies.json", dependencies)
        backend, binary, _ = prepare_variant(task, toolchain, snapshots, [], run / "compiled")
        compiled, symbols = backend.inspect(binary)
        report.update(catalog(task, snapshots, compiled, symbols, options))
        report.update(discovery_status="DISCOVERED", dependencies_sha256=digest(dependencies))
        save_json(run / "symbols.json", symbols)
        save_json(run / "functions.json", compiled)
    except (BackendError, SpecificationError, OSError, ValueError) as exc:
        report["reasons"].append(str(exc))
    save_json(run / "report.json", report)
    save_json(output / "report.json", report)
    save_json(output / "status.json", {"status": "COMPLETE", "run": str(run), "report_sha256": digest(report)})
    return report
