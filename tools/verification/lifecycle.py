"""Induction over closed persistent C state and separate ranking obligations.

The initializer and event function are real program functions. The induction
step starts from an arbitrary compiler-typed state satisfying a supplied
invariant, rather than enumerating a fixed number of events.
"""
from copy import deepcopy
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
import json
import re
from uuid import uuid4

from .backend import BackendError, CBMC, save_json
from .discovery import constant_value, integer_domain, pure_type, resolve_type, walk
from .engine import analyze, dependency_manifest, digest, prepare_variant
from .expression import compile_expression
from .shadow import private_havoc_target, symbol_name, typ
from .source import sha256
from .spec import SpecificationError, identifier


PREFIX = "vulgate_lifecycle_"
ROOT = PREFIX + "root"
PROPERTY = "vulgate.lifecycle."


@dataclass(frozen=True)
class Lifecycle:
    header: Path
    state_type: str
    initialize: str
    step: str
    invariant: dict
    active: dict | None = None
    rank: dict | None = None
    compile_from: Path | None = None

    def __post_init__(self):
        if not re.fullmatch(r"(?:struct )?[A-Za-z_][A-Za-z0-9_]*", self.state_type):
            raise SpecificationError("lifecycle state_type must be a typedef name or struct tag")
        for name in (self.initialize, self.step):
            identifier(name)
            if name.startswith((PREFIX, "__CPROVER", "__vulgate_")):
                raise SpecificationError("lifecycle function uses a reserved name")
        if self.initialize == self.step:
            raise SpecificationError("initializer and event function must be distinct")
        if (self.active is None) != (self.rank is None):
            raise SpecificationError("progress requires both active and rank expressions")
        for expression in (self.invariant, self.active, self.rank):
            if expression is not None and set(compile_expression(expression)[1]) - {"state"}:
                raise SpecificationError("lifecycle expressions may observe only state")

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        required = {"schema", "header", "state_type", "initialize", "step", "invariant"}
        if (not isinstance(data, dict) or not required <= set(data) or
                set(data) - required - {"active", "rank", "compile_from"} or data["schema"] != 1):
            raise SpecificationError("expected lifecycle schema 1")
        if any(not isinstance(data[key], str) for key in ("header", "state_type", "initialize", "step")):
            raise SpecificationError("lifecycle paths and function/type names must be strings")
        header = (path.parent / data["header"]).resolve()
        if not header.is_file():
            raise SpecificationError("lifecycle header does not exist")
        selected = data.get("compile_from")
        if selected is not None and not isinstance(selected, str):
            raise SpecificationError("compile_from must name a task source")
        return cls(header, data["state_type"], data["initialize"], data["step"], data["invariant"],
                   data.get("active"), data.get("rank"), (path.parent / selected).resolve() if selected else None)

    def to_dict(self):
        return {"header": str(self.header), "state_type": self.state_type, "initialize": self.initialize,
                "step": self.step, "invariant": self.invariant, "active": self.active, "rank": self.rank,
                "compile_from": str(self.compile_from) if self.compile_from else None}


def state_leaves(value, symbols, access="state", depth=0):
    """Enumerate actual integer leaves; padding is not persistent logical state."""
    if depth > 16 or not pure_type(value, symbols):
        raise SpecificationError("unsupported recursive, volatile or atomic lifecycle state")
    value = resolve_type(value, symbols)
    kind = value.get("id")
    if integer_domain(value) is not None:
        return [access]
    if kind == "c_enum":
        return state_leaves(value["sub"][0], symbols, access, depth+1)
    if kind == "array":
        size = constant_value(value.get("namedSub", {}).get("size", {}))
        if size is None or not 1 <= size <= 4096:
            raise SpecificationError("lifecycle state arrays require a fixed extent in 1..4096")
        leaves = [leaf for index in range(size) for leaf in
                  state_leaves(value["sub"][0], symbols, f"({access})[{index}]", depth+1)]
    elif kind == "struct":
        leaves = []
        for component in value.get("namedSub", {}).get("components", {}).get("sub", []):
            named = component.get("namedSub", {})
            if named.get("#is_padding", {}).get("id") == "1":
                continue
            name = named.get("name", {}).get("id", "")
            identifier(name)
            leaves.extend(state_leaves(named.get("type", {}), symbols, f"({access}).{name}", depth+1))
    else:
        raise SpecificationError(f"lifecycle persistent state does not yet support {kind or 'missing type'}")
    if not leaves or len(leaves) > 4096:
        raise SpecificationError("lifecycle state requires 1..4096 scalar leaves")
    return leaves


def frame_audit(functions, symbols, lifecycle, state_type):
    """Establish that each event's retained state is captured by its argument."""
    bodies = {f["name"]: f for f in functions}
    reasons, assumptions, visited, edges = set(), [], set(), {}
    queue = [lifecycle.initialize, lifecycle.step]
    for entry in queue:
        symbol = symbols.get(entry, {})
        signature = symbol.get("type", {})
        parameters = signature.get("namedSub", {}).get("parameters", {}).get("sub", [])
        if (not bodies.get(entry, {}).get("instructions") or symbol.get("isFileLocal") or
                signature.get("namedSub", {}).get("return_type", {}).get("id") != "empty" or len(parameters) != 1 or
                parameters[0].get("namedSub", {}).get("type", {}).get("id") != "pointer"):
            reasons.add(f"{entry} must define an externally visible void function with one state pointer")
        else:
            types = [parameters[0]["namedSub"]["type"]]
            types.extend(symbols.get(name, {}).get("type", {}) for name in bodies[entry].get("parameterIdentifiers", []))
            if any(value.get("id") != "pointer" or len(value.get("sub", [])) != 1 or
                   resolve_type(value["sub"][0], symbols) != resolve_type(state_type, symbols) for value in types):
                reasons.add(f"{entry} parameter type does not match the compiled state object")
    while queue:
        name = queue.pop()
        if name in visited or name.startswith("__vulgate_"):
            continue
        visited.add(name)
        body = bodies.get(name, {})
        if not body.get("instructions"):
            signature = symbols.get(name, {}).get("type", {})
            result = signature.get("namedSub", {}).get("return_type", {})
            parameters = signature.get("namedSub", {}).get("parameters", {}).get("sub", [])
            if name in ("malloc", "free"):
                continue  # Whole-event cleanup checks discharge these allocations.
            if name.startswith("nondet_") and not parameters and integer_domain(result) is not None:
                continue
            reasons.add(f"unframed external function {name}")
            continue
        writes, allocated = Counter(), set()
        for item in body["instructions"]:
            operands = item.get("code", {}).get("sub", [])
            if item["instructionId"] in ("ASSIGN", "FUNCTION_CALL") and operands:
                lhs = symbol_name(operands[0])
                if lhs:
                    writes[lhs] += 1
                    if (item["instructionId"] == "FUNCTION_CALL" and symbol_name(operands[1]) == "malloc" and
                            symbols.get(lhs, {}).get("isAuxiliary")):
                        allocated.add(lhs)
        allocated = {value for value in allocated if writes[value] == 1}

        def representation(value):
            if isinstance(value, dict):
                return {key: representation(item) for key, item in value.items() if not key.startswith("#")}
            if isinstance(value, list):
                return [representation(item) for item in value]
            return value

        for instruction in body["instructions"]:
            kind = instruction["instructionId"]
            if kind in ("START_THREAD", "END_THREAD", "ATOMIC_BEGIN", "ATOMIC_END") or (
                    kind == "OTHER" and private_havoc_target(instruction, symbols) is None):
                reasons.add(f"unframed event instruction {kind} in {name}")
            if kind == "ASSUME":
                assumptions.append({"function": name, "location": instruction.get("sourceLocation", {})})
            if kind == "FUNCTION_CALL":
                callee = instruction.get("code", {}).get("sub", [{}, {}])[1]
                if callee.get("id") != "symbol":
                    reasons.add(f"unresolved event call in {name}")
                else:
                    called = symbol_name(callee)
                    queue.append(called)
                    edges.setdefault(name, set()).add(called)
            for tree in (instruction.get("code", {}), instruction.get("guard", {})):
                for node in walk(tree):
                    node_type = typ(node)
                    if resolve_type(node_type, symbols).get("id") == "union":
                        reasons.add(f"event uses an unframed union representation in {name}")
                    if not pure_type(node_type, symbols) and node_type.get("id") not in ("empty", "nil", "code"):
                        reasons.add(f"volatile, atomic or unresolved event type in {name}")
                    operands = node.get("sub", [])
                    if (node.get("id") == "side_effect" and
                            node.get("namedSub", {}).get("statement", {}).get("id") == "nondet"):
                        try:
                            state_leaves(node_type, symbols)
                        except SpecificationError:
                            reasons.add(f"event obtains an unframed nondeterministic object in {name}")
                    if node.get("id") == "constant" and node_type.get("id") == "pointer":
                        value = node.get("namedSub", {}).get("value", {}).get("id", "")
                        if value not in ("NULL", "0"):
                            reasons.add(f"event contains an unframed pointer constant in {name}")
                    if node.get("id") == "typecast" and operands:
                        source, destination = typ(operands[0]).get("id"), node_type.get("id")
                        if (source == "pointer" and destination not in ("pointer", "bool", "c_bool") or
                                destination == "pointer" and source != "pointer" and constant_value(operands[0]) != 0):
                            reasons.add(f"event observes or fabricates pointer representation in {name}")
                        if source == destination == "pointer":
                            old = resolve_type(typ(operands[0]).get("sub", [{}])[0], symbols)
                            new = resolve_type(node_type.get("sub", [{}])[0], symbols)
                            fresh_allocation = old.get("id") == "empty" and symbol_name(operands[0]) in allocated
                            if new.get("id") != "empty" and not fresh_allocation and representation(old) != representation(new):
                                reasons.add(f"event uses unframed pointer reinterpretation in {name}")
                    if node.get("id") in ("pointer_object", "object_descriptor", "string_constant"):
                        reasons.add(f"unframed object representation in {name}")
                    if node.get("id") == "symbol":
                        ident = symbol_name(node)
                        symbol = symbols.get(ident, {})
                        if (symbol.get("isStaticLifetime") and node_type.get("id") != "code" and
                                not ident.startswith("__vulgate_")):
                            declared = symbol.get("type", {})
                            if declared.get("namedSub", {}).get("#constant", {}).get("id") != "1":
                                reasons.add(f"persistent object outside state: {ident}")
                            else:
                                try:
                                    state_leaves(declared, symbols)
                                except SpecificationError:
                                    reasons.add(f"unsupported constant global object: {ident}")
                    if node.get("id") == "address_of":
                        if any(symbols.get(symbol_name(child), {}).get("isStaticLifetime") and
                               typ(child).get("id") != "code" and not symbol_name(child).startswith("__vulgate_")
                               for child in walk(node)):
                            reasons.add(f"event exposes an address outside persistent state in {name}")
    event_functions, pending = set(), [lifecycle.step]
    while pending:
        name = pending.pop()
        if name not in event_functions:
            event_functions.add(name)
            pending.extend(edges.get(name, ()))
    return {"status": "CLOSED_STATE" if not reasons else "UNKNOWN", "reasons": sorted(reasons),
            "functions": sorted(visited), "environment_assumptions": assumptions,
            "event_assumptions": [item for item in assumptions if item["function"] in event_functions],
            "scope": "Sequential event state consists of the complete integer/aggregate state argument; "
                     "per-event allocations must be cleaned up before return."}


def harness(lifecycle, toolchain, phase, leaves=()):
    header = toolchain.path(lifecycle.header)
    if any(c in header for c in ('"', '\n', '\r')):
        raise SpecificationError("unsupported lifecycle header path")
    invariant = compile_expression(lifecycle.invariant)[0]
    lines = [f'#include "{header}"', f'typedef int {PREFIX}header_end;',
             'extern void __CPROVER_assert(_Bool, const char *);',
             'extern void __CPROVER_assume(_Bool);',
             f'extern void {lifecycle.initialize}({lifecycle.state_type} *);',
             f'extern void {lifecycle.step}({lifecycle.state_type} *);',
             f'extern {lifecycle.state_type} nondet_vulgate_lifecycle_state(void);',
             f'static void {PREFIX}observe(unsigned long long value) {{ }}',
             f'void {ROOT}(void) {{']
    if phase == "initiation":
        lines += [f'{lifecycle.state_type} state;', f'{lifecycle.initialize}(&state);']
    else:
        lines += [f'{lifecycle.state_type} state = nondet_vulgate_lifecycle_state();',
                  f'__CPROVER_assume({invariant});']
        if phase == "progress":
            active, rank = compile_expression(lifecycle.active)[0], compile_expression(lifecycle.rank)[0]
            lines += [f'__CPROVER_assume({active});',
                      f'__CPROVER_assert(1, "{PROPERTY}active");',
                      f'__CPROVER_assert(({rank}) >= 0, "{PROPERTY}rank_nonnegative");',
                      f'unsigned long long before = ({rank});']
        else:
            lines += [f'__CPROVER_assert(1, "{PROPERTY}domain");']
        lines += [f'{lifecycle.step}(&state);']
    lines += [f'{PREFIX}observe((unsigned long long)({leaf}));' for leaf in leaves]
    if phase == "progress":
        lines += [f'__CPROVER_assert(!({active}) || (({rank}) >= 0 && (unsigned long long)({rank}) < before), '
                  f'"{PROPERTY}descent");']
    else:
        lines += [f'__CPROVER_assert({invariant}, "{PROPERTY}{phase}");']
    lines += ['}']
    return "\n".join(lines) + "\n"


def header_digest(data):
    normalized = re.sub(rb'(?m)^\s*#\s+\d+[^\r\n]*[\r\n]*', b'', data)
    marker = f'typedef int {PREFIX}header_end;'.encode()
    if normalized.count(marker) != 1:
        raise SpecificationError("ambiguous compiled lifecycle header boundary")
    return sha256(normalized.split(marker)[0])


def qualify_harness(data, expected):
    """User headers may configure types, but cannot rewrite proof scaffolding."""
    normalized = re.sub(rb'(?m)^\s*#\s+\d+[^\r\n]*[\r\n]*', b'', data)
    marker = f'typedef int {PREFIX}header_end;'.encode()
    if normalized.count(marker) != 1:
        raise SpecificationError("ambiguous compiled lifecycle header boundary")
    header, body = normalized.split(marker)
    if PREFIX.encode() in header or PROPERTY.encode() in header:
        raise SpecificationError("state header uses the reserved lifecycle namespace")
    token = rb'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9]*|>>=|<<=|\.\.\.|\+\+|--|->|<<|>>|<=|>=|==|!=|&&|\|\||[+*/%&|^=-]=|\#\#|[^\s]'''
    expected_body = expected.encode().split(marker)[1]
    if re.findall(token, body) != re.findall(token, expected_body):
        raise SpecificationError("generated lifecycle harness changed during preprocessing")


def phase_task(task, lifecycle, source, phase):
    units = task.units
    if task.compilation_database is not None or task.units:
        from .build import load_units
        selected = lifecycle.compile_from or task.sources[0]
        unit = next((u for u in load_units(task) if u.source == selected), None)
        if unit is None:
            raise SpecificationError("compile_from must name a task source")
        units = (*units, {"source": str(source), "directory": str(unit.directory),
                         "compiler": unit.compiler, "flags": list(unit.preprocess_flags)})
    if phase == "initiation":
        targets = (PROPERTY + phase,)
    elif phase == "consecution":
        targets = (*task.targets, PROPERTY + "domain", PROPERTY + phase)
    else:
        targets = tuple(PROPERTY + key for key in ("active", "rank_nonnegative", "descent"))
    return replace(task, sources=(*task.sources, source), entry=ROOT, targets=targets, units=units)


def phase_status(report):
    query = report.get("protected", {})
    if report.get("conditional_on_environment") or query.get("conditional_on_environment"):
        return "UNKNOWN"
    qualification = report.get("pass_preservation", {}).get("qualification", {})
    if (query.get("completeness") != "COMPLETE_FOR_HARNESS" or query.get("initialization") == "UNKNOWN" or
            any(p["status"] != "QUALIFIED_STRUCTURE" for p in qualification.get("policies", []))):
        return "UNKNOWN"
    obligations = [query.get(key) for key in ("target", "contracts_and_runtime_checks", "initialization")]
    if "REFUTED" in obligations:
        return "REFUTED_OBLIGATION"
    if (all(status == "PROVED_FOR_HARNESS" for status in obligations) and
            report.get("pass_preservation", {}).get("status") == "PROVED_FOR_HARNESS" and
            report.get("nonvacuity", {}).get("status") == "ESTABLISHED_FOR_HARNESS"):
        return "PROVED_FOR_HARNESS"
    return "UNKNOWN"


def verify_lifecycle(task, toolchain, lifecycle, policies, output):
    task, lifecycle, policies = deepcopy((task, lifecycle, policies))
    output = Path(output).resolve()
    run = output / "runs" / uuid4().hex
    run.mkdir(parents=True)
    save_json(output / "status.json", {"status": "STARTED", "run": str(run)})
    phases, audit, dependencies = {}, None, None

    def finish(status, progress, reasons):
        report = {"schema": 1, "status": "UNKNOWN", "lifecycle_status": status, "progress_status": progress,
                  "conditional_on_environment": bool(task.environment),
                  "deployment_ready": False, "run": str(run), "contract": lifecycle.to_dict(), "phases": phases,
                  "policies": [p.to_dict() for p in policies], "policy_sha256": digest([p.to_dict() for p in policies]),
                  "state_audit": audit, "dependencies_sha256": digest(dependencies) if dependencies else None,
                  "reasons": reasons,
                  "scope": "Induction over any number of completed sequential calls of the declared event function. "
                           "The supplied invariant must include all initialized persistent state. "
                           "A failed induction/ranking obligation may use an unreachable invariant state; it is not a proof of an actual execution failure.",
                  "progress_assumptions": ["the event driver continues invoking steps while active",
                                           "persistent state is retained and changed only by the declared event",
                                           "no asynchronous mutation outside the declared state"],
                  "pending": ["runtime binding and deployment validation", "broader persistent heap/external-state support"]}
        save_json(run / "report.json", report)
        save_json(output / "report.json", report)
        save_json(output / "status.json", {"status": "COMPLETE", "run": str(run), "report_sha256": digest(report)})
        return report

    try:
        if task.environment:
            raise SpecificationError("environment summaries require separate induction/discovery qualification")
        if not task.memory_cleanup:
            raise SpecificationError("lifecycle qualification requires per-event memory cleanup checks")
        if lifecycle.compile_from is not None and lifecycle.compile_from not in task.sources:
            raise SpecificationError("compile_from must name a task source")
        if any(p.function == ROOT or p.translation_unit not in task.sources for p in policies):
            raise SpecificationError("lifecycle policies must bind original program functions")
        versions = toolchain.versions()
        base = CBMC(toolchain, task, run / "original")
        originals = base.preprocess()
        for snapshot in originals:
            data = snapshot["path"].read_bytes()
            if PREFIX.encode() in data or PROPERTY.encode() in data:
                raise SpecificationError("program uses the reserved lifecycle namespace")
        source_manifest = dependency_manifest(task, versions, originals)
        dependencies = {"program": source_manifest, "contract": lifecycle.to_dict()}
        save_json(run / "dependencies.json", dependencies)
        probe = run / "probe.c"
        probe_text = harness(lifecycle, toolchain, "initiation")
        probe.write_text(probe_text, encoding="utf-8")
        probing = phase_task(task, lifecycle, probe, "initiation")
        preprocessor = CBMC(toolchain, probing, run / "probe-preprocessed")
        snapshots = preprocessor.preprocess()
        qualify_harness(snapshots[-1]["path"].read_bytes(), probe_text)
        if probe.read_text(encoding="utf-8") != probe_text:
            raise SpecificationError("generated lifecycle source changed during the state audit")
        probe_dependencies = dependency_manifest(probing, versions, snapshots)
        if probe_dependencies["preprocessed"][:-1] != source_manifest["preprocessed"]:
            raise SpecificationError("program/build dependencies changed before the state audit")
        header_hash = header_digest(snapshots[-1]["path"].read_bytes())
        dependencies["header_preprocessed_sha256"] = header_hash
        save_json(run / "dependencies.json", dependencies)
        compiled, binary, _ = prepare_variant(probing, toolchain, snapshots, policies, run / "probe")
        functions, symbols = compiled.inspect(binary)
        state = [symbol["type"] for name, symbol in symbols.items()
                 if name.startswith(ROOT + "::") and symbol.get("baseName") == "state"]
        if len(state) != 1:
            raise SpecificationError("expected one compiler-bound persistent state object")
        leaves = state_leaves(state[0], symbols)
        audit = frame_audit(functions, symbols, lifecycle, state[0])
        audit["state_leaves"] = leaves
        save_json(run / "state-audit.json", audit)
        if audit["status"] != "CLOSED_STATE":
            return finish("UNKNOWN", "UNKNOWN" if lifecycle.rank is not None else "NOT_REQUESTED", audit["reasons"])
        for phase in ("initiation", "consecution", *(("progress",) if lifecycle.rank is not None else ())):
            source = run / (phase + ".c")
            source_text = harness(lifecycle, toolchain, phase, leaves)
            source.write_text(source_text, encoding="utf-8")
            derived = phase_task(task, lifecycle, source, phase)
            folder = run / phase
            checked = analyze(derived, toolchain, policies, folder)
            phases[phase] = {"status": phase_status(checked), "verification": str(folder / "report.json"),
                             "dependencies_sha256": checked.get("dependencies_sha256")}
            if not checked.get("dependencies_sha256"):
                return finish("UNKNOWN", "UNKNOWN", [f"{phase} has no dependency-bound evidence"])
            actual = json.loads((folder / "dependencies.json").read_text(encoding="utf-8"))
            generated = folder / "preprocessed" / f"unit-{len(task.sources):03}.i"
            qualify_harness(generated.read_bytes(), source_text)
            if source.read_text(encoding="utf-8") != source_text:
                raise SpecificationError("generated lifecycle source changed during verification")
            if ({key: actual[key] for key in ("toolchain", "implementation")} !=
                    {key: source_manifest[key] for key in ("toolchain", "implementation")} or
                    actual["preprocessed"][:-1] != source_manifest["preprocessed"] or
                    header_digest(generated.read_bytes()) != header_hash):
                return finish("UNKNOWN", "UNKNOWN", ["program/build/toolchain dependencies changed during induction"])
            if phase == "initiation" and phases[phase]["status"] != "PROVED_FOR_HARNESS":
                return finish("INITIATION_REFUTED" if phases[phase]["status"] == "REFUTED_OBLIGATION" else "UNKNOWN",
                              "UNKNOWN" if lifecycle.rank is not None else "NOT_REQUESTED", ["initializer did not establish the state invariant"])
        closed = phases["consecution"]["status"]
        status = {"PROVED_FOR_HARNESS": "PROVED_INDUCTIVELY", "REFUTED_OBLIGATION": "NOT_INDUCTIVE"}.get(closed, "UNKNOWN")
        progress = "NOT_REQUESTED"
        if lifecycle.rank is not None:
            progress = {"PROVED_FOR_HARNESS": "PROVED_DESCENT", "REFUTED_OBLIGATION": "RANKING_REFUTED"}.get(phases["progress"]["status"], "UNKNOWN")
            if status != "PROVED_INDUCTIVELY" or audit["event_assumptions"]:
                progress = "UNKNOWN"
        return finish(status, progress, ["event assumptions prevent a total progress claim"] if audit["event_assumptions"] and lifecycle.rank is not None else [])
    except (BackendError, SpecificationError, OSError, ValueError) as exc:
        return finish("UNKNOWN", "UNKNOWN" if lifecycle.rank is not None else "NOT_REQUESTED", [str(exc)])
