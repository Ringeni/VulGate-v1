"""Counterexample-guided synthesis of C-typed observation decision tables."""
from dataclasses import dataclass, replace
from copy import deepcopy
import json
from pathlib import Path
import re
from uuid import uuid4

from .backend import save_json
from .decisions import SearchLimit, solve
from .engine import analyze, digest
from .spec import SpecificationError, TablePolicy


@dataclass(frozen=True)
class Sketch:
    entries: tuple[TablePolicy, ...]
    max_rounds: int = 64
    solver_nodes: int = 100000

    def __post_init__(self):
        if not self.entries or len(self.entries) > 16:
            raise SpecificationError("a synthesis sketch requires 1..16 entries")
        if len({p.name for p in self.entries}) != len(self.entries) or len(
                {(p.translation_unit, p.function) for p in self.entries}) != len(self.entries):
            raise SpecificationError("sketch IDs and function entries must be unique")
        for value, limit in ((self.max_rounds, 10000), (self.solver_nodes, 10000000)):
            if type(value) is not int or not 1 <= value <= limit:
                raise SpecificationError("invalid synthesis search budget")

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data, path.parent)

    @classmethod
    def from_dict(cls, data, directory):
        if (not isinstance(data, dict) or set(data) - {"schema", "entries", "max_rounds", "solver_nodes"}
                or data.get("schema") != 1 or not isinstance(data.get("entries"), list)):
            raise SpecificationError("expected synthesis sketch schema 1")
        entries = []
        for item in data["entries"]:
            if not isinstance(item, dict) or set(item) != {"id", "translation_unit", "function", "predicates", "returns"}:
                raise SpecificationError("unsupported synthesis entry fields")
            if not isinstance(item["predicates"], list) or len(item["predicates"]) > 8:
                raise SpecificationError("at most 8 Boolean observation predicates per entry")
            entries.append(TablePolicy.from_dict({"id": item["id"], "translation_unit": item["translation_unit"],
                "function": item["function"], "table": {"predicates": item["predicates"], "returns": item["returns"],
                "decisions": [0] * (2**len(item["predicates"]))}}, Path(directory)))
        return cls(tuple(entries), data.get("max_rounds", 64), data.get("solver_nodes", 100000))

    def to_dict(self):
        return {"schema": 1, "max_rounds": self.max_rounds, "solver_nodes": self.solver_nodes,
                "entries": [{"id": p.name, "translation_unit": str(p.translation_unit), "function": p.function,
                             "predicates": list(p.predicates), "returns": list(p.return_actions)} for p in self.entries]}


def decision_variables(policies):
    return [(p.name, region) for p in policies for region in range(len(p.decisions))]


def trace_nogood(property_result, policies, qualification):
    """Use complete entry/decision pairs, otherwise exclude only this candidate.

Omitting a decision could overgeneralize a refutation. Missing/unknown values,
unmatched calls, partial evaluations and unsupported trace shapes therefore
fall back to the full candidate assignment, which is still a sound exclusion.
"""
    variables = decision_variables(policies)
    indices = {key: n for n, key in enumerate(variables)}
    candidate = tuple((indices[p.name, r], value) for p in policies for r, value in enumerate(p.decisions))
    by_id = {p.name: p for p in policies}
    owners = {function: item["policy_id"] for item in qualification["policies"]
              for function in item.get("compiled_functions", [])}
    names = {f"__vulgate_region_{p.name}": (p.name, "region") for p in policies}
    names.update({f"__vulgate_decision_{p.name}": (p.name, "decision") for p in policies})
    pending, regions, decisions, events = set(), {}, {}, []
    trace = property_result.get("trace", [])

    def fallback(reason):
        return candidate, {"method": "full_candidate", "reason": reason, "events": events}

    if not trace or trace[-1].get("stepType") != "failure":
        return fallback("missing complete failure trace")
    for step in trace:
        if step.get("thread", 0) != 0:
            return fallback("concurrent trace")
        kind = step.get("stepType")
        owner = owners.get(step.get("function", {}).get("identifier"))
        if owner is not None and kind == "function-call":
            if owner in pending:
                return fallback("nested call before an entry decision completed")
            pending.add(owner)
            regions.pop(owner, None)
        elif owner is not None and kind == "function-return" and owner in pending:
            return fallback("return without a recorded entry decision")
        if kind != "assignment" or step.get("hidden") or step.get("lhs") not in names:
            continue
        owner, role = names[step["lhs"]]
        binary = step.get("value", {}).get("binary", "")
        if not isinstance(binary, str) or re.fullmatch("[01]{1,64}", binary) is None:
            return fallback("unknown observation or decision value")
        value = int(binary, 2)
        if owner not in pending:
            return fallback("decision values without an entry call")
        if role == "region":
            regions[owner] = value
            continue
        policy, region = by_id[owner], regions.get(owner)
        if region is None or not 0 <= region < len(policy.decisions) or policy.decisions[region] != value:
            return fallback("decision trace does not match the compiled candidate")
        index = indices[owner, region]
        if index in decisions and decisions[index] != value:
            return fallback("inconsistent decisions for an observation region")
        decisions[index] = value
        events.append({"entry": owner, "region": region, "decision": value})
        pending.remove(owner)
    if pending or not events:
        return fallback("partial or missing entry evaluation trace")
    return tuple(sorted(decisions.items())), {"method": "decision_prefix", "events": events}


def synthesize(task, toolchain, sketch, output, *, expected_dependencies=None):
    task, sketch = deepcopy((task, sketch))
    output = Path(output).resolve()
    run = output / "runs" / uuid4().hex
    run.mkdir(parents=True)
    save_json(output / "status.json", {"status": "STARTED", "run": str(run)})
    input_spec = sketch.to_dict()
    save_json(run / "sketch.json", input_spec)
    variables = decision_variables(sketch.entries)
    sizes = [len(p.return_actions) + 1 for p in sketch.entries for _ in p.decisions]
    exclusions, rounds, dependencies = [], [], expected_dependencies
    accepted = None

    def finish(status, reasons):
        report = {"schema": 1, "status": "UNKNOWN", "synthesis_status": status, "reasons": reasons,
                  "conditional_on_environment": bool(task.environment),
                  "deployment_ready": False, "scope": "finite observation sketch and declared root harness",
                  "run": str(run), "variables": [{"entry": name, "region": region} for name, region in variables],
                  "sketch_sha256": digest(input_spec),
                  "domain_sizes": sizes, "dependencies_sha256": dependencies, "rounds": rounds,
                  "accepted_policies": accepted, "nogoods": exclusions,
                  "pending": ["inductive lifecycle/progress contracts", "runtime binding and deployment validation"]}
        save_json(run / "report.json", report)
        save_json(output / "report.json", report)
        save_json(output / "status.json", {"status": "COMPLETE", "report_sha256": digest(report), "run": str(run)})
        return report

    if task.environment:
        return finish("UNKNOWN", ["environment summaries require separate policy-generation qualification"])
    for iteration in range(sketch.max_rounds):
        try:
            assignment, nodes = solve(sizes, exclusions, sketch.solver_nodes)
        except SearchLimit as exc:
            return finish("UNKNOWN", [str(exc)])
        if assignment is None:
            return finish("INFEASIBLE_FOR_SKETCH", ["all decision tables contradict verified refutations"])
        offset, policies = 0, []
        for entry in sketch.entries:
            count = len(entry.decisions)
            policies.append(replace(entry, decisions=tuple(assignment[offset:offset + count])))
            offset += count
        folder = run / f"round-{iteration:04}"
        save_json(folder / "policies.json", {"schema": 1, "policies": [p.to_dict() for p in policies]})
        report = analyze(task, toolchain, policies, folder / "verification", action_cache=output / "action_cache")
        record = {"iteration": iteration, "decisions": assignment, "solver_nodes": nodes,
                  "verification": str(folder / "verification/report.json"), "feedback": []}
        rounds.append(record)
        current = report.get("dependencies_sha256")
        if current is None:
            return finish("UNKNOWN", report.get("reasons", ["verification did not complete"]))
        if dependencies is not None and dependencies != current:
            return finish("UNKNOWN", ["program, contracts, implementation or toolchain changed during synthesis"])
        dependencies = current
        query = report["protected"]
        qualification = report["pass_preservation"]["qualification"]
        if (query["completeness"] != "COMPLETE_FOR_HARNESS" or
                any(p["status"] != "QUALIFIED_STRUCTURE" for p in qualification["policies"]) or
                query["initialization"] == "UNKNOWN"):
            return finish("UNKNOWN", ["incomplete semantics or unsupported observation/initialization evidence"])
        if report["nonvacuity"]["status"] != "ESTABLISHED_FOR_HARNESS":
            return finish("UNKNOWN", ["original target-site non-vacuity was not established"])
        if (all(query[key] == "PROVED_FOR_HARNESS" for key in ("target", "contracts_and_runtime_checks", "initialization"))
                and report["pass_preservation"]["status"] == "PROVED_FOR_HARNESS"):
            path = run / "policies.json"
            payload = {"schema": 1, "policies": [p.to_dict() for p in policies]}
            save_json(path, payload)
            accepted = {"path": str(path), "sha256": digest(payload), "verification": record["verification"]}
            accepted["conditional_actions"] = [{
                "entry": p.name, "region": region,
                "action": {"kind": "PASS"} if decision == 0 else {"kind": "RETURN", "value": p.return_actions[decision - 1]},
                "reachability": query["reachability"].get(f"__VG_REACH_REGION:{p.name}:{region}", "UNKNOWN"),
                "scope": "selected joint policy under the declared harness; alternative decisions are not certified",
            } for p in policies for region, decision in enumerate(p.decisions)]
            return finish("SOLVED_FOR_HARNESS", [])
        failures = [p for p in query["properties"] if p["status"] == "FAILURE" and
                    not p.get("description", "").startswith("__VG_REACH_")]
        if not failures:
            return finish("UNKNOWN", ["remaining obligations lack refutations usable for refinement"])
        for failure in failures:
            clause, explanation = trace_nogood(failure, policies, qualification)
            # JSON-friendly lists are also accepted by the finite-domain solver.
            stored = [list(item) for item in clause]
            if stored not in exclusions:
                exclusions.append(stored)
            record["feedback"].append({"property": failure["property"], "description": failure["description"],
                                       "nogood": stored, **explanation})
        save_json(folder / "feedback.json", record)
    # Establish infeasibility even when the last allowed round supplied the
    # final conflict; a budget limit alone never establishes it.
    try:
        assignment, _ = solve(sizes, exclusions, sketch.solver_nodes)
    except SearchLimit as exc:
        return finish("UNKNOWN", [str(exc)])
    return finish("INFEASIBLE_FOR_SKETCH" if assignment is None else "UNKNOWN",
                  ["all decision tables contradict verified refutations" if assignment is None else "synthesis round limit reached"])
