"""Verification orchestration over compiled C, with content-bound action reuse."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path

from . import implementation_dependencies
from .backend import CBMC, BackendError, save_json
from .environment import apply_environment, environment_report, freeze_environment
from .family import family_evidence
from .observation import nonvacuity, pass_evidence, qualify
from .source import family_state, instrument, sha256
from .spec import FamilyPolicy, Policy, SpecificationError


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def dependency_manifest(task, versions, snapshots):
    environment = freeze_environment(task, snapshots)
    return {"task": task.semantic_spec(), "toolchain": versions,
            "preprocessed": [{"source": str(s["source"]), "sha256": s["sha256"],
                              **({"build": s["build"]} if "build" in s else {})} for s in snapshots],
            "implementation": implementation_dependencies(),
            **({"environment": environment} if environment else {})}


def compiler_call_graph(functions, symbols, targets, max_distance=3):
    edges, open_calls = [], []
    for function in functions:
        for instruction in function.get("instructions", []):
            if instruction.get("instructionId") != "FUNCTION_CALL":
                continue
            operands = instruction.get("code", {}).get("sub", [])
            if len(operands) < 2:
                open_calls.append({"caller": function["name"], "reason": "unknown call encoding"})
                continue
            callee = operands[1]
            if callee.get("id") == "symbol":
                name = callee.get("namedSub", {}).get("identifier", {}).get("id")
                if name:
                    edges.append({"caller": function["name"], "callee": name,
                                  "location": instruction.get("sourceLocation", {})})
                    continue
            open_calls.append({"caller": function["name"], "location": instruction.get("sourceLocation", {}),
                               "expression": callee})
    distance = {target: 0 for target in targets}
    queue = list(distance)
    for callee in queue:
        if distance[callee] >= max_distance:
            continue
        for edge in edges:
            if edge["callee"] == callee and edge["caller"] not in distance:
                distance[edge["caller"]] = distance[callee] + 1
                queue.append(edge["caller"])
    candidates = []
    for name in queue:
        symbol = symbols.get(name, {})
        if name.startswith("__CPROVER"):
            continue
        candidates.append({"symbol": name, "name": symbol.get("baseName", name), "distance": distance[name],
                           "location": symbol.get("location", {}), "type": symbol.get("type", {}),
                           "module": symbol.get("module"), "position": "entry"})
    return {"edges": edges, "unresolved_calls": open_calls, "candidates": candidates,
            "graph_source": "compiled CBMC GOTO", "max_distance": max_distance}


def prepare_variant(task, toolchain, snapshots, policies, folder, nondeterministic=False, pass_only=False):
    backend = CBMC(toolchain, task, folder)
    backend.environment_evidence = freeze_environment(task, snapshots, policies)
    paths, bindings, roots = [], [], 0
    initialize_family = any(isinstance(p, FamilyPolicy) and p.selection == "fixed_table" for p in policies)
    for index, snapshot in enumerate(snapshots):
        selected = [p for p in policies if p.translation_unit == snapshot["source"]]
        frozen = snapshot["path"].read_bytes()
        if sha256(frozen) != snapshot["sha256"]:
            raise SpecificationError("preprocessed source snapshot changed before compilation")
        data, bound, found = instrument(apply_environment(snapshot, frozen), selected, task.entry, True,
                                      nondeterministic, pass_only, initialize_family)
        destination = folder / f"unit-{index:03}.i"
        destination.write_bytes(data)
        paths.append(destination)
        bindings.extend(bound)
        roots += found
    if roots != 1:
        raise SpecificationError(f"expected one root function definition, found {roots}")
    state = folder / "verification-state.c"
    state.write_text("_Bool __vulgate_blocked = 0;\n"
                     "extern void __CPROVER_havoc_object(void *);\n"
                     "_Bool __vulgate_choose(void) {\n"
                     "  _Bool value = 0; __CPROVER_havoc_object(&value); return value;\n}\n"
                     "_Bool __vulgate_literal_probe(const void *object) { return 0; }\n"
                     "void __vulgate_shadow_template(int *object) {\n"
                     "  __CPROVER_field_decl_local(\"vulgate_uninitialized\", (_Bool)1);\n"
                     "  __CPROVER_field_decl_global(\"vulgate_uninitialized\", (_Bool)1);\n"
                     "  _Bool dirty = __CPROVER_get_field(object, \"vulgate_uninitialized\");\n"
                     "  _Bool literal = __vulgate_literal_probe(object);\n"
                     "  __CPROVER_assert(!dirty, \"vulgate.initialized_read\");\n"
                     "  __CPROVER_set_field(object, \"vulgate_uninitialized\", (_Bool)0);\n"
                     "}\n" + family_state(policies), encoding="utf-8")
    binary = backend.compile([*paths, state], units=snapshots)
    return backend, binary, bindings


def analyze(task, toolchain, policies, output, *, action_cache=None):
    task, policies = deepcopy((task, policies))
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    save_json(output / "status.json", {"status": "STARTED"})
    try:
        return _analyze(task, toolchain, policies, output, action_cache)
    except (BackendError, SpecificationError, OSError, ValueError) as exc:
        report = {"status": "UNKNOWN", "reasons": [str(exc)], "deployment_ready": False,
                  "conditional_on_environment": bool(task.environment)}
        save_json(output / "report.json", report)
        save_json(output / "status.json", {"status": "FAILED", "reason": str(exc)})
        return report


def _analyze(task, toolchain, policies, output, action_cache):
    if len({p.name for p in policies}) != len(policies) or len({(p.translation_unit, p.function) for p in policies}) != len(policies):
        raise SpecificationError("policy IDs and entry bindings must be unique")
    for policy in policies:
        if policy.translation_unit not in task.sources:
            raise SpecificationError(f"policy {policy.name} refers to a translation unit outside the task")
    versions = toolchain.versions()
    preprocessing = CBMC(toolchain, task, output / "preprocessed")
    snapshots = preprocessing.preprocess()
    dependencies = dependency_manifest(task, versions, snapshots)
    environment = freeze_environment(task, snapshots, policies)
    save_json(output / "dependencies.json", dependencies)
    baseline_backend, binary, _ = prepare_variant(task, toolchain, snapshots, [], output / "baseline")
    baseline = baseline_backend.check(binary)
    functions, symbols = baseline_backend.inspect(binary)
    owners = {function["name"] for function in functions for instruction in function.get("instructions", [])
              if instruction["instructionId"] == "ASSERT" and
              instruction.get("sourceLocation", {}).get("comment") in task.targets}
    graph = compiler_call_graph(functions, symbols, owners)
    if environment:
        excluded_names = {item.function for item in task.environment}
        graph['environment_excluded_candidates'] = [candidate for candidate in graph['candidates']
                                                     if candidate['name'] in excluded_names]
        graph['candidates'] = [candidate for candidate in graph['candidates'] if candidate['name'] not in excluded_names]
        graph['conditional_on_environment'] = True
    save_json(output / "candidates.json", graph)
    actions = []
    for policy, return_value in ((p, value) for p in policies for value in p.return_actions):
        action = {"translation_unit": str(policy.translation_unit), "function": policy.function,
                  "return": return_value}
        key = digest({"dependencies": dependencies, "action": action, "choice": "nondeterministic_each_entry"})
        cache_file = (Path(action_cache) if action_cache is not None else output / "action_cache") / (key + ".json")
        evidence = None
        if cache_file.is_file():
            try:
                envelope = json.loads(cache_file.read_text(encoding="utf-8"))
                if (envelope["sha256"] == digest(envelope["payload"]) and envelope["payload"]["key"] == key
                        and envelope["payload"]["query"]["completeness"] == "COMPLETE_FOR_HARNESS"
                        and envelope["payload"]["contract_status"] != "UNKNOWN"
                        and envelope["payload"]["initialization_status"] != "UNKNOWN"):
                    evidence = envelope["payload"]
            except (ValueError, KeyError, TypeError):
                pass
        hit = evidence is not None
        if evidence is None:
            # Nondeterministic PASS/BLOCK preserves arbitrary choices at every
            # reached invocation; it includes states introduced by earlier refusals.
            unconditional = Policy("action", policy.translation_unit, policy.function, return_value, {"const": True})
            action_backend, action_binary, _ = prepare_variant(task, toolchain, snapshots, [unconditional],
                                                              output / "actions" / key, True)
            checked = action_backend.check(action_binary)
            evidence = {"key": key, "action": action, "scope": "declared root harness",
                        "choice": "nondeterministic_each_entry", "query": checked,
                        "contract_status": checked["contracts_and_runtime_checks"],
                        "initialization_status": checked["initialization"],
                        "conditional_on_environment": bool(environment)}
            save_json(cache_file, {"payload": evidence, "sha256": digest(evidence)})
        actions.append({"policy_id": policy.name, "cache_hit": hit, **evidence})
    backend, binary, bindings = prepare_variant(task, toolchain, snapshots, policies, output / "protected")
    compiled_functions, compiled_symbols = backend.inspect(binary)
    qualification = qualify(compiled_functions, compiled_symbols, policies)
    protected = backend.check(binary)
    if policies:
        pass_backend, pass_binary, _ = prepare_variant(task, toolchain, snapshots, policies,
                                                       output / "pass_only", pass_only=True)
        pass_functions, pass_symbols = pass_backend.inspect(pass_binary)
        pass_qualification = qualify(pass_functions, pass_symbols, policies)
        pass_only = pass_backend.check(pass_binary)
    else:
        pass_only, pass_qualification = baseline, qualification
    qualification["pass_only_policies"] = pass_qualification["policies"]
    qualification['pass_only_context_requirements'] = pass_qualification['context_requirements']
    correspondence = pass_evidence(qualification, pass_only, protected, policies)
    if any(p["reasons"] for p in pass_qualification["policies"]):
        correspondence["status"] = "UNKNOWN"
        correspondence["reasons"].append("PASS-only compiled guard structure is not qualified")
    freeze_environment(task, snapshots, policies)
    implementation_dependencies()
    report = {"schema": 1, "status": "REFUTED" if protected["status"] == "REFUTED" else "UNKNOWN", "baseline": baseline,
              "protected": protected, "actions": actions, "bindings": bindings,
              "dependencies_sha256": digest(dependencies), "deployment_ready": False,
              "pass_preservation": correspondence, "pass_only": pass_only,
              "nonvacuity": nonvacuity(baseline, protected, policies, task.targets),
              **environment_report(environment),
              "lifecycle_scope": "entire supplied root harness, including its repeated calls",
              "pending": ["broader observation discovery and live generator evaluation", "inductive lifecycle/progress contracts",
                          "runtime binding and deployment validation"]}
    family = family_evidence(report, policies)
    if family is not None:
        report["family"] = family
    save_json(output / "report.json", report)
    save_json(output / "status.json", {"status": "COMPLETE", "report_sha256": digest(report)})
    return report
