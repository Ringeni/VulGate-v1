"""Qualify joint policy families and expand conditional action domains."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from .backend import save_json
from .spec import FamilyPolicy, SpecificationError, TablePolicy


def family_status(report, obligation):
    if report.get("conditional_on_environment"):
        return "UNKNOWN"
    query = report.get("protected", {})
    qualification = report.get("pass_preservation", {}).get("qualification", {})
    if (query.get("completeness") != "COMPLETE_FOR_HARNESS" or query.get("initialization") == "UNKNOWN" or
            not qualification.get("policies") or
            any(p["status"] != "QUALIFIED_STRUCTURE" for p in qualification["policies"])):
        return "UNKNOWN"
    keys = ["contracts_and_runtime_checks", "initialization"] + (["target"] if obligation == "policy" else [])
    if any(query.get(key) == "REFUTED" for key in keys):
        return "REFUTED"
    if (all(query.get(key) == "PROVED_FOR_HARNESS" for key in keys) and
            report.get("pass_preservation", {}).get("status") == "PROVED_FOR_HARNESS" and
            report.get("nonvacuity", {}).get("status") == "ESTABLISHED_FOR_HARNESS"):
        return "PROVED_FOR_HARNESS"
    return "UNKNOWN"


def family_evidence(report, policies):
    if not any(isinstance(p, FamilyPolicy) for p in policies):
        return None
    contracts = family_status(report, "contracts")
    rows = []
    reachability = report["protected"].get("reachability", {})
    for policy in policies:
        if not isinstance(policy, FamilyPolicy):
            continue
        for region, domain in enumerate(policy.domains):
            for choice in domain:
                reached = reachability.get(f"__VG_REACH_ACTION:{policy.name}:{region}:{choice}", "UNKNOWN")
                rows.append({"entry": policy.name, "region": region, "choice": choice,
                    "action": {"kind": "PASS"} if choice == 0 else {"kind": "RETURN", "value": policy.return_actions[choice-1]},
                    "reachability": reached,
                    "contract_domain_status": ("QUALIFIED_WITH_JOINT_FAMILY" if contracts == "PROVED_FOR_HARNESS" and reached == "REACHABLE" else
                                               "UNREACHABLE_IN_FAMILY" if reached == "UNREACHABLE" else "NOT_QUALIFIED_WITH_FAMILY")})
    return {"contract_status": contracts, "policy_status": family_status(report, "policy"),
            "conditional_on_environment": bool(report.get("conditional_on_environment")),
            "joint_policies": [p.to_dict() for p in policies], "conditional_domains": rows,
            "dependencies_sha256": report["dependencies_sha256"],
            "scope": "All choices allowed by this entire joint family under the declared harness. "
                     "fixed_table choices persist for the whole root execution; per_invocation choices may change on every call. "
                     "Domains qualified in different families cannot be merged without another joint query."}


def seed_family(policy, selection=None):
    if isinstance(policy, FamilyPolicy):
        return replace(policy, selection=selection or policy.selection)
    if isinstance(policy, TablePolicy):
        predicates, actions, decisions = policy.predicates, policy.return_actions, policy.decisions
    else:
        predicates, actions, decisions = (policy.guard,), policy.return_actions, (0, 1)
    return FamilyPolicy(policy.name, policy.translation_unit, policy.function, predicates, actions,
                        tuple((d,) for d in decisions), selection or "fixed_table")


def expand_family(task, toolchain, policies, output, *, selection=None, obligation="policy", max_queries=64):
    from .engine import analyze, digest
    if selection not in (None, "fixed_table", "per_invocation") or obligation not in ("policy", "contracts"):
        raise SpecificationError("unsupported family selection or qualification obligation")
    if type(max_queries) is not int or not 1 <= max_queries <= 4096:
        raise SpecificationError("family query limit must be in 1..4096")
    if not policies:
        raise SpecificationError("family expansion requires a nonempty seed")
    task, policies = deepcopy((task, policies))
    current = [seed_family(p, selection) for p in policies]
    output = Path(output).resolve()
    run = output / "runs" / uuid4().hex
    run.mkdir(parents=True)
    save_json(output / "status.json", {"status": "STARTED", "run": str(run)})
    save_json(run / "seed.json", {"schema": 1, "policies": [p.to_dict() for p in current]})
    queries, dependencies, accepted, unresolved = [], None, None, False

    def finish(status, reasons):
        report = {"schema": 1, "status": "REFUTED" if status == "SEED_REFUTED" else "UNKNOWN",
                  "conditional_on_environment": bool(task.environment),
                  "family_expansion_status": status, "obligation": obligation, "deployment_ready": False,
                  "run": str(run), "queries": queries, "max_queries": max_queries,
                  "dependencies_sha256": dependencies, "accepted_family": accepted, "reasons": reasons,
                  "scope": "Greedy joint-domain expansion containing the seed, within its supplied observation/action basis. "
                           "Maximality is by domain inclusion, not maximum size or minimum refusal rate.",
                  "pending": ["inductive lifecycle/progress contracts", "runtime binding and deployment validation"]}
        save_json(run / "report.json", report)
        save_json(output / "report.json", report)
        save_json(output / "status.json", {"status": "COMPLETE", "run": str(run), "report_sha256": digest(report)})
        return report

    def query(candidate, addition):
        nonlocal dependencies, accepted
        folder = run / f"query-{len(queries):04}"
        payload = {"schema": 1, "policies": [p.to_dict() for p in candidate]}
        save_json(folder / "policies.json", payload)
        result = analyze(task, toolchain, candidate, folder / "verification", action_cache=output / "action_cache")
        status = family_status(result, obligation)
        record = {"addition": addition, "status": status, "family_sha256": digest(payload),
                  "verification": str(folder / "verification/report.json")}
        queries.append(record)
        actual = result.get("dependencies_sha256")
        if not isinstance(actual, str) or not actual or (dependencies is not None and actual != dependencies):
            record["status"] = "UNKNOWN"
            accepted = None
            return "DEPENDENCIES_CHANGED"
        dependencies = actual
        if status == "PROVED_FOR_HARNESS":
            path = run / "family.json"
            save_json(path, payload)
            accepted = {"path": str(path), "sha256": digest(payload), "verification": record["verification"],
                        "obligation": obligation, "family_evidence": result["family"]}
        return status

    if task.environment:
        return finish("UNKNOWN", ["environment summaries require separate policy-generation qualification"])
    first = query(current, None)
    if first != "PROVED_FOR_HARNESS":
        return finish("SEED_REFUTED" if first == "REFUTED" else "UNKNOWN", ["seed family did not qualify"])
    for index in range(len(current)):
        for region in range(len(current[index].domains)):
            for choice in range(len(current[index].return_actions)+1):
                if choice in current[index].domains[region]:
                    continue
                if len(queries) == max_queries:
                    return finish("QUALIFIED_PARTIAL", ["family query limit reached; the last accepted family remains qualified"])
                domains = list(current[index].domains)
                domains[region] = tuple(sorted((*domains[region], choice)))
                candidate = list(current)
                candidate[index] = replace(current[index], domains=tuple(domains))
                status = query(candidate, {"entry": current[index].name, "region": region, "choice": choice})
                if status == "DEPENDENCIES_CHANGED":
                    return finish("UNKNOWN", ["dependencies changed or could not be established during family expansion"])
                if status == "PROVED_FOR_HARNESS":
                    current = candidate
                elif status == "UNKNOWN":
                    unresolved = True
    # A refuted addition remains refuted in any later superset. Therefore one
    # pass proves inclusion maximality when all addition queries completed.
    return finish("QUALIFIED_PARTIAL" if unresolved else "MAXIMAL_FOR_SEED",
                  ["some alternative domains remain unknown"] if unresolved else [])
