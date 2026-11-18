"""Qualify compiled observations and state the scope of PASS correspondence.

The argument is structural: an entry guard that terminates, has defined reads,
and changes no program state is a stuttering step when false. Source insertion
preserves the original body. A PASS-only query checks original all-PASS paths;
the protected query also covers states introduced by earlier BLOCK decisions.
"""
from .shadow import private_havoc_target, symbol_name, typ
from .spec import FamilyPolicy
from .correspondence import sensitive_sites
from .storage_types import storage_type


PROVED = "PROVED_FOR_HARNESS"
PURE_OPERATORS = {
    "nil", "constant", "symbol", "typecast", "address_of", "dereference", "member", "index",
    "if", "and", "or", "not", "bitnot", "unary-", "+", "-", "*", "/", "mod", "=", "notequal",
    "<", "<=", ">", ">=", "bitand", "bitor", "bitxor", "shl", "lshr", "ashr",
}
SCALAR_TYPES = {"signedbv", "unsignedbv", "c_bool", "bool", "pointer", "c_enum", "c_enum_tag"}


def qualify(functions, symbols, policies):
    """Audit the actual compiled evaluation, including implicit temporary writes."""
    requirements = sensitive_sites(functions)
    concurrency = [site for site in requirements if site['reason'].startswith('concurrent')]
    layout_sensitive = [site for site in requirements if site['reason'].startswith('program observes')]
    results = []
    for policy in policies:
        issues, observed = set(), {}

        def check_type(value, seen=()):
            if not isinstance(value, dict):
                issues.add("missing compiler type")
                return
            kind, named = value.get("id"), value.get("namedSub", {})
            for qualifier in ("#volatile", "#atomic"):
                if named.get(qualifier, {}).get("id") == "1":
                    issues.add(f"observation has {qualifier[1:]} type")
            if kind in ("struct_tag", "union_tag", "c_enum_tag"):
                tag = named.get("identifier", {}).get("id")
                if tag not in symbols:
                    issues.add("unresolved observation type tag")
                elif tag not in seen:
                    check_type(symbols[tag].get("type"), (*seen, tag))
            elif kind not in SCALAR_TYPES | {"array", "struct", "union", "empty", "nil"}:
                issues.add(f"unsupported observation type {kind}")
            # Pointee and unselected members are not read by reading a pointer
            # or an address. Actual dereference/member operands carry their types.

        def expression(value):
            if value.get("id") not in PURE_OPERATORS:
                issues.add(f"observation expression {value.get('id')}")
            check_type(typ(value))
            check_type(storage_type(value, symbols))
            if value.get("id") == "symbol":
                name = symbol_name(value)
                symbol = symbols.get(name)
                if symbol is None:
                    issues.add(f"unresolved observation symbol {name}")
                else:
                    check_type(symbol.get("type"))
                    if not symbol.get("isAuxiliary") and not symbol.get("baseName", "").startswith("__vulgate_"):
                        observed[name] = {"type": symbol.get("type"), "location": symbol.get("location", {})}
            for operand in value.get("sub", []):
                expression(operand)

        regions = []
        for function in functions:
            instructions = function.get("instructions", [])
            starts = [n for n, i in enumerate(instructions) if i["instructionId"] == "ASSERT" and
                      i.get("sourceLocation", {}).get("comment") == f"__VG_REACH_POLICY:{policy.name}"]
            ends = [n for n, i in enumerate(instructions) if i["instructionId"] == "ASSERT" and
                    i.get("sourceLocation", {}).get("comment") == f"__VG_REACH_EVALUATED:{policy.name}"]
            if starts or ends:
                if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
                    issues.add("ambiguous compiled guard region")
                else:
                    regions.append((function["name"], instructions, starts[0], ends[0]))
        if len(regions) != 1:
            issues.add("expected one compiled guard region")
        return_types = []
        for name, instructions, start, end in regions:
            return_type = symbols.get(name, {}).get("type", {}).get("namedSub", {}).get("return_type", {})
            return_types.append(return_type)
            if return_type.get("id") == "empty":
                if any(value is not None for value in policy.return_actions):
                    issues.add("void function requires a void return action")
            elif return_type.get("id") in ("signedbv", "unsignedbv", "c_bool", "c_enum", "c_enum_tag"):
                if any(value is None for value in policy.return_actions):
                    issues.add("non-void function requires an integer return action")
            elif return_type.get("id") == "pointer":
                # The source emitter preserves integer constant zero, which C
                # converts to the function's actual null pointer return type.
                if any(type(value) is not int or value != 0 for value in policy.return_actions):
                    issues.add("pointer function requires a null pointer return action (integer 0)")
            else:
                issues.add("return action type is outside the supported integer/void/null-pointer domain")
            begin_location = instructions[start]["locationNumber"]
            end_location = instructions[end]["locationNumber"]
            positions = {i["locationNumber"]: n for n, i in enumerate(instructions)}
            declared, choice_havocs = set(), 0
            for item in instructions[start + 1:end]:
                kind = item["instructionId"]
                operands = item.get("code", {}).get("sub", [])
                if kind == "DECL" and len(operands) == 1:
                    declared.add(symbol_name(operands[0]))
                    check_type(typ(operands[0]))
                elif kind == "ASSIGN" and len(operands) == 2:
                    lhs, rhs = operands
                    identifier = symbol_name(lhs)
                    symbol = symbols.get(identifier, {})
                    private = (symbol.get("isAuxiliary") or symbol.get("baseName", "") in {
                        f"__vulgate_guard_{policy.name}", f"__vulgate_region_{policy.name}",
                        f"__vulgate_decision_{policy.name}", *({f"__vulgate_sample_{policy.name}"}
                            if isinstance(policy, FamilyPolicy) and policy.selection == "per_invocation" else set())})
                    if (lhs.get("id") != "symbol" or identifier not in declared or not private or
                            symbol.get("isStaticLifetime")):
                        issues.add("guard writes outside a fresh private temporary")
                    expression(rhs)
                elif kind == "OTHER" and isinstance(policy, FamilyPolicy) and policy.selection == "per_invocation":
                    target = private_havoc_target(item, symbols, f"__vulgate_sample_{policy.name}")
                    if target is None or symbol_name(target) not in declared:
                        issues.add("family choice modifies more than its fresh private scalar")
                    else:
                        choice_havocs += 1
                        check_type(typ(target))
                elif kind == "GOTO":
                    expression(item.get("guard", {}))
                    for target in item.get("targets", []):
                        if target not in positions or not item["locationNumber"] < target <= end_location:
                            issues.add("guard evaluation has a cycle or escaping branch")
                elif kind not in ("SKIP", "LOCATION", "DEAD"):
                    issues.add(f"guard evaluation instruction {kind}")
            if isinstance(policy, FamilyPolicy) and policy.selection == "per_invocation" and choice_havocs != 1:
                issues.add("expected one fresh family choice per invocation")
            # Entry from the original body into the guard interior would break
            # the single-entry, terminating-evaluation argument.
            for n, item in enumerate(instructions):
                if not start <= n < end and any(begin_location < target < end_location
                                                for target in item.get("targets", [])):
                    issues.add("external branch enters guard evaluation")
        results.append({"policy_id": policy.name, "status": "UNKNOWN" if issues else
                        "REQUIRES_CONTEXT_UNREACHABILITY" if requirements else "QUALIFIED_STRUCTURE",
                        "reasons": sorted(issues), "observations": observed,
                        "compiled_functions": [region[0] for region in regions], "return_types": return_types,
                        **({"family_selection": policy.selection} if isinstance(policy, FamilyPolicy) else {})})
    return {"policies": results, "concurrency": concurrency, "layout_sensitive": layout_sensitive,
            "context_requirements": requirements,
            "execution_model": "sequential C harness; no asynchronous state mutation"}


def pass_evidence(qualification, pass_only, protected, policies):
    reasons = [f"{p['policy_id']}: {reason}" for p in qualification["policies"] for reason in p["reasons"]]
    context_evidence = []
    for label, query in (("all-PASS original paths", pass_only), ("protected paths", protected)):
        for obligation in ("completeness", "contracts_and_runtime_checks", "initialization"):
            expected = "COMPLETE_FOR_HARNESS" if obligation == "completeness" else PROVED
            if query.get(obligation) != expected:
                reasons.append(f"{label}: {obligation} lacks complete defined-execution evidence")
        sites = qualification.get('pass_only_context_requirements' if label == 'all-PASS original paths'
                                  else 'context_requirements', qualification.get('context_requirements', []))
        for site in sites:
            status = query.get('reachability', {}).get(site['marker'], 'UNKNOWN')
            context_evidence.append({'query': label, **site, 'status': status})
            if status != 'UNREACHABLE':
                reasons.append(f"{label}: {site['reason']} ({site['function']}, {status})")
    inactive = []
    for policy in policies:
        marker = f"__VG_REACH_EVALUATED:{policy.name}"
        if protected.get("reachability", {}).get(marker) != "REACHABLE":
            inactive.append(policy.name)
    return {"status": "UNKNOWN" if reasons else PROVED, "reasons": reasons,
            "context_unreachability": context_evidence,
            "inactive_policy_entries": inactive,
            "method": "compiler-qualified pure entry insertion with all-PASS and protected definedness checks",
            "scope": "Each false guard preserves state before the original body; all-PASS executions preserve "
                     "original behavior in the declared sequential harness. After any BLOCK, correspondence "
                     "is local to the current entry state, not to the original root execution.",
            "excludes": ["timing", "concurrent scheduling", "asynchronous external state",
                         "native stack limits and layout", "runtime machine-code correspondence"],
            "qualification": qualification}


def nonvacuity(baseline, protected, policies, targets):
    sites = (baseline.get("initialization_evidence") or {}).get("target_sites", [])
    target_status = {}
    for target in targets:
        values = [baseline.get("reachability", {}).get(site["marker"], "UNKNOWN")
                  for site in sites if site["target"] == target]
        target_status[target] = ("REACHABLE" if "REACHABLE" in values else
                                 "UNREACHABLE" if values and all(v == "UNREACHABLE" for v in values) else "UNKNOWN")
    policies_reached = {p.name: protected.get("reachability", {}).get(f"__VG_REACH_POLICY:{p.name}", "UNKNOWN")
                       for p in policies}
    return {"status": "ESTABLISHED_FOR_HARNESS" if target_status and
            all(s == "REACHABLE" for s in target_status.values()) else "NOT_ESTABLISHED",
            "baseline_target_sites": target_status, "protected_policy_entries": policies_reached,
            "meaning": "Each requested target site has a symbolic original-program path after preceding assumptions; "
                       "definedness is reported separately. This does not prove input representativeness or target violation."}
