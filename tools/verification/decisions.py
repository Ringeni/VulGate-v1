"""Finite-domain constraint solving for observation-table decisions.

A nogood is a conjunction of (variable == decision) choices known to fail.
Every new candidate must change at least one choice in each nogood. Propagation
and exhaustive DFS solve these constraints; a node limit never means UNSAT.
"""


class SearchLimit(RuntimeError):
    pass


def solve(domain_sizes, nogoods, node_limit=100000):
    if any(type(size) is not int or size < 1 for size in domain_sizes):
        raise ValueError("decision domains must be nonempty")
    clauses = []
    for nogood in nogoods:
        values = {}
        contradictory = False
        for variable, value in nogood:
            if not 0 <= variable < len(domain_sizes) or not 0 <= value < domain_sizes[variable]:
                raise ValueError("nogood outside decision domain")
            if variable in values and values[variable] != value:
                contradictory = True
            values[variable] = value
        if not contradictory:
            clauses.append(tuple(values.items()))
    stack = [[set(range(size)) for size in domain_sizes]]
    nodes = 0
    while stack:
        nodes += 1
        if nodes > node_limit:
            raise SearchLimit("decision solver node limit reached")
        domains = stack.pop()
        changed, conflict, unresolved = True, False, []
        while changed and not conflict:
            changed, unresolved = False, []
            for clause in clauses:
                if any(value not in domains[variable] for variable, value in clause):
                    continue
                flexible = [(variable, value) for variable, value in clause if len(domains[variable]) > 1]
                if not flexible:
                    conflict = True
                    break
                if len(flexible) == 1:
                    variable, value = flexible[0]
                    domains[variable].remove(value)
                    changed = True
                else:
                    unresolved.append(flexible)
        if conflict:
            continue
        if not unresolved:
            return [min(domain) for domain in domains], nodes
        variable = min({v for clause in unresolved for v, _ in clause}, key=lambda v: (len(domains[v]), v))
        # DFS visits PASS (0) first. This is a deterministic preference, not an
        # optimization claim about the number or probability of refusals.
        for value in sorted(domains[variable], reverse=True):
            child = [set(domain) for domain in domains]
            child[variable] = {value}
            stack.append(child)
    return None, nodes
