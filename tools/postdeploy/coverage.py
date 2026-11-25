"""Paired request coverage with exact edge identities and McNemar statistics."""
from collections import Counter
import hashlib
import json
import math


def edges(trace):
    return set(zip([-1, *trace], trace))


class PairCoverage:
    def __init__(self) -> None:
        self.baseline_hits: Counter = Counter()
        self.patched_hits: Counter = Counter()
        self.lost: Counter = Counter()
        self.gained: Counter = Counter()
        self.gained_error: Counter = Counter()
        self.paths: list[dict] = []
        self.incomplete = 0

    def add(self, case_id, baseline, patched) -> None:
        if not baseline.get('trace_complete') or not patched.get('trace_complete'):
            self.incomplete += 1
            return
        b, t = edges(baseline['trace']), edges(patched['trace'])
        self.baseline_hits.update(b)
        self.patched_hits.update(t)
        self.lost.update(b - t)
        self.gained.update(t - b)
        if patched.get('error_fallback'):
            self.gained_error.update(t - b)
        self.paths.append({'case_id': case_id, 'same_sequence': baseline['trace'] == patched['trace'],
                           'lost_edges': len(b - t), 'gained_edges': len(t - b),
                           'baseline_signature': hashlib.sha256(json.dumps(baseline['trace']).encode()).hexdigest(),
                           'patched_signature': hashlib.sha256(json.dumps(patched['trace']).encode()).hexdigest()})

    def finish(self) -> dict:
        baseline_hits, patched_hits = self.baseline_hits, self.patched_hits
        lost, gained, gained_error = self.lost, self.gained, self.gained_error
        paths, incomplete = self.paths, self.incomplete
        return _finish_coverage(baseline_hits, patched_hits, lost, gained, gained_error, paths, incomplete)


def summarize(pairs):
    coverage = PairCoverage()
    for case_id, baseline, patched in pairs:
        coverage.add(case_id, baseline, patched)
    return coverage.finish()


def _finish_coverage(baseline_hits, patched_hits, lost, gained, gained_error, paths, incomplete):
    tests = []
    for edge in sorted(set(baseline_hits) | set(patched_hits)):
        a, b = lost[edge], gained[edge]
        n = a + b
        probability = min(1.0, 2 * sum(math.comb(n, k) for k in range(min(a, b) + 1)) / 2 ** n) if n else 1.0
        tests.append({'edge': list(edge), 'baseline_episodes': baseline_hits[edge],
                      'patched_episodes': patched_hits[edge], 'lost': a, 'gained': b, 'p': probability})
    ordered = sorted(tests, key=lambda x: x['p'])
    adjusted = 1.0
    for i in range(len(ordered) - 1, -1, -1):
        adjusted = min(adjusted, ordered[i]['p'] * len(ordered) / (i + 1))
        ordered[i]['q_bh'] = adjusted
    old, new = set(baseline_hits), set(patched_hits)
    return {'complete_episodes': len(paths), 'incomplete_episodes': incomplete,
            'baseline_edges': len(old), 'patched_edges': len(new),
            'lost_edge_union': len(old - new), 'gained_edge_union': len(new - old),
            'gained_error_edges_union': len(set(gained_error)),
            'retained_fraction': len(old & new) / len(old) if old else None,
            'changed_sequences': sum(not x['same_sequence'] for x in paths),
            'scope': 'same-build paired ordinary operation episodes; reference paths are not compared',
            'statistical_note': 'exploratory BH-adjusted exact McNemar over observed edge universe',
            'paths': paths, 'edge_tests': tests}
