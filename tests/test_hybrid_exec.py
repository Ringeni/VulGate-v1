from tools.postdeploy.hybrid_exec import (
    HYBRID_STAGE_TIMEOUT_SEC,
    NO_HAZARD_ON_SEARCHED_POINTS,
    apply_searched_point_claim,
    merge_hybrid_results,
    searched_neighborhood_record,
)


def test_clear_neighborhood_becomes_no_hazard_on_searched_points():
    merged = merge_hybrid_results([
        {
            'status': 'completed',
            'point': {'length': 16, 'reserved': 1},
            'properties': [
                {'description': 'vg.obligation.action_continuation_safe', 'status': 'SUCCESS'},
                {'description': 'vg.target.violation_w1', 'status': 'SUCCESS'},
            ],
        },
        {
            'status': 'completed',
            'point': {'length': 0, 'reserved': 1},
            'properties': [
                {'description': 'vg.obligation.action_continuation_safe', 'status': 'SUCCESS'},
                {'description': 'vg.target.violation_w1', 'status': 'SUCCESS'},
            ],
        },
    ])
    assert merged['reason'] == 'hybrid_neighborhood_clear'
    assert apply_searched_point_claim('PROVED_IN_BOUNDED_DOMAIN', True) == NO_HAZARD_ON_SEARCHED_POINTS
    rows = [
        {'status': 'completed', 'point': {'length': 16, 'reserved': 1}},
        {'status': 'completed', 'point': {'length': 0, 'reserved': 1}},
    ]
    record = searched_neighborhood_record(rows, [
        'vg.obligation.action_continuation_safe',
    ], 2)
    assert record == {
        'claim': '已搜索点上未发现危险',
        'unwind': 2,
        'points': [{'length': 16, 'reserved': 1}, {'length': 0, 'reserved': 1}],
        'assertions': ['vg.obligation.action_continuation_safe'],
    }


def test_hybrid_stage_timeout_is_60_seconds():
    assert HYBRID_STAGE_TIMEOUT_SEC == 60


def test_interrupted_or_refuted_search_keeps_its_status():
    assert apply_searched_point_claim('PROVED_IN_BOUNDED_DOMAIN', False) == 'PROVED_IN_BOUNDED_DOMAIN'
    assert apply_searched_point_claim('UNRESOLVED', True) == 'UNRESOLVED'
    assert apply_searched_point_claim('VIOLATED', True) == 'VIOLATED'
    timed_out = merge_hybrid_results([
        {'status': 'completed', 'point': {'alias': 4}, 'properties': [{'description': 'vg.target.violation_w1', 'status': 'SUCCESS'}]},
        {'status': 'unresolved', 'reason': 'TimeoutExpired', 'point': {'alias': 0}, 'properties': []},
    ])
    assert timed_out['status'] == 'unresolved'
    assert timed_out['reason'] == 'TimeoutExpired'
    refuted = merge_hybrid_results([
        {
            'status': 'completed',
            'point': {'alias': 4},
            'properties': [{'description': 'vg.target.violation_w1', 'status': 'FAILURE'}],
        },
    ])
    assert refuted['reason'] == 'hybrid_counterexample'
