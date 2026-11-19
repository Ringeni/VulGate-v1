"""Prove the symbolic guard model is derived from the installed main-chain .vg patch.

`tools/postdeploy/dsl_front.py` converts `runtime/dsl/patches/<case>.vg` into the
`vulgate.patch/v2` guard/action/map mapping consumed by
`case_compiler.compile_case`.  These tests compile the DSL-derived mapping and
the legacy YAML mapping through the same `compile_case`/`compile_guard` path and
pin the result.

The DSL is the source of truth for verification; the committed `.vg` files were
corrected after the declarative20 YAML specs were generated, so the two encodings
are NOT byte-identical.  The known divergences are asserted explicitly below so
accidental drift in the DSL, the YAML specs or the front-end fails loudly:

- CVE-2026-15176: the DSL tests `flags & 8`; the YAML selector names the
  `uri_changed` bit field and resolves it to the nginx-1.31.6 layout mask 32.
  Hook/ABI/read chains/action are identical; the bytecode differs only in that
  one immediate.
- CVE-2026-111497 with `CVE-2026-111497-single.vg` (the fusion the single-entry
  install path uses): it sets `sample_present = 1` and reads `available_in` from
  the caller local, while the YAML observer/map records both as map slots and
  keeps the `sample_present == 0` map-missing disjunct.
- CVE-2026-111497 with the full `.vg` (what `dsl_front.patch_path` selects for
  the case): the parsed predicate is identical; the only encoding difference is
  `capacity`, which the YAML forces into a constant-valued VM argument
  (`force_vm_arg_constant`) while the DSL keeps it a compile-time constant.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.postdeploy import dsl_front  # noqa: E402
from runtime.dsl import parser as dsl_parser  # noqa: E402
from tools.postdeploy.case_compiler import compile_case, load_spec_file, sha256_file  # noqa: E402
from tools.postdeploy.expressions import compile_guard  # noqa: E402
from tools.postdeploy.obligations import _selector_c_expr  # noqa: E402

SPECS = ROOT / 'build' / 'declarative20-specs'
DSL_PATCHES = ROOT / 'runtime' / 'dsl' / 'patches'

# Guard rule sha256 pinned from the DSL-derived model (compile_guard output of
# the derived policy/fields, i.e. exactly the deployment rule bytecode).
DSL_BYTECODE_SHA256 = {
    'CVE-2026-15176': 'a0033c9f6462f717940ad658ca5a0b53efa42fde3085f66d75dfc0bca455fc75',
    'CVE-2026-111497': '6e4acec3250477f22643c52ed19a1df3562f42de305cabcfa7a19bb604c1efb8',
    'CVE-2026-111497-single': '6f7b70815fec50e16bdda17a717bf00d72f791306717cbe371c2b0ef15338287',
}

YAML_BYTECODE_SHA256 = {
    'CVE-2026-15176': '211c3124008d1bb823c95b6adb979e85f684d5958eae7b63a3b360e443cb6e9c',
    'CVE-2026-111497': '5d14b0886436ffb500df981bc5178d17c7fc94851b03b444cb78d1b387c6fb9d',
}


def _load_specs(case_id: str) -> tuple[dict, dict, dict]:
    if not SPECS.is_dir():
        pytest.skip('build/declarative20-specs is not available')
    cbmc = Path(os.environ.get('VULGATE_CBMC', '/opt/vulgate-cbmc/toolchain-bin/cbmc'))
    if not cbmc.is_file():
        pytest.skip('CBMC toolchain is not available')
    case_dir = SPECS / 'cases' / case_id
    if not case_dir.is_dir():
        pytest.skip(f'{case_id} specs are not available')
    vuln = load_spec_file(case_dir / 'vuln.yaml')
    patch = load_spec_file(case_dir / 'patch.yaml')
    profile_path = SPECS / 'app_profiles' / (str(vuln['application']) + '.yaml')
    if not profile_path.is_file():
        pytest.skip(f'{vuln["application"]} app profile is not available')
    profile = load_spec_file(profile_path)
    executable = ((profile.get('builds') or {}).get('baseline') or {}).get('executable')
    if not executable or not Path(executable).is_file():
        pytest.skip(f'baseline artifacts for {case_id} are not available')
    return vuln, patch, profile


def _guard(ir: dict) -> dict:
    assert len(ir['guards']) == 1
    return ir['guards'][0]


def _parsed(text: str) -> str:
    return ast.dump(ast.parse(text, mode='eval').body)


def _read_chain_by_name(guard: dict, name: str) -> dict:
    return guard['resolved_vm_args'][guard['fields'][name]['index']]


def test_patch_path_lookup_is_deterministic() -> None:
    assert dsl_front.patch_path('CVE-2026-15176').name == 'CVE-2026-15176.vg'
    assert dsl_front.patch_path('CVE-2026-111497').name == 'CVE-2026-111497.vg'
    assert dsl_front.patch_path('CVE-2026-000000') is None


def test_15176_guard_model_comes_from_dsl(tmp_path: Path) -> None:
    vuln, yaml_patch, profile = _load_specs('CVE-2026-15176')
    vg_path = dsl_front.patch_path('CVE-2026-15176')
    assert vg_path == DSL_PATCHES / 'CVE-2026-15176.vg'

    derived = dsl_front.derive_patch_spec(vg_path, yaml_patch)
    dsl_ir = compile_case(vuln, derived, profile, tmp_path / 'dsl')
    yaml_ir = compile_case(vuln, yaml_patch, profile, tmp_path / 'yaml')
    dsl_guard = _guard(dsl_ir)
    yaml_guard = _guard(yaml_ir)

    # The compiled case records that the guard rule came from the exact .vg file.
    vg_sha = sha256_file(vg_path)
    assert dsl_ir['deployment']['patch_source'] == 'dsl'
    assert dsl_ir['deployment']['dsl_patch'] == str(vg_path.resolve())
    assert dsl_ir['identities']['dsl_patch_sha256'] == vg_sha
    assert dsl_guard['rule_source'] == 'dsl'
    assert dsl_guard['dsl_patch_sha256'] == vg_sha
    assert dsl_ir['defect_anchors'] == yaml_ir['defect_anchors']

    # The verifier reads compile_guard(derived policy, derived fields) as the rule.
    rule_bytes = Path(dsl_guard['rule_path']).read_bytes()
    assert compile_guard(dsl_guard['policy_source'], dsl_guard['fields']) == rule_bytes
    assert dsl_guard['bytecode_sha256'] == DSL_BYTECODE_SHA256['CVE-2026-15176']

    # Structural agreement with the YAML case: hook, ABI, read chains, action.
    for key in ('function', 'module', 'arg_types', 'return_type', 'action_id',
                'resolved_action', 'fields', 'resolved_vm_args'):
        assert dsl_guard[key] == yaml_guard[key], key

    # Resolved global reads carry the C symbol name, so the source-level GOTO can
    # render the DSL chain instead of rejecting a raw ELF offset.
    alias_selector = dsl_guard['resolved_vm_args'][dsl_guard['fields']['alias']['index']]
    global_index = alias_selector['reads'][1]['index']['global']
    assert global_index['symbol_c_name'] == 'ngx_http_core_module'
    rendered, _checks = _selector_c_expr(alias_selector, ['r', 'path', 'root_length', 'reserved'])
    assert '&ngx_http_core_module' in rendered

    # Known divergence: the DSL keeps its literal mask; the YAML resolves the
    # named bit field through the nginx-1.31.6 profile layout.
    assert '(flags & 8)' in dsl_guard['policy_source']
    assert yaml_guard['policy_source'] == 'alias != 0 and (flags & 32) != 0'
    assert yaml_guard['bytecode_sha256'] == YAML_BYTECODE_SHA256['CVE-2026-15176']
    assert dsl_guard['bytecode_sha256'] != yaml_guard['bytecode_sha256']


def test_111497_guard_model_comes_from_dsl(tmp_path: Path) -> None:
    vuln, yaml_patch, profile = _load_specs('CVE-2026-111497')
    vg_path = dsl_front.patch_path('CVE-2026-111497')
    assert vg_path == DSL_PATCHES / 'CVE-2026-111497.vg'

    derived = dsl_front.derive_patch_spec(vg_path, yaml_patch)
    dsl_ir = compile_case(vuln, derived, profile, tmp_path / 'dsl')
    yaml_ir = compile_case(vuln, yaml_patch, profile, tmp_path / 'yaml')
    dsl_guard = _guard(dsl_ir)
    yaml_guard = _guard(yaml_ir)

    vg_sha = sha256_file(vg_path)
    assert dsl_ir['deployment']['patch_source'] == 'dsl'
    assert dsl_guard['rule_source'] == 'dsl'
    assert dsl_guard['dsl_patch_sha256'] == vg_sha
    rule_bytes = Path(dsl_guard['rule_path']).read_bytes()
    assert compile_guard(dsl_guard['policy_source'], dsl_guard['fields']) == rule_bytes
    assert dsl_guard['bytecode_sha256'] == DSL_BYTECODE_SHA256['CVE-2026-111497']

    for key in ('function', 'module', 'arg_types', 'return_type', 'action_id', 'resolved_action'):
        assert dsl_guard[key] == yaml_guard[key], key
    assert _parsed(dsl_guard['policy_source']) == _parsed(yaml_guard['policy_source'])

    # The read chains both encodings share are identical.
    for name in ('remaining', 'occupied', 'next_in', 'last_in'):
        assert _read_chain_by_name(dsl_guard, name) == _read_chain_by_name(yaml_guard, name), name
    assert dsl_guard['fields']['available_in'] == yaml_guard['fields']['available_in']
    assert dsl_guard['fields']['sample_present'] == yaml_guard['fields']['sample_present']
    assert dsl_guard['map_reads'] == yaml_guard['map_reads']

    # Known encoding divergence: the YAML forces the constant capacity into a
    # constant-valued VM argument; the DSL keeps it a compile-time constant.
    assert dsl_guard['fields']['capacity'] == {'constant': 8}
    capacity_index = yaml_guard['fields']['capacity']['index']
    assert yaml_guard['fields']['capacity'] == {'source': 'arg', 'index': capacity_index}
    assert yaml_guard['resolved_vm_args'][capacity_index] == {'constant': 8}
    assert yaml_guard['bytecode_sha256'] == YAML_BYTECODE_SHA256['CVE-2026-111497']
    assert dsl_guard['bytecode_sha256'] != yaml_guard['bytecode_sha256']


def test_111497_single_fusion_divergence(tmp_path: Path) -> None:
    vuln, yaml_patch, profile = _load_specs('CVE-2026-111497')
    single = DSL_PATCHES / 'CVE-2026-111497-single.vg'

    # The deterministic lookup prefers the exact-file name; the single-entry
    # fusion is a separate fallback, so derive it explicitly here.
    derived = dsl_front.derive_patch_spec(single, yaml_patch)
    dsl_ir = compile_case(vuln, derived, profile, tmp_path / 'single')
    yaml_ir = compile_case(vuln, yaml_patch, profile, tmp_path / 'yaml')
    dsl_guard = _guard(dsl_ir)
    yaml_guard = _guard(yaml_ir)

    rule_bytes = Path(dsl_guard['rule_path']).read_bytes()
    assert compile_guard(dsl_guard['policy_source'], dsl_guard['fields']) == rule_bytes
    assert dsl_guard['bytecode_sha256'] == DSL_BYTECODE_SHA256['CVE-2026-111497-single']

    # Known divergence: the fusion hardcodes map presence and reads the caller
    # local directly instead of the observer/map slots.
    assert dsl_guard['fields']['sample_present'] == {'constant': 1}
    assert dsl_guard['fields']['available_in'] == {'source': 'reg', 'index': 0}
    assert yaml_guard['fields']['sample_present'] == {'source': 'slot', 'index': 1}
    assert yaml_guard['fields']['available_in'] == {'source': 'slot', 'index': 0}
    assert dsl_guard['map_reads'] == []
    assert yaml_guard['map_reads']
    assert 'sample_present' not in dsl_guard['policy_source']
    assert 'sample_present == 0' in yaml_guard['policy_source']
    assert dsl_guard['bytecode_sha256'] != DSL_BYTECODE_SHA256['CVE-2026-111497']

def test_install_hook_count_matches_vg_mounts() -> None:
    """The main chain installs every mount of the .vg, so the receipt's
    required-hook count must be the DSL mount count, not the legacy
    guard+observer count (the mapping only carries guards)."""
    for case_id, expected in (('CVE-2026-15176', 1), ('CVE-2026-111497', 2)):
        path = dsl_front.patch_path(case_id)
        assert path is not None
        derived = dsl_front.derive_patch_spec(path)
        assert derived['install_hook_count'] == len(dsl_parser.load(path).mounts) == expected

    single = dsl_front.derive_patch_spec(DSL_PATCHES / 'CVE-2026-111497-single.vg')
    assert single['install_hook_count'] == 1

def test_every_main_chain_patch_derives_a_guard_model() -> None:
    """The verify chain must be able to derive *every* installed .vg patch, not
    just the two exercised end-to-end cases."""
    patches = sorted(DSL_PATCHES.glob('*.vg'))
    assert len(patches) >= 20
    for path in patches:
        derived = dsl_front.derive_patch_spec(path)
        assert derived['install_hook_count'] == len(dsl_parser.load(path).mounts) >= 1, path.name
        assert derived['guards'], path.name
        for guard in derived['guards']:
            assert guard['action_id'] in derived['actions'], (path.name, guard['id'])
