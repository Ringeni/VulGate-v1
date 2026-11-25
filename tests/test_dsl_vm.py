from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.dsl import parser, vm  # noqa: E402

SAMPLE = '''
action REJECT:
{
    return_type: int
    return: -73
}

mount sample:
{
    location: symbol="target_fn", args=[pointer, uint64], return=int
    nature: intercept
    behavior:
    {
        value["length"] = vg_read_u32(arg0 + 8);
        if (value["length"] > 10) {
            return block("REJECT");
        }
    }
}
'''


def test_compile_sample_to_vm() -> None:
    patch = parser.parse(SAMPLE)
    compiled = vm.compile_patch(patch, overrides={'length': 11})
    assert compiled.mounts[0].code
    assert len(compiled.mounts[0].code) % 8 == 0
    # last two instructions are mov r0, (0|1); exit
    assert compiled.mounts[0].code[-8] == 0x95


def test_generated_patches_compile_with_overrides() -> None:
    values = {'activated': 0, 'throws': 0, 'uploads': 0,
              'alias': 1, 'flags': 32, 'previous': 1,
              'captures': 1, 'counter': 250,
              'remaining': 0, 'sample_present': 0}
    for path in sorted((ROOT / 'runtime' / 'dsl' / 'patches').glob('*.vg')):
        if path.stem.startswith('CVE-2026-111497'):
            # Observer/guard pair and its single-mount fusion both depend on
            # runtime resolution (dsl_resolve) before they compile.
            continue
        patch = parser.load(path)
        compiled = vm.compile_patch(patch, overrides=values)
        assert compiled.mounts
        assert all(mount.code for mount in compiled.mounts)


def test_map_observer_compiles() -> None:
    path = ROOT / 'tests' / 'workloads' / 'dsl' / 'map_demo.vg'
    patch = parser.load(path)
    compiled = vm.compile_patch(patch, {})
    assert [mount.nature for mount in compiled.mounts] == ['read_point', 'intercept']
    assert compiled.maps and compiled.maps[0]['id'] == 'limits'
    assert compiled.maps[0]['keys'] == {
        '0': 'very_long_variable_name_for_map_key',
    }
    assert compiled.mounts[0].action_id is None
    assert compiled.mounts[1].action_id == 'REJECT'


def test_nested_reads_and_rhs_binary_use_scratch_without_clobber() -> None:
    text = '''
action DENY:
{
    return_type: int
    return: -1
}

mount nested:
{
    location: symbol="target_fn", args=[pointer, uint64], return=int
    nature: intercept
    behavior:
    {
        value["clcf"] = vg_read_pointer(vg_read_pointer(arg0 + 40) + vg_read_u64(global("mod") + 0) * 8);
        value["cnt"] = vg_read_u32(value["clcf"] + 16);
        if ((value["cnt"] & 255) >= (250 * 1) && value["cnt"] <= 0x80000000) {
            return block("DENY");
        }
    }
}
'''
    compiled = vm.compile_patch(parser.parse(text), {'mod': 0x555555601234})
    code = compiled.mounts[0].code
    assert code and len(code) % 8 == 0
    rows = [code[i:i + 8] for i in range(0, len(code), 8)]
    assert any(row[0] == vm.OP_CALL and int.from_bytes(row[4:8], 'little', signed=True) == vm.HELPER_SCRATCH_STORE for row in rows)
    assert any(row[0] == vm.OP_MOV_K32 for row in rows)



