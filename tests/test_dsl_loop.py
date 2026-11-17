from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.dsl import parser, vm  # noqa: E402


def test_compile_bounded_loop_demo() -> None:
    patch = parser.load(ROOT / 'tests' / 'workloads' / 'dsl' / 'loop_demo.vg')
    compiled = vm.compile_patch(patch, {})
    assert len(compiled.mounts) == 2
    code = compiled.mounts[0].code
    assert code and len(code) % 8 == 0
    rows = list(struct.iter_unpack('<BBhi', code))
    assert any(row[0] == 0x25 and row[2] < 0 for row in rows)


def test_loop_bound_is_capped() -> None:
    text = '''
map m:
{
    capacity: 16
}

action REJECT:
{
    return_type: int
    return: -1
}

mount bad:
{
    location: symbol="target_fn", args=[uint64], return=int
    nature: intercept
    behavior:
    {
        for (i = 0; i < 257; i++) {
            map["m"][i] = 1;
        }
        if (true) {
            return block("REJECT");
        }
    }
}
'''
    try:
        vm.compile_patch(parser.parse(text), {})
    except vm.ExprError:
        return
    raise AssertionError('loop bound above the compiler cap was accepted')
