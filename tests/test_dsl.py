from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.dsl import parser, vm  # noqa: E402

SAMPLE = '''action REJECT:
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
    if (value["length"] > 10 && arg1 != 0) {
        return block("REJECT");
    }
    }
}
'''


def test_parse_mount_and_action() -> None:
    patch = parser.parse(SAMPLE)
    assert list(patch.actions) == ['REJECT']
    assert patch.actions['REJECT'].return_type == 'int'
    assert patch.actions['REJECT'].value == -73
    mount = patch.mounts[0]
    assert mount.symbol == 'target_fn'
    assert mount.args == ['pointer', 'uint64']
    assert mount.return_type == 'int'
    assert mount.nature == '拦截点'
    assert 'return block("REJECT")' in mount.body


def test_compile_renders_vm_bytecode() -> None:
    patch = parser.parse(SAMPLE)
    compiled = vm.compile_patch(patch, {})
    assert compiled.mounts[0].symbol == 'target_fn'
    assert len(compiled.mounts[0].code) > 0
    assert compiled.mounts[0].action_id == 'REJECT'


def test_read_point_nature() -> None:
    text = SAMPLE.replace('nature: intercept', 'nature: read_point')
    patch = parser.parse(text)
    assert patch.mounts[0].nature == '读取点'


def test_invalid_nature_rejected() -> None:
    text = SAMPLE.replace('nature: intercept', 'nature: unknown')
    with pytest.raises(parser.DSLParseError):
        parser.parse(text)


def test_all_generated_patches_compile() -> None:
    values = {'activated': 0, 'throws': 0, 'uploads': 0,
              'alias': 1, 'flags': 32, 'previous': 1,
              'captures': 1, 'counter': 250,
              'remaining': 0, 'sample_present': 0}
    patches = sorted((ROOT / 'runtime' / 'dsl' / 'patches').glob('*.vg'))
    # 20 declarative patches, plus the single-mount Brotli fusion variant.
    assert len(patches) >= 20
    for path in patches:
        if path.stem.startswith('CVE-2026-111497'):
            # Observer/guard pair and its single-mount fusion both depend on
            # runtime resolution (dsl_resolve) before they compile.
            continue
        patch = parser.load(path)
        assert patch.mounts
        compiled = vm.compile_patch(patch, overrides=values)
        assert len(compiled.mounts) == len(patch.mounts)
        assert all(mount.code for mount in compiled.mounts)


def test_chinese_keywords_still_accepted() -> None:
    text = SAMPLE.replace('action REJECT', '动作 REJECT') \
        .replace('return_type: int', '返回类型: int') \
        .replace('return: -73', '返回: -73') \
        .replace('mount sample', '挂载点 sample') \
        .replace('location:', '位置:') \
        .replace('args=', '参数=[').replace(', return=int', '], 返回=int') \
        .replace('nature: intercept', '性质: 拦截点') \
        .replace('behavior:', '行为:')
    patch = parser.parse(text)
    assert patch.mounts[0].symbol == 'target_fn'
    assert patch.actions['REJECT'].value == -73
