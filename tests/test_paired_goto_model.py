"""Regression tests for well-formed bitvector types in synthesized paired models.

CBMC rejects any bitvector type without an explicit ``width`` when a GOTO binary
is validated.  ``pointer_typet::check`` delegates to ``bitvector_typet::check``,
so a pointer type synthesized without a width surfaces as the misleading error
``bitvector type must have width`` during ``goto-instrument
--validate-goto-binary``.  These tests pin the synthesized types that caused the
nginx paired-GOTO export to fail.
"""
import copy

from tools.postdeploy.paired_goto import _output_pointer_argument
from tools.verification.shadow import _allocator_shadow_marks

BITVECTOR_IDS = {"signedbv", "unsignedbv", "bv", "floatbv", "fixedbv", "c_bool", "pointer"}


def _widthess_types(node, path="expr"):
    """Yield paths of bitvector/pointer types that lack a usable width."""
    found = []
    if isinstance(node, dict):
        if node.get("id") in BITVECTOR_IDS:
            fields = node.get("namedSub") or {}
            width = fields.get("width") or node.get("width")
            value = width.get("id") if isinstance(width, dict) else width
            if value in (None, "", "0"):
                found.append((path, node.get("id")))
        for key, child in node.items():
            found.extend(_widthess_types(child, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            found.extend(_widthess_types(child, f"{path}[{index}]"))
    return found


def _helper_parameter_type():
    return {
        "id": "pointer",
        "namedSub": {"width": {"id": "64"}},
        "sub": [{"id": "empty"}],
    }


def test_object_form_output_pointer_type_carries_pointer_width():
    symbols = {"__vg_out": {"type": {"id": "signedbv", "namedSub": {"width": {"id": "32"}}}}}
    expr = _output_pointer_argument(symbols, "__vg_out", "object", _helper_parameter_type())

    assert expr is not None
    assert expr["id"] == "typecast"
    assert _widthess_types(expr) == []
    address_of_type = expr["sub"][0]["namedSub"]["type"]
    assert address_of_type["id"] == "pointer"
    assert address_of_type["namedSub"]["width"] == {"id": "64"}
    assert address_of_type["sub"] == [{"id": "signedbv", "namedSub": {"width": {"id": "32"}}}]


def test_object_form_uses_helper_parameter_pointer_width():
    symbols = {"__vg_out": {"type": {"id": "empty"}}}
    helper_type = {
        "id": "pointer",
        "namedSub": {"width": {"id": "32"}},
        "sub": [{"id": "empty"}],
    }
    expr = _output_pointer_argument(symbols, "__vg_out", "object", helper_type)
    assert expr["sub"][0]["namedSub"]["type"]["namedSub"]["width"] == {"id": "32"}


def test_allocator_shadow_mark_fallbacks_are_well_formed():
    mark_type = {
        "id": "code",
        "namedSub": {
            "parameters": {
                "id": "",
                "sub": [
                    {"id": "parameter", "namedSub": {"#identifier": {"id": "p"}}},
                    {"id": "parameter", "namedSub": {"#identifier": {"id": "size"}}},
                    {"id": "parameter", "namedSub": {"#identifier": {"id": "dirty"}}},
                ],
            },
        },
    }
    symbols = {
        "__vg_mark_alloc": {"baseName": "__vg_mark_alloc", "type": mark_type},
    }
    arguments = {"sub": [
        {"id": "symbol", "namedSub": {"identifier": {"id": "buffer"}}},
        {"id": "constant", "namedSub": {"value": {"id": "16"}}},
        {"id": "symbol", "namedSub": {"identifier": {"id": "flag"}}},
        {"id": "nil"},
    ]}
    counter = {"value": 0}

    def fresh(node):
        counter["value"] += 1
        return copy.deepcopy(node)

    def located(node, donor):
        return node

    result = _allocator_shadow_marks(
        "malloc", {"id": "symbol"}, arguments, {"id": "nil"},
        [], symbols, fresh, located,
    )
    assert result
    assert _widthess_types(result) == []
