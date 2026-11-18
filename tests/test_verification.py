from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tools.verification.backend import classify
from tools.verification.engine import analyze
from tools.verification.expression import compile_expression
from tools.verification.source import functions, instrument
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.toolchain import ProcessResult, Toolchain


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests/verification_cases"


def solver_result(properties, returncode=10):
    return ProcessResult([], returncode, json.dumps([{"result": properties}, {"cProverStatus": "failure"}]), "")


def prop(name, description, status):
    return {"property": name, "description": description, "status": status}


@pytest.mark.parametrize("node", [
    {"call": "system"}, {"op": "=", "args": [{"var": "a"}, {"const": 1}]},
    {"op": "++", "args": [{"var": "a"}]}, {"var": "a;return 0"},
    {"var": "__CPROVER_assume"}, {"const": 2**64},
])
def test_expression_rejects_effects_and_invalid_syntax(node):
    with pytest.raises(SpecificationError):
        compile_expression(node)


def test_expression_accepts_arbitrary_field_names_and_short_circuit():
    node = {"op": "&&", "args": [{"var": "object"}, {"op": "<=", "args": [
        {"base": {"var": "object"}, "field": "remaining", "pointer": True}, {"const": 27}]}]}
    text, variables = compile_expression(node)
    assert "&&" in text and "->remaining" in text and variables == ["object"]


def test_compiler_backend_never_promotes_missing_results_or_timeouts():
    assert classify(ProcessResult([], 0, "[]", ""), ["target"])["status"] == "UNKNOWN"
    assert classify(ProcessResult([], None, "", "", True), ["target"])["status"] == "UNKNOWN"
    assert classify(solver_result([prop("x.1", "different", "SUCCESS")]), ["target"])["target"] == "UNKNOWN"


@pytest.mark.parametrize("name", ["root.unwind.0", "root.no-body.external", "root.recursion.1"])
def test_incomplete_solver_semantics_are_unknown(name):
    report = classify(solver_result([prop("x.1", "target", "SUCCESS"), prop(name, "incomplete", "FAILURE")]), ["target"])
    assert report["completeness"] == "UNKNOWN"
    assert report["target"] == "UNKNOWN"


def test_experimental_initialization_is_not_a_definitive_refutation():
    report = classify(solver_result([prop("x.1", "target", "SUCCESS"),
                                    prop("x.uninitialized_local.1", "maybe uninitialized", "FAILURE")]), ["target"])
    assert report["status"] == "UNKNOWN"
    assert report["initialization_diagnostics"][0]["status"] == "FAILURE"


def test_entry_instrumentation_changes_selected_function_only(tmp_path):
    code = b"int untouched(void) { return 7; }\nint selected(int x) { return x; }"
    policy = Policy("p", tmp_path / "any.c", "selected", -1, {"const": True})
    transformed, bindings, _ = instrument(code, [policy], "absent", False)
    assert b"int untouched(void) { return 7; }" in transformed
    assert transformed.count(b"__VG_REACH_POLICY:p") == 1
    assert [f.name for f in functions(code)] == ["untouched", "selected"]
    assert bindings[0]["function"] == "selected"


@pytest.fixture
def toolchain():
    config = os.environ.get("VULGATE_TOOLCHAIN")
    if not config:
        pytest.skip("set VULGATE_TOOLCHAIN to run real compiler/solver integration tests")
    return Toolchain.load(config)


def test_real_c_caller_continuation(toolchain, tmp_path):
    task = Task.load(CASES / "output_contract/task.json")
    policies = Policy.load_many(CASES / "output_contract/policies.json")
    report = analyze(task, toolchain, policies, tmp_path)
    assert report["baseline"]["contracts_and_runtime_checks"] == "PROVED_FOR_HARNESS"
    assert report["baseline"]["initialization"] == "PROVED_FOR_HARNESS"
    assert report["protected"]["contracts_and_runtime_checks"] == "REFUTED"
    assert report["protected"]["initialization"] == "REFUTED"
    violations = [p for p in report["protected"]["properties"] if p["status"] == "FAILURE"]
    assert any(p["description"] == "contract.output_initialized_to_zero" for p in violations)


def test_real_guard_change_reuses_action_and_rechecks_coverage(toolchain, tmp_path):
    task = Task.load(CASES / "scalar_target/task.json")
    policies = Policy.load_many(CASES / "scalar_target/policies.json")
    initial = analyze(task, toolchain, policies, tmp_path)
    assert initial["baseline"]["target"] == "REFUTED"
    assert initial["protected"]["target"] == "PROVED_FOR_HARNESS"
    assert initial["pass_preservation"]["status"] == "PROVED_FOR_HARNESS"
    assert initial["nonvacuity"]["status"] == "ESTABLISHED_FOR_HARNESS"
    weakened = replace(policies[0], guard={"op": ">", "args": [{"var": "count"}, {"const": 5}]})
    updated = analyze(task, toolchain, [weakened], tmp_path)
    assert updated["protected"]["target"] == "REFUTED"
    assert updated["actions"][0]["cache_hit"]
    assert initial["actions"][0]["key"] == updated["actions"][0]["key"]


def make_task(tmp_path, source, *, unwind=8):
    file = tmp_path / "input.c"
    file.write_text(source, encoding="utf-8")
    return Task(tmp_path / "task.json", (file,), "root", ("target",), unwind=unwind, timeout=30)


@pytest.mark.parametrize("body,reason", [
    ("extern unsigned nondet_uint(void); void root(void) { unsigned n=nondet_uint(); "
     "__CPROVER_assume(n<8); unsigned i=0; while(i<n) ++i; __CPROVER_assert(i==n,\"target\"); }", ".unwind."),
    ("extern void external(int *); void root(void) { int x=0; external(&x); "
     "__CPROVER_assert(x==0,\"target\"); }", ".no-body."),
])
def test_real_incompleteness_is_preserved(toolchain, tmp_path, body, reason):
    task = make_task(tmp_path, "extern void __CPROVER_assert(_Bool,const char*); "
                     "extern void __CPROVER_assume(_Bool); " + body, unwind=2)
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report["protected"]["completeness"] == "UNKNOWN"
    assert any(reason in text for text in report["protected"]["reasons"])


def test_real_preexisting_caller_resource_obligation(toolchain, tmp_path):
    task = make_task(tmp_path, '''
#include <stdlib.h>
extern void __CPROVER_assert(_Bool,const char*);
int process(int *owned) { __CPROVER_assert(*owned==0,"target"); return 0; }
void root(void) {
    int *owned=malloc(sizeof(int));
    if(!owned) return;
    *owned=0;
    int rc=process(owned);
    if(rc<0) return;
    free(owned);
}
''')
    policy = Policy("reject", task.sources[0], "process", -1, {"const": True})
    report = analyze(task, toolchain, [policy], tmp_path / "result")
    assert report["baseline"]["contracts_and_runtime_checks"] == "PROVED_FOR_HARNESS"
    assert report["baseline"]["initialization"] == "PROVED_FOR_HARNESS"
    assert report["protected"]["contracts_and_runtime_checks"] == "REFUTED"
    assert any("cleanup" in p["property"] or "leak" in p["property"]
               for p in report["protected"]["properties"] if p["status"] == "FAILURE")


def test_real_multiple_translation_units_and_header_invalidation(toolchain, tmp_path):
    header = tmp_path / "limits.h"
    header.write_text("#define CAPACITY 4\n", encoding="utf-8")
    implementation = tmp_path / "implementation.c"
    implementation.write_text('#include "limits.h"\nextern void __CPROVER_assert(_Bool,const char*);\n'
                              'int compute(unsigned n) { __CPROVER_assert(n<=CAPACITY,"target"); return 0; }', encoding="utf-8")
    harness = tmp_path / "harness.c"
    harness.write_text('extern void __CPROVER_assume(_Bool); extern unsigned nondet_uint(void); '
                       'extern int compute(unsigned); void root(void) { unsigned n=nondet_uint(); '
                       '__CPROVER_assume(n<8); compute(n); }', encoding="utf-8")
    task = Task(tmp_path / "task.json", (implementation, harness), "root", ("target",), timeout=30)
    policy = Policy("bound", implementation, "compute", -1,
                    {"op": ">", "args": [{"var": "n"}, {"const": 4}]})
    before = analyze(task, toolchain, [policy], tmp_path / "result")
    assert before["protected"]["target"] == "PROVED_FOR_HARNESS"
    header.write_text("#define CAPACITY 3\n", encoding="utf-8")
    after = analyze(task, toolchain, [policy], tmp_path / "result")
    assert after["protected"]["target"] == "REFUTED"
    assert not after["actions"][0]["cache_hit"]
    assert before["actions"][0]["key"] != after["actions"][0]["key"]


@pytest.mark.parametrize("declaration,reason", [
    ("volatile int sample=1;", "volatile"),
    ("_Atomic int sample=1;", "atomic"),
    ("double sample=1.0;", "floatbv"),
])
def test_real_observation_type_qualification(toolchain, tmp_path, declaration, reason):
    task = make_task(tmp_path, 'extern void __CPROVER_assert(_Bool,const char*);\n' + declaration + '''
int operation(int n) { __CPROVER_assert(n==0,"target"); return n; }
void root(void) { operation(0); }
''')
    policy = Policy("sample_guard", task.sources[0], "operation", -1,
                    {"op": ">", "args": [{"var": "sample"}, {"const": 2}]})
    report = analyze(task, toolchain, [policy], tmp_path / "result")
    assert report["pass_preservation"]["status"] == "UNKNOWN", report
    assert any(reason in item for item in report["pass_preservation"]["reasons"])


def test_real_short_circuit_guard_preserves_pass(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern void __CPROVER_assert(_Bool,const char*);
extern _Bool nondet_bool(void);
struct Sample { int count; };
int operation(struct Sample *sample) { __CPROVER_assert(1,"target"); return 0; }
void root(void) { struct Sample sample={3}; operation(nondet_bool() ? &sample : 0); }
''')
    policy = Policy("inspect", task.sources[0], "operation", -1, {"op": "&&", "args": [
        {"var": "sample"}, {"op": ">", "args": [
            {"base": {"var": "sample"}, "field": "count", "pointer": True}, {"const": 4}]}]})
    report = analyze(task, toolchain, [policy], tmp_path / "result")
    assert report["pass_preservation"]["status"] == "PROVED_FOR_HARNESS", report["pass_preservation"]
    assert report["nonvacuity"]["baseline_target_sites"]["target"] == "REACHABLE"


def test_real_partial_guard_evaluation_is_not_pass_evidence(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern void __CPROVER_assert(_Bool,const char*);
int operation(int divisor) { __CPROVER_assert(1,"target"); return 0; }
void root(void) { operation(0); }
''')
    policy = Policy("divide", task.sources[0], "operation", -1,
                    {"op": "/", "args": [{"const": 8}, {"var": "divisor"}]})
    report = analyze(task, toolchain, [policy], tmp_path / "result")
    assert report["pass_preservation"]["status"] == "UNKNOWN"
    assert report["protected"]["contracts_and_runtime_checks"] == "REFUTED"
    assert any("division by zero" in p["description"] for p in report["protected"]["properties"]
               if p["status"] == "FAILURE")


def test_real_pass_proof_does_not_require_blocked_original_paths_to_be_defined(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern void __CPROVER_assert(_Bool,const char*);
extern _Bool nondet_bool(void);
int operation(int divisor) {
    __CPROVER_assert(divisor!=0,"target");
    return 8/divisor;
}
void root(void) { operation(nondet_bool()); }
''')
    policy = Policy("zero", task.sources[0], "operation", -1,
                    {"op": "==", "args": [{"var": "divisor"}, {"const": 0}]})
    report = analyze(task, toolchain, [policy], tmp_path / "result")
    assert report["baseline"]["contracts_and_runtime_checks"] == "REFUTED"
    assert report["protected"]["contracts_and_runtime_checks"] == "PROVED_FOR_HARNESS"
    assert report["pass_preservation"]["status"] == "PROVED_FOR_HARNESS", report["pass_preservation"]


def test_real_address_representation_needs_more_than_structural_pass_proof(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern void __CPROVER_assert(_Bool,const char*);
int operation(int n) {
    unsigned long address=(unsigned long)&n;
    __CPROVER_assert(address==address,"target");
    return 0;
}
void root(void) { operation(0); }
''')
    policy = Policy("inspect", task.sources[0], "operation", -1,
                    {"op": ">", "args": [{"var": "n"}, {"const": 4}]})
    report = analyze(task, toolchain, [policy], tmp_path / "result")
    assert report["pass_preservation"]["status"] == "UNKNOWN"
    assert any("address representation" in item for item in report["pass_preservation"]["reasons"])


def test_real_inconsistent_assumptions_do_not_establish_nonvacuity(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern void __CPROVER_assert(_Bool,const char*);
extern void __CPROVER_assume(_Bool);
extern unsigned nondet_uint(void);
void root(void) {
    unsigned count=nondet_uint();
    __CPROVER_assume(count<2);
    __CPROVER_assume(count>3);
    __CPROVER_assert(count==1,"target");
}
''')
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report["baseline"]["reachability"]["__VG_REACH_ROOT"] == "REACHABLE"
    assert report["baseline"]["target"] == "PROVED_FOR_HARNESS"
    assert report["nonvacuity"]["status"] == "NOT_ESTABLISHED"
    assert report["nonvacuity"]["baseline_target_sites"]["target"] == "UNREACHABLE"


def test_incomplete_solver_cannot_prove_unreachability():
    report = classify(solver_result([prop("site.1", "__VG_REACH_TARGET:0", "SUCCESS"),
                                    prop("target.1", "target", "SUCCESS"),
                                    prop("loop.unwind.0", "unwind", "FAILURE")]), ["target"])
    assert report["reachability"]["__VG_REACH_TARGET:0"] == "UNKNOWN"


@pytest.mark.parametrize("source,expected", [
    ('struct S {int a; int b;}; void root(void) { struct S s; s.a=7; '
     '__CPROVER_assert(s.a==7,"target"); }', "PROVED_FOR_HARNESS"),
    ('struct S {int a; int b;}; void root(void) { struct S s; s.a=7; '
     '__CPROVER_assert(s.b==0,"target"); }', "REFUTED"),
    ('void root(void) { int a[2]; a[0]=7; __CPROVER_assert(a[0]==7,"target"); }', "PROVED_FOR_HARNESS"),
    ('void root(void) { int a[2]; a[0]=7; __CPROVER_assert(a[1]==7,"target"); }', "REFUTED"),
    ('struct S {int n;}; void root(void) { struct S *p=0; '
     '__CPROVER_assert(!(p && p->n),"target"); }', "PROVED_FOR_HARNESS"),
    ('int global; void root(void) { __CPROVER_assert(global==0,"target"); }', "PROVED_FOR_HARNESS"),
    ('void root(void) { char *p="ab"; __CPROVER_assert(p[1]==98,"target"); }', "PROVED_FOR_HARNESS"),
    ('void root(void) { _Bool flag=1; __CPROVER_assert(flag,"target"); }', "PROVED_FOR_HARNESS"),
])
def test_real_shadow_memory_storage_semantics(toolchain, tmp_path, source, expected):
    task = make_task(tmp_path, 'extern void __CPROVER_assert(_Bool,const char*);\n' + source)
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report["protected"]["initialization"] == expected, report["protected"].get("initialization_evidence")
