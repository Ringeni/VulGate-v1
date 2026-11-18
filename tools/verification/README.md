# Compiler-backed context verification

This package analyzes real C translation units and the actual continuation in a supplied root harness. Program behavior is obtained from CBMC's compiler and symbolic execution, rather than a handwritten Python interpreter of each program.

The implementation is being developed against the requirements in `docs/ai/GENERAL_IMPLEMENTATION_PLAN.md`. The complete research method remains an active implementation task. Reports preserve pending obligations, and `deployment_ready` remains false.

## Run

Install CBMC **6.11.0**, including `goto-cc`, `goto-instrument`, `cbmc`, and `symtab2gb`, and the existing Frontier Python dependencies (`tree-sitter`, `tree-sitter-c`). With the executables on PATH:

```sh
python -m tools.verification tests/verification_cases/scalar_target/task.json \
  --policies tests/verification_cases/scalar_target/policies.json \
  --output build/verification/scalar
```

An optional toolchain JSON selects a tool directory or a WSL distribution:

```json
{
  "bin_dir": "/path/to/cbmc/usr/bin",
  "wsl_distribution": "Ubuntu-24.04"
}
```

Omit `wsl_distribution` for native Linux/macOS/Windows tools. For WSL, run the Python CLI on Windows; source/output paths must be accessible via `/mnt/<drive>/`. Tool invocations use argv arrays, preserve command logs, and apply timeouts.

## Task input

```json
{
  "schema": 1,
  "sources": ["implementation.c", "harness.c"],
  "entry": "verify_request",
  "targets": ["target.capacity"],
  "include_dirs": ["include"],
  "defines": ["CONFIG_FEATURE=1"],
  "unwind": 16,
  "object_bits": 8,
  "timeout": 60,
  "memory_cleanup": true
}
```

Paths are relative to the input JSON. `targets` identifies exact assertion descriptions supplied independently of the policy, for example `__CPROVER_assert(size <= capacity, "target.capacity")`. The C harness specifies input construction, environmental choices, assumptions, operation completion and custom contracts. Additional assertions are contract obligations; they are never silently disabled. Native pointer/bounds/overflow checks and optional allocation-cleanup checks remain enabled.

`object_bits` (1..32, default 8) configures CBMC's pointer object-number width.
It is included in task evidence. Exceeding the backend's object capacity remains
UNKNOWN. Runtime queries use at least 12 bits for the VM's additional local
objects and record the effective setting, together with the VM loop bound.

Preprocessed sources that disable checks through `#pragma CPROVER check disable` are currently unsupported and produce UNKNOWN. Toolchain fingerprint queries are bounded; a fingerprint timeout also produces an explicit UNKNOWN report instead of leaving synthesis interrupted.

Interrupted backend queries retain messages from complete JSON objects in the
output prefix. Reports include `backend_warnings`, `backend_errors`,
`last_message`, and `last_observed_phase`; the latter records the actual phase
message and does not infer where execution stopped. `output_complete` describes
JSON syntax only. Shadow warnings are also retained in
`initialization_backend_warnings` for compact reports. Timeouts, abnormal exits,
and incomplete output remain UNKNOWN with no partial property or reachability
evidence. The raw command log remains the source for the full output.

### Explicit environment summaries

Ordinary root verification can replace the body of an explicitly named
environment function with a supplied C summary. For example, a logging boundary
can be projected out of a resource-ownership query under a stated assumption:

```json
"environment": [
  {
    "translation_unit": "src/logging.c",
    "function": "record_message",
    "body_file": "contracts/record_message.body.c",
    "assumption": "For this root, logging returns without changing the request, its allocations or its file handles; log output is outside the observations."
  }
]
```

The body file contains one complete compound statement, such as
`{ (void)message; }` when `message` is an original parameter. It is inserted in
the original function's parameter/type scope after preprocessing. The original
signature and linkage remain in place, and the compiler checks the replacement
body against them. The body file cannot contain preprocessing directives or
depend on unexpanded macros. This first interface requires a function definition
in the selected translation unit; declarations alone are not replaceable.
Ordinary explicitly supplied C translation units remain available for defining
external API contracts.

The root, policy entries, and reserved instrumentation functions cannot be
summarized. An original body containing assertion/assumption tokens or reserved
instrumentation is rejected. Summary bodies cannot contain assertion/assumption
tokens, reserved instrumentation names, pragmas, inline assembly or explicit
nonlocal termination operations. Summary behavior remains an explicit assumption;
these checks do not prove it implements or overapproximates the original function.
In particular, a logging projection must state the applicable callback, state and
resource assumptions. Existing pointer, initialization and cleanup checks still
apply to the resulting symbolic program and its caller continuations.

Baseline, action, protected and PASS-only queries all use the same frozen
summary bytes. `dependencies.json` and the verification report record each
original body, summary body, hashes, original signature, source location,
compilation context and assumption. A body or assumption change invalidates
action-cache identity; a changed body file during a run is rejected. Original
preprocessed snapshots are retained without edits.

Reports containing summaries set `conditional_on_environment: true` and mark
each correspondence `ASSUMED_NOT_PROVED`. Their symbolic results concern the
program under those assumptions. Runtime export/checking, discovery, synthesis,
family expansion and lifecycle induction explicitly refuse these tasks in this
first version. No native artifact is exported from a summary-based proof, and
no equivalence to original logging, allocator or operating-system code is
claimed. Native correspondence and resource/environment induction require
separate qualification.

## Build configuration and translation units

Use `compilation_database` to select a `compile_commands.json`, or `units` to provide explicit compiler options per source:

```json
{
  "schema": 1,
  "sources": ["src/operation.c", "harness.c"],
  "entry": "root",
  "targets": ["target.capacity"],
  "compilation_database": "build/compile_commands.json",
  "units": [
    {"source": "src/operation.c", "output": "build/operation.o"},
    {"source": "harness.c", "flags": ["-std=c11", "-m64"]}
  ]
}
```

Task-relative paths select sources, the database and optional output records. Database source, include, response-file and output paths are interpreted in the recorded compilation working directory. The original source argument spelling is preserved, including relative `__FILE__` strings. Multiple records for one source require an `output` selector. Sources missing from the database, including a verification-only harness, require explicit `flags`. An explicit unit may also specify `directory` and `compiler` (default: task directory and `gcc`). Database-selected units permit only `source` and `output`; flags are not silently overridden. Task-wide `include_dirs` and `defines` remain explicit additions after the unit's arguments.

The reader accepts `arguments` arrays and restricted `command` strings. `command_syntax` is `auto`, `posix` or `windows`; automatic selection uses the database working directory. Shell expansion and compound commands are rejected; commands are executed as argument arrays. GNU driver response files support nested inclusion and quoting, and record their byte hashes. A database produced by a Windows build requires a native Windows backend; the Windows-to-WSL backend requires the database from the WSL build with host-accessible sources. Native Linux paths outside Windows-mounted drives are not accessible through this backend.

GCC-style C driver names, including GCC/Clang/cc and ccache/sccache prefixes, are recognized. The actual compiler is resolved and fingerprinted. It preprocesses each unit using its working directory and ordered macro/include options. GOTO compilation preserves the effective C language standard, word size, char signedness and short-wchar option per unit, then links the resulting objects. Build outputs and dependency-file destinations are removed and recorded; the original build tree receives no object/dependency output from these analysis commands. Supported preprocessing options include explicit C language selection, include paths/files, macro definitions/undefinitions, sysroot, common optimization, debug, warning and PIC options. Unknown semantic options, such as `-fwrapv`, `-ffast-math`, `-Ofast`, packing and compiler plugins, produce UNKNOWN. They are not silently dropped. Changes to database records or response files invalidate cached evidence, even when the resulting source text happens to be unchanged.

Each configured unit also undergoes native/GOTO ABI qualification. A compiler probe compares fundamental type sizes and alignments, representative structure sizes/member offsets, char/wchar properties and endianness. Units with incompatible profiles are rejected before linking. This is a check of the stated type/layout profile, not arbitrary application-layout or machine-code correspondence. GCC x86-64 signed-char and unsigned-char configurations have passed integration tests. **CBMC 6.11.0's i386 long-double alignment disagrees with GCC**, so the tested `-m32` configuration returns UNKNOWN with the failing ABI assertion. Clang command names are accepted, but empirical Clang qualification and broader ABI coverage remain pending. Tasks that omit both database and unit options retain the existing default backend path; they do not gain a native ABI qualification claim.

Build recipes, compiler identity, ABI probes, preprocessing snapshots and working directories are retained in `preprocessed/build.json`, `dependencies.json` and the command logs. A changed preprocessing snapshot is rejected before variant compilation. This binds verification to the analyzed snapshot; installation-time source/build freshness and complete dependency-race checks remain separate requirements.

A relocatable multi-file example is provided in `tests/verification_cases/compilation_database/`, with its own task, compilation database, response file and synthesis sketch. See that directory's README for the command and expected policy.

### Context-dependent native options

`-fno-strict-overflow`, `-fno-delete-null-pointer-checks` and
`-ftrivial-auto-var-init=zero` are retained during native preprocessing,
compilation and runtime export. Every symbolic query records a separate
`build_semantics` result. The model uses stronger obligations: no reached
signed/pointer overflow, valid pointer accesses, and explicit initialization
before reads. Implicit initialization of volatile or atomic automatic storage
has an instruction-level unsupported-effect obligation, including nested
aggregate members. Concurrent/atomic execution also requires separate modeling.

A completed query satisfying those obligations can establish that these option
differences do not affect its execution. This does not implement all wrapping
arithmetic or implicit-zero behavior. When the stronger obligations fail, the
native result and native reachability remain `UNKNOWN`; raw solver properties
and `abstract_model_statuses` are retained. This prevents an abstract
uninitialized value or a wrapping addition from being learned as a native
program refutation. A target refutation remains valid when the option
correspondence itself is proved. Structural PASS correspondence has its own
layout and context obligations and is not discharged by this option check.

The native-option tests include actual GCC execution, volatile scalar/member/
array cases, policy-conditioned PASS paths and actual VM export with a native
caller. `-fno-strict-aliasing` and `-fno-allow-store-data-races` also use these
contextual checks. `-fstrict-flex-arrays=3` adds guarded unsupported obligations
for accessing or taking an address of a fixed trailing array member. This
conservative implementation does not yet prove even an in-bounds trailing
member access; it prevents the allocation-bound backend model from claiming
strict subobject-bound agreement. Nontrailing arrays remain supported.

The explicitly listed x86-64 code-generation options in `build_options.py`
are retained in native objects and ABI probes. The machine profile requires
x86-64 LP64, and per-unit stack calling conventions must agree. GNU dependency
output options are recorded separately; macro prefix maps are applied by the
native preprocessor. Native options are collected during argv parsing, not
filtered from a flat list where an include operand could resemble a flag.
16-bit, freestanding and other unlisted profiles remain rejected.

Native compiler queries for object size and compile-time constancy need a
separate correspondence model. Current query-containing functions must be
unreachable. Private, never-called typed binding functions retain the actual
compiler identities of query-containing definitions, including GNU inline
clones, TU-local functions and asm redirections. After linking, each source
site's entry assertion is restored on its resolved function when necessary;
original branches and call targets are preserved. Duplicate reachability
descriptions aggregate every occurrence. Missing markers or unresolved bindings
cannot be discharged by source-name absence. The source-reference graph is
diagnostic context only. This limitation is explicit
in `build_semantics.compiler_queries`; raw abstract outcomes never become
native refutations when correspondence is missing.

After resolving these entries, the backend removes the exact recorded private
binding functions and their symbol values. It checks the reserved namespace in
every unit, validates each helper's inert address-return body, confirms every
entry obligation, and rejects references from retained program code or symbols.
Original function addresses remain present. This prevents analysis metadata
from enlarging the program's indirect-call target set. Each query record saves
`binding_metadata_removed` after the checks succeed.

### Indirect calls and callback target obligations

The backend applies CBMC's flow-insensitive value-set function-pointer pass to
the shadow-instrumented model. Object, field and assignment relationships propose
call targets; unresolved calls use the backend's broad fallback. The standard
transformation preserves the original dereference, compares the pointer against
candidate addresses, and asserts target-set membership before truncating any
unmatched path. The original read/initialization checks precede this conversion.

Every generated target-set assertion receives a unique description, saved in
`verification.indirect-targets.json`. `indirect_call_targets` requires the exact
expected assertion set, success at every occurrence and complete execution
semantics. Missing, failed or unresolved obligations make all query conclusions
UNKNOWN; raw model results remain diagnostic data. Baseline, action, protected,
PASS-only and actual VM variants qualify their own target sets. This mechanism
uses compiler symbols and IR, with no application-specific callback list.

Generator feedback exposes program counterexamples only when the protected
query is REFUTED with complete execution, determinate initialization, qualified
indirect targets and qualified native build semantics. Other query results stay
in diagnostic feedback and do not become learned policy refutations.

## Policies

```json
{
  "schema": 1,
  "policies": [{
    "id": "capacity_guard",
    "translation_unit": "implementation.c",
    "function": "process",
    "return": -1,
    "guard": {
      "op": ">",
      "args": [{"var": "count"}, {"const": 4}]
    }
  }]
}
```

The expression language supports integer/Boolean constants, identifiers, field/index reads, and pure unary/binary operators. Calls, assignments, increment/decrement, statements and private verification identifiers are rejected. Actual C types and conversions are checked by the compiler. A null `return` emits a void return. Multiple entries are checked together in the same protected execution.

Field read example:

```json
{"base": {"var": "input"}, "field": "length", "pointer": true}
```

The implementation inserts guards into parsed, compiler-preprocessed function bodies. The preserved preprocessed files bind included headers and active macro configuration. Compiler-generated GOTO functions/symbols supply call edges, source identities and types.

## Observation-table synthesis

The same verification backend can synthesize a joint policy for multiple entries. Supply a finite observation sketch instead of guards:

```sh
python -m tools.verification tests/verification_cases/scalar_target/task.json \
  --synthesize tests/verification_cases/scalar_target/sketch.json \
  --output build/verification/synthesis
```

The sketch contains candidate predicates and return actions, not a program-specific execution model:

```json
{
  "schema": 1,
  "entries": [{
    "id": "capacity_filter",
    "translation_unit": "program.c",
    "function": "perform_operation",
    "predicates": [{"op": ">", "args": [{"var": "count"}, {"const": 4}]}],
    "returns": [-1]
  }],
  "max_rounds": 64,
  "solver_nodes": 100000
}
```

Each predicate is evaluated once at every reached entry, in the supplied order, using C truth conversion. Predicate zero supplies the least significant bit of the observation-region index. A decision table chooses PASS (0) or return action `k` (the `k-1` entry of `returns`) for every region. This represents arbitrary Boolean combinations of the supplied predicates and supports different return values in different regions. A zero-predicate sketch has one region and therefore cannot distinguish any contexts at that entry. Input limits are 16 entries, 8 predicates per entry and 16 return actions per entry. Predicates must be valid even in regions assigned PASS; for optional pointer reads, supply a short-circuit expression such as `p && p->count > limit` as one predicate.

Synthesis starts with PASS everywhere. Each round compiles and verifies the entire protected program, including actual caller continuations and repeated invocations. A failed property supplies a trace of the decisions that led to it. The next candidate must change at least one decision in that prefix. The finite-domain solver propagates these exclusions and searches the remaining tables. It prefers PASS deterministically but does not claim minimum refusal rate or minimum number of blocked regions.

Trace generalization requires paired function-entry and completed-decision events, concrete values, the expected compiler function bindings and agreement with the candidate table. If the trace is incomplete or unsuitable, only the complete current candidate is excluded. Missing function bodies, incomplete loop expansion, unsupported observations and incomplete initialization evidence stop refinement as UNKNOWN. They do not create exclusion clauses. Sources, contracts, implementation and toolchain must retain the same dependency digest across all rounds. Complete action-family evidence is shared across rounds; UNKNOWN cache entries are retried.

The output `report.json` distinguishes:

- `SOLVED_FOR_HARNESS`: the selected joint table satisfies target, contract/runtime, initialization, PASS and non-vacuity obligations for the declared harness.
- `INFEASIBLE_FOR_SKETCH`: the finite-domain constraints exclude every table in this particular observation/action sketch. More observations, other entries or other actions may change that result.
- `UNKNOWN`: a solver/round limit, missing semantics, unsupported construct or unresolved obligation prevented a conclusion.

Each run has a unique `runs/<id>/` directory containing the sketch, every candidate, verification logs, structured feedback and the accepted policy if one exists. `accepted_policies` binds the policy data to a digest and its verification report. Its `sha256` is the canonical JSON digest used by `engine.digest` (sorted keys, compact separators, ASCII escaping), rather than the digest of pretty-printed file bytes. Selected actions are also listed per region with protected-program reachability; this evidence concerns the selected joint policy, not hypothetical alternative decisions. The generated policy file can be passed directly to `--policies` for independent verification:

```json
{
  "schema": 1,
  "policies": [{
    "id": "capacity_filter",
    "translation_unit": "/absolute/path/program.c",
    "function": "perform_operation",
    "table": {
      "predicates": [{"op": ">", "args": [{"var": "count"}, {"const": 4}]}],
      "returns": [-1],
      "decisions": [0, 1]
    }
  }]
}
```

The `--synthesize` mode solves a supplied finite predicate/action basis. The construction modes below can discover or generate that basis. Arbitrary-event induction and runtime installation correspondence remain separate requirements. Consequently, the overall report retains `status: UNKNOWN` and `deployment_ready: false` even when `synthesis_status` is `SOLVED_FOR_HARNESS`; the CLI exit code remains 2.

## Joint policy families and conditional action domains

A family replaces each table decision with a nonempty set of allowed decisions.
Decision 0 is PASS and decision `k > 0` returns `returns[k-1]`:

```json
{
  "schema": 1,
  "policies": [{
    "id": "capacity_gate",
    "translation_unit": "program.c",
    "function": "process_count",
    "family": {
      "predicates": [{"op": ">", "args": [{"var": "count"}, {"const": 4}]}],
      "returns": [-1, -2],
      "domains": [[0], [1, 2]],
      "selection": "fixed_table"
    }
  }]
}
```

Ordinary `--policies` verifies every choice in the whole joint Cartesian family.
`fixed_table` selects one action for each entry/region before the root body and
keeps it for the entire root execution, including recursive root calls.
`per_invocation` selects a fresh allowed action at every entry invocation. Thus
two constant policies returning different errors may each satisfy a repeat-call
consistency contract, while arbitrary switching between them can violate it.
The choices use fresh private symbolic scalars; they do not assume program inputs
or write user storage. Generated family initialization receives the same actual
write tracking as application code.

`family.contract_status` covers contracts, runtime checks, initialization and
PASS/non-vacuity evidence. `family.policy_status` additionally requires target
coverage. Per-region action rows record reachability and whether the action is
qualified with this entire joint family. Unreachable choices are identified
separately. A refuted family does not individually refute every action it contains.
Domains from separately qualified families cannot be unioned without a new joint
query: entries can impose coupled constraints on each other's allowed actions.
Unconditional single-action reports remain separate evidence.

To expand a supplied guard, table or family seed:

```sh
python -m tools.verification tests/verification_cases/policy_family/task.json \
  --expand-family tests/verification_cases/policy_family/seed.json \
  --family-selection fixed_table --family-obligation policy \
  --family-query-limit 64 --output build/verification/family
```

The default obligation is `policy`; `contracts` qualifies return compatibility
without requiring target coverage. Existing family seeds retain their selection
unless overridden; guard/table seeds default to `fixed_table`. Expansion tries
one action addition at a time and verifies the complete enlarged family before
retaining it. Failed additions remain failed in supersets, so a complete pass
establishes inclusion maximality for this seed and supplied basis. It does not
find a globally largest family, correlated non-Cartesian families, or a minimum
refusal policy. Choosing another seed or action order may change the result.

Reports distinguish `MAXIMAL_FOR_SEED`, `QUALIFIED_PARTIAL` (query budget or
unresolved alternatives), `SEED_REFUTED` and `UNKNOWN`. Every query records its
policy digest and verification report. Changed or unestablished dependencies
invalidate acceptance. `accepted_family` names the exported `family.json`, its
digest and supporting evidence. The export can be independently checked with
`--policies`. Overall status still retains pending lifecycle/runtime obligations,
`deployment_ready: false`, and CLI exit code 2 for qualified results. See the
repeat-call example in `tests/verification_cases/policy_family/`.

## Persistent-state induction and progress

`--lifecycle contract.json` checks a supplied persistent-state invariant using
the actual initializer and event functions. It can be combined with `--policies`
for a guard, table or family, or used on the unmodified program. Construction
and family expansion are separate modes; their exported policies are normal
inputs to this verification command.

```json
{
  "schema": 1,
  "header": "state.h",
  "state_type": "struct WorkState",
  "initialize": "initialize_work",
  "step": "process_event",
  "invariant": {"op": "<=", "args": [
    {"base": {"var": "state"}, "field": "remaining", "pointer": false},
    {"base": {"var": "state"}, "field": "budget", "pointer": false}
  ]},
  "active": {"op": ">", "args": [
    {"base": {"var": "state"}, "field": "remaining", "pointer": false}, {"const": 0}
  ]},
  "rank": {"base": {"var": "state"}, "field": "remaining", "pointer": false}
}
```

The header defines the state type, which is a typedef name or a named struct.
Both program functions have signature `void function(State *)`. An application
adapter can construct event inputs and invoke the original request handlers;
its C body is analyzed too. Expressions use the normal pure AST and may refer
only to the generated local `state` object. Optional `active` and `rank` must
occur together. The optional contract-file-relative `compile_from` source selects the
unit configuration inherited by generated harnesses; it defaults to the first
task source. Header paths are contract-file-relative. The full task's original
sources and per-unit build settings remain part of every proof query.

The initializer is checked from a fresh uninitialized state. The induction step
starts with an arbitrary compiler-typed object, assumes the invariant, invokes
one actual event and asserts the invariant again. Generated calls also read
every logical scalar leaf before a state can be retained; the implicit state
invariant includes complete initialization, without treating structure padding
as a user field. The target, caller contracts, resource checks, pure-observation
qualification and non-vacuity checks use the existing backend. Thus a completed
induction covers any number of event calls, while `unwind` continues to bound
execution inside each initializer/event query. Incomplete inner execution
cannot establish induction. This mode's execution context is the declared
initializer and repeated event adapter; it does not reinterpret arbitrary other
code in `task.entry` as part of that adapter. The ordinary `--policies` mode
continues to verify the original root harness separately.

The state audit follows compiled direct calls from initializer and event entries,
including policy observations. Mutable globals, static locals, unresolved calls,
concurrent/volatile/atomic state, fabricated or arbitrary nondeterministic
pointers, union/object-representation views, and escaping global addresses
prevent a closed-state conclusion. Pointer reinterpretations are restricted;
ordinary typed allocation from a fresh compiler-identified malloc result and
conversion to void pointers for cleanup remain supported.
The implemented persistent domain has integer/Boolean/enum leaves, nested structs
and fixed arrays, with at most 4096 leaves and depth 16. Persistent pointers,
unions and floating state need further representation/heap contracts. Per-event
allocation is checked with memory cleanup enabled, so heap objects cannot remain
as unrepresented state. These restrictions are audited from compiler types and
instructions, not inferred from function names or a handwritten execution model.

Progress has its own query: from every active invariant state, the declared rank
is nonnegative and either the next state is inactive or its rank strictly
decreases. Complete execution semantics and absence of event-pruning assumptions
are needed to conclude progress. A driver that continues invoking events while
active is an explicit premise; external scheduling fairness is not inferred.
An early return can satisfy the safety invariant yet fail this ranking query.

Reports distinguish `PROVED_INDUCTIVELY`, `INITIATION_REFUTED`, `NOT_INDUCTIVE` and
`UNKNOWN`. Progress is `PROVED_DESCENT`, `RANKING_REFUTED`, `NOT_REQUESTED` or
`UNKNOWN`. A failed consecution or ranking check can use an unreachable state
allowed by the supplied invariant; it does not by itself establish an actual
execution failure or nontermination. Strengthening the invariant or changing
the rank can change that result. Family checks use a common invariant for all
permitted choices, which can be stronger than an invariant relating state to a
particular fixed table.

Every phase retains its generated source, compiled state audit and ordinary
verification report. Original source/build/toolchain identities and the expanded
state header are checked across phases. Generated proof code is also compared
token-by-token after preprocessing; header macros cannot silently rewrite its
obligations or field reads. The expected template stays in memory, and generated
source files are checked for edits during queries. A change invalidates the combined proof.
All lifecycle commands still retain overall UNKNOWN and deployment readiness
false until runtime correspondence and the remaining system obligations are met.
See `tests/verification_cases/lifecycle/` for a reproducible symbolic-budget task.

## Automatic discovery and basis refinement

The construction layer can now supply the finite basis from compiler evidence:

```sh
python -m tools.verification tests/verification_cases/scalar_target/task.json \
  --discover --toolchain /path/to/toolchain.json --output build/verification/discovery
python -m tools.verification tests/verification_cases/scalar_target/task.json \
  --auto-synthesize --toolchain /path/to/toolchain.json --output build/verification/automatic
```

Discovery compiles the actual task using the same preprocessing and build pipeline as verification. It binds candidate function symbols to translation units, walks caller edges from the target assertion owners, and reads actual parameter/return types. The root harness is excluded from automatic gating because it specifies the environment and operation-completion contracts. Same-name static functions retain their translation-unit identity. Unsupported return types and unbound symbols are listed in `excluded`; unresolved calls are retained in the graph.

Candidate observations come from entry-visible compiled conditions, parameters, declared file-scope state, struct fields, and fixed-array elements. Lexical declarations establish whether a name precedes the entry; the compiler supplies its object identity and type. Parameter shadowing and translation-unit-local objects are preserved. Thread-local, volatile/atomic and unsupported state are omitted. Optional pointer reads receive short-circuit non-null prerequisites; fixed-array indices receive lower/upper bounds before the read. Only lossless nonconstant numeric casts are translated; typed constant conversions are interpreted explicitly. Observations that are complements are deduplicated when their syntactic partition can be recognized. Constants from compiled program expressions provide further thresholds. This is proposal generation, not proof of a policy or object lifetime; the verification queries check those reads.

Bounded GOTO traversal translates conditions through actual/formal argument bindings and scalar/local assignments. Expressions denote values at the proposed entry. Capturing a value before a write preserves that snapshot; subsequent fresh memory reads are not confused with the snapshot. Indirect writes and calls invalidate global and address-escaped local mappings; this stage does not assume callee-effect or return-value summaries. Branch paths are considered separately, and recursive calls, loop back edges, unsupported effects and exhausted budgets appear in each candidate's `flow_omissions`. Interprocedural condition provenance records the caller chain. A translated condition is still only a candidate observation: skipping an earlier state update can violate a caller contract even when that observation is well-defined.

Return proposals include existing constant returns, small type-compatible constants and constants from the compiled program. These values are not assumed to be valid error returns. The actual caller contracts determine which actions are usable. Each entry's observation/action catalog is finite; truncations and rejected entries are reported.

`--auto-synthesize` initially uses one proposed predicate per entry, then tries limits of 2, 4 and 8 when a complete search refutes the previous basis. Identical sketches are skipped. Each attempt runs the ordinary whole-program table synthesizer. Program, contracts, build, implementation and toolchain must retain the discovery dependency digest; a changed dependency prevents acceptance and invalidates feedback for the old program. This does not claim exhaustive observation discovery, an optimal policy, or a proof when symbolic execution is incomplete.

Optional `--discovery-options options.json` controls the catalog:

```json
{"schema": 1, "max_distance": 3, "max_entries": 8, "max_predicates": 8, "max_actions": 8, "field_depth": 2,
 "array_elements": 4, "max_leaves": 64, "max_globals": 32, "call_depth": 2, "flow_steps": 512}
```

The first five limits are respectively 1..64, 1..16, 1..8, 1..16 and 1..4. Array enumeration is limited to 1..32 elements per dimension, total leaves to 1..512, globals to 1..1024, call depth to 1..8, and traversal steps to 1..100000 per entry. Limits define the finite proposal catalog; they do not certify exhaustive discovery. Raw pointers do not acquire inferred array extents. More precise alias/effect/return summaries and recursive/loop transformations remain future discovery work. A supplied or externally generated sketch can use other expressions supported by the normal policy language and verifier.

Construction reports distinguish `SOLVED_FOR_HARNESS`, `EXHAUSTED_CANDIDATES` and `UNKNOWN`. Exhaustion means the particular catalogs/proposal budgets have been used, not that the program has no feasible policy. Discovery itself returns `DISCOVERED` with `UNVERIFIED_PROPOSALS`. All commands retain overall UNKNOWN, exit code 2 and `deployment_ready: false` while lifecycle and runtime obligations are pending.

## External generators and optional Responses adapter

`--generator generator.json` uses a configured executable adapter to propose sketches and refine them from verification feedback:

```json
{
  "schema": 1,
  "command": ["python", "my_generator.py"],
  "directory": ".",
  "max_attempts": 4,
  "timeout": 120,
  "max_output_bytes": 1048576,
  "max_rounds": 64,
  "solver_nodes": 100000
}
```

The directory is relative to the configuration file. The command is an argv array executed without a shell. The adapter receives one UTF-8 JSON request on stdin. It contains a request identity, dependency digest, task contract identifiers, typed candidate catalog, bounded function excerpts, unresolved calls, search budgets and previous feedback. Verification feedback includes failed-property descriptions and representative traces; truncated traces are explicitly marked. Excerpts and feedback are program data, not executable instructions.

The adapter must write exactly one JSON response on stdout:

```json
{"schema": 1, "request_id": "echo the request identity", "sketch": {"schema": 1, "entries": [], "max_rounds": 64, "solver_nodes": 100000}}
```

The empty entries array above is only an envelope illustration: a usable response needs 1..16 valid entries in the normal sketch format. Entries must come from the offered catalog and cannot target the root harness. A generator may propose new expressions and return values. The normal expression grammar, compiler, initialization tracking, caller contracts, PASS check, non-vacuity probes and synthesis queries remain authoritative. A malformed or stale response is feedback, not a policy. An infeasible sketch supplies semantic feedback so the next request can refine observations/actions. UNKNOWN results never become learned refutations.

Each attempt preserves request/response files, process exit/timeout, stdout/stderr byte counts and hashes, the proposed sketch, synthesis report and feedback. Process duration and accepted stdout size are bounded. Process logs are streamed to files; the stdout acceptance limit is checked after exit and is not a disk-output quota or process sandbox. Adapters are user-selected executables. They should only emit proposals and keep the program, harness and verifier unchanged; dependency checks prevent acceptance of evidence for a changed analyzed program.

An optional adapter is included:

```sh
python -m pip install -r tools/verification/requirements-generator.txt
python -m tools.verification task.json --generator generator.json \
  --toolchain /path/to/toolchain.json --output build/verification/generated
```

For this adapter, set `command` to `["python", "-m", "tools.verification.openai_generator", "--model", "YOUR_MODEL_ID"]` and `directory` to the repository root. The model is explicitly chosen by the user and must support Structured Outputs. The SDK reads `OPENAI_API_KEY` from the adapter environment. The adapter calls the Responses API with the recursive `generator_sketch.schema.json`, `strict: true`, `store: false`, no SDK retries, and a configurable timeout/output-token limit. It checks completed status and handles missing, incomplete or declined output as failure. JSON schema validation does not replace verification.

The adapter follows the official [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs) and [Responses create reference](https://developers.openai.com/api/reference/resources/responses/methods/create), retrieved on 2026-11-03. Its protocol reads/writes UTF-8 bytes independently of the Windows standard-stream locale, and its output-token limit must be at least 16. Automated tests use a local adapter process and a mock Responses client; no live model evaluation or project-source transmission is part of that test evidence. Offline discovery and synthesis require neither the SDK nor an API key.

## Initialization and resource semantics

Initialization is tracked on the typed GOTO representation using CBMC Symbolic Shadow Memory. Reads check the object's metadata; assignments and returned values update it. Pointer writes therefore update the object actually aliased by the pointer, including objects belonging to callers. Struct fields and array elements are tracked separately. Conditional read checks retain their control-flow guards.

The GOTO representation is exported and reimported through CBMC's `symtab2gb` interface. Control-flow targets are relocated to include the inserted checks. Metadata is private to verification. The stock experimental `--uninitialized-check` was audited and found to report a false positive on initialization through a pointer argument; it is not used as authoritative initialization evidence.

`object_bits` (default 8, accepted range 1..32, strictly below the compiled
pointer width) controls CBMC's finite object-number encoding. Before inserting
shadow checks, the backend aligns `__CPROVER_max_malloc_size` in both the symbol
table and initialization body with that encoding. Otherwise CBMC rebuilds the
global initializer and removes inserted tracking. An initializer marker must
survive into the completed solver result; missing evidence keeps initialization
UNKNOWN. The effective encoding and maximum allocation size are recorded.
Runtime queries use at least 12 object bits to accommodate the VM's objects.
These are bounds of the CBMC memory model, not native allocation limits.

CBMC's standard allocation/deallocation models are used for malloc/free, and its lifetime/leak/cleanup properties remain enabled. Its implementation-private allocator variables are outside user-memory initialization obligations. Unsupported memory effects and unresolved shadow-memory operations keep initialization results UNKNOWN. Support is extended by checking new language/storage cases against the real backend.

An assignment to an ordinary, nonvolatile struct bit-field can execute without
granting initialized shadow bytes. The original assignment, its RHS checks and
its address dependencies remain in the program. This permits write-only fields
without marking an unwritten neighbour in the same storage byte initialized.
Each such transfer records a reachability marker. If initialization checks fail
and any deferred write has not been proved unreachable, initialization is
UNKNOWN: the failure may reflect the conservative transfer and cannot be used
as a policy counterexample. Bit-field reads, read-modify-write operations,
volatile/atomic fields and union storage retain their separate qualification
requirements. This is write-only support, not precise bit-level tracking.

## Observation qualification and PASS correspondence

The compiler places each guard evaluation between uniquely identified verification markers. The qualifier inspects this region in typed GOTO IR: expression types must be supported, writes may only initialize fresh private temporaries, control flow must be acyclic and stay inside the evaluation, and original code may not branch into its interior. Symbol-table types are checked as well as expression types, since an implicit conversion may remove a qualifier from an expression. Volatile/atomic reads, floating-point observations, unresolved types, calls and unsupported effects prevent qualification.

PASS evidence combines this structural check with two symbolic queries. The complete protected program checks defined guard reads and caller execution, including states introduced by earlier refusals. A separate `pass_only/` variant evaluates each guard and assumes its result is false before entering the unchanged original body. This query is explicitly conditional on every gate choosing PASS. These assumptions are never used for action-family checks, target coverage or original-program reachability. A path that the policy blocks need not be a defined original execution for PASS correspondence to hold.

For the supported sequential C harness, a false, defined, pure guard changes no program state before the preserved original body. Thus all-PASS executions preserve original behavior. After an earlier BLOCK, this argument concerns the current entry state; it does not equate the entire modified history with an original root execution. Whole-query contract/initialization obligations are required conservatively, so unrelated failures can keep PASS evidence UNKNOWN. Native stack layout/limits, timing, concurrency, asynchronous state and machine-code/runtime correspondence are outside this evidence. Programs that expose pointer representations require a stronger correspondence argument and remain UNKNOWN.

`nonvacuity` separately reports whether each requested target assertion site has a symbolic path in the original program after the assumptions preceding that site. An entry marker before harness assumptions is not sufficient. Contradictory assumptions therefore produce `NOT_ESTABLISHED`, even when a target assertion is vacuously true. This check establishes neither input representativeness nor that the target is violated. Execution definedness remains a separate obligation, and incomplete unwinding cannot prove a site unreachable.

## Evidence and statuses

- `baseline/` executes the original program.
- `protected/` executes all supplied guards and the actual callers.
- `pass_only/` checks the explicitly conditional all-PASS execution and contributes to structural PASS evidence.
- `actions/` checks each return action with a nondeterministic PASS/BLOCK choice at every invocation. This includes histories changed by earlier refusals.
- `action_cache/` reuses action queries when the preprocessed program, task, implementation, toolchain, entry and return value are unchanged. A guard edit still triggers whole-policy checking.
- `candidates.json` contains compiler-derived call relationships and unresolved calls.
- `dependencies.json` and command logs bind inputs, headers, options and backend results.
- `report.json` separates target, contracts/runtime checks, initialization, completeness, typed PASS evidence and non-vacuity.

`PROVED_FOR_HARNESS` applies to an individual completed obligation under the supplied harness and model semantics. Unwinding assertions are always enabled: insufficient loop/recursion expansion, missing function bodies, unsupported effects, missing target properties, invalid output, solver failure and timeout are never promoted to proof. Property failures retain compiler-generated execution traces.

The overall CLI currently returns 1 for refuted supplied policies and 2 for incomplete overall qualification. Broader observation discovery, live generator evaluation, persistent-heap/external-state induction, correspondence models and runtime deployment binding remain under development; the overall command does not yet authorize deployment.

## Tests

### Pinned toolchain setup

From the repository root, `python -m tools.setup_verification --prefix NEW_DIR
--wsl Ubuntu-24.04` creates a private CBMC installation and a Python virtual
environment. Windows requires an existing Ubuntu 24.04 x86-64 WSL distribution;
the native Linux form omits `--wsl`. CPython >= 3.11, GCC and dpkg-deb must already
be available on their respective hosts. Windows CPython 3.13 with WSL is the
tested installation profile. No system package installation or root operation
is performed.

The official CBMC 6.11.0 Debian package is SHA-256 pinned. Python dependencies
use `requirements-verification.lock` with exact versions, accepted wheel
hashes, `--require-hashes` and `--only-binary`. `--archive FILE --wheelhouse DIR`
supports predownloaded inputs. The prefix must be new; partial or existing
directories are not overwritten. Virtual environments must stay at their
installation path.

Keep the printed `manifest_sha256`. `python -m tools.setup_verification
--prefix DIR --check --manifest-sha256 SHA256` checks managed files, Linux
symlink targets, tool identities, Python dependency versions, the recorded
host/GCC and the lock/setup implementation. Python bytecode caches are excluded
from the source/binary inventory. OS libraries remain host prerequisites; this
is not a complete operating-system image lock. The emitted `toolchain.json`
and virtual-environment Python are the inputs to the verification commands.

WSL tool execution uses `--exec` so arguments reach the executable directly;
backslashes and quotes are not reinterpreted by a default shell.

### Native runtime export

`--export-runtime --policies policies.json` builds typed function-entry adapters
and a linkable native archive using the existing policy DSL compiler, assembler
and `runtime/vm.c`. Observations retain their C expression types and evaluation
order. The VM consumes a finite Boolean region number; a separate Boolean VM
monitor selects each integer, void or null pointer return action. Family inputs require a
concrete policy table to be selected and verified before export.

For a pointer-returning function, use JSON `"return": 0` (or `"returns": [0]`
in a table/sketch). The source insertion emits the C integer constant zero;
the compiler converts it to the function's actual pointer type, including
typedefs, qualified pointees, multiple indirections and function pointers.
JSON `null` still denotes `return;` for a void function. Nonzero pointer
return actions are unsupported. Automatic discovery proposes only zero for
pointer returns. A null return still requires the ordinary caller, resource,
initialization and PASS checks: skipping an output write can invalidate it.

Export requires completed target, caller/runtime, initialization, PASS and
non-vacuity obligations. It then recompiles the exact generated native source
bytes and the actual VM into a second symbolic query over the original root.
The error adapter is strengthened to an assertion to prove that invalid VM
results cannot occur. Native self-tests exhaust all declared observation
regions. Native objects use the recorded per-unit compiler/ABI settings;
unconfigured tasks acquire explicit default GCC units for ABI qualification.

The output includes `.i` sources, `.o` files, a static archive, compiler-produced
monitor DSL/assembly/bytecode, verification results and a SHA-256 manifest.
`--check-runtime MANIFEST --runtime-sha256 EXPECTED_SHA256 --policies ...`
rechecks assets and current program, policy, build, implementation, VM/compiler
source and tool identities. The caller retains the manifest pin from export.

`BUILT_FOR_HARNESS` and `CURRENT_FOR_HARNESS` describe a checked archive under
the declared root context. Final application linking, installation checks and
machine-code correspondence beyond native compiler trust remain separate work.
The CLI retains overall UNKNOWN and `deployment_ready=false`. The
`tests/verification_cases/runtime_contract/` fixture includes a native driver.

For a captured Linux kernel task, add `--runtime-environment linux-kernel` to
runtime export. Helpers then use the recorded kernel headers/macros and working
directory; `__KERNEL__` is required. Failure adapters trap on impossible
decisions, and an exported `vulgate_runtime_selftest()` object checks every
region. The actual VM is verified over the original root before native object
compilation. The result is `BUILT_FOR_GUEST_VALIDATION`, with a
`PENDING_KERNEL_GUEST` native self-test; its independent freshness status is
`CURRENT_FOR_GUEST_VALIDATION`. These statuses keep final Kbuild/image binding
and guest execution as outstanding obligations. No host module is loaded by
export or freshness checking.

`python -m tools.kernel_binding build` supplies the next stage: an independent
Kbuild directory, recipe/byte correspondence checks, objtool processing, final
image binding and a callable boot check. See [kernel image binding](../KERNEL_BINDING.md)
for its supported profile and the separate diskless QEMU validation command.

Initialization effects unsupported by the shadow transformer receive explicit
unreachability assertions at their actual instruction positions. A complete
proof that an effect cannot execute allows qualification; a reachable effect,
missing property or incomplete query keeps initialization UNKNOWN. This does
not provide a memory-effect model for an operation merely because another
program reaches it safely.

Unit tests run without CBMC. Integration tests require an explicit toolchain configuration:

```powershell
$env:VULGATE_TOOLCHAIN='path/to/toolchain.json'
python -m pytest tests/test_verification.py tests/test_synthesis.py tests/test_build_configuration.py tests/test_construction.py tests/test_family.py tests/test_lifecycle.py -q
```

The test suite uses independent, benign contract fixtures and generated C programs. It checks real caller initialization, ownership established before a callee, guard weakening, multiple translation units, header-dependent invalidation, incomplete loops, unknown external functions and storage semantics. Additional cases distinguish pure short-circuit reads from volatile/atomic/floating-point observations, partial guard evaluation, address-sensitive behavior, blocked original paths and contradictory harness assumptions. It does not execute exploit workloads.

Synthesis tests compare the decision solver with exhaustive finite-domain enumeration, and exercise real C counterexamples, observation conflicts, multiple return values, changed state after refusal, jointly selected entries, void-return type binding, unknown-cache retry, fingerprint timeout, disabled backend checks and incomplete-search/semantic outcomes.

Build tests check database selection, response-file semantics against GCC, macro ordering, explicit C language selection, relative source names and working directories, per-unit language/ABI options, cache invalidation, static same-name symbols in distinct units, snapshot integrity and ABI mismatch reporting.

Construction tests check compiler-derived fields/actions, automatic observation refinement after infeasibility, static entry binding, generator JSON/request identity, timeout and size limits, schema and semantic feedback, harness-entry rejection, dependency changes and the optional Responses adapter's request/output handling. Local generator fixtures exercise the real verification loop; Responses client tests use a substitute client and do not establish live-model policy quality.
