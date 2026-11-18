# DSL -> VM -> Frida integration status

Branch: `symbolic-verification`

The verification prototype imported from the original VulGate checkout is kept
under:

```text
tools/postdeploy/
tools/verification/
runtime/experiment/
experiments/postdeploy/
```

The old Frida bundle installer is replaced for the patched worker by the
current DSL -> VM -> Frida chain:

```text
runtime.dsl.parser
runtime.dsl.resolve
runtime.dsl.vm
runtime.dsl.vm_run._script
```

`tools/postdeploy/process.py` now accepts a `dsl` profile field and installs the
resulting `.vg` through `vm_run`; `tools/postdeploy/runner.py` enables it only
for the patched world.

## Brotli result

Profile:

```text
build/postdeploy-brotli/profile.json
```

Patch used for installation:

```text
runtime/dsl/patches/CVE-2026-111497-single.vg
```

The single-entry form is required because the current DSL Frida script installs
one mount per entry; the original observer+guard pair cannot be represented as
one entry in this branch yet.

Server run:

```text
build/postdeploy-brotli/run-dsl-v6
```

Results:

```text
pipeline_completed: true
functional_pass: true
symbolic_resolved: true
vm_summary: unsat
queries: reach sat, diff sat, equal sat, ...
regions: changed + unchanged
```

The original prototype's Frida event stream is not emitted by the current DSL
script, so `monitor.decisions` is zero and the monitor cannot replay per-hit
snapshots. The symbolic stage and functional comparison do run.

## Frida 17 API fix

`runtime/dsl/vm_run.py` now reads memory through NativePointer methods:

```js
address.readU8() / readU16() / readU32() / readU64() / readPointer()
```

instead of the removed `Memory.readU8` family. This is required for caller
locals and callsite observers on the installed Frida version.

## Nginx installation

`tools/postdeploy/http_process.py` and `evaluate.py` now pass the case's
`runtime/dsl/patches/<case>.vg` to the HTTP workers. A direct nginx check with
CVE-2026-15176 installed through this path returns:

```text
/plain          -> 200
/files/file.txt -> 500
```

The DSL installation itself works for nginx. The full declarative20 evaluation
still fails earlier in the symbolic GOTO stage when it must regenerate the
paired GOTO. As a diagnostic bridge, VULGATE_REUSE_SYMBOLIC=<dir> can load a
precomputed symbolic-verification.json.

Using the original declarative20-results/CVE-2026-15176 symbolic result:

``	ext
installation: INSTALLED_AND_VERIFIED
vm_bytecode_equivalence: PROVED
action_and_caller_continuation: PROVED_IN_BOUNDED_DOMAIN
target_vulnerability_elimination: PROVED_IN_BOUNDED_DOMAIN
hooks triggered: 0/1
``

This proves the current DSL install and the rest of the evaluation pipeline can
run for nginx; it does not prove the newly generated paired GOTO.

## Nginx attempt

The generated 20-case specs and nginx 1.29.6/1.31.6/1.31.7 builds/sources were
copied to the server. `evaluate_case` for CVE-2026-15176 gets through deployment,
snapshot/trace anchoring, and paired GOTO generation, then stops at:

```text
goto-instrument --validate-goto-binary
ERROR: bitvector type must have width
```

or the same invariant during `--drop-unused-functions`.

The original pre-built GOTO for the same case validates with the same CBMC
6.11.0 toolchain, so the remaining failure is in the newly generated typed GOTO
or in the current transport path, not in the installed tool binaries.

## Next work

1. Fix generated typed GOTO width encoding for nginx.
2. Add DSL event snapshots for monitor replay.
3. Run one nginx case without precomputed symbolic reuse.
4. Port the same DSL installation path to all declarative20 app profiles.
