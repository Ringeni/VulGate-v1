# Twenty-case deployment and functional-impact experiment

Recorded 2026-11-13. The final evidence archive is:

`D:/Codex/2026-11-03/goal-042fb9fb-01ec-4a00-960b-c95a63665f9e/outputs/benchmark20-20261112/`

Start with `REPORT.zh-CN.md`, `PATCHES.zh-CN.md`, and `OFFICIAL_LINKS.zh-CN.md` there. Each CVE has deployment JSON, executable VM bytecode, a separate return-action catalog, native episode evidence, official source diffs, and a readable entry-equivalent diff.

## Measured results

- 20 cases: 9 Nginx, 8 Apache httpd, 2 PHP, 1 Brotli.
- 329 ordinary functional cases, 987 baseline/patched/official-reference executions.
- 82 affected normal cases across 16 policies; these are corpus counts, not a production false-positive-rate estimate.
- 20,993 actual VM decisions and 164 BLOCK decisions; monitor diagnostics zero.
- All 21 installed guards have scalar VM-expression equivalence proofs.
- Nineteen cases additionally have 20 non-vacuous local `must_block => BLOCK` proofs over exact installed bytecode.
- The Brotli case retains bounded source differential analysis of `WriteRingBuffer` and functional mutation with feedback.
- Regression suite: 20 tests passed, including negative contract checks.

## Interpretation

The native deployment and ordinary functional tests ran for all 20 cases. Whole-CVE sufficiency and action/continuation safety have not been proved for all 20. The new HTTP/PHP cases use VM summaries, independently declared local contracts, and native functional comparison; they do not yet implement the full real-application-state differential-symbolic stage.

The archive explicitly records gaps in the AIO, map, captures, PHP, session-cookie, and input-charset paths. The existing Brotli guard's connection to the official block-switch repair also remains unproved. Coarse feature-cut variants are labeled separately from the earlier six fine-grained illustrations.

Normal feature losses include missing upload-progress state despite HTTP 200, discarded multipart fields/files, removed HTML comments, rejected DAV updates, failed rewrite, and unavailable HTTP/2 or character conversion paths.

## Entry points

- `experiments/postdeploy/benchmark20/build.py`: pinned real server builds with selected coverage instrumentation.
- `experiments/postdeploy/benchmark20/suite.py`: 17 HTTP-server case configurations and three-world execution.
- `experiments/postdeploy/benchmark20/php_multipart.py`: the second PHP deployment variant.
- `experiments/postdeploy/benchmark20/run_contracts.py`: local obligations against actual bytecode.
- `tools/postdeploy/contract.py`: CBMC local implication and non-vacuity checks.
- `experiments/postdeploy/benchmark20/export_results.py`: evidence and patch-view archive.
- `experiments/postdeploy/benchmark20/audit_archive.py`: evidence, version-range, bytecode, monitor-total, and artifact-pin cross-checks.

Final selected run paths are recorded in `selected_runs()`. CVE-2026-9256 uses Nginx 1.31.0 after checking the vendor's affected-version range. CVE-2026-60005 uses the corrected 64-bit `ncaptures` selector. Earlier runs remain historical evidence and are not selected for the final aggregate.

Official PHP changes are a shared dependency-preserving review set, with unresolved hunk attribution retained explicitly. They are not two independently validated minimal source patches. Nginx/httpd reference binaries use fixed official release versions, which also contain unrelated release updates.
