import argparse
import json
from pathlib import Path
import sys

from .engine import analyze
from .family import expand_family
from .lifecycle import Lifecycle, verify_lifecycle
from .construction import Generator, construct
from .discovery import DiscoveryOptions, discover
from .spec import Policy, SpecificationError, Task
from .synthesis import Sketch, synthesize
from .toolchain import Toolchain


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify return policies against actual C caller execution")
    parser.add_argument("task", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--policies", type=Path)
    mode.add_argument("--synthesize", type=Path, metavar="SKETCH", help="synthesize an observation decision table")
    mode.add_argument("--discover", action="store_true", help="discover typed program-entry and observation proposals")
    mode.add_argument("--auto-synthesize", action="store_true", help="discover and refine an observation basis automatically")
    mode.add_argument("--generator", type=Path, metavar="CONFIG", help="request sketches from a configured external generator")
    mode.add_argument("--expand-family", type=Path, metavar="POLICIES", help="qualify and expand conditional action domains from a seed")
    parser.add_argument("--family-selection", choices=("fixed_table", "per_invocation"))
    parser.add_argument("--family-obligation", choices=("policy", "contracts"), default="policy")
    parser.add_argument("--family-query-limit", type=int, default=64)
    parser.add_argument("--lifecycle", type=Path, metavar="CONTRACT", help="prove persistent-state induction and optional progress")
    runtime_mode = parser.add_mutually_exclusive_group()
    runtime_mode.add_argument("--export-runtime", action="store_true", help="verify and compile typed entry adapters with the existing VM")
    runtime_mode.add_argument("--check-runtime", type=Path, metavar="MANIFEST", help="check a pinned runtime bundle against current sources")
    parser.add_argument("--runtime-sha256", help="caller-pinned manifest SHA-256 required by --check-runtime")
    parser.add_argument('--runtime-environment', choices=('userspace', 'linux-kernel'),
                        help='native runtime export environment (default: userspace)')
    parser.add_argument("--discovery-options", type=Path, help="limits for automatic entry/observation discovery")
    parser.add_argument("--toolchain", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        task = Task.load(args.task)
        toolchain = Toolchain.load(args.toolchain)
        if args.runtime_sha256 and not args.check_runtime:
            raise SpecificationError("--runtime-sha256 requires --check-runtime")
        if args.runtime_environment and not args.export_runtime:
            raise SpecificationError('--runtime-environment requires --export-runtime')
        if args.export_runtime or args.check_runtime:
            from .runtime import check_runtime, export_runtime
            if any((args.lifecycle, args.expand_family, args.discover, args.auto_synthesize, args.generator, args.synthesize)) or not args.policies:
                raise SpecificationError("runtime modes require --policies and ordinary root verification")
            policies = Policy.load_many(args.policies)
            report = (check_runtime(task, toolchain, policies, args.check_runtime, args.runtime_sha256, args.output)
                      if args.check_runtime else export_runtime(task, toolchain, policies, args.output,
                          runtime_environment=args.runtime_environment or 'userspace'))
        elif args.lifecycle:
            if any((args.expand_family, args.discover, args.auto_synthesize, args.generator, args.synthesize)):
                raise SpecificationError("--lifecycle accepts --policies or an unmodified program")
            report = verify_lifecycle(task, toolchain, Lifecycle.load(args.lifecycle),
                                      Policy.load_many(args.policies) if args.policies else [], args.output)
        elif args.expand_family:
            report = expand_family(task, toolchain, Policy.load_many(args.expand_family), args.output,
                                   selection=args.family_selection, obligation=args.family_obligation, max_queries=args.family_query_limit)
        elif args.discover:
            report = discover(task, toolchain, args.output, DiscoveryOptions.load(args.discovery_options))
        elif args.auto_synthesize or args.generator:
            report = construct(task, toolchain, args.output, options=DiscoveryOptions.load(args.discovery_options),
                               generator=Generator.load(args.generator) if args.generator else None)
        elif args.synthesize:
            report = synthesize(task, toolchain, Sketch.load(args.synthesize), args.output)
        else:
            policies = Policy.load_many(args.policies) if args.policies else []
            report = analyze(task, toolchain, policies, args.output)
    except (OSError, ValueError, SpecificationError) as exc:
        print(json.dumps({"status": "UNKNOWN", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "report": str(args.output.resolve() / "report.json"),
                      "deployment_ready": report["deployment_ready"],
                      "conditional_on_environment": bool(report.get("conditional_on_environment")),
                      **{k: report[k] for k in ("synthesis_status", "discovery_status", "construction_status", "family_expansion_status", "lifecycle_status", "progress_status", "runtime_status") if k in report}}, ensure_ascii=False))
    return {"PROVED": 0, "REFUTED": 1, "UNKNOWN": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
