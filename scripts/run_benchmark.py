"""CLI entry point: regenerate fixtures, run the benchmark, optionally write a report.

Usage:
    python scripts/run_benchmark.py            # run benchmark, print metrics
    python scripts/run_benchmark.py --save     # also write reports/evaluation-latest.json
    python scripts/run_benchmark.py --fixtures # materialize fixtures first
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKSPACE / "services" / "api"))
sys.path.insert(0, str(WORKSPACE))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Warden evaluation benchmark.")
    parser.add_argument("--save", action="store_true", help="write reports/evaluation-latest.json")
    parser.add_argument("--fixtures", action="store_true", help="materialize fixtures first")
    args = parser.parse_args()

    if args.fixtures:
        from make_fixtures import main as fixtures_main

        fixtures_main()

    from app.analysis.pipeline import AnalysisPipeline
    from app.domain.registry import ControlRegistry, EvidenceRegistry
    from app.evaluation.benchmark import BenchmarkRunner

    frameworks = WORKSPACE / "frameworks"
    registry = ControlRegistry(frameworks)
    evidence = EvidenceRegistry(frameworks)
    pipeline = AnalysisPipeline(registry, evidence)

    result = BenchmarkRunner(pipeline).run()
    print(json.dumps({
        "accuracy": result["accuracy"],
        "false_positive_rate": result["false_positive_rate"],
        "missed_violation_rate": result["missed_violation_rate"],
        "evidence_reference_validity": result["evidence_reference_validity"],
        "deterministic_reproducible": result["deterministic_reproducible"],
        "duration_ms": result["duration_ms"],
        "total": result["total"],
    }, indent=2))

    if args.save:
        reports = WORKSPACE / "reports"
        reports.mkdir(exist_ok=True)
        (reports / "evaluation-latest.json").write_text(
            json.dumps(result, indent=2, default=str), encoding="utf-8"
        )
        print(f"saved -> {reports / 'evaluation-latest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
