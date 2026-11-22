"""Run several independent Version 2 synthetic populations and summarize uncertainty."""

from __future__ import annotations

import argparse
import json
import sys
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.generate_research_dataset_v2 import generate
from scripts.train_decision_tree_v2 import evaluate_partition, fit_primary, train_rule_baseline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
V2_DIR = PROJECT_ROOT / "data" / "research" / "v2"
SEED_DIR = V2_DIR / "seeds"


def summarize(values: list[float]) -> dict:
    array = np.asarray(values)
    return {
        "mean": float(np.mean(array)),
        "std": float(np.std(array, ddof=1)) if len(array) > 1 else 0.0,
        "min": float(np.min(array)),
        "max": float(np.max(array)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--seeds", nargs="+", type=int, default=[2026, 2027, 2028, 2029, 2030])
    parser.add_argument("--output-dir", type=Path, default=SEED_DIR)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    seed_results = []
    for seed in args.seeds:
        dataset = args.output_dir / f"dataset_seed_{seed}.csv"
        generate(args.count, seed, dataset)

        model, _, train, test = fit_primary(dataset)
        baseline = train_rule_baseline(train)
        result = evaluate_partition(model, baseline, train, test, seed=seed)
        seed_results.append(
            {
                "seed": seed,
                "rows": len(pd.read_csv(dataset)),
                "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
                "decision_tree": result["decision_tree"],
                "rule_baseline": result["rule_baseline"],
            }
        )

    metric_names = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
    )
    summary = {"seeds": args.seeds, "populations": seed_results}
    for detector in ("decision_tree", "rule_baseline"):
        summary[detector] = {
            metric: summarize(
                [row[detector][metric] for row in seed_results]
            )
            for metric in metric_names
        }

    (V2_DIR / "seed_evaluation.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
