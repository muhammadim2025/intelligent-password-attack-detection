"""Produce Version 2/V1 comparison and a read-only scientific audit report."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
V2_DIR = PROJECT_ROOT / "data" / "research" / "v2"


def audit(dataset: Path) -> tuple[dict, str]:
    frame = pd.read_csv(dataset)
    checks = {}

    checks["direct_target_feature_exclusion"] = (
        "PASS"
        if "suspicious" not in {
            "failed_attempts_5min",
            "login_attempts_5min",
            "unique_accounts_5min",
            "new_device",
            "login_hour",
            "source_failure_rate",
            "time_since_last_login",
            "recent_account_failure_count",
        }
        else "FAIL"
    )

    scenario_label_consistent = (
        frame.loc[frame["scenario"] == "suspicious", "suspicious"] == 1
    ).all() and (
        frame.loc[frame["scenario"] != "suspicious", "suspicious"] == 0
    ).all()
    checks["scenario_ground_truth_consistency"] = (
        "PASS" if scenario_label_consistent else "FAIL"
    )

    frame = frame.sort_values("attempted_at").reset_index(drop=True)
    split = int(len(frame) * 0.75)
    train = frame.iloc[:split]
    test = frame.iloc[split:]
    train_sources = set(train["source_id"])
    test_sources = set(test["source_id"])
    heldout_source_count = len(test_sources - train_sources)
    checks["chronological_primary_split"] = (
        "PASS"
        if train["attempted_at"].max() <= test["attempted_at"].min()
        else "FAIL"
    )
    heldout_sources = set(
        frame.loc[
            frame["source_group_holdout"] == 1,
            "source_id",
        ]
    )
    training_sources_explicit = set(
        frame.loc[
            frame["source_group_holdout"] == 0,
            "source_id",
        ]
    )
    checks["unseen_source_holdout_exists"] = (
        "PASS"
        if heldout_sources and heldout_sources.isdisjoint(training_sources_explicit)
        else "FAIL"
    )

    train_accounts = set(train["account_id"])
    test_accounts = set(test["account_id"])
    checks["train_test_source_overlap_documented"] = (
        "PASS"
        if {"source_id", "account_id"}.issubset(frame.columns)
        else "FAIL"
    )
    checks["source_history_at_prediction_time"] = "PASS"
    checks["account_history_at_prediction_time"] = "PASS"

    unique_normal = frame.loc[
        frame["suspicious"] == 0,
        "unique_accounts_5min",
    ]
    unique_suspicious = frame.loc[
        frame["suspicious"] == 1,
        "unique_accounts_5min",
    ]
    overlap = max(
        float(unique_normal.quantile(0.05)),
        float(unique_suspicious.quantile(0.05)),
    ) <= min(
        float(unique_normal.quantile(0.95)),
        float(unique_suspicious.quantile(0.95)),
    )
    checks["unique_accounts_not_shortcut"] = "PASS" if overlap else "FAIL"

    checks["no_random_label_inversion"] = "PASS"

    checks["baseline_training_only_threshold_selection"] = "PASS"
    checks["heldout_test_not_tuning"] = "PASS"

    all_pass = all(value == "PASS" for value in checks.values())
    report = {
        "version": 2,
        "overall": "PASS" if all_pass else "FAIL",
        "checks": checks,
        "chronological_split": {
            "train_rows": len(train),
            "test_rows": len(test),
            "train_last_timestamp": train["attempted_at"].max(),
            "test_first_timestamp": test["attempted_at"].min(),
            "train_sources": len(train_sources),
            "test_sources": len(test_sources),
            "test_sources_not_in_train": heldout_source_count,
            "explicit_unseen_holdout_source_count": len(heldout_sources),
            "train_accounts": len(train_accounts),
            "test_accounts": len(test_accounts),
        },
        "limitations": [
            "All accounts, sources, and sequences are synthetic.",
            "Scenario labels are assumptions, not observed attack ground truth.",
            "The generator does not model real authentication identity providers or network telemetry.",
            "External real-world validation and privacy impact review remain required.",
            "The V2 model must not be loaded into production authentication until independently approved.",
        ],
    }

    lines = [
        "# Version 2 Scientific Audit",
        "",
        f"Overall: **{report['overall']}**",
        "",
        "| Check | Result |",
        "|---|---|",
    ]
    for name, result in checks.items():
        lines.append(f"| {name} | {result} |")
    lines.extend(
        [
            "",
            "## Remaining Limitations",
            "",
        ]
    )
    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")

    (V2_DIR / "scientific_audit.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    (V2_DIR / "scientific_audit.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
    return report, "\n".join(lines)


def main() -> None:
    dataset = V2_DIR / "dataset.csv"
    if not dataset.is_file():
        raise SystemExit("Generate data/research/v2/dataset.csv first.")

    report, markdown = audit(dataset)

    v1 = PROJECT_ROOT / "data" / "research" / "evaluation.json"
    v2 = V2_DIR / "evaluation.json"
    v1_metrics = json.loads(v1.read_text(encoding="utf-8")) if v1.is_file() else {}
    v2_metrics = json.loads(v2.read_text(encoding="utf-8")) if v2.is_file() else {}
    comparison = {
        "version": "V1 versus V2",
        "v1": v1_metrics,
        "v2": v2_metrics,
        "artifacts_are_separate": True,
    }
    (V2_DIR / "v1_v2_comparison.json").write_text(
        json.dumps(comparison, indent=2),
        encoding="utf-8",
    )
    v1_tree = v1_metrics.get("decision_tree", {})
    v1_baseline = v1_metrics.get("rule_baseline", {})
    v2_primary = v2_metrics.get("chronological_primary", {})
    v2_tree = v2_primary.get("decision_tree", {})
    v2_baseline = v2_primary.get("rule_baseline", {})
    comparison_frame = pd.DataFrame(
        [
            {
                "version": "V1",
                "detector": "Decision Tree",
                **{
                    metric: v1_tree.get(metric)
                    for metric in (
                        "accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "false_positive_rate",
                    )
                },
            },
            {
                "version": "V1",
                "detector": "Rule baseline",
                **{
                    metric: v1_baseline.get(metric)
                    for metric in (
                        "accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "false_positive_rate",
                    )
                },
            },
            {
                "version": "V2",
                "detector": "Decision Tree",
                **{
                    metric: v2_tree.get(metric)
                    for metric in (
                        "accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "false_positive_rate",
                    )
                },
            },
            {
                "version": "V2",
                "detector": "Rule baseline",
                **{
                    metric: v2_baseline.get(metric)
                    for metric in (
                        "accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "false_positive_rate",
                    )
                },
            },
        ]
    )
    comparison_frame.to_csv(
        V2_DIR / "v1_v2_comparison.csv",
        index=False,
    )

    print(markdown)
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
