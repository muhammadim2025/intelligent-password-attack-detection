"""Train and evaluate the Decision Tree on the synthetic research dataset."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GridSearchCV, TimeSeriesSplit
from sklearn.tree import DecisionTreeClassifier, plot_tree

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET = PROJECT_ROOT / "data" / "synthetic" / "authentication_events.csv"
MODEL_PATH = PROJECT_ROOT / "instance" / "decision_tree.joblib"
REPORT_DIR = PROJECT_ROOT / "data" / "research"

FEATURE_COLUMNS = [
    "failed_attempts_5min",
    "login_attempts_5min",
    "unique_accounts_5min",
    "new_device",
    "login_hour",
    "source_failure_rate",
    "time_since_last_login",
    "recent_account_failure_count",
]


def rule_baseline(row: pd.Series) -> int:
    return int(
        row["failed_attempts_5min"] >= 8
        or row["source_failure_rate"] >= 0.90
    )


def metrics(y_true, y_pred) -> dict[str, float | list[list[int]]]:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "confusion_matrix": matrix.tolist(),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }


def train(dataset: Path, model_path: Path, report_dir: Path) -> dict:
    frame = pd.read_csv(dataset)
    required = set(FRAME_FEATURES := FEATURE_COLUMNS) | {"suspicious", "attempted_at"}
    missing = required - set(frame.columns)
    if missing:
        raise RuntimeError(f"Synthetic dataset is missing columns: {sorted(missing)}")
    if frame["suspicious"].nunique() != 2:
        raise RuntimeError("Synthetic dataset must contain both target classes.")

    frame = frame.sort_values("attempted_at").reset_index(drop=True)
    split = int(len(frame) * 0.75)
    train_frame = frame.iloc[:split]
    test_frame = frame.iloc[split:]
    x_train = train_frame[FEATURE_COLUMNS]
    y_train = train_frame["suspicious"]
    x_test = test_frame[FEATURE_COLUMNS]
    y_test = test_frame["suspicious"]

    grid = GridSearchCV(
        DecisionTreeClassifier(random_state=42, class_weight="balanced"),
        {
            "max_depth": [4, 6, 8, 10],
            "min_samples_split": [10, 25, 50],
            "min_samples_leaf": [5, 10, 20],
        },
        scoring="f1",
        cv=TimeSeriesSplit(n_splits=4),
        n_jobs=-1,
    )
    grid.fit(x_train, y_train)
    model = grid.best_estimator_

    start = time.perf_counter()
    tree_predictions = model.predict(x_test)
    tree_latency = (time.perf_counter() - start) / max(1, len(x_test)) * 1000.0

    start = time.perf_counter()
    baseline_predictions = x_test.apply(rule_baseline, axis=1).to_numpy()
    baseline_latency = (time.perf_counter() - start) / max(1, len(x_test)) * 1000.0

    tree_metrics = metrics(y_test, tree_predictions)
    baseline_metrics = metrics(y_test, baseline_predictions)
    tree_metrics["prediction_latency_ms"] = tree_latency
    baseline_metrics["prediction_latency_ms"] = baseline_latency

    report_dir.mkdir(parents=True, exist_ok=True)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    artifact = {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "metrics": tree_metrics,
        "comparison": {
            "decision_tree": tree_metrics,
            "rule_baseline": baseline_metrics,
        },
        "synthetic": True,
        "dataset_seed": 42,
    }
    # Use joblib for trusted local artifacts only.
    import joblib
    joblib.dump(artifact, model_path)

    (report_dir / "evaluation.json").write_text(
        json.dumps(
            {
                "synthetic": True,
                "rows": len(frame),
                "train_rows": len(train_frame),
                "test_rows": len(test_frame),
                "best_parameters": grid.best_params_,
                "decision_tree": tree_metrics,
                "rule_baseline": baseline_metrics,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    fig, ax = plt.subplots(figsize=(7, 5))
    labels = ["Accuracy", "Precision", "Recall", "F1"]
    tree_values = [
        tree_metrics["accuracy"],
        tree_metrics["precision"],
        tree_metrics["recall"],
        tree_metrics["f1"],
    ]
    baseline_values = [
        baseline_metrics["accuracy"],
        baseline_metrics["precision"],
        baseline_metrics["recall"],
        baseline_metrics["f1"],
    ]
    x = range(len(labels))
    ax.bar([n - 0.18 for n in x], tree_values, width=0.36, label="Decision Tree")
    ax.bar([n + 0.18 for n in x], baseline_values, width=0.36, label="Rule baseline")
    ax.set_xticks(list(x), labels)
    ax.set_ylim(0, 1)
    ax.legend()
    ax.set_title("Synthetic Authentication Detection Comparison")
    fig.tight_layout()
    fig.savefig(report_dir / "metrics_comparison.png", dpi=160)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(12, 7))
    plot_tree(
        model,
        feature_names=FEATURE_COLUMNS,
        class_names=["Normal", "Suspicious"],
        filled=True,
        max_depth=4,
        ax=ax,
        fontsize=8,
    )
    fig.tight_layout()
    fig.savefig(report_dir / "decision_tree.png", dpi=160)
    plt.close(fig)

    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument("--report-dir", type=Path, default=REPORT_DIR)
    args = parser.parse_args()
    if not args.dataset.is_file():
        raise SystemExit("Generate data/synthetic/authentication_events.csv first.")
    artifact = train(args.dataset, args.model, args.report_dir)
    print(f"Model: {args.model}")
    print(json.dumps(artifact["metrics"], indent=2))


if __name__ == "__main__":
    main()
