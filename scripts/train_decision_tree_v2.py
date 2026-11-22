"""Train and evaluate the separate Version 2 synthetic Decision Tree experiment."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Callable

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
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
V2_DIR = PROJECT_ROOT / "data" / "research" / "v2"
PRIMARY_DATASET = V2_DIR / "dataset.csv"
MODEL_DIR = PROJECT_ROOT / "instance" / "v2"
MODEL_PATH = MODEL_DIR / "decision_tree_v2.joblib"

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


def metrics(y_true, y_pred) -> dict:
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


def train_rule_baseline(frame: pd.DataFrame) -> Callable[[pd.DataFrame], np.ndarray]:
    """Tune an independent multi-feature rule using training rows only."""
    y = frame["suspicious"].to_numpy()
    x = frame[FEATURE_COLUMNS]
    cv = TimeSeriesSplit(n_splits=4)

    candidates = []
    for failure_threshold in (3, 5, 7):
        for rate_threshold in (0.55, 0.70, 0.85):
            for account_threshold in (2, 3, 4):
                for score_threshold in (1.5, 2.0, 2.5, 3.0):
                    fold_scores = []
                    for train_index, validation_index in cv.split(x):
                        predictions = baseline_predictions(
                            x.iloc[validation_index],
                            failure_threshold,
                            rate_threshold,
                            account_threshold,
                            score_threshold,
                        )
                        fold_scores.append(
                            f1_score(
                                y[validation_index],
                                predictions,
                                zero_division=0,
                            )
                        )
                    candidates.append(
                        (
                            float(np.mean(fold_scores)),
                            failure_threshold,
                            rate_threshold,
                            account_threshold,
                            score_threshold,
                        )
                    )

    _, failure_threshold, rate_threshold, account_threshold, score_threshold = max(
        candidates,
        key=lambda item: item[0],
    )

    def predictor(rows: pd.DataFrame) -> np.ndarray:
        return baseline_predictions(
            rows,
            failure_threshold,
            rate_threshold,
            account_threshold,
            score_threshold,
        )

    predictor.thresholds = {  # type: ignore[attr-defined]
        "failed_attempt_threshold": failure_threshold,
        "source_failure_rate_threshold": rate_threshold,
        "targeted_account_threshold": account_threshold,
        "weighted_score_threshold": score_threshold,
    }
    return predictor


def baseline_predictions(
    rows: pd.DataFrame,
    failure_threshold: int,
    rate_threshold: float,
    account_threshold: int,
    score_threshold: float,
) -> np.ndarray:
    """Independent traditional rule: weighted evidence, not the scenario label."""
    score = (
        1.0 * (rows["failed_attempts_5min"] >= failure_threshold)
        + 1.0 * (rows["source_failure_rate"] >= rate_threshold)
        + 1.0 * (rows["unique_accounts_5min"] >= account_threshold)
        + 0.6 * (rows["recent_account_failure_count"] >= 3)
        + 0.5 * (
            (rows["login_hour"] <= 5)
            | (rows["login_hour"] >= 22)
        )
        + 0.4 * (rows["new_device"] == 1)
        + 0.3 * (rows["time_since_last_login"] <= 300)
    )
    return (score >= score_threshold).astype(int).to_numpy()


def bootstrap_metric(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    metric_name: str,
    seed: int,
    iterations: int = 1000,
) -> tuple[float, float, float]:
    rng = np.random.default_rng(seed)
    values = []
    for _ in range(iterations):
        indices = rng.integers(0, len(y_true), len(y_true))
        yt = y_true[indices]
        yp = y_pred[indices]
        if metric_name == "accuracy":
            value = accuracy_score(yt, yp)
        elif metric_name == "precision":
            value = precision_score(yt, yp, zero_division=0)
        elif metric_name == "recall":
            value = recall_score(yt, yp, zero_division=0)
        elif metric_name == "f1":
            value = f1_score(yt, yp, zero_division=0)
        else:
            matrix = confusion_matrix(yt, yp, labels=[0, 1])
            tn, fp, _, _ = matrix.ravel()
            value = fp / (fp + tn) if fp + tn else 0.0
        values.append(value)
    array = np.asarray(values)
    return (
        float(np.mean(array)),
        float(np.percentile(array, 2.5)),
        float(np.percentile(array, 97.5)),
    )


def fit_primary(
    dataset: Path,
) -> tuple[DecisionTreeClassifier, dict, pd.DataFrame, pd.DataFrame]:
    frame = pd.read_csv(dataset).sort_values("attempted_at").reset_index(drop=True)
    required = set(FEATURE_COLUMNS) | {"attempted_at", "suspicious", "source_id", "account_id"}
    missing = required - set(frame.columns)
    if missing:
        raise RuntimeError(f"Version 2 dataset is missing columns: {sorted(missing)}")

    split = int(len(frame) * 0.75)
    train = frame.iloc[:split].copy()
    test = frame.iloc[split:].copy()

    grid = GridSearchCV(
        DecisionTreeClassifier(random_state=42, class_weight="balanced"),
        {
            "max_depth": [3, 5, 7, 10],
            "min_samples_split": [20, 50, 100],
            "min_samples_leaf": [10, 25, 50],
        },
        scoring="f1",
        cv=TimeSeriesSplit(n_splits=4),
        n_jobs=-1,
    )
    grid.fit(train[FEATURE_COLUMNS], train["suspicious"])
    model = grid.best_estimator_
    model.test_parameters = grid.best_params_  # type: ignore[attr-defined]
    return model, grid.best_params_, train, test


def evaluate_partition(
    model: DecisionTreeClassifier,
    baseline_predictor: Callable[[pd.DataFrame], np.ndarray],
    train: pd.DataFrame,
    test: pd.DataFrame,
    seed: int,
) -> dict:
    del train
    x_test = test[FEATURE_COLUMNS]
    y_test = test["suspicious"].to_numpy()

    start = time.perf_counter()
    tree_predictions = model.predict(x_test)
    tree_latency = (time.perf_counter() - start) / max(1, len(y_test)) * 1000.0

    start = time.perf_counter()
    baseline_predictions_array = baseline_predictor(x_test)
    baseline_latency = (time.perf_counter() - start) / max(1, len(y_test)) * 1000.0

    tree_metrics = metrics(y_test, tree_predictions)
    baseline_metrics = metrics(y_test, baseline_predictions_array)
    tree_metrics["prediction_latency_ms"] = tree_latency
    baseline_metrics["prediction_latency_ms"] = baseline_latency

    event_uncertainty = {}
    for name in ("accuracy", "precision", "recall", "f1", "false_positive_rate"):
        event_uncertainty[name] = dict(
            zip(
                ("mean", "ci2_5", "ci97_5"),
                bootstrap_metric(
                    y_test,
                    tree_predictions,
                    name,
                    seed=seed,
                ),
            )
        )

    return {
        "decision_tree": tree_metrics,
        "rule_baseline": baseline_metrics,
        "bootstrap_event_uncertainty": event_uncertainty,
    }


def save_visuals(
    model: DecisionTreeClassifier,
    frame: pd.DataFrame,
    output_dir: Path,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    split = int(len(frame) * 0.75)
    train = frame.iloc[:split]
    test = frame.iloc[split:]

    tree_predictions = model.predict(test[FEATURE_COLUMNS])
    baseline_predictor = train_rule_baseline(train)
    baseline_predictions_array = baseline_predictor(test[FEATURE_COLUMNS])

    fig, ax = plt.subplots(figsize=(7, 5))
    labels = ["Accuracy", "Precision", "Recall", "F1"]
    tree_metrics = metrics(test["suspicious"].to_numpy(), tree_predictions)
    baseline_metrics = metrics(test["suspicious"].to_numpy(), baseline_predictions_array)
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
    x = np.arange(len(labels))
    ax.bar(x - 0.18, tree_values, width=0.36, label="Decision Tree")
    ax.bar(x + 0.18, baseline_values, width=0.36, label="Rule baseline")
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1)
    ax.legend()
    ax.set_title("Version 2: Scenario-Based Synthetic Authentication")
    fig.tight_layout()
    fig.savefig(output_dir / "metrics_comparison.png", dpi=160)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(13, 8))
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
    fig.savefig(output_dir / "decision_tree.png", dpi=160)
    plt.close(fig)

    permutation = permutation_importance(
        model,
        test[FEATURE_COLUMNS],
        test["suspicious"],
        scoring="f1",
        n_repeats=30,
        random_state=42,
    )
    permutation_importance_json = {
        feature: {
            "mean": float(permutation.importances_mean[index]),
            "std": float(permutation.importances_std[index]),
        }
        for index, feature in enumerate(FEATURE_COLUMNS)
    }
    impurity_importance = {
        feature: float(model.feature_importances_[index])
        for index, feature in enumerate(FEATURE_COLUMNS)
    }
    return {
        "permutation": permutation_importance_json,
        "impurity": impurity_importance,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=PRIMARY_DATASET)
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument("--output-dir", type=Path, default=V2_DIR)
    args = parser.parse_args()
    if not args.dataset.is_file():
        raise SystemExit("Generate data/research/v2/dataset.csv first.")

    frame = pd.read_csv(args.dataset).sort_values("attempted_at").reset_index(drop=True)
    model, best_parameters, train, test = fit_primary(args.dataset)
    baseline_predictor = train_rule_baseline(train)

    primary = evaluate_partition(model, baseline_predictor, train, test, seed=2026)
    heldout_sources = set(
        frame.loc[
            frame["source_group_holdout"] == 1,
            "source_id",
        ].unique()
    )
    group_train_frame = frame.loc[
        frame["source_id"].isin(heldout_sources) == False
    ].sort_values("attempted_at").reset_index(drop=True)
    group_test = frame.loc[
        frame["source_id"].isin(heldout_sources)
    ].sort_values("attempted_at").reset_index(drop=True)

    group_grid = GridSearchCV(
        DecisionTreeClassifier(random_state=42, class_weight="balanced"),
        {
            "max_depth": [3, 5, 7, 10],
            "min_samples_split": [20, 50, 100],
            "min_samples_leaf": [10, 25, 50],
        },
        scoring="f1",
        cv=TimeSeriesSplit(n_splits=4),
        n_jobs=-1,
    )
    group_grid.fit(
        group_train_frame[FEATURE_COLUMNS],
        group_train_frame["suspicious"],
    )
    group_model = group_grid.best_estimator_
    group_baseline = train_rule_baseline(group_train_frame)
    group_metrics = evaluate_partition(
        group_model,
        group_baseline,
        group_train_frame,
        group_test,
        seed=2026,
    )

    importance = save_visuals(model, frame, args.output_dir)
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "version": 2,
            "synthetic": True,
            "primary_metrics": primary,
            "group_disjoint_metrics": {
                "heldout_source_count": len(heldout_sources),
                "train_source_count": len(set(group_train_frame["source_id"])),
                "test_rows": len(group_test),
                "tree_best_parameters": group_grid.best_params_,
                "baseline_thresholds": getattr(group_baseline, "thresholds", {}),
                **group_metrics,
            },
        },
        args.model,
    )

    unique_accounts = frame["unique_accounts_5min"]
    label_by_unique = frame.groupby("unique_accounts_5min")["suspicious"].mean()
    shortcut_check = {
        "unique_accounts_suspicious_label_mean": {
            str(key): float(value)
            for key, value in label_by_unique.to_dict().items()
        },
        "unique_accounts_feature_std_normal": float(
            frame.loc[frame["suspicious"] == 0, "unique_accounts_5min"].std()
        ),
        "unique_accounts_feature_std_suspicious": float(
            frame.loc[frame["suspicious"] == 1, "unique_accounts_5min"].std()
        ),
        "unique_accounts_feature_range": [
            int(unique_accounts.min()),
            int(unique_accounts.max()),
        ],
    }

    evaluation = {
        "version": 2,
        "synthetic": True,
        "rows": len(frame),
        "train_rows": len(train),
        "test_rows": len(test),
        "best_parameters": best_parameters,
        "baseline_thresholds": getattr(
            baseline_predictor,
            "thresholds",
            {},
        ),
        "chronological_primary": primary,
        "group_disjoint_unseen_sources": {
            "heldout_source_count": len(heldout_sources),
            "train_source_count": len(set(group_train_frame["source_id"])),
            "test_rows": len(group_test),
            "tree_best_parameters": group_grid.best_params_,
            "baseline_thresholds": getattr(group_baseline, "thresholds", {}),
            **group_metrics,
        },
        "feature_importance": importance,
        "shortcut_check": shortcut_check,
    }
    (args.output_dir / "evaluation.json").write_text(
        json.dumps(evaluation, indent=2),
        encoding="utf-8",
    )
    (args.output_dir / "feature_importance.json").write_text(
        json.dumps(importance, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(evaluation, indent=2))


if __name__ == "__main__":
    main()
