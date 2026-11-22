"""Scientific-integrity tests for the separate Version 2 experiment."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from scripts.generate_research_dataset_v2 import generate
from scripts.train_decision_tree_v2 import FEATURE_COLUMNS


def test_v2_dataset_generation_is_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    generate(1000, 2026, first)
    generate(1000, 2026, second)
    assert first.read_bytes() == second.read_bytes()


def test_v2_labels_are_scenario_based(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.csv"
    generate(1000, 2026, dataset)
    frame = pd.read_csv(dataset)
    assert (
        frame.loc[frame["scenario"] == "suspicious", "suspicious"] == 1
    ).all()
    assert (
        frame.loc[frame["scenario"] != "suspicious", "suspicious"] == 0
    ).all()
    assert "suspicious" not in FEATURE_COLUMNS


def test_v2_primary_split_is_chronological(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.csv"
    generate(1000, 2026, dataset)
    frame = pd.read_csv(dataset).sort_values("attempted_at").reset_index(drop=True)
    split = int(len(frame) * 0.75)
    train = frame.iloc[:split]
    test = frame.iloc[split:]
    assert train["attempted_at"].max() <= test["attempted_at"].min()
    assert set(FEATURE_COLUMNS).issubset(frame.columns)


def test_v2_source_holdout_is_separate(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.csv"
    generate(1000, 2026, dataset)
    frame = pd.read_csv(dataset)
    holdout = set(
        frame.loc[
            frame["source_group_holdout"] == 1,
            "source_id",
        ]
    )
    training_sources = set(
        frame.loc[
            frame["source_group_holdout"] == 0,
            "source_id",
        ]
    )
    assert holdout
    assert holdout.isdisjoint(training_sources)


def test_v2_primary_artifacts_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "data" / "research" / "v2" / "dataset.csv").is_file()
    assert (root / "data" / "research" / "v2" / "evaluation.json").is_file()
    assert (root / "data" / "research" / "v2" / "seed_evaluation.json").is_file()
    assert (root / "instance" / "v2" / "decision_tree_v2.joblib").is_file()
