"""Safe loading and prediction for the locally trained Decision Tree."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import pickle

from app.detection.features import RESEARCH_FEATURE_COLUMNS

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "instance" / "decision_tree.joblib"
DEPLOYMENT_MODEL_PATH = PROJECT_ROOT / "model_artifacts" / "decision_tree.joblib"


class ModelUnavailableError(RuntimeError):
    pass


def _default_model_path() -> Path:
    # Prefer the tracked deployment artifact when present, but keep the legacy
    # instance path for local development and existing tests/scripts.
    if DEPLOYMENT_MODEL_PATH.is_file():
        return DEPLOYMENT_MODEL_PATH
    return MODEL_PATH


def load_model(path: Path | None = None) -> dict[str, Any]:
    model_path = Path(path) if path is not None else _default_model_path()
    if not model_path.is_file():
        raise ModelUnavailableError("The trusted local Decision Tree model is unavailable.")
    try:
        artifact = joblib.load(model_path)
    except (
        OSError,
        EOFError,
        ValueError,
        ImportError,
        AttributeError,
        pickle.UnpicklingError,
    ) as error:
        raise ModelUnavailableError("The local Decision Tree model could not be loaded.") from error
    if not isinstance(artifact, dict):
        raise ModelUnavailableError("The model artifact has an invalid format.")
    if artifact.get("feature_columns") != list(RESEARCH_FEATURE_COLUMNS):
        raise ModelUnavailableError("The model feature schema does not match this application.")
    if "model" not in artifact:
        raise ModelUnavailableError("The model artifact does not contain a classifier.")
    return artifact


def predict(features: dict[str, int | float], path: Path | None = None) -> tuple[int, float]:
    artifact = load_model(path)
    values = pd.DataFrame(
        [[float(features[name]) for name in RESEARCH_FEATURE_COLUMNS]],
        columns=list(RESEARCH_FEATURE_COLUMNS),
    )
    probabilities = artifact["model"].predict_proba(values)[0]
    prediction = int(artifact["model"].predict(values)[0])
    probability = float(probabilities[1] if len(probabilities) > 1 else probabilities[0])
    return prediction, probability


def feature_explanation(features: dict[str, int | float]) -> str:
    parts = []
    if float(features.get("failed_attempts_5min", 0)) >= 5:
        parts.append("5-minute failures are elevated")
    if float(features.get("unique_accounts_5min", 0)) >= 4:
        parts.append("multiple accounts were targeted")
    if int(features.get("unique_ips_5min", 1)) >= 3:
        parts.append("same account used from multiple source IPs recently")
    if float(features.get("source_failure_rate", 0)) >= 0.75:
        parts.append("the source failure rate is elevated")
    if features.get("new_device"):
        parts.append("the login used a new-device signal")
    if int(features.get("unusual_login_time", 0)) == 1:
        parts.append("login time is outside the learned usual pattern")
    if not parts:
        return "No strong suspicious behavioral feature was detected."
    return "; ".join(parts) + "."
