"""Decision Tree training, evaluation, and trusted local serialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib

from app.detection.features import RESEARCH_FEATURE_COLUMNS


def save_model(
    model,
    path: Path,
    *,
    metrics: dict[str, Any],
    comparison: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_columns": list(RESEARCH_FEATURE_COLUMNS),
            "metrics": metrics,
            "comparison": comparison,
            "synthetic": True,
        },
        path,
    )
