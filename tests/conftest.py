"""Shared fixtures: a small model trained on synthetic data and exported to ONNX once per session."""

from pathlib import Path

import pandas as pd
import pytest
from sklearn.pipeline import Pipeline

from tests.synthetic_data import generate
from train import build_pipeline, export_onnx

# Values the synthetic model must get right; used by the API tests.
ATTACK = "7 UNION SELECT password, username FROM users--"
BENIGN = "alice"


@pytest.fixture(scope="session")
def synthetic_df() -> pd.DataFrame:
    return pd.DataFrame(generate(), columns=["query", "label"])


@pytest.fixture(scope="session")
def trained_pipeline(synthetic_df: pd.DataFrame) -> Pipeline:
    # Small but structurally identical to production: char (1,4) TF-IDF with
    # sublinear TF, Random Forest. Fewer trees and features keep it fast.
    pipeline = build_pipeline(n_estimators=20, max_features=5_000, n_jobs=1)
    return pipeline.fit(synthetic_df["query"], synthetic_df["label"])


@pytest.fixture(scope="session")
def onnx_model(trained_pipeline: Pipeline, synthetic_df: pd.DataFrame, tmp_path_factory) -> tuple[Path, dict]:
    """(path, fidelity stats) of the verified ONNX export."""
    path = tmp_path_factory.mktemp("model") / "sqli_detector.onnx"
    stats = export_onnx(trained_pipeline, path, synthetic_df["query"].tolist())
    return path, stats
