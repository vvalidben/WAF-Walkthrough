"""Dataset cleaning and the ONNX export with its fidelity gate (train.py)."""

from pathlib import Path

import numpy as np
import onnx
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline

import train
from text_preprocessing import PREPROCESSING_ID
from train import (
    ONNX_MAX_ABS_DIFF,
    DatasetError,
    OnnxExportError,
    build_pipeline,
    clean_dataset,
    export_onnx,
    load_dataset,
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# --- dataset loading -------------------------------------------------------


def test_clean_dataset_normalises_and_drops_unusable_rows() -> None:
    raw = pd.DataFrame({
        "Query": ["a", "a", "b", "b", "c", "  ", "d", "e"],
        "Label": ["0", "0", "0", "1", "2", "1", "1", " 1 "],
    })
    df = clean_dataset(raw)
    # duplicate "a" kept once; "b" has both labels; label 2 and blank query dropped
    assert df.to_dict("records") == [
        {"query": "a", "label": 0}, {"query": "d", "label": 1}, {"query": "e", "label": 1},
    ]


def test_sql_tokens_are_not_read_as_missing_values(tmp_path: Path) -> None:
    csv = _write(tmp_path / "d.csv", "query,label\nNULL,1\nNA,1\nnone,0\nn/a,0\n")
    assert sorted(load_dataset(csv)["query"]) == ["NA", "NULL", "n/a", "none"]


def test_load_dataset_errors(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="not found"):
        load_dataset(tmp_path / "missing.csv")
    with pytest.raises(DatasetError, match="missing required column"):
        load_dataset(_write(tmp_path / "cols.csv", "text,label\na,0\n"))
    with pytest.raises(DatasetError, match="'sqli' samples"):
        load_dataset(_write(tmp_path / "one_class.csv", "query,label\na,0\nb,0\nc,1\n"))


# --- ONNX export -------------------------------------------------------------


def test_export_matches_sklearn(onnx_model: tuple[Path, dict]) -> None:
    path, stats = onnx_model
    assert path.is_file()
    assert stats["max_abs_diff"] <= ONNX_MAX_ABS_DIFF
    assert stats["decision_flips"] == {"0.5": 0, "0.8": 0}


def test_export_metadata_and_graph(onnx_model: tuple[Path, dict], trained_pipeline: Pipeline) -> None:
    model = onnx.load(onnx_model[0])
    meta = {p.key: p.value for p in model.metadata_props}
    assert meta["preprocessing"] == PREPROCESSING_ID
    classes = meta["classes"].split(",")
    assert classes[int(meta["positive_class_index"])] == "1"
    ops = {node.op_type for node in model.graph.node}
    # Locale-dependent lowercasing would fail to load on python:slim; the
    # ML-domain Normalizer is replaced by a faster equivalent.
    assert "StringNormalizer" not in ops
    assert "Normalizer" not in ops
    assert {"Relu", "ReduceL2"} <= ops


def test_fidelity_gate_rejects_unpatched_sublinear_tf(
    trained_pipeline: Pipeline, synthetic_df: pd.DataFrame, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without the sublinear-TF fix, skl2onnx computes log(tf + 1): the gate
    # must catch that drift and write nothing.
    monkeypatch.setattr(train, "_patch_sublinear_tf", lambda model: None)
    target = tmp_path / "bad.onnx"
    with pytest.raises(OnnxExportError, match="diverges from scikit-learn"):
        export_onnx(trained_pipeline, target, synthetic_df["query"].tolist())
    assert not target.exists()
    assert not target.with_name(target.name + ".tmp").exists()


def test_export_refuses_ngram_range_not_starting_at_one(synthetic_df: pd.DataFrame, tmp_path: Path) -> None:
    pipeline = build_pipeline(n_estimators=5, max_features=2_000, n_jobs=1)
    pipeline.set_params(tfidf__ngram_range=(2, 4))
    pipeline.fit(synthetic_df["query"], synthetic_df["label"])
    with pytest.raises(OnnxExportError, match="ngram_range starting at 1"):
        export_onnx(pipeline, tmp_path / "m.onnx", [])
    assert not (tmp_path / "m.onnx").exists()


def test_convertible_vectorizer_adds_missing_characters_with_zero_weight(trained_pipeline: Pipeline) -> None:
    tfidf = trained_pipeline.named_steps["tfidf"]
    trimmed = type(tfidf)(**tfidf.get_params())
    # A vocabulary that has the bigram "mü" but not the character "ü".
    trimmed.vocabulary_ = {"m": 0, "mü": 1}
    trimmed.idf_ = np.array([1.5, 2.0], dtype=np.float32)
    completed, added = train._convertible_vectorizer(trimmed)
    assert added == 1
    assert completed.vocabulary_["ü"] == 2
    assert completed.idf_.tolist() == [1.5, 2.0, 0.0]
    assert "ü" not in trimmed.vocabulary_  # the original is left untouched
