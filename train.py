"""Train a SQL injection detector: char n-gram TF-IDF + Random Forest.

Saves the scikit-learn pipeline (.pkl, for training tools) and an ONNX export
(.onnx, served by the API with ONNX Runtime) next to it.

Usage:
    python train.py --data data/sqli.csv --output models/sqli_detector.pkl
    python train.py --onnx-from models/sqli_detector_optimized.pkl   # export an existing model only
"""

import argparse
import copy
import logging
import os
import sys
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from importlib.metadata import version as package_version
from pathlib import Path

import joblib
import numpy as np
import onnx
import onnxruntime as ort
import pandas as pd
import sklearn
from onnx import helper, numpy_helper
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import StringTensorType
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from text_preprocessing import PREPROCESSING_ID, preprocess

logger = logging.getLogger("sqli.train")

QUERY_COLUMN = "query"
LABEL_COLUMN = "label"
VALID_LABELS = (0, 1)
CLASS_NAMES = ("safe", "sqli")
# Stratified splitting needs at least two samples of every class.
MIN_SAMPLES_PER_CLASS = 2

# ONNX export fidelity gate: every validation value must score within this of
# scikit-learn, or the export fails and no .onnx file is written.
ONNX_MAX_ABS_DIFF = 1e-4
ONNX_DECISION_THRESHOLDS = (0.5, 0.8)  # WAF parameter and header thresholds, for the report
# Inputs where text conversion diverged or is most likely to; always checked.
ONNX_EDGE_CASES = (
    "a  b", "a\t\tb", "a \t\n b", "  leading", "trailing   ", "\u00a0nbsp\u2003em\u3000ideographic",
    "\u00c9COLE Stra\u00dfe", "\u0130stanbul", "\u01c5 title case", "\u0391\u0392\u0393 \u03a3\u0395\u039b",
    "\ufb00 \u1e9e", "\U0001f600' OR 1=1--", "x\x00y", "aaaaa", "2120," * 5, "A" * 3000 + "' OR 1=1",
    "' AND 1  =  utl_inaddr.get_host_address   (    (   SELECT DISTINCT  (  USERNAME  )   FROM  ",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
)


class DatasetError(ValueError):
    """Raised when the training CSV is missing, malformed or unusable."""


class OnnxExportError(RuntimeError):
    """The ONNX model would not score like the scikit-learn pipeline."""


def read_csv_safely(path: Path, encoding: str = "utf-8") -> pd.DataFrame:
    """Read a CSV as strings, raising DatasetError on missing or malformed files."""
    if not path.is_file():
        raise DatasetError(f"Dataset not found: {path}")
    try:
        # keep_default_na=False stops pandas turning payloads such as "NULL"
        # or "NA" into NaN, which would silently drop real SQL tokens.
        return pd.read_csv(path, encoding=encoding, keep_default_na=False, dtype=str)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeError) as exc:
        raise DatasetError(f"Could not parse CSV {path}: {exc}") from exc


def clean_dataset(raw: pd.DataFrame) -> pd.DataFrame:
    """Normalise to (query, label) and drop unusable rows.

    Rows with empty queries or labels other than 0/1 are dropped, as are
    duplicate queries (which would leak between train and test) and queries
    that appear with conflicting labels.
    """
    raw = raw.copy()
    # Tolerate "Query"/"Label" headers as used by common public datasets.
    raw.columns = [str(column).strip().lower() for column in raw.columns]
    if raw.columns.duplicated().any():
        raise DatasetError(f"CSV has duplicate column names (case-insensitive): {list(raw.columns)}")
    missing = {QUERY_COLUMN, LABEL_COLUMN} - set(raw.columns)
    if missing:
        raise DatasetError(
            f"CSV is missing required column(s) {sorted(missing)}; found {list(raw.columns)}"
        )

    queries = raw[QUERY_COLUMN].astype(str)
    labels = pd.to_numeric(raw[LABEL_COLUMN].astype(str).str.strip(), errors="coerce")

    valid = labels.isin(VALID_LABELS) & (queries.str.strip().str.len() > 0)
    dropped_invalid = int((~valid).sum())
    if dropped_invalid:
        logger.warning("Dropped %d row(s) with an empty query or a label other than 0/1", dropped_invalid)

    df = pd.DataFrame(
        {QUERY_COLUMN: queries[valid], LABEL_COLUMN: labels[valid].astype(int)}
    ).drop_duplicates()

    conflicting = df[QUERY_COLUMN].duplicated(keep=False)
    if conflicting.any():
        logger.warning(
            "Dropped %d row(s) whose query appears with both labels", int(conflicting.sum())
        )
        df = df[~conflicting]
    return df.reset_index(drop=True)


def load_dataset(path: Path, encoding: str = "utf-8") -> pd.DataFrame:
    """Load, clean and sanity-check the labelled training dataset."""
    df = clean_dataset(read_csv_safely(path, encoding=encoding))

    counts = df[LABEL_COLUMN].value_counts()
    for label, name in zip(VALID_LABELS, CLASS_NAMES):
        if counts.get(label, 0) < MIN_SAMPLES_PER_CLASS:
            raise DatasetError(
                f"Need at least {MIN_SAMPLES_PER_CLASS} '{name}' samples (label={label}); "
                f"found {counts.get(label, 0)}"
            )

    logger.info(
        "Loaded %d usable samples (%d safe, %d sqli)", len(df), counts.get(0, 0), counts.get(1, 0)
    )
    return df


def build_pipeline(
    n_estimators: int = 100,
    max_features: int | None = 50_000,
    random_state: int = 42,
    n_jobs: int = -1,
) -> Pipeline:
    """Build the vectorizer + classifier pipeline."""
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(1, 4),
        lowercase=True,  # SQL keywords are case-insensitive; "UnIoN" == "union"
        sublinear_tf=True,  # dampens repeated padding characters
        max_features=max_features,
        dtype=np.float32,
    )
    classifier = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",  # SQLi datasets are usually imbalanced
        n_jobs=n_jobs,
        random_state=random_state,
    )
    return Pipeline([("tfidf", vectorizer), ("clf", classifier)])


def evaluate(pipeline: Pipeline, x_test: pd.Series, y_test: pd.Series) -> dict[str, object]:
    """Print a classification report and confusion matrix; return the report as a dict."""
    predictions = pipeline.predict(x_test)

    print("\n=== Classification report ===")
    print(
        classification_report(
            y_test, predictions, labels=list(VALID_LABELS), target_names=CLASS_NAMES, digits=4
        )
    )

    matrix = confusion_matrix(y_test, predictions, labels=list(VALID_LABELS))
    print("=== Confusion matrix (rows = actual, columns = predicted) ===")
    print(
        pd.DataFrame(
            matrix,
            index=[f"actual_{name}" for name in CLASS_NAMES],
            columns=[f"pred_{name}" for name in CLASS_NAMES],
        ).to_string()
    )
    false_negatives = int(matrix[1, 0])
    if false_negatives:
        print(f"\nWARNING: {false_negatives} SQLi sample(s) in the test set were classified as safe.")

    return classification_report(
        y_test,
        predictions,
        labels=list(VALID_LABELS),
        target_names=CLASS_NAMES,
        output_dict=True,
    )


def save_model(pipeline: Pipeline, path: Path) -> None:
    """Write the pipeline atomically so a running API never reads a partial file."""
    # Train on all cores, serve single-threaded: for one request at a time,
    # per-tree thread dispatch makes predictions several times slower.
    if "clf__n_jobs" in pipeline.get_params():
        pipeline.set_params(clf__n_jobs=1)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    joblib.dump(pipeline, tmp_path, compress=3)
    os.replace(tmp_path, path)
    logger.info("Saved model to %s", path.resolve())


def _patch_sublinear_tf(model: onnx.ModelProto) -> None:
    """Make the graph compute scikit-learn's sublinear TF: 1 + log(tf) where tf > 0.

    skl2onnx emits log(tf + 1) instead. That shifted every feature (tf=1 terms
    about 2% high, tf=2 about 4% low after normalisation) and moved scores by
    up to 0.16, enough to flip decisions.
    """
    graph = model.graph
    vectorizer = next((n for n in graph.node if n.op_type == "TfIdfVectorizer"), None)
    add = next((n for n in graph.node if vectorizer and n.op_type == "Add" and vectorizer.output[0] in n.input), None)
    log = next((n for n in graph.node if add and n.op_type == "Log" and add.output[0] in n.input), None)
    if not (vectorizer and add and log):
        raise OnnxExportError("Unexpected skl2onnx graph: TfIdfVectorizer -> Add -> Log (sublinear TF) not found")

    tf, sublinear = vectorizer.output[0], log.output[0]
    graph.initializer.append(numpy_helper.from_array(np.array(1.0, np.float32), "sublinear_one"))
    # Relu(log(tf) + 1): absent terms give log(0) + 1 = -inf, which Relu turns
    # into 0. The output is a dense [N, vocabulary] matrix, so this uses the
    # fewest and cheapest element-wise passes (measured against Where/Greater
    # and a lookup-table variant: 30% faster at batch 32).
    replacement = [
        helper.make_node("Log", [tf], ["sublinear_log"]),
        helper.make_node("Add", ["sublinear_log", "sublinear_one"], ["sublinear_1p_log"]),
        helper.make_node("Relu", ["sublinear_1p_log"], [sublinear]),
    ]
    position = list(graph.node).index(add)
    graph.node.remove(add)
    graph.node.remove(log)
    for offset, node in enumerate(replacement):
        graph.node.insert(position + offset, node)
    _drop_unused_initializers(model)


def _replace_normalizer(model: onnx.ModelProto) -> None:
    """Replace ai.onnx.ml Normalizer (L2) with ReduceL2 + Div: same result, about 3x faster.

    The ML-domain Normalizer was the second most expensive node (21% of the
    run time at batch 32). Rows whose norm is 0 stay all-zero, as in
    scikit-learn.
    """
    graph = model.graph
    normalizer = next((n for n in graph.node if n.op_type == "Normalizer"), None)
    if normalizer is None:
        raise OnnxExportError("Unexpected skl2onnx graph: Normalizer not found")
    norm = next((a.s.decode() for a in normalizer.attribute if a.name == "norm"), "")
    if norm != "L2":
        raise OnnxExportError(f"Only L2 normalisation is supported, got {norm!r}")
    source, target = normalizer.input[0], normalizer.output[0]
    graph.initializer.append(numpy_helper.from_array(np.array(1e-30, np.float32), "l2_epsilon"))
    replacement = [
        helper.make_node("ReduceL2", [source], ["l2_norm"], axes=[1], keepdims=1),
        helper.make_node("Max", ["l2_norm", "l2_epsilon"], ["l2_norm_safe"]),
        helper.make_node("Div", [source, "l2_norm_safe"], [target]),
    ]
    position = list(graph.node).index(normalizer)
    graph.node.remove(normalizer)
    for offset, node in enumerate(replacement):
        graph.node.insert(position + offset, node)


def _drop_unused_initializers(model: onnx.ModelProto) -> None:
    graph = model.graph
    used = {name for node in graph.node for name in node.input}
    for initializer in [i for i in graph.initializer if i.name not in used]:
        graph.initializer.remove(initializer)


def _remove_string_normalizer(model: onnx.ModelProto) -> None:
    """Drop the graph's lowercasing (StringNormalizer): the API lowercases in Python.

    Its lowercasing is locale-dependent, and ONNX Runtime on Linux refuses to
    load the model unless the en_US.UTF-8 locale is installed (python:slim
    images don't have it). text_preprocessing.preprocess() already applies
    scikit-learn's str.lower(), so the node only added a failure mode.
    """
    graph = model.graph
    for node in [n for n in graph.node if n.op_type == "StringNormalizer"]:
        source, target = node.input[0], node.output[0]
        for consumer in graph.node:
            for i, name in enumerate(consumer.input):
                if name == target:
                    consumer.input[i] = source
        graph.node.remove(node)


def _convertible_vectorizer(tfidf: TfidfVectorizer) -> tuple[TfidfVectorizer, int]:
    """Return a vectorizer skl2onnx can convert without dropping n-grams, and how many entries were added.

    skl2onnx encodes each character n-gram as a sequence of single-character
    tokens that must also be in the vocabulary; if one is missing it refuses
    the n-gram ("ambiguities between n-grams and tokens"). That happens with
    ngram_range not starting at 1, and when max_features breaks a frequency
    tie by keeping "mü" but dropping "ü" (retraining on the combined dataset
    did exactly that). The missing characters are added to a copy with an IDF
    weight of 0: their TF-IDF value is always 0, so they change neither the L2
    norm nor any feature, and the trees never reference them. Same scores,
    convertible vocabulary.
    """
    vocabulary = tfidf.vocabulary_
    unigrams = {term for term in vocabulary if len(term) == 1}
    missing = sorted({char for term in vocabulary if len(term) > 1 for char in term} - unigrams)
    if not missing:
        return tfidf, 0
    completed = copy.deepcopy(tfidf)
    size = len(vocabulary)
    completed.vocabulary_ = {**vocabulary, **{char: size + i for i, char in enumerate(missing)}}
    completed.idf_ = np.concatenate([tfidf.idf_, np.zeros(len(missing), dtype=tfidf.idf_.dtype)])
    return completed, len(missing)


def _onnx_probabilities(session: ort.InferenceSession, values: list[str], positive_index: int) -> np.ndarray:
    chunks = []
    for start in range(0, len(values), 512):
        batch = np.array([preprocess(v) for v in values[start:start + 512]], dtype=object).reshape(-1, 1)
        chunks.append(session.run(["probabilities"], {"input": batch})[0][:, positive_index])
    return np.concatenate(chunks)


def export_onnx(pipeline: Pipeline, path: Path, validation_values: Sequence[str]) -> dict[str, object]:
    """Convert the pipeline to ONNX, verify it scores like scikit-learn, and save it.

    The fidelity gate compares ONNX Runtime with scikit-learn on
    `validation_values` plus ONNX_EDGE_CASES. Two converter defects
    (whitespace handling, sublinear TF) made the plain skl2onnx output score
    some attacks up to 0.41 lower; any such divergence now fails the export
    (OnnxExportError) and nothing is written.
    Returns the fidelity statistics and ONNX Runtime single-request latency.
    """
    tfidf, clf = pipeline.named_steps["tfidf"], pipeline.named_steps["clf"]
    if (tfidf.analyzer, tfidf.lowercase, tfidf.preprocessor, tfidf.strip_accents) != ("char", True, None, None):
        raise OnnxExportError(
            "ONNX export expects TfidfVectorizer(analyzer='char', lowercase=True) without custom preprocessing "
            f"(see text_preprocessing.py); got analyzer={tfidf.analyzer!r}, lowercase={tfidf.lowercase}"
        )
    if tfidf.ngram_range[0] != 1:
        # skl2onnx then emits a TfIdfVectorizer node ONNX Runtime rejects
        # ("Number of items must compose whole 3-grams").
        raise OnnxExportError(f"ONNX export needs ngram_range starting at 1, got {tfidf.ngram_range}")

    convertible, added = _convertible_vectorizer(tfidf)
    if added:
        logger.info("Added %d zero-weight character(s) to the vocabulary so every n-gram converts", added)
    try:
        model = convert_sklearn(
            Pipeline([("tfidf", convertible), ("clf", clf)]),
            initial_types=[("input", StringTensorType([None, 1]))],
            options={id(clf): {"zipmap": False}},  # probabilities as a plain [N, 2] tensor
            target_opset=17,
        )
    except Exception as exc:  # skl2onnx raises RuntimeError/NotImplementedError/...
        raise OnnxExportError(f"skl2onnx could not convert the pipeline: {exc}") from exc
    if tfidf.sublinear_tf:
        _patch_sublinear_tf(model)
    _replace_normalizer(model)
    _remove_string_normalizer(model)
    _drop_unused_initializers(model)
    onnx.checker.check_model(model)

    positive_index = [int(c) for c in clf.classes_].index(1)
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    try:
        session = ort.InferenceSession(model.SerializeToString(), options, providers=["CPUExecutionProvider"])
    except Exception as exc:  # onnxruntime's Fail/InvalidGraph errors
        raise OnnxExportError(f"ONNX Runtime rejected the converted model: {exc}") from exc

    values = [str(v) for v in validation_values] + list(ONNX_EDGE_CASES)
    expected = pipeline.predict_proba(values)[:, positive_index]
    # Rounded as the API rounds (api.py, SQLiDetector.sqli_probabilities), so
    # float32 results for exact-threshold scores (e.g. 240/300 trees = 0.8)
    # compare like scikit-learn's float64 ones.
    actual = np.round(_onnx_probabilities(session, values, positive_index).astype(np.float64), 6)
    diff = np.abs(expected - actual)
    worst = int(diff.argmax())
    stats: dict[str, object] = {
        "values_checked": len(values),
        "max_abs_diff": float(diff.max()),
        # Exact ties (e.g. 240/300 trees = 0.8) land on either side of the
        # threshold through float rounding in both libraries; not counted.
        "decision_flips": {
            str(t): int((((expected >= t) != (actual >= t)) & (np.abs(expected - t) > 1e-6)).sum())
            for t in ONNX_DECISION_THRESHOLDS
        },
    }
    if diff[worst] > ONNX_MAX_ABS_DIFF:
        raise OnnxExportError(
            f"ONNX model diverges from scikit-learn: max |diff| {diff[worst]:.3g} > {ONNX_MAX_ABS_DIFF} "
            f"(scikit-learn {expected[worst]:.4f}, ONNX {actual[worst]:.4f} for {values[worst][:80]!r})"
        )

    timings = []
    for i in range(30):
        started = time.perf_counter()
        _onnx_probabilities(session, [f"value {i}"], positive_index)
        timings.append((time.perf_counter() - started) * 1000)
    stats["inference_latency_ms"] = round(float(np.median(timings)), 2)

    # The API checks these before serving the model (api.py, SQLiDetector).
    helper.set_model_props(model, {
        "preprocessing": PREPROCESSING_ID,
        "positive_class_index": str(positive_index),
        "classes": ",".join(str(int(c)) for c in clf.classes_),
        "scikit_learn_version": sklearn.__version__,
        "skl2onnx_version": package_version("skl2onnx"),
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "fidelity_max_abs_diff": f"{stats['max_abs_diff']:.3g}",
        "fidelity_values_checked": str(len(values)),
    })

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    onnx.save_model(model, tmp_path)
    os.replace(tmp_path, path)
    logger.info(
        "Saved ONNX model to %s (fidelity: max |diff| %.2g over %d values; ONNX Runtime %.2f ms per value)",
        path.resolve(), stats["max_abs_diff"], len(values), stats["inference_latency_ms"],
    )
    return stats


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the SQL injection detector.")
    parser.add_argument("--data", type=Path, default=Path("data/sqli.csv"), help="Labelled CSV dataset")
    parser.add_argument("--output", type=Path, default=Path("models/sqli_detector.pkl"), help="Where to save the model")
    parser.add_argument("--encoding", default="utf-8", help="CSV file encoding (e.g. utf-16)")
    parser.add_argument("--test-size", type=float, default=0.2, help="Fraction held out for evaluation")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of trees")
    parser.add_argument(
        "--max-features",
        type=int,
        default=50_000,
        help="Max TF-IDF vocabulary size (0 = unlimited)",
    )
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--onnx-from",
        type=Path,
        help="Don't train: export this saved .pkl to ONNX (validated on --data's test split)",
    )
    args = parser.parse_args(argv)

    if not 0.0 < args.test_size < 1.0:
        parser.error("--test-size must be between 0 and 1")
    if args.n_estimators < 1:
        parser.error("--n-estimators must be >= 1")
    if args.max_features < 0:
        parser.error("--max-features must be >= 0")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)

    try:
        df = load_dataset(args.data, encoding=args.encoding)
        x_train, x_test, y_train, y_test = train_test_split(
            df[QUERY_COLUMN],
            df[LABEL_COLUMN],
            test_size=args.test_size,
            stratify=df[LABEL_COLUMN],
            random_state=args.random_state,
        )
    except DatasetError as exc:
        logger.error("%s", exc)
        return 1
    except ValueError as exc:  # e.g. test split too small to contain both classes
        logger.error("Could not split dataset: %s", exc)
        return 1

    if args.onnx_from:
        try:
            # Only ever load a pickle you produced yourself (joblib = pickle).
            pipeline = joblib.load(args.onnx_from)
            export_onnx(pipeline, args.onnx_from.with_suffix(".onnx"), x_test.tolist())
        except (OSError, OnnxExportError) as exc:
            logger.error("ONNX export failed: %s", exc)
            return 1
        return 0

    pipeline = build_pipeline(
        n_estimators=args.n_estimators,
        max_features=args.max_features or None,
        random_state=args.random_state,
    )
    logger.info("Training on %d samples, evaluating on %d", len(x_train), len(x_test))
    pipeline.fit(x_train, y_train)

    evaluate(pipeline, x_test, y_test)

    try:
        save_model(pipeline, args.output)
        export_onnx(pipeline, args.output.with_suffix(".onnx"), x_test.tolist())
    except OSError as exc:
        logger.error("Could not save model to %s: %s", args.output, exc)
        return 1
    except OnnxExportError as exc:
        logger.error("ONNX export failed (the .pkl was saved; the API serves only .onnx): %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
