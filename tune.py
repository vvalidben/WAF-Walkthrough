"""Hyperparameter search for the SQLi detector pipeline.

Usage:
    python tune.py --data data/sqli.csv                         # randomized search
    python tune.py --search grid                                # exhaustive, smaller grid
    python tune.py --n-iter 40 --scoring recall --cv 5

The search runs on the training split only. The held-out test split is scored
once with the best model, so the reported metrics are not tuned on.

Among candidates whose CV score is within --score-tolerance of the best, the
one that predicts fastest is chosen: the model sits in the request path of
the WAF, where every millisecond counts against its timeout.
"""

import argparse
import json
import logging
import sys
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import get_scorer_names
from sklearn.model_selection import (
    GridSearchCV,
    RandomizedSearchCV,
    StratifiedKFold,
    train_test_split,
)

from train import (
    LABEL_COLUMN,
    QUERY_COLUMN,
    DatasetError,
    OnnxExportError,
    build_pipeline,
    evaluate,
    export_onnx,
    load_dataset,
    save_model,
)

logger = logging.getLogger("sqli.tune")

# Sampled by --search random.
RANDOM_SPACE: dict[str, list[Any]] = {
    # Starting at 1: the ONNX export can't convert char n-grams that don't.
    "tfidf__ngram_range": [(1, 3), (1, 4), (1, 5)],
    "tfidf__max_features": [20_000, 50_000, 100_000],
    "tfidf__min_df": [1, 2, 3],
    "tfidf__sublinear_tf": [True, False],
    "clf__n_estimators": [50, 100, 200, 300],
    "clf__max_depth": [None, 30, 60, 100],
    "clf__min_samples_leaf": [1, 2, 4],
    "clf__max_features": ["sqrt", "log2"],
}

# Every combination is fitted by --search grid, so keep it small (32 x cv fits).
GRID_SPACE: dict[str, list[Any]] = {
    "tfidf__ngram_range": [(1, 3), (1, 4)],
    "tfidf__max_features": [20_000, 50_000],
    "clf__n_estimators": [50, 150],
    "clf__max_depth": [None, 60],
    "clf__min_samples_leaf": [1, 2],
}


# Single-request inference above this leaves too little of the WAF's 50 ms budget.
LATENCY_WARNING_MS = 25.0


def prefer_fastest(tolerance: float) -> Callable[[dict[str, Any]], int]:
    """Refit strategy: the fastest-scoring candidate within `tolerance` of the best score."""

    def choose(cv_results: dict[str, Any]) -> int:
        scores = np.asarray(cv_results["mean_test_score"], dtype=float)
        score_times = np.asarray(cv_results["mean_score_time"], dtype=float)
        eligible = np.flatnonzero(scores >= np.nanmax(scores) - tolerance)
        return int(eligible[np.argmin(score_times[eligible])])

    return choose


def single_request_latency_ms(model: Any, repeats: int = 30) -> float:
    """Median time to score one value, as the API does per request."""
    model.predict_proba(["warm up"])
    timings = []
    for i in range(repeats):
        started = time.perf_counter()
        model.predict_proba([f"value {i}"])
        timings.append((time.perf_counter() - started) * 1000)
    return float(np.median(timings))


def build_search(
    search: str,
    n_iter: int,
    cv: int,
    scoring: str,
    n_jobs: int,
    random_state: int,
    score_tolerance: float,
) -> GridSearchCV | RandomizedSearchCV:
    # Parallelise across CV fits, not inside each forest, to avoid
    # oversubscribing cores. This also leaves the saved model single-threaded,
    # which suits per-request inference in the API.
    pipeline = build_pipeline(random_state=random_state, n_jobs=1)
    folds = StratifiedKFold(n_splits=cv, shuffle=True, random_state=random_state)
    common: dict[str, Any] = {
        "scoring": scoring,
        "cv": folds,
        "n_jobs": n_jobs,
        "refit": prefer_fastest(score_tolerance),
        "error_score": "raise",
        "verbose": 1,
    }
    if search == "grid":
        return GridSearchCV(pipeline, GRID_SPACE, **common)
    return RandomizedSearchCV(
        pipeline, RANDOM_SPACE, n_iter=n_iter, random_state=random_state, **common
    )


def top_candidates(search: GridSearchCV | RandomizedSearchCV, k: int = 5) -> pd.DataFrame:
    results = pd.DataFrame(search.cv_results_)
    columns = ["rank_test_score", "mean_test_score", "std_test_score", "mean_score_time", "params"]
    return results.sort_values("rank_test_score")[columns].head(k)


def to_jsonable(params: dict[str, Any]) -> dict[str, Any]:
    return {key: list(value) if isinstance(value, tuple) else value for key, value in params.items()}


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    logger.info("Wrote tuning report to %s", path)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tune the SQLi detector hyperparameters.")
    parser.add_argument("--data", type=Path, default=Path("data/sqli.csv"))
    parser.add_argument("--output", type=Path, default=Path("models/sqli_detector_optimized.pkl"))
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--search", choices=["random", "grid"], default="random")
    parser.add_argument("--n-iter", type=int, default=20, help="Candidates sampled by random search")
    parser.add_argument("--cv", type=int, default=5, help="Stratified CV folds")
    parser.add_argument(
        "--scoring",
        default="f1",
        help="scikit-learn scorer, computed for the sqli class (e.g. f1, recall, average_precision)",
    )
    parser.add_argument(
        "--score-tolerance",
        type=float,
        default=0.001,
        help="Prefer the fastest candidate within this much of the best CV score (0 = best score only)",
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--n-jobs", type=int, default=-1, help="Parallel CV fits (-1 = all cores)")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args(argv)

    if args.scoring not in get_scorer_names():
        parser.error(f"Unknown scorer {args.scoring!r}")
    if not 0.0 < args.test_size < 1.0:
        parser.error("--test-size must be between 0 and 1")
    if args.cv < 2:
        parser.error("--cv must be >= 2")
    if args.n_iter < 1:
        parser.error("--n-iter must be >= 1")
    if args.score_tolerance < 0:
        parser.error("--score-tolerance must be >= 0")
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
    except ValueError as exc:
        logger.error("Could not split dataset: %s", exc)
        return 1

    if y_train.value_counts().min() < args.cv:
        logger.error("Smallest class has fewer than --cv=%d training samples; lower --cv", args.cv)
        return 1

    search = build_search(
        args.search,
        args.n_iter,
        args.cv,
        args.scoring,
        args.n_jobs,
        args.random_state,
        args.score_tolerance,
    )
    logger.info(
        "Running %s search (scoring=%s, cv=%d) on %d training samples",
        args.search,
        args.scoring,
        args.cv,
        len(x_train),
    )
    started = datetime.now(timezone.utc)
    search.fit(x_train, y_train)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    # A callable refit leaves best_score_ unset; read the chosen candidate's score.
    best_cv_score = float(search.cv_results_["mean_test_score"][search.best_index_])
    top_cv_score = float(np.nanmax(search.cv_results_["mean_test_score"]))
    print(
        f"\n=== Chosen parameters (CV {args.scoring} = {best_cv_score:.4f}; "
        f"best seen {top_cv_score:.4f}) ==="
    )
    for name, value in sorted(search.best_params_.items()):
        print(f"  {name:28} {value}")
    print("\n=== Top candidates ===")
    with pd.option_context("display.max_colwidth", None, "display.width", 200):
        print(top_candidates(search).to_string(index=False))

    test_report = evaluate(search.best_estimator_, x_test, y_test)

    latency_ms = single_request_latency_ms(search.best_estimator_)
    print(f"\nSingle-request inference latency (scikit-learn): {latency_ms:.1f} ms (median)")

    try:
        save_model(search.best_estimator_, args.output)
        # The API serves the ONNX export (models/sqli_detector_optimized.onnx).
        onnx_stats = export_onnx(search.best_estimator_, args.output.with_suffix(".onnx"), x_test.tolist())
        print(f"Single-request inference latency (ONNX Runtime, as served): {onnx_stats['inference_latency_ms']:.2f} ms")
        if onnx_stats["inference_latency_ms"] > LATENCY_WARNING_MS:
            print(
                f"WARNING: above {LATENCY_WARNING_MS:.0f} ms. Behind the WAF's 50 ms timeout this "
                "model will cause frequent fail-open; raise --score-tolerance or use fewer trees."
            )
        write_report(
            args.output.with_suffix(".json"),
            {
                "created_at": started.isoformat(),
                "search": args.search,
                "scoring": args.scoring,
                "cv_folds": args.cv,
                "best_cv_score": best_cv_score,
                "top_cv_score": top_cv_score,
                "score_tolerance": args.score_tolerance,
                "inference_latency_ms": round(latency_ms, 2),
                "onnx": onnx_stats,
                "best_params": to_jsonable(search.best_params_),
                "test_report": test_report,
                "n_train": len(x_train),
                "n_test": len(x_test),
                "search_seconds": round(elapsed, 1),
                "scikit_learn_version": sklearn.__version__,
                "data": str(args.data),
            },
        )
    except OSError as exc:
        logger.error("Could not save outputs: %s", exc)
        return 1
    except OnnxExportError as exc:
        logger.error("ONNX export failed (the .pkl was saved; the API serves only .onnx): %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
