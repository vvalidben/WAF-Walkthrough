"""FastAPI service (api.py): scanning, input validation, model checks, feedback and micro-batching."""

import asyncio
import csv
import dataclasses
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import onnx
import pytest
from fastapi.testclient import TestClient

import api
from tests.conftest import ATTACK, BENIGN

FEEDBACK_KEY = "test-feedback-key-0123456789"


@pytest.fixture
def make_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Factory: a TestClient whose app loads `model_path` (lifespan runs on enter)."""

    def make(model_path: Path, feedback_key: str | None = FEEDBACK_KEY) -> TestClient:
        monkeypatch.setattr(api, "settings", dataclasses.replace(
            api.settings,
            model_path=model_path,
            keep_warm_s=0,
            max_queue_ms=5_000,  # generous: CI runners can be slow
            feedback_api_key=feedback_key,
            feedback_csv_path=tmp_path / "feedback" / "custom_traffic.csv",
            feedback_lock_path=tmp_path / "feedback.lock",
        ))
        (tmp_path / "feedback").mkdir(exist_ok=True)
        return TestClient(api.app)

    return make


@pytest.fixture
def client(make_client, onnx_model) -> Iterator[TestClient]:
    with make_client(onnx_model[0]) as test_client:
        yield test_client


def _auth(key: str = FEEDBACK_KEY) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# --- scanning ------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok", "model_loaded": True}


def test_scan_verdicts(client: TestClient) -> None:
    attack = client.post("/scan", json={"query": ATTACK})
    benign = client.post("/scan", json={"query": BENIGN})
    assert attack.status_code == benign.status_code == 200
    assert attack.json()["verdict"] == "malicious" and attack.json()["sqli_probability"] >= 0.5
    assert benign.json()["verdict"] == "safe" and benign.json()["sqli_probability"] < 0.5
    assert attack.headers["X-Request-ID"] == attack.json()["request_id"]
    assert attack.headers["Cache-Control"] == "no-store"


def test_scan_matches_scikit_learn(client: TestClient, trained_pipeline) -> None:
    values = [ATTACK, BENIGN, "' AND 1  =  1 --", "Straße  İstanbul"]
    expected = trained_pipeline.predict_proba(values)[:, 1]
    got = client.post("/scan/batch", json={"queries": values}).json()["probabilities"]
    assert got == pytest.approx(expected.tolist(), abs=1e-3)  # API rounds to 4 decimals


def test_batch_flags_the_right_items(client: TestClient) -> None:
    body = client.post("/scan/batch", json={"queries": [BENIGN, ATTACK, "bob"]}).json()
    assert body["verdict"] == "malicious"
    assert body["flagged_indices"] == [1]
    assert body["max_index"] == 1
    assert body["item_count"] == 3


@pytest.mark.parametrize("payload", [
    {"query": ""},
    {"query": "   "},
    {"query": 123},
    {"query": "x", "extra": 1},
    {"query": "x" * (api.settings.max_query_length + 1)},
    {},
])
def test_scan_rejects_invalid_input(client: TestClient, payload: dict) -> None:
    response = client.post("/scan", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"


def test_validation_errors_do_not_reflect_input(client: TestClient) -> None:
    marker = "<script>reflected-marker</script>"
    response = client.post("/scan", json={"query": 1, "extra": marker})
    assert response.status_code == 422
    assert "reflected-marker" not in response.text


def test_batch_size_limit(client: TestClient) -> None:
    too_many = ["a"] * (api.settings.max_batch_size + 1)
    assert client.post("/scan/batch", json={"queries": too_many}).status_code == 422
    assert client.post("/scan/batch", json={"queries": []}).status_code == 422


def test_lone_surrogates_are_rejected_cleanly(client: TestClient) -> None:
    # Valid JSON, invalid UTF-8: a clean 422, never a 500. (The WAF converts
    # values to valid UTF-8 first, so it never sends these.)
    response = client.post("/scan", content=b'{"query": "a\\ud800b"}', headers={"Content-Type": "application/json"})
    assert response.status_code == 422


# --- model checks: fail closed with 503 ------------------------------------------


def test_missing_model_answers_503(make_client, tmp_path: Path) -> None:
    with make_client(tmp_path / "nope.onnx") as client:
        assert client.get("/health").status_code == 503
        response = client.post("/scan", json={"query": "x"})
        assert response.status_code == 503
        assert response.json()["error"] == "model_unavailable"


def test_model_with_other_preprocessing_is_refused(make_client, onnx_model, tmp_path: Path) -> None:
    model = onnx.load(onnx_model[0])
    for prop in model.metadata_props:
        if prop.key == "preprocessing":
            prop.value = "something-else-v2"
    path = tmp_path / "other.onnx"
    onnx.save_model(model, path)
    with make_client(path) as client:
        assert client.get("/health").json()["model_loaded"] is False


# --- feedback ------------------------------------------------------------------------


def _feedback(**overrides) -> dict:
    return {"query": "Mozilla/5.0 (X11) like Gecko", "label": 0, "source": "header:user-agent",
            "flagged_by": "analyst", "request_id": "abc123", **overrides}


def test_feedback_disabled_without_key(make_client, onnx_model) -> None:
    with make_client(onnx_model[0], feedback_key=None) as client:
        response = client.post("/feedback", json=_feedback(), headers=_auth())
        assert response.status_code == 503


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong-key-0123456789"}, {"Authorization": FEEDBACK_KEY}])
def test_feedback_requires_bearer_key(client: TestClient, headers: dict) -> None:
    assert client.post("/feedback", json=_feedback(), headers=headers).status_code == 401


def test_feedback_records_once_and_keeps_values_intact(client: TestClient, tmp_path: Path) -> None:
    value = 'line one\nline "two", with comma'
    first = client.post("/feedback", json=_feedback(query=value), headers=_auth())
    again = client.post("/feedback", json=_feedback(query=value), headers=_auth())
    assert (first.status_code, first.json()["status"]) == (201, "recorded")
    assert (again.status_code, again.json()["status"]) == (201, "duplicate")

    path = tmp_path / "feedback" / "custom_traffic.csv"
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["query"] == value
    assert rows[0]["label"] == "0"
    assert rows[0]["flagged_by"] == "analyst"
    assert b"\r\n" not in path.read_bytes()


@pytest.mark.parametrize("bad", [
    {"label": 2}, {"label": "0"}, {"query": "a\x00b"}, {"request_id": "../etc"}, {"source": "x" * 101},
])
def test_feedback_validation(client: TestClient, bad: dict) -> None:
    assert client.post("/feedback", json=_feedback(**bad), headers=_auth()).status_code == 422


def test_feedback_store_concurrent_appends(tmp_path: Path) -> None:
    store = api.FeedbackStore(tmp_path / "f.csv", tmp_path / "f.lock", max_bytes=10_000_000)
    results: list[bool] = []
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            results.append(store.append({"query": f"value {i % 10}", "label": 0}))
        except BaseException as exc:  # surfaced below; a thread can't fail the test itself
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    with open(tmp_path / "f.csv", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert errors == []
    assert results.count(True) == 10 and results.count(False) == 20  # 10 distinct values
    assert sorted(row["query"] for row in rows) == [f"value {i}" for i in range(10)]


def test_feedback_store_size_limit(tmp_path: Path) -> None:
    store = api.FeedbackStore(tmp_path / "f.csv", tmp_path / "f.lock", max_bytes=1)
    store.append({"query": "first", "label": 0})
    with pytest.raises(api.FeedbackStoreError):
        store.append({"query": "second", "label": 0})


# --- micro-batching --------------------------------------------------------------------


class _FakeDetector:
    """Scores len(value) / 100 and records each model call's batch."""

    def __init__(self, delay_s: float = 0.0) -> None:
        self.calls: list[list[str]] = []
        self.delay_s = delay_s

    def sqli_probabilities(self, values: list[str]) -> list[float]:
        self.calls.append(list(values))
        time.sleep(self.delay_s)
        return [len(v) / 100 for v in values]


def test_microbatcher_returns_each_request_its_own_scores() -> None:
    async def scenario() -> tuple[list, _FakeDetector]:
        detector = _FakeDetector(delay_s=0.02)
        batcher = api.MicroBatcher(detector, max_values=16, max_wait_ms=5_000)
        jobs = [batcher.score(["x" * n, "y" * (n + 1)]) for n in range(1, 9)]
        results = await asyncio.gather(*jobs)
        await batcher.close()
        return results, detector

    results, detector = asyncio.run(scenario())
    for n, (probabilities, _ms) in enumerate(results, start=1):
        assert probabilities == [n / 100, (n + 1) / 100]
    assert len(detector.calls) < 8  # concurrent requests shared model calls
    assert max(len(call) for call in detector.calls) <= 16


def test_microbatcher_sheds_requests_that_waited_too_long() -> None:
    async def scenario() -> list:
        detector = _FakeDetector(delay_s=0.2)
        batcher = api.MicroBatcher(detector, max_values=1, max_wait_ms=50)
        first = asyncio.ensure_future(batcher.score(["a"]))
        await asyncio.sleep(0.01)  # the first call is now running
        second = asyncio.ensure_future(batcher.score(["b"]))
        results = await asyncio.gather(first, second, return_exceptions=True)
        await batcher.close()
        return results

    first, second = asyncio.run(scenario())
    assert first[0] == [0.01]
    assert isinstance(second, api.Overloaded)
