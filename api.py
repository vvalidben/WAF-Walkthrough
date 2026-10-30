"""FastAPI service that scans user input for SQL injection in real time.

Run with:
    uvicorn api:app --host 0.0.0.0 --port 8000

Configuration (environment variables):
    SQLI_MODEL_PATH        ONNX model exported by train.py/tune.py (default: models/sqli_detector.onnx)
    SQLI_ORT_THREADS       ONNX Runtime threads per worker process (default: 1)
    SQLI_THRESHOLD         P(sqli) at/above which input is malicious (default: 0.5)
    SQLI_MAX_QUERY_LENGTH  max accepted query length in characters (default: 10000)
    SQLI_MAX_BATCH_SIZE    max items per /scan/batch request (default: 128)
    SQLI_MAX_QUEUE_MS      shed requests (503) that waited longer than this for the model (default: 250)
    SQLI_MAX_BATCH_VALUES  max values scored together in one model call (default: 16)
    SQLI_KEEP_WARM_S       run a dummy prediction after this many idle seconds; 0 = off (default: 5)
    SQLI_LOG_PREVIEW       log the first 120 chars of malicious input (default: false)
    SQLI_ENABLE_DOCS       expose /docs and /openapi.json (default: true)
    FEEDBACK_API_KEY       bearer token for POST /feedback; unset = endpoint disabled (min 16 chars)
    FEEDBACK_CSV_PATH      CSV that feedback rows are appended to (default: data/feedback/custom_traffic.csv)
    FEEDBACK_LOCK_PATH     lock file shared by the worker processes (default: <temp dir>/sqli_feedback.lock)
    FEEDBACK_MAX_BYTES     refuse new feedback once the CSV is this large (default: 52428800)
"""

import asyncio
import collections
import contextlib
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

import anyio
import numpy as np
import onnxruntime as ort
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictInt, StrictStr
from starlette.exceptions import HTTPException as StarletteHTTPException

from text_preprocessing import PREPROCESSING_ID, preprocess

try:  # POSIX (the container)
    import fcntl
except ImportError:  # Windows (local development)
    fcntl = None
    import msvcrt

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("sqli.api")
audit_logger = logging.getLogger("sqli.audit")

PREVIEW_CHARS = 120


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    model_path: Path
    ort_threads: int
    threshold: float
    max_query_length: int
    max_batch_size: int
    max_queue_ms: float
    max_batch_values: int
    keep_warm_s: float
    log_preview: bool
    enable_docs: bool
    feedback_api_key: str | None
    feedback_csv_path: Path
    feedback_lock_path: Path
    feedback_max_bytes: int

    @classmethod
    def from_env(cls) -> "Settings":
        try:
            threshold = float(os.getenv("SQLI_THRESHOLD", "0.5"))
            max_query_length = int(os.getenv("SQLI_MAX_QUERY_LENGTH", "10000"))
            max_batch_size = int(os.getenv("SQLI_MAX_BATCH_SIZE", "128"))
            max_queue_ms = float(os.getenv("SQLI_MAX_QUEUE_MS", "250"))
            max_batch_values = int(os.getenv("SQLI_MAX_BATCH_VALUES", "16"))
            keep_warm_s = float(os.getenv("SQLI_KEEP_WARM_S", "5"))
            feedback_max_bytes = int(os.getenv("FEEDBACK_MAX_BYTES", str(50 * 1024 * 1024)))
            ort_threads = int(os.getenv("SQLI_ORT_THREADS", "1"))
        except ValueError as exc:
            raise RuntimeError(f"Invalid numeric configuration: {exc}") from exc
        if not 0.0 < threshold < 1.0:
            raise RuntimeError("SQLI_THRESHOLD must be strictly between 0 and 1")
        if max_query_length < 1:
            raise RuntimeError("SQLI_MAX_QUERY_LENGTH must be >= 1")
        if max_batch_size < 1:
            raise RuntimeError("SQLI_MAX_BATCH_SIZE must be >= 1")
        if max_queue_ms <= 0:
            raise RuntimeError("SQLI_MAX_QUEUE_MS must be > 0")
        if max_batch_values < 1:
            raise RuntimeError("SQLI_MAX_BATCH_VALUES must be >= 1")
        if ort_threads < 1:
            raise RuntimeError("SQLI_ORT_THREADS must be >= 1")
        feedback_api_key = os.getenv("FEEDBACK_API_KEY") or None
        if feedback_api_key is not None and len(feedback_api_key) < 16:
            raise RuntimeError("FEEDBACK_API_KEY must be at least 16 characters")
        return cls(
            model_path=Path(os.getenv("SQLI_MODEL_PATH", "models/sqli_detector.onnx")),
            ort_threads=ort_threads,
            threshold=threshold,
            max_query_length=max_query_length,
            max_batch_size=max_batch_size,
            max_queue_ms=max_queue_ms,
            max_batch_values=max_batch_values,
            keep_warm_s=keep_warm_s,
            log_preview=_env_bool("SQLI_LOG_PREVIEW", False),
            enable_docs=_env_bool("SQLI_ENABLE_DOCS", True),
            feedback_api_key=feedback_api_key,
            feedback_csv_path=Path(os.getenv("FEEDBACK_CSV_PATH", "data/feedback/custom_traffic.csv")),
            feedback_lock_path=Path(
                os.getenv("FEEDBACK_LOCK_PATH", os.path.join(tempfile.gettempdir(), "sqli_feedback.lock"))
            ),
            feedback_max_bytes=feedback_max_bytes,
        )


settings = Settings.from_env()


def audit(level: int, event: str, **fields: Any) -> None:
    """Emit one JSON security event per line.

    JSON encoding escapes newlines and control characters, so attacker-supplied
    text cannot forge extra log entries (log injection).
    """
    record = {"event": event, "ts": datetime.now(timezone.utc).isoformat(), **fields}
    audit_logger.log(level, json.dumps(record, ensure_ascii=True, default=str))


class SQLiDetector:
    """ONNX Runtime session for the exported pipeline (TF-IDF + Random Forest).

    The model is the .onnx file written by train.py/tune.py (export_onnx),
    which verified it scores like the scikit-learn pipeline. Inference runs in
    ONNX Runtime's C++ kernels with the GIL released. Unlike the former joblib
    pickle, loading an .onnx file cannot execute code.
    """

    def __init__(self, session: ort.InferenceSession, threshold: float) -> None:
        metadata = session.get_modelmeta().custom_metadata_map
        if metadata.get("preprocessing") != PREPROCESSING_ID:
            # Without matching preprocessing the model scores differently
            # (e.g. attacks padded with spaces); refuse rather than mispredict.
            raise ValueError(
                f"Model expects preprocessing {metadata.get('preprocessing')!r}, this API implements "
                f"{PREPROCESSING_ID!r}; export the model with the matching train.py"
            )
        inputs, outputs = session.get_inputs(), {o.name: o for o in session.get_outputs()}
        if len(inputs) != 1 or inputs[0].type != "tensor(string)":
            raise ValueError(f"Expected one string input, got {[(i.name, i.type) for i in inputs]}")
        if outputs.get("probabilities") is None or outputs["probabilities"].type != "tensor(float)":
            raise ValueError(f"Expected a float 'probabilities' output, got {list(outputs)}")
        classes = metadata.get("classes", "").split(",")
        self._positive_index = int(metadata["positive_class_index"])
        if classes[self._positive_index:self._positive_index + 1] != ["1"]:
            raise ValueError(f"positive_class_index does not point at class 1; classes={classes}")
        self._session = session
        self._input = inputs[0].name
        self.threshold = threshold
        self.metadata = metadata

    @classmethod
    def load(cls, path: Path, threshold: float, threads: int) -> "SQLiDetector":
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {path}")
        options = ort.SessionOptions()
        # One thread per session: gunicorn already runs one process per core
        # budget, and per-session thread pools on top would oversubscribe the
        # CPU, which is exactly the kind of contention behind latency spikes.
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        options.log_severity_level = 3  # errors only
        session = ort.InferenceSession(str(path), options, providers=["CPUExecutionProvider"])
        return cls(session, threshold)

    def sqli_probabilities(self, queries: list[str]) -> list[float]:
        # One vectorised call: scoring many values costs little more than one.
        # Lone surrogates (valid in JSON, not in UTF-8) can't cross into ONNX
        # Runtime; they become "?", as the WAF does with invalid bytes.
        batch = np.array(
            [preprocess(q.encode("utf-8", "replace").decode("utf-8")) for q in queries], dtype=object
        ).reshape(-1, 1)
        probabilities = self._session.run(["probabilities"], {self._input: batch})[0]
        # Rounded to 6 decimals: Random Forest probabilities are multiples of
        # 1/n_trees, so exactly 0.5 or 0.8 is common, and float32 returns it as
        # 0.79999995 - just under the threshold scikit-learn's float64 meets.
        return np.round(probabilities[:, self._positive_index].astype(np.float64), 6).tolist()


def _reject_blank(value: str) -> str:
    # The value itself is not stripped: whitespace can be part of a payload.
    if not value.strip():
        raise ValueError("query must not be empty or whitespace only")
    return value


QueryText = Annotated[
    StrictStr,
    Field(min_length=1, max_length=settings.max_query_length),
    AfterValidator(_reject_blank),
]


class FeedbackStoreError(Exception):
    """The feedback CSV cannot take more rows (full, or not a query/label CSV)."""


class FeedbackStore:
    """Appends labelled rows to the custom-traffic CSV used by fetch_data.py.

    Several Gunicorn worker processes may write at once, so every append runs
    under an exclusive lock on a separate lock file (flock on POSIX). The lock
    lives in the container's /tmp by default: all workers of one container
    share it, while the CSV itself may sit on a bind mount where locking is
    unreliable. Each row is written with a single O_APPEND write, so a reader
    never sees rows interleaved.

    The extra columns are an audit trail; training reads only query and label.
    An existing file keeps its own header: rows are written in its column order.
    """

    COLUMNS = ("query", "label", "source", "flagged_by", "request_id", "flagged_at")

    def __init__(self, path: Path, lock_path: Path, max_bytes: int) -> None:
        self.path = path
        self.lock_path = lock_path
        self.max_bytes = max_bytes

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+b") as handle:
            if fcntl is not None:
                fcntl.flock(handle, fcntl.LOCK_EX)
            else:
                handle.seek(0)
                # LK_LOCK retries only once a second and gives up after ~10 s
                # (OSError EDEADLK); poll instead and wait as long as flock does.
                while True:
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        time.sleep(0.005)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle, fcntl.LOCK_UN)
                else:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

    def _scan(self, query: str, label: int) -> tuple[list[str], bool]:
        """Return the file's (lower-cased) header and whether query+label is already present."""
        try:
            with open(self.path, newline="", encoding="utf-8-sig") as handle:
                reader = csv.reader(handle)
                header = [column.strip().lower() for column in next(reader, [])]
                if "query" not in header or "label" not in header:
                    raise FeedbackStoreError(f"{self.path} has no query/label header: {header}")
                qi, li = header.index("query"), header.index("label")
                duplicate = any(
                    len(row) > max(qi, li) and row[qi] == query and row[li].strip() == str(label)
                    for row in reader
                )
        except (csv.Error, UnicodeDecodeError) as exc:
            raise FeedbackStoreError(f"{self.path} is not a readable CSV: {exc}") from exc
        return header, duplicate

    def append(self, row: dict[str, Any]) -> bool:
        """Append `row`; return False if the same query and label are already present."""
        with self._locked():
            size = self.path.stat().st_size if self.path.exists() else 0
            if size >= self.max_bytes:
                raise FeedbackStoreError(f"{self.path} reached FEEDBACK_MAX_BYTES")

            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator="\n")
            if size:
                header, duplicate = self._scan(row["query"], row["label"])
                if duplicate:
                    return False
            else:
                header = list(self.COLUMNS)
                writer.writerow(header)
            writer.writerow([row.get(column, "") for column in header])
            data = buffer.getvalue().encode("utf-8")

            # O_BINARY: on Windows, os.open otherwise translates "\n" to "\r\n",
            # which would also alter newlines inside quoted values.
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
            fd = os.open(self.path, flags, 0o640)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            return True


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: QueryText = Field(description="Raw user input to scan.", examples=["' OR 1=1 --"])


class BatchScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    queries: list[QueryText] = Field(
        min_length=1,
        max_length=settings.max_batch_size,
        description="Individual input values (e.g. each request parameter) to scan together.",
        examples=[["alice", "1' OR '1'='1"]],
    )


def _require_csv_safe(value: str) -> str:
    # The row ends up in a CSV that pandas reads for training: NUL bytes and
    # lone surrogates (valid in JSON, not in UTF-8) would break that file.
    if "\x00" in value:
        raise ValueError("value must not contain NUL characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("value must be valid UTF-8") from exc
    return value


ShortText = Annotated[StrictStr, Field(max_length=100), AfterValidator(_require_csv_safe)]


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: Annotated[QueryText, AfterValidator(_require_csv_safe)] = Field(
        description="The exact value the WAF flagged.", examples=["Mozilla/5.0 (Linux; Android 10; K) ..."]
    )
    label: Annotated[StrictInt, Field(ge=0, le=1)] = Field(description="0 = safe (false positive), 1 = SQL injection.")
    source: ShortText = Field("", description="Where the WAF found the value, e.g. header:user-agent.")
    flagged_by: ShortText = Field("", description="Who reviewed it, e.g. the Slack user.")
    request_id: Annotated[StrictStr, Field(max_length=64, pattern=r"^[A-Za-z0-9_-]*$")] = ""


class FeedbackResponse(BaseModel):
    request_id: str
    status: Literal["recorded", "duplicate"]


class ScanResponse(BaseModel):
    request_id: str
    verdict: Literal["safe", "malicious"]
    is_malicious: bool
    confidence: float = Field(description="Model probability for the returned verdict (0-1).")
    sqli_probability: float = Field(description="Model probability that the input is SQLi (0-1).")
    threshold: float
    scanned_at: datetime


class BatchScanResponse(BaseModel):
    request_id: str
    verdict: Literal["safe", "malicious"] = Field(description="'malicious' if any item is.")
    is_malicious: bool
    confidence: float = Field(description="Model probability for the returned verdict (0-1).")
    sqli_probability: float = Field(description="Highest SQLi probability across all items.")
    max_index: int = Field(description="Index of the highest-scoring item.")
    flagged_indices: list[int] = Field(description="Indices of items at or above the threshold.")
    probabilities: list[float] = Field(description="Per-item SQLi probabilities, in request order.")
    item_count: int
    threshold: float
    scanned_at: datetime


class ErrorResponse(BaseModel):
    request_id: str | None
    error: str
    detail: Any = None


class Overloaded(Exception):
    """The request waited too long for the model, or its client already gave up."""


@dataclass
class _Job:
    queries: list[str]
    future: asyncio.Future
    queued_at: float
    request: Request | None


class MicroBatcher:
    """Scores the concurrent requests of this worker process together.

    A Random Forest's prediction cost is mostly fixed per call (per-tree
    overhead): in the container one value took ~11 ms and 100 values ~22 ms.
    Scoring requests one at a time capped each worker at ~90 requests/s, and a
    single client's burst of 100 requests queued past the WAF's 50 ms timeout,
    so 84 of 100 attacks failed open uninspected. Instead, one loop per worker
    makes one model call at a time, and each call takes every request that
    queued up in the meantime (up to SQLI_MAX_BATCH_VALUES values).

    Still only one prediction per process at a time: concurrent predictions in
    one process just compete for the GIL. Requests that waited longer than
    SQLI_MAX_QUEUE_MS, or whose client already hung up (the WAF timed out),
    are dropped before the call instead of adding to the backlog.
    """

    def __init__(self, detector: SQLiDetector, max_values: int, max_wait_ms: float) -> None:
        self._detector = detector
        self._max_values = max_values
        self._max_wait_ms = max_wait_ms
        self._queue: collections.deque[_Job] = collections.deque()
        self._wakeup = asyncio.Event()
        self.last_inference = time.monotonic()
        self._task = asyncio.create_task(self._run())

    async def score(self, queries: list[str], request: Request | None = None) -> tuple[list[float], float]:
        """Return (probabilities, milliseconds of the model call that scored them)."""
        job = _Job(queries, asyncio.get_running_loop().create_future(), time.perf_counter(), request)
        self._queue.append(job)
        self._wakeup.set()
        return await job.future

    async def _take_batch(self) -> list[_Job]:
        batch: list[_Job] = []
        size = 0
        while self._queue and (not batch or size + len(self._queue[0].queries) <= self._max_values):
            job = self._queue.popleft()
            if job.future.done():
                continue
            waited_ms = (time.perf_counter() - job.queued_at) * 1000
            if waited_ms > self._max_wait_ms or (job.request is not None and await job.request.is_disconnected()):
                job.future.set_exception(Overloaded())
                continue
            batch.append(job)
            size += len(job.queries)
        return batch

    async def _run(self) -> None:
        while True:
            await self._wakeup.wait()
            self._wakeup.clear()
            while self._queue:
                batch = await self._take_batch()
                if not batch:
                    continue
                values = [query for job in batch for query in job.queries]
                started = time.perf_counter()
                try:
                    # A worker thread keeps the event loop free to accept and queue requests.
                    probabilities = await anyio.to_thread.run_sync(self._detector.sqli_probabilities, values)
                except Exception as exc:  # noqa: BLE001 - delivered to every waiting request
                    for job in batch:
                        if not job.future.done():
                            job.future.set_exception(exc)
                    continue
                elapsed_ms = (time.perf_counter() - started) * 1000
                self.last_inference = time.monotonic()
                offset = 0
                for job in batch:
                    count = len(job.queries)
                    if not job.future.done():
                        job.future.set_result((probabilities[offset:offset + count], elapsed_ms))
                    offset += count

    async def close(self) -> None:
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        while self._queue:
            job = self._queue.popleft()
            if not job.future.done():
                job.future.set_exception(Overloaded())


async def keep_warm(app: FastAPI, idle_seconds: float) -> None:
    """Run a dummy prediction whenever this worker has been idle for `idle_seconds`.

    After a few idle minutes the first real prediction took 60-80 ms instead
    of ~8 ms (cold CPU caches, model memory paged out), which is longer than
    the WAF's timeout, so that request failed open uninspected. Costs one
    ~8 ms prediction per interval.
    """
    while True:
        await asyncio.sleep(idle_seconds)
        batcher: MicroBatcher | None = app.state.batcher
        if batcher is None or time.monotonic() - batcher.last_inference < idle_seconds:
            continue
        with contextlib.suppress(Overloaded):
            await batcher.score(["keep-warm ' value"])


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.batcher = None
    try:
        app.state.detector = SQLiDetector.load(settings.model_path, settings.threshold, settings.ort_threads)
        logger.info(
            "Loaded ONNX model from %s (threshold=%.2f, exported %s, fidelity max |diff| %s)",
            settings.model_path, settings.threshold,
            app.state.detector.metadata.get("exported_at", "?"), app.state.detector.metadata.get("fidelity_max_abs_diff", "?"),
        )
        app.state.batcher = MicroBatcher(app.state.detector, settings.max_batch_values, settings.max_queue_ms)
    except Exception:
        # Stay up so /health can report the problem; /scan answers 503 (fail closed).
        logger.exception("Failed to load model from %s; /scan will return 503", settings.model_path)
        app.state.detector = None

    app.state.feedback_store = None
    if settings.feedback_api_key:
        app.state.feedback_store = FeedbackStore(
            settings.feedback_csv_path, settings.feedback_lock_path, settings.feedback_max_bytes
        )
        if not os.access(settings.feedback_csv_path.parent, os.W_OK):
            logger.error("Feedback directory %s is not writable; /feedback will fail", settings.feedback_csv_path.parent)
        else:
            logger.info("Feedback enabled; appending to %s", settings.feedback_csv_path)

    warmer = asyncio.create_task(keep_warm(app, settings.keep_warm_s)) if settings.keep_warm_s > 0 else None
    yield
    if warmer:
        warmer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await warmer
    if app.state.batcher:
        await app.state.batcher.close()


app = FastAPI(
    title="SQL Injection Detector",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)


def _client_ip(request: Request) -> str | None:
    # Behind a reverse proxy, run uvicorn with --proxy-headers and
    # --forwarded-allow-ips so this reflects the real client address.
    return request.client.host if request.client else None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


@app.middleware("http")
async def add_request_id(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    # Always server-generated: a client-supplied ID could be used to poison logs.
    request.state.request_id = uuid.uuid4().hex
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default handler echoes the offending input back; never reflect
    # potentially malicious payloads, return only location and reason.
    errors = [
        {"loc": [str(part) for part in err.get("loc", ())], "msg": err.get("msg"), "type": err.get("type")}
        for err in exc.errors()
    ]
    audit(
        logging.INFO,
        "scan_rejected",
        request_id=_request_id(request),
        client_ip=_client_ip(request),
        path=request.url.path,
        error_types=sorted({str(err["type"]) for err in errors}),
    )
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(request_id=_request_id(request), error="invalid_request", detail=errors).model_dump(),
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(request_id=_request_id(request), error=str(exc.detail)).model_dump(),
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error (request_id=%s)", _request_id(request))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(request_id=_request_id(request), error="internal_error").model_dump(),
    )


async def run_inference(request: Request, queries: list[str]) -> tuple[list[float], float]:
    """Score `queries` via this worker's MicroBatcher: (probabilities, model-call milliseconds).

    A request that waited longer than SQLI_MAX_QUEUE_MS, or whose client hung
    up, is shed with 503 "overloaded".
    """
    try:
        return await request.app.state.batcher.score(queries, request)
    except Overloaded:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "overloaded") from None


@app.get("/health")
def health(request: Request) -> JSONResponse:
    loaded = request.app.state.detector is not None
    return JSONResponse(
        status_code=status.HTTP_200_OK if loaded else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "ok" if loaded else "model_unavailable", "model_loaded": loaded},
    )


@app.post(
    "/scan",
    response_model=ScanResponse,
    responses={
        422: {"model": ErrorResponse, "description": "Empty, oversized or malformed input"},
        503: {"model": ErrorResponse, "description": "Model not loaded, or overloaded"},
    },
)
async def scan(payload: ScanRequest, request: Request) -> ScanResponse:
    detector: SQLiDetector | None = request.app.state.detector
    if detector is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "model_unavailable")

    request_id = _request_id(request) or uuid.uuid4().hex
    probabilities, latency_ms = await run_inference(request, [payload.query])
    probability = probabilities[0]

    is_malicious = probability >= detector.threshold
    verdict: Literal["safe", "malicious"] = "malicious" if is_malicious else "safe"

    # Log a hash and length rather than the raw input: payloads may contain
    # PII or secrets, and the hash still lets analysts correlate repeat attacks.
    event: dict[str, Any] = {
        "request_id": request_id,
        "client_ip": _client_ip(request),
        "verdict": verdict,
        "sqli_probability": round(probability, 4),
        "threshold": detector.threshold,
        "query_sha256": _sha256(payload.query),
        "query_length": len(payload.query),
        "latency_ms": round(latency_ms, 2),
    }
    if is_malicious:
        if settings.log_preview:
            event["query_preview"] = payload.query[:PREVIEW_CHARS]
        audit(logging.WARNING, "sqli_detected", **event)
    else:
        audit(logging.INFO, "scan_clean", **event)

    return ScanResponse(
        request_id=request_id,
        verdict=verdict,
        is_malicious=is_malicious,
        confidence=round(probability if is_malicious else 1.0 - probability, 4),
        sqli_probability=round(probability, 4),
        threshold=detector.threshold,
        scanned_at=datetime.now(timezone.utc),
    )


@app.post(
    "/scan/batch",
    response_model=BatchScanResponse,
    responses={
        422: {"model": ErrorResponse, "description": "Empty, oversized or malformed input"},
        503: {"model": ErrorResponse, "description": "Model not loaded, or overloaded"},
    },
)
async def scan_batch(payload: BatchScanRequest, request: Request) -> BatchScanResponse:
    """Scan several values in one call, e.g. every parameter of an HTTP request (used by the WAF)."""
    detector: SQLiDetector | None = request.app.state.detector
    if detector is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "model_unavailable")

    request_id = _request_id(request) or uuid.uuid4().hex
    probabilities, latency_ms = await run_inference(request, payload.queries)

    max_index = max(range(len(probabilities)), key=probabilities.__getitem__)
    probability = probabilities[max_index]
    flagged = [i for i, p in enumerate(probabilities) if p >= detector.threshold]
    is_malicious = bool(flagged)
    verdict: Literal["safe", "malicious"] = "malicious" if is_malicious else "safe"

    event: dict[str, Any] = {
        "request_id": request_id,
        "client_ip": _client_ip(request),
        "verdict": verdict,
        "sqli_probability": round(probability, 4),
        "threshold": detector.threshold,
        "item_count": len(payload.queries),
        "flagged_count": len(flagged),
        "flagged_sha256": [_sha256(payload.queries[i]) for i in flagged],
        "latency_ms": round(latency_ms, 2),
    }
    if is_malicious:
        if settings.log_preview:
            event["query_preview"] = payload.queries[max_index][:PREVIEW_CHARS]
        audit(logging.WARNING, "sqli_detected", **event)
    else:
        audit(logging.INFO, "scan_clean", **event)

    return BatchScanResponse(
        request_id=request_id,
        verdict=verdict,
        is_malicious=is_malicious,
        confidence=round(probability if is_malicious else 1.0 - probability, 4),
        sqli_probability=round(probability, 4),
        max_index=max_index,
        flagged_indices=flagged,
        probabilities=[round(p, 4) for p in probabilities],
        item_count=len(probabilities),
        threshold=detector.threshold,
        scanned_at=datetime.now(timezone.utc),
    )


def require_feedback_key(request: Request) -> None:
    """Check the bearer token. Runs before the body is validated."""
    if not settings.feedback_api_key:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "feedback_disabled")
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        token.encode("utf-8", "surrogateescape"), settings.feedback_api_key.encode("utf-8")
    ):
        audit(logging.WARNING, "feedback_unauthorized", request_id=_request_id(request), client_ip=_client_ip(request))
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "unauthorized", headers={"WWW-Authenticate": "Bearer"}
        )


@app.post(
    "/feedback",
    status_code=status.HTTP_201_CREATED,
    response_model=FeedbackResponse,
    dependencies=[Depends(require_feedback_key)],
    responses={
        401: {"model": ErrorResponse, "description": "Missing or wrong bearer token"},
        422: {"model": ErrorResponse, "description": "Invalid feedback"},
        503: {"model": ErrorResponse, "description": "Feedback disabled, or storage unavailable/full"},
    },
)
def feedback(payload: FeedbackRequest, request: Request) -> FeedbackResponse:
    """Record a reviewed label (e.g. a false positive flagged from Slack) for the next training run.

    Plain `def`: file I/O and lock waits run in the threadpool, off the event loop.
    """
    store: FeedbackStore | None = request.app.state.feedback_store
    request_id = _request_id(request) or uuid.uuid4().hex
    row = {
        "query": payload.query,
        "label": payload.label,
        "source": payload.source,
        "flagged_by": payload.flagged_by,
        "request_id": payload.request_id,
        "flagged_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        recorded = store.append(row) if store else False
    except FeedbackStoreError as exc:
        logger.error("Cannot record feedback: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "feedback_storage_rejected")
    except OSError:
        logger.exception("Could not write feedback to %s", settings.feedback_csv_path)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "feedback_storage_unavailable")

    audit(
        logging.INFO,
        "feedback_recorded" if recorded else "feedback_duplicate",
        request_id=request_id,
        client_ip=_client_ip(request),
        label=payload.label,
        source=payload.source,
        flagged_by=payload.flagged_by,
        waf_request_id=payload.request_id,
        query_sha256=_sha256(payload.query),
        query_length=len(payload.query),
    )
    return FeedbackResponse(request_id=request_id, status="recorded" if recorded else "duplicate")
