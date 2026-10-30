# syntax=docker/dockerfile:1

# The model is served as ONNX (models/*.onnx), so this image needs neither
# scikit-learn nor the training Python version; requirements-api.txt pins the
# runtime. For fully reproducible builds, pin the base image by digest as well.
ARG PYTHON_VERSION=3.14

# ---- build stage: install dependencies into an isolated venv ---------------
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements-api.txt /tmp/requirements-api.txt
RUN pip install --no-compile -r /tmp/requirements-api.txt

# ---- runtime stage: no build tooling, non-root user ------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    SQLI_MODEL_PATH=/models/sqli_detector_optimized.onnx \
    SQLI_ENABLE_DOCS=false \
    WEB_CONCURRENCY=2

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# Application code stays root-owned and read-only to the runtime user.
COPY api.py gunicorn.conf.py text_preprocessing.py ./

USER app

EXPOSE 8000

# /health returns 503 when the model failed to load, which marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]

CMD ["gunicorn", "--config", "gunicorn.conf.py", "api:app"]
