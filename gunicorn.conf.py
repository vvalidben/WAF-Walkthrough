"""Gunicorn settings for the SQLi detector API (used by the Docker image)."""

import os

bind = os.getenv("BIND", "0.0.0.0:8000")
worker_class = "uvicorn_worker.UvicornWorker"
# Each worker loads its own copy of the model, so size this against memory.
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "30"))
graceful_timeout = 30
keepalive = 5

# Recycle workers periodically to bound slow memory growth.
max_requests = 1000
max_requests_jitter = 100

# Heartbeat files go to tmpfs so the root filesystem can be mounted read-only.
worker_tmp_dir = "/dev/shm"

# The runtime-management socket isn't needed in a container, and it would
# otherwise try to write under $HOME on the read-only filesystem.
control_socket_disable = True

# Only trust X-Forwarded-For from these addresses (set to your reverse proxy).
forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")

# Header limits (Gunicorn defaults, stated explicitly).
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
