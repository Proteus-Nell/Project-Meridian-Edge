# Production server image (CLAUDE.md §5 container checklist): non-root,
# read-only filesystem (see docker-compose.yml's read_only + tmpfs), no shell
# entrypoint, secrets via environment only. DEBUG=0 is enforced at boot by
# _assert_production_safe (app/main.py), not by anything in this image.

FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
COPY --from=builder /install /usr/local
WORKDIR /app
COPY app ./app

RUN groupadd --system meridian_edge && useradd --system --gid meridian_edge --no-create-home meridian_edge
USER meridian_edge

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000

# Exec form: no shell in the running container. --no-reload / no --reload
# flag - that's a dev-only uvicorn feature that re-execs the process, which a
# read-only root filesystem does not support cleanly.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
