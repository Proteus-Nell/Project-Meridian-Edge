# Production server image (container checklist): non-root,
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
#
# --proxy-headers makes uvicorn read X-Forwarded-For, so request.client.host is
# the browser rather than the reverse proxy. Without it the per-IP rate limits
# and the security log would see one address for all traffic. It is stated
# explicitly even though uvicorn currently defaults it on, so the behaviour does
# not depend on that default.
#
# WHICH peers are trusted to set that header is the FORWARDED_ALLOW_IPS
# environment variable (uvicorn reads it directly), set in docker-compose to the
# proxy's network only. It defaults to 127.0.0.1, so an image run without it
# ignores the header rather than believing it. Never set it to "*": that lets
# any client forge its own address and bypass the per-IP limits.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
