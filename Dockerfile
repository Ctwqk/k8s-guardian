# syntax=docker/dockerfile:1

# ---- build: turn the project and all of its dependencies into wheels --------------------------
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY k8s_guardian ./k8s_guardian
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# ---- runtime: slim, non-root, no kubectl, no shell-outs ---------------------------------------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GUARDIAN_DB_PATH=/data/guardian.db

RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin guardian \
 && mkdir /data && chown guardian:guardian /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels k8s-guardian && rm -rf /wheels

USER 10001:10001
WORKDIR /data
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('GUARDIAN_PORT', '8000'), timeout=3)"]
ENTRYPOINT ["k8s-guardian"]
CMD ["serve"]
