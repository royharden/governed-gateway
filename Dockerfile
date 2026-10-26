FROM python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36
LABEL agentports.project="m8" agentports.instance="r03-rv2" agentports.owner="0064"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
WORKDIR /app
COPY docker/requirements.txt /app/docker/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/docker/requirements.txt
# Explicit allowlist: no repo metadata, credentials, environment files or exports.
COPY src /app/src
COPY migrations /app/migrations
COPY fixtures /app/fixtures
COPY tests/eval /app/tests/eval
COPY tests/docker /app/tests/docker
COPY docker/run_sqlite_e2e.py /app/docker/run_sqlite_e2e.py
ENV TMPDIR=/m8-runtime
ENTRYPOINT ["python", "/app/docker/run_sqlite_e2e.py"]
