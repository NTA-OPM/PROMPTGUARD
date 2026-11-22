# syntax=docker/dockerfile:1
FROM python:3.15-slim AS build
WORKDIR /src
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY deployment/constraints-api.txt ./constraints.txt
RUN pip wheel --no-deps --wheel-dir /wheels . \
 && pip wheel --wheel-dir /wheels -c constraints.txt "fastapi" "uvicorn" "pydantic" "pyyaml" "typer"

FROM python:3.15-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PROMPTGUARD_RATE_LIMIT_PER_MINUTE=120 PROMPTGUARD_ENABLE_DOCS=false
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin promptguard
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels promptguard-oss fastapi uvicorn \
 && rm -rf /wheels
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"
# Bind to 0.0.0.0 inside the container only; publish the port to localhost in compose.
CMD ["uvicorn", "promptguard.api.app:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
