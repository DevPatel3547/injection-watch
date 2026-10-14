# InjectionWatch API image (read API + submissions). The detector/WARC tooling is included too.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE LICENSE-DATA.md ./
COPY injectionwatch ./injectionwatch
RUN pip install --no-cache-dir --upgrade pip build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    INJECTIONWATCH_DB=/data/injectionwatch.db \
    INJECTIONWATCH_RATE_DB=/data/ratelimit.db
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[api]" && rm -f /tmp/*.whl \
    && useradd --system --uid 10001 --home /data iw && mkdir -p /data && chown iw /data
USER iw
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"
# Behind a reverse proxy you control, set INJECTIONWATCH_TRUST_PROXY=1 so rate limits key on the client.
CMD ["injectionwatch", "--log-level", "INFO", "serve", "--host", "0.0.0.0", "--port", "8000", "--db", "/data/injectionwatch.db"]
