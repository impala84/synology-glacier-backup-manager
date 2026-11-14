FROM python:3.12-alpine

RUN apk add --no-cache tzdata && addgroup -g 1026 glacier && adduser -D -u 1026 -G glacier glacier
WORKDIR /app
COPY app /app/app
COPY runner/glacier-runner.py /app/runner/glacier-runner.py
RUN mkdir -p /data /logs && chown -R glacier:glacier /data /logs
USER glacier
ENV PYTHONUNBUFFERED=1 GBM_DATA_DIR=/data GBM_LOG_DIR=/logs GBM_PORT=8787
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health', timeout=5)"
CMD ["python", "-m", "app.server"]
