FROM python:3.12-alpine
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    HOST=0.0.0.0 \
    PORT=8080 \
    LOG_DIR=/data \
    CAPTURE_MODE=metadata
WORKDIR /app
COPY src /app/src
RUN addgroup -S sensor && adduser -S -G sensor -u 10001 sensor \
    && mkdir -p /data /fleet && chown sensor:sensor /data /fleet
USER sensor
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/healthz",timeout=2)' || exit 1
CMD ["python", "-m", "deceptionsensor"]
