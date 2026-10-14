ARG BASE_IMAGE=python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce
FROM ${BASE_IMAGE}

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
RUN mkdir -p /state && chown 10001:10001 /state
COPY --chown=10001:10001 src/ /app/src/
USER 10001:10001
ENTRYPOINT ["python"]
CMD ["-c", "import signal; signal.pause()"]
