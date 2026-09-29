FROM python:3.12-slim AS build
WORKDIR /src
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
# Non-root: the worker reads customer log data and calls out to an API; there
# is no reason for it to be able to write anywhere it should not.
RUN useradd --create-home --uid 10001 worker
COPY --from=build /install /usr/local
WORKDIR /app
COPY worker/ ./worker/
USER worker
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "worker.main"]
