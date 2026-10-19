# Build stage
FROM python:3.10-slim AS builder

WORKDIR /app
COPY pyproject.toml .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir build && \
    python -m build --wheel --no-isolation

# Runtime stage
FROM python:3.10-slim

WORKDIR /app

COPY --from=builder /app/dist/*.whl .
RUN pip install --no-cache-dir *.whl && rm *.whl

COPY src/ /app/src/
COPY run.py /app/

EXPOSE 8001

CMD ["python", "run.py", "server"]

