# Production Dockerfile for AI Security Gateway
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application source code
COPY . .

# Environment defaults
ENV GATEWAY_HOST=0.0.0.0
ENV GATEWAY_PORT=8000
ENV LLM_PROVIDER=mock
ENV AUDIT_DB_PATH=/app/gateway.db
ENV PYTHONPATH=/app

EXPOSE 8000 8501

# Default command runs the gateway API
CMD ["uvicorn", "gateway.api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--factory"]
