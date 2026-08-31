# Production-ready Python Dockerfile with Non-Root Security Context
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Prevent Python from writing pyc files and buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install minimal OS dependencies & create non-root user
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --shell /bin/bash --create-home appuser \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code with proper ownership in single layer
COPY --chown=appuser:appgroup . .

# Switch to non-root user for principle of least privilege
USER appuser

# Expose Streamlit default port
EXPOSE 8501

# Healthcheck for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Launch Streamlit with non-root security context
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
