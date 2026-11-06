# ==============================================================================
# Production Dockerfile for RSA & JWT Studio
# ==============================================================================
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    HOST=0.0.0.0

# Set workspace directory
WORKDIR /app

# Install curl for healthchecks and clean up apt cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies first (leverages Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create an unprivileged user to run the container securely
RUN useradd -m -u 1000 -s /bin/bash appuser

# Copy application files and grant ownership to appuser
COPY --chown=appuser:appuser . .

# Switch to the non-root user
USER appuser

# Expose default port (Render, Cloud Run, and Fly.io override via $PORT)
EXPOSE 5000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-5000}/api/health || exit 1

# Launch the production server
CMD ["python", "server.py"]
