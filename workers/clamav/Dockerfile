FROM python:3.11-slim

# Install ClamAV and dependencies
RUN apt-get update && \
    apt-get install -y \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create directories for ClamAV
RUN mkdir -p /var/log/clamav /var/lib/clamav && \
    chown -R clamav:clamav /var/log/clamav /var/lib/clamav

WORKDIR /app

# Copy Python requirements and install
COPY workers/clamav/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY common ./common
COPY workers/clamav ./worker

# Set Python path
ENV PYTHONPATH=/app

# Update ClamAV database on startup and start worker
CMD ["sh", "-c", "freshclam --no-warnings && celery -A worker.tasks worker --loglevel=info -Q clamav"]