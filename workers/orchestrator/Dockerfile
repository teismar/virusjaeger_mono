FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install
COPY workers/orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY common ./common
COPY workers/orchestrator ./worker

# Set Python path
ENV PYTHONPATH=/app

# Start orchestrator worker
CMD ["celery", "-A", "worker.tasks", "worker", "--loglevel=info", "-Q", "orchestrator"]