FROM python:3.11-slim
WORKDIR /app
COPY workers/scan/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY common ./common
COPY workers/scan ./worker
ENV PYTHONPATH=/app
CMD ["celery", "-A", "worker.tasks", "worker", "--loglevel=info", "-Q", "scan"]
