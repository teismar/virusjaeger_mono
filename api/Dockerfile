FROM python:3.11-slim
WORKDIR /app
# Copy only requirements first for layer caching
COPY api/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# Copy source (context is repo root)
COPY common ./common
COPY api ./api
ENV PYTHONPATH=/app
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
