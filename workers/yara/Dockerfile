FROM python:3.11-slim

# Install system dependencies for Yara
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libssl-dev \
    libmagic-dev \
    pkg-config \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Yara from source (latest version)
RUN curl -L https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz | tar xz && \
    cd yara-4.3.2 && \
    ./bootstrap.sh && \
    ./configure --enable-cuckoo --enable-magic && \
    make && make install && \
    ldconfig && \
    cd .. && rm -rf yara-4.3.2

WORKDIR /app

# Copy Python requirements and install
COPY workers/yara/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY common ./common
COPY workers/yara ./worker

# Create directory for Yara rules
RUN mkdir -p /app/yara-rules

# Set Python path
ENV PYTHONPATH=/app

# Start worker
CMD ["celery", "-A", "worker.tasks", "worker", "--loglevel=info", "-Q", "yara"]