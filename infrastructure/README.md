# VirusJaeger Infrastructure

This directory contains the complete Docker Compose infrastructure for the VirusJaeger self-hosted VirusTotal clone.

## Architecture Overview

The infrastructure consists of multiple layers:

### Application Services
- **API** (`api`): FastAPI backend service providing the REST API
- **Frontend** (`frontend`): React-based web interface (minimal implementation)

### Scanning Workers
- **worker-scan**: Original simulated scanner (for development/testing)
- **worker-clamav**: ClamAV-based antivirus scanning engine
- **worker-yara**: Yara rule-based malware detection engine  
- **worker-orchestrator**: Multi-engine scan coordinator

### Infrastructure Services
- **postgres**: Primary database for metadata and scan results
- **rabbitmq**: Message queue for task distribution
- **opensearch**: Search and indexing engine (future use)
- **minio**: Object storage for file samples

## Quick Start

```bash
# From repository root
cd infrastructure
docker compose up --build

# Access services:
# API Documentation: http://localhost:8000/docs
# Frontend: http://localhost:3000
# RabbitMQ Management: http://localhost:15672 (guest/guest)
# MinIO Console: http://localhost:9001 (minioadmin/minioadmin)
```

## Scanning Engines

### ClamAV Worker
- Real-time virus scanning using ClamAV signatures
- Automatic signature database updates on startup
- Queue: `clamav`

### Yara Worker  
- Rule-based malware detection
- Supports custom Yara rules
- Built-in test rules for PE files and suspicious strings
- Queue: `yara`

### Orchestrator Worker
- Coordinates scanning across multiple engines
- Aggregates results from all available scanners
- Provides unified verdict based on engine consensus
- Queue: `orchestrator`

## Configuration

### Environment Variables

All workers support these environment variables:
- `POSTGRES_DSN`: Database connection string
- `RABBITMQ_URL`: Message queue connection
- `PYTHONUNBUFFERED`: Python output buffering (set to 1)

### Volumes

- `file_storage`: Shared storage for uploaded files
- `clamav_db`: ClamAV signature database persistence
- `yara_rules`: Custom Yara rules storage
- `postgres_data`: Database persistence
- `rabbitmq_data`: Message queue persistence
- `opensearch_data`: Search index persistence
- `minio_data`: Object storage persistence

## Custom Yara Rules

Place custom `.yar` files in the `yara_rules` volume to extend detection capabilities:

```bash
# Copy rules to the volume (example)
docker compose exec worker-yara cp /path/to/custom.yar /app/yara-rules/
```

## Scaling

To scale individual worker types:

```bash
# Scale ClamAV workers
docker compose up --scale worker-clamav=3

# Scale Yara workers  
docker compose up --scale worker-yara=2
```

## API Integration

The API automatically detects available scanning engines and routes tasks accordingly. Use the orchestrator for comprehensive multi-engine scanning:

```python
# Submit file for multi-engine scanning
celery_app.send_task('orchestrator.scan_file', args=[sha256, file_content])
```

## Monitoring

### Health Checks
```bash
# Check engine health
curl http://localhost:8000/health

# RabbitMQ queue status
curl http://localhost:15672/api/queues
```

### Logs
```bash
# View worker logs
docker compose logs worker-clamav
docker compose logs worker-yara
docker compose logs worker-orchestrator
```

## Security Considerations

- ClamAV signature updates require internet access
- File storage volumes should be properly secured
- Database credentials should be changed for production
- Consider network isolation between scanning workers
- Implement proper file size and type restrictions

## Development

For development, you can run individual services:

```bash
# Start only core services
docker compose up postgres rabbitmq

# Add specific workers
docker compose up worker-clamav worker-yara
```