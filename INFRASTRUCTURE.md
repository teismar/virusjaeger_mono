# VirusJaeger Multi-Engine Antivirus Infrastructure

## Overview

This implementation provides a comprehensive Docker Compose infrastructure for VirusJaeger with multiple custom antivirus containers, transforming it into a true self-hosted VirusTotal clone.

## What Was Built

### 🔧 Core Infrastructure
- **Complete Docker Compose setup** with persistent volumes and proper networking
- **Infrastructure management script** (`manage.sh`) for easy operations
- **Comprehensive documentation** and setup guides
- **Testing framework** to validate the entire infrastructure

### 🛡️ Antivirus Engines

#### ClamAV Worker (`worker-clamav`)
- Real antivirus scanning using ClamAV signatures
- Automatic signature database updates on startup
- Python integration via `pyclamd`
- Persistent volume for signature storage

#### Yara Worker (`worker-yara`)  
- Rule-based malware detection engine
- Custom Yara rules support with sample rules provided
- File type detection and analysis
- Configurable rule sets with hot-reloading capability

#### Orchestrator Worker (`worker-orchestrator`)
- Multi-engine scan coordination
- Result aggregation and consensus-based verdicts
- Parallel execution across all available engines
- Health monitoring for all scanning services

#### Simulated Worker (`worker-scan`)
- Original development/testing scanner (retained for compatibility)
- Quick testing without real AV overhead

### 🌐 Enhanced API

#### New Endpoints
- `POST /files?multi_engine=true` - Upload with multi-engine scanning option
- `POST /files/multi-engine` - Dedicated multi-engine endpoint (authenticated)
- `GET /health` - Enhanced health checks showing all engine statuses

#### Features
- Multi-engine scanning support with engine selection
- Real-time health monitoring of all AV engines
- Backward compatibility with existing single-engine workflows
- Comprehensive scan result aggregation

### 📦 Infrastructure Components

#### Persistent Volumes
- `postgres_data` - Database persistence
- `rabbitmq_data` - Message queue persistence  
- `clamav_db` - ClamAV signature database
- `yara_rules` - Custom Yara rules storage
- `file_storage` - Shared file storage for samples
- `opensearch_data` - Search index persistence
- `minio_data` - Object storage persistence

#### Services Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │      API         │    │   Orchestrator  │
│   (React UI)    │───▶│   (FastAPI)      │───▶│    Worker       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                        ┌──────────────────┐    ┌─────────────────┐
                        │    RabbitMQ      │    │   Engine Pool   │
                        │  (Task Queue)    │    │                 │
                        └──────────────────┘    │  ┌─────────────┐│
                                │                │  │   ClamAV    ││
                                ▼                │  │   Worker    ││
                        ┌──────────────────┐    │  └─────────────┘│
                        │   PostgreSQL     │    │  ┌─────────────┐│
                        │   (Metadata)     │    │  │    Yara     ││
                        └──────────────────┘    │  │   Worker    ││
                                                │  └─────────────┘│
                                                │  ┌─────────────┐│
                                                │  │ Simulated   ││
                                                │  │  Worker     ││
                                                │  └─────────────┘│
                                                └─────────────────┘
```

## Usage Examples

### Basic File Upload
```bash
# Single-engine scanning (original behavior)
curl -X POST "http://localhost:8000/files" -F "file=@sample.exe"

# Multi-engine scanning via query parameter
curl -X POST "http://localhost:8000/files?multi_engine=true" -F "file=@sample.exe"
```

### Multi-Engine Scanning (Authenticated)
```bash
# Comprehensive multi-engine analysis
curl -H "Authorization: Bearer demo-api-key" \
     -X POST "http://localhost:8000/files/multi-engine" \
     -F "file=@sample.exe"
```

### Health Monitoring
```bash
# Check overall system health
curl "http://localhost:8000/health"

# Example response with engine status
{
  "status": "ok",
  "api": "healthy", 
  "engines": {
    "tasks.scan_file": "healthy",
    "clamav.scan_file": "healthy", 
    "yara.scan_file": "healthy"
  }
}
```

## Management Operations

### Starting Infrastructure
```bash
cd infrastructure
./manage.sh start

# Or manually
docker compose up -d
```

### Scaling Workers
```bash
./manage.sh scale

# Or manually scale specific services
docker compose up -d --scale worker-clamav=3 --scale worker-yara=2
```

### Updating Signatures
```bash
./manage.sh update-clamav
```

### Custom Yara Rules
```bash
# Add custom rules to the yara_rules volume
./manage.sh setup-rules

# Copy custom rules
docker run --rm -v $(pwd)/custom-rules:/source -v virusjaeger_yara_rules:/dest alpine:latest cp /source/*.yar /dest/
```

## Security Features

### Production Hardening
- Environment variable configuration for secrets
- Isolated networks for worker containers
- Configurable file size and type restrictions
- API key authentication for sensitive operations
- Persistent volume encryption (configurable)

### Signature Management
- Automatic ClamAV signature updates on container start
- Custom Yara rule management with version control
- Isolated signature storage with proper permissions

## Result Aggregation

The orchestrator provides intelligent result aggregation:

```json
{
  "verdict": "malicious",
  "total_score": 2,
  "max_possible_score": 3,
  "engines": {
    "scan": {"verdict": "clean", "engine": "simulated", "score": 0},
    "clamav": {"verdict": "malicious", "engine": "clamav", "score": 1, "details": "Win.Test.EICAR_HDB-1"},
    "yara": {"verdict": "malicious", "engine": "yara", "score": 1, "matches": [{"rule": "EICAR_Test_File"}]}
  },
  "scan_summary": "Scanned by 3 engines, 2 detected threats"
}
```

## Performance Characteristics

### Scalability
- Each worker type can be independently scaled
- Stateless workers enable horizontal scaling
- Queue-based task distribution prevents bottlenecks
- Persistent volumes maintain state across restarts

### Efficiency
- Parallel scanning across multiple engines
- Shared file storage reduces duplication
- Optimized container images with multi-stage builds
- Configurable resource limits per worker type

## File Structure

```
infrastructure/
├── docker-compose.yml          # Main orchestration file
├── manage.sh                  # Infrastructure management script
├── test-infrastructure.sh     # Validation and testing script
├── README.md                  # Comprehensive documentation
├── .env.example              # Configuration template
├── .gitignore                # Infrastructure-specific ignores
└── yara-rules/
    └── default.yar           # Sample Yara detection rules

workers/
├── clamav/                   # ClamAV antivirus worker
│   ├── Dockerfile
│   ├── requirements.txt
│   └── tasks.py
├── yara/                     # Yara rule-based worker  
│   ├── Dockerfile
│   ├── requirements.txt
│   └── tasks.py
├── orchestrator/             # Multi-engine coordinator
│   ├── Dockerfile
│   ├── requirements.txt
│   └── tasks.py
└── scan/                     # Original simulated worker
    ├── Dockerfile
    ├── requirements.txt  
    └── tasks.py
```

This implementation successfully transforms VirusJaeger into a production-ready, self-hosted VirusTotal clone with real antivirus capabilities and comprehensive multi-engine scanning infrastructure.