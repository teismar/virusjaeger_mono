# VirusJaeger (Proof of Concept)

API-first, containerized malware sample analysis workflow inspired by VirusTotal. Modular monorepo layout prepared for splitting each component into its own repository later.

## Components (directories become future repos)
- `api/` FastAPI service: ingest files, expose reports.
- `workers/scan/` Celery worker performing (simulated) AV scanning.
- `common/` Shared Python library (DB models, config, hashing helpers).
- `frontend/` React (Vite) dark UI consuming only the public API.
- `infrastructure/` Orchestration (`docker-compose.yml`).
- `mockup/` Initial system diagram.

## Architecture (current PoC)
Upload -> API stores metadata (Postgres) -> enqueues scan task (RabbitMQ) -> worker simulates scan, updates DB -> client polls `/files/{sha256}` -> optional future indexing (OpenSearch) & object storage (MinIO) placeholders already in compose for scaling.

## Scaling Considerations
- Stateless API: scale horizontally behind a reverse proxy/load balancer.
- Celery queue separation by concern (e.g., `scan`, `metadata`, `index`). Add more workers per queue.
- Datastores already network services (Postgres, OpenSearch, MinIO). Swap to managed offerings easily.
- Hash is primary key for idempotency & dedup.
- Use S3 (MinIO) for file blobs; DB keeps metadata only.

## Run (Dev PoC)
```bash
# Start stack (first build)
cd infrastructure
docker compose up --build
# API: http://localhost:8000/docs
# Frontend: http://localhost:3000
```
Upload a file in UI, watch status poll until finished.

## API (initial)
- `POST /files` multipart file -> `{ sha256, status }`
- `GET /files/{sha256}` -> report JSON
- `GET /health` -> service health

## Next Steps / Ideas
- Real ClamAV integration container & signature updates.
- Additional workers: metadata extraction (PE headers, EXIF, strings), YARA / LiveHunt rules, sandbox detonation.
- OpenSearch indexing + `/search` endpoint.
- Auth (API keys), rate limiting, abuse prevention.
- File type detection & pipeline branching.
- Caching layer (Redis) for hot reports.
- Websocket or Server-Sent Events for push updates instead of polling.
- Multi-engine scoring aggregation.
- Tagging & retrohunt queries.
- Storage lifecycle mgmt + encryption.

## Disclaimer
This is a demo scaffold. NOT production ready (security, validation, error handling, observability missing).
# virusjaeger_mono
