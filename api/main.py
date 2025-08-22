from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import aiofiles
import os
from common.hashing import compute_hashes
from common.db import Base, engine, SessionLocal, Sample
from sqlalchemy import select
from common.config import settings
from common.celery_app import celery_app

app = FastAPI(title="VirusJaeger API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/files")
async def upload_file(file: UploadFile = File(...)):
    # size limit
    contents = await file.read()
    if len(contents) > settings.max_file_size_mb * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large")
    # compute hashes
    import io
    md5_hex, sha1_hex, sha256_hex = compute_hashes(io.BytesIO(contents))

    async with SessionLocal() as session:
        stmt = select(Sample).where(Sample.sha256 == sha256_hex)
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()
        if existing:
            return existing_to_dict(existing)
        sample = Sample(sha256=sha256_hex, sha1=sha1_hex, md5=md5_hex, size=len(contents), filename=file.filename)
        session.add(sample)
        await session.commit()
    # Write to local temp (simulate object storage) for PoC
    os.makedirs('/tmp/samples', exist_ok=True)
    async with aiofiles.open(f"/tmp/samples/{sha256_hex}", 'wb') as f:
        await f.write(contents)
    celery_app.send_task('tasks.scan_file', args=[sha256_hex])
    return {"sha256": sha256_hex, "status": "queued"}

@app.get("/files/{sha256}")
async def get_report(sha256: str):
    async with SessionLocal() as session:
        stmt = select(Sample).where(Sample.sha256 == sha256)
        res = await session.execute(stmt)
        sample = res.scalar_one_or_none()
        if not sample:
            raise HTTPException(status_code=404, detail="Not found")
        return existing_to_dict(sample)

def existing_to_dict(sample: Sample):
    return {
        "sha256": sample.sha256,
        "sha1": sample.sha1,
        "md5": sample.md5,
        "filename": sample.filename,
        "size": sample.size,
        "status": sample.scan_status,
        "result": sample.scan_result,
        "created_at": sample.created_at.isoformat(),
    }

@app.get("/search")
async def search(q: str = Query(..., min_length=3, max_length=64)):
    # Very naive LIKE-based search across filename or exact hash match
    from sqlalchemy import select, or_
    async with SessionLocal() as session:
        stmt = select(Sample).where(
            or_(Sample.filename.ilike(f"%{q}%"), Sample.sha256 == q, Sample.md5 == q, Sample.sha1 == q)
        ).limit(25)
        res = await session.execute(stmt)
        samples = res.scalars().all()
        return [existing_to_dict(s) for s in samples]
