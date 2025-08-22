from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import aiofiles
import os
import random
from typing import Optional, List
from common.hashing import compute_hashes
from common.db import Base, engine, SessionLocal, Sample
from sqlalchemy import select
from common.config import settings
# Make Celery optional for local development
try:
    from common.celery_app import celery_app
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False

app = FastAPI(
    title="VirusJaeger API", 
    version="0.2.0",
    description="A self-hosted VirusTotal clone API for malware analysis",
    contact={
        "name": "VirusJaeger API",
        "url": "https://github.com/teismar/virusjaeger_mono",
    },
    license_info={
        "name": "MIT",
    },
)
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
    
    # Submit scan task (with fallback for local development)
    if CELERY_AVAILABLE:
        try:
            celery_app.send_task('tasks.scan_file', args=[sha256_hex])
        except Exception:
            # Fallback to mock scanning for local development
            await _mock_scan_file(sha256_hex)
    else:
        # Mock scanning when Celery is not available
        await _mock_scan_file(sha256_hex)
    
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

async def _mock_scan_file(sha256: str):
    """Mock scan function for local development when Celery is not available"""
    import asyncio
    # Simulate some processing delay
    await asyncio.sleep(1)
    
    # Simulated scan: randomly decide malicious/clean
    verdict = random.choice(['clean', 'malicious'])
    result = {
        'verdict': verdict, 
        'engine': 'simulated', 
        'score': 1 if verdict == 'malicious' else 0,
        'engines': {
            'mock_engine': {
                'detected': verdict == 'malicious',
                'result': 'Trojan.Generic' if verdict == 'malicious' else 'Clean',
                'version': '1.0.0',
                'update': '20241222'
            }
        },
        'scan_date': '2024-12-22T12:00:00Z'
    }
    
    async with SessionLocal() as session:
        stmt = select(Sample).where(Sample.sha256 == sha256)
        res = await session.execute(stmt)
        sample = res.scalar_one_or_none()
        if sample:
            sample.scan_status = 'finished'
            sample.scan_result = result
            await session.commit()

# Simple API key validation (in production, use proper authentication)
api_keys = {"demo-api-key": {"name": "Demo User", "daily_quota": 1000, "used_today": 0}}

async def validate_api_key(authorization: Optional[str] = Header(None)):
    """Optional API key validation for automation endpoints"""
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]  # Remove "Bearer " prefix
        if api_key in api_keys:
            return api_keys[api_key]
    return None

@app.get("/search")
async def search(q: str = Query(..., min_length=3, max_length=64)):
    """Search for files by filename or hash"""
    # Very naive LIKE-based search across filename or exact hash match
    from sqlalchemy import select, or_
    async with SessionLocal() as session:
        stmt = select(Sample).where(
            or_(Sample.filename.ilike(f"%{q}%"), Sample.sha256 == q, Sample.md5 == q, Sample.sha1 == q)
        ).limit(25)
        res = await session.execute(stmt)
        samples = res.scalars().all()
        return [existing_to_dict(s) for s in samples]

@app.post("/files/rescan")
async def rescan_file(
    sha256: str = Query(..., description="SHA256 hash of the file to rescan"), 
    api_user: dict = Depends(validate_api_key)
):
    """Rescan an existing file (requires API key)"""
    if not api_user:
        raise HTTPException(status_code=401, detail="API key required for rescan")
    
    async with SessionLocal() as session:
        stmt = select(Sample).where(Sample.sha256 == sha256)
        res = await session.execute(stmt)
        sample = res.scalar_one_or_none()
        if not sample:
            raise HTTPException(status_code=404, detail="File not found")
        
        # Reset scan status and trigger rescan
        sample.scan_status = 'pending'
        sample.scan_result = None
        await session.commit()
        
        # Submit scan task
        if CELERY_AVAILABLE:
            try:
                celery_app.send_task('tasks.scan_file', args=[sha256])
            except Exception:
                await _mock_scan_file(sha256)
        else:
            await _mock_scan_file(sha256)
        
        return {"sha256": sha256, "status": "queued", "message": "Rescan initiated"}

@app.post("/urls")
async def scan_url(
    url: str = Query(..., description="URL to scan"), 
    api_user: dict = Depends(validate_api_key)
):
    """Submit a URL for scanning (requires API key)"""
    if not api_user:
        raise HTTPException(status_code=401, detail="API key required for URL scanning")
    
    # Basic URL validation
    import re
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Generate a unique ID for the URL scan
    import hashlib
    url_id = hashlib.sha256(url.encode()).hexdigest()[:16]
    
    # Mock URL scanning result
    verdict = random.choice(['clean', 'malicious', 'suspicious'])
    result = {
        'url': url,
        'verdict': verdict,
        'engines': {
            'url_scanner': {
                'detected': verdict != 'clean',
                'result': 'Phishing' if verdict == 'malicious' else ('Suspicious' if verdict == 'suspicious' else 'Clean'),
                'version': '1.0.0'
            }
        },
        'scan_date': '2024-12-22T12:00:00Z'
    }
    
    return {
        "scan_id": url_id,
        "url": url,
        "status": "finished",
        "result": result
    }

@app.get("/urls/{scan_id}")
async def get_url_report(scan_id: str):
    """Get URL scan report"""
    # This is a mock implementation - in real system would store URL scans in DB
    return {
        "scan_id": scan_id,
        "status": "finished",
        "result": {
            "verdict": "clean",
            "engines": {
                "url_scanner": {
                    "detected": False,
                    "result": "Clean",
                    "version": "1.0.0"
                }
            }
        }
    }

@app.get("/statistics")
async def get_statistics():
    """Get system statistics"""
    async with SessionLocal() as session:
        from sqlalchemy import func
        total_samples = await session.scalar(select(func.count(Sample.id)))
        finished_scans = await session.scalar(
            select(func.count(Sample.id)).where(Sample.scan_status == 'finished')
        )
        
        return {
            "total_samples": total_samples or 0,
            "finished_scans": finished_scans or 0,
            "pending_scans": (total_samples or 0) - (finished_scans or 0),
            "engines": {
                "mock_engine": {
                    "version": "1.0.0",
                    "last_update": "2024-12-22T12:00:00Z"
                }
            }
        }

@app.post("/files/batch")
async def batch_upload(files: List[UploadFile] = File(...), api_user: dict = Depends(validate_api_key)):
    """Batch file upload (requires API key)"""
    if not api_user:
        raise HTTPException(status_code=401, detail="API key required for batch operations")
    
    if len(files) > 10:  # Limit batch size
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch")
    
    results = []
    for file in files:
        try:
            # Reuse the upload logic from the single file endpoint
            contents = await file.read()
            if len(contents) > settings.max_file_size_mb * 1024 * 1024:
                results.append({
                    "filename": file.filename,
                    "error": "File too large"
                })
                continue
                
            import io
            md5_hex, sha1_hex, sha256_hex = compute_hashes(io.BytesIO(contents))
            
            async with SessionLocal() as session:
                stmt = select(Sample).where(Sample.sha256 == sha256_hex)
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                if existing:
                    results.append({
                        "filename": file.filename,
                        "sha256": sha256_hex,
                        "status": "exists",
                        "scan_status": existing.scan_status
                    })
                    continue
                    
                sample = Sample(
                    sha256=sha256_hex, 
                    sha1=sha1_hex, 
                    md5=md5_hex, 
                    size=len(contents), 
                    filename=file.filename
                )
                session.add(sample)
                await session.commit()
            
            # Save file
            os.makedirs('/tmp/samples', exist_ok=True)
            async with aiofiles.open(f"/tmp/samples/{sha256_hex}", 'wb') as f:
                await f.write(contents)
            
            # Submit scan
            if CELERY_AVAILABLE:
                try:
                    celery_app.send_task('tasks.scan_file', args=[sha256_hex])
                except Exception:
                    await _mock_scan_file(sha256_hex)
            else:
                await _mock_scan_file(sha256_hex)
            
            results.append({
                "filename": file.filename,
                "sha256": sha256_hex,
                "status": "queued"
            })
            
        except Exception as e:
            results.append({
                "filename": file.filename,
                "error": str(e)
            })
    
    return {"batch_results": results}

@app.get("/api-info")
async def api_info():
    """Get API information and usage"""
    return {
        "api_version": "0.2.0",
        "endpoints": {
            "public": [
                "GET /health",
                "POST /files",
                "GET /files/{sha256}",
                "GET /search",
                "GET /statistics",
                "GET /urls/{scan_id}"
            ],
            "authenticated": [
                "POST /files/rescan",
                "POST /urls",
                "POST /files/batch"
            ]
        },
        "authentication": {
            "type": "Bearer token",
            "header": "Authorization: Bearer <api-key>",
            "demo_key": "demo-api-key"
        },
        "limits": {
            "max_file_size_mb": settings.max_file_size_mb,
            "max_batch_size": 10,
            "daily_quota": 1000
        }
    }
