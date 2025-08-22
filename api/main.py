from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import aiofiles
import os
import random
from typing import Optional, List
from datetime import datetime, timedelta
from common.hashing import compute_hashes
from common.db import Base, engine, SessionLocal, Sample, User, ApiKey
from common.auth import verify_password, get_password_hash, create_access_token, verify_token, generate_api_key
from sqlalchemy import select, update
from common.config import settings
# Make Celery optional for local development
try:
    from common.celery_app import celery_app
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False

# Pydantic models for request/response
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    is_active: bool
    created_at: datetime
    daily_quota: int
    used_today: int

class Token(BaseModel):
    access_token: str
    token_type: str

class ApiKeyCreate(BaseModel):
    name: str

class ApiKeyResponse(BaseModel):
    id: int
    key: str
    name: str
    is_active: bool
    created_at: datetime

app = FastAPI(
    title="VirusJaeger API", 
    version="0.3.0",
    description="A self-hosted VirusTotal clone API for malware analysis with user authentication",
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

# OAuth2 scheme for JWT tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Optional[User]:
    """Get current user from JWT token."""
    if not token:
        return None
    
    payload = verify_token(token)
    if not payload:
        return None
        
    user_id = payload.get("sub")
    if not user_id:
        return None
        
    async with SessionLocal() as session:
        stmt = select(User).where(User.id == int(user_id), User.is_active == True)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current admin user."""
    if not current_user or not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

async def validate_api_key(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    """Validate API key from database."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
        
    api_key = authorization[7:]  # Remove "Bearer " prefix
    
    async with SessionLocal() as session:
        stmt = select(ApiKey, User).join(User, ApiKey.user_id == User.id).where(
            ApiKey.key == api_key,
            ApiKey.is_active == True,
            User.is_active == True
        )
        result = await session.execute(stmt)
        row = result.first()
        
        if not row:
            return None
            
        api_key_obj, user = row
        
        # Update last used timestamp
        stmt_update = update(ApiKey).where(ApiKey.id == api_key_obj.id).values(
            last_used=datetime.utcnow()
        )
        await session.execute(stmt_update)
        await session.commit()
        
        return {
            "user_id": user.id,
            "username": user.username,
            "daily_quota": user.daily_quota,
            "used_today": user.used_today,
            "is_admin": user.is_admin
        }

async def create_default_admin():
    """Create default admin user if none exists."""
    async with SessionLocal() as session:
        stmt = select(User).where(User.is_admin == True)
        result = await session.execute(stmt)
        admin_exists = result.first()
        
        if not admin_exists:
            admin_user = User(
                username="admin",
                email="admin@virusjaeger.local",
                password_hash=get_password_hash("admin123"),
                is_admin=True,
                daily_quota=10000
            )
            session.add(admin_user)
            await session.commit()
            
            # Create API key for admin
            api_key = ApiKey(
                key="admin-" + generate_api_key(),
                user_id=admin_user.id,
                name="Default Admin Key"
            )
            session.add(api_key)
            await session.commit()
            print(f"Created default admin user with API key: {api_key.key}")

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await create_default_admin()

# Authentication endpoints
@app.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    """Register a new user."""
    async with SessionLocal() as session:
        # Check if username or email already exists
        stmt = select(User).where(
            (User.username == user_data.username) | (User.email == user_data.email)
        )
        result = await session.execute(stmt)
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )
        
        # Create new user
        user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=get_password_hash(user_data.password)
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        
        return UserResponse(**user.__dict__)

@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and get access token."""
    async with SessionLocal() as session:
        stmt = select(User).where(User.username == form_data.username, User.is_active == True)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user or not verify_password(form_data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token = create_access_token(data={"sub": str(user.id)})
        return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return UserResponse(**current_user.__dict__)

@app.post("/auth/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    api_key_data: ApiKeyCreate,
    current_user: User = Depends(get_current_user)
):
    """Create a new API key for the current user."""
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    async with SessionLocal() as session:
        api_key = ApiKey(
            key=generate_api_key(),
            user_id=current_user.id,
            name=api_key_data.name
        )
        session.add(api_key)
        await session.commit()
        await session.refresh(api_key)
        
        return ApiKeyResponse(**api_key.__dict__)

@app.get("/auth/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(current_user: User = Depends(get_current_user)):
    """List API keys for the current user."""
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    async with SessionLocal() as session:
        stmt = select(ApiKey).where(ApiKey.user_id == current_user.id)
        result = await session.execute(stmt)
        api_keys = result.scalars().all()
        
        return [ApiKeyResponse(**key.__dict__) for key in api_keys]

# Admin endpoints
@app.get("/admin/users", response_model=List[UserResponse])
async def list_users(admin_user: User = Depends(get_current_admin_user)):
    """List all users (admin only)."""
    async with SessionLocal() as session:
        stmt = select(User)
        result = await session.execute(stmt)
        users = result.scalars().all()
        
        return [UserResponse(**user.__dict__) for user in users]

@app.patch("/admin/users/{user_id}")
async def update_user(
    user_id: int,
    is_admin: Optional[bool] = None,
    is_active: Optional[bool] = None,
    daily_quota: Optional[int] = None,
    admin_user: User = Depends(get_current_admin_user)
):
    """Update user properties (admin only)."""
    async with SessionLocal() as session:
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        updates = {}
        if is_admin is not None:
            updates["is_admin"] = is_admin
        if is_active is not None:
            updates["is_active"] = is_active
        if daily_quota is not None:
            updates["daily_quota"] = daily_quota
            
        if updates:
            stmt_update = update(User).where(User.id == user_id).values(**updates)
            await session.execute(stmt_update)
            await session.commit()
        
        return {"message": "User updated successfully"}

@app.get("/health")
async def health():
    health_status = {"status": "ok", "api": "healthy"}
    
    # Check scanning engines if Celery is available
    if CELERY_AVAILABLE:
        try:
            # Check orchestrator health
            task = celery_app.send_task('orchestrator.health_check', args=[])
            engines_health = task.get(timeout=10)
            health_status["engines"] = engines_health
        except Exception as e:
            health_status["engines"] = {"error": f"Could not check engines: {str(e)}"}
    else:
        health_status["engines"] = {"note": "Celery not available, using mock scanning"}
    
    return health_status

@app.post("/files")
async def upload_file(file: UploadFile = File(...), multi_engine: bool = Query(False, description="Use multi-engine scanning (ClamAV + Yara + Simulated)")):
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
            if multi_engine:
                # Use orchestrator for multi-engine scanning
                celery_app.send_task('orchestrator.scan_file', args=[sha256_hex, contents])
            else:
                # Use original single-engine scanning
                celery_app.send_task('tasks.scan_file', args=[sha256_hex])
        except Exception:
            # Fallback to mock scanning for local development
            await _mock_scan_file(sha256_hex)
    else:
        # Mock scanning when Celery is not available
        await _mock_scan_file(sha256_hex)
    
    scan_type = "multi-engine" if multi_engine else "single-engine"
    return {"sha256": sha256_hex, "status": "queued", "scan_type": scan_type}

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

@app.post("/files/multi-engine")
async def upload_file_multi_engine(
    file: UploadFile = File(...),
    api_user: dict = Depends(validate_api_key)
):
    """Upload and scan file with multiple antivirus engines (requires API key)"""
    if not api_user:
        raise HTTPException(status_code=401, detail="API key required for multi-engine scanning")
    
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
            # If file exists, trigger a fresh multi-engine scan
            existing.scan_status = 'pending'
            existing.scan_result = None
            await session.commit()
        else:
            sample = Sample(sha256=sha256_hex, sha1=sha1_hex, md5=md5_hex, size=len(contents), filename=file.filename)
            session.add(sample)
            await session.commit()
    
    # Write to local temp (simulate object storage) for PoC
    os.makedirs('/tmp/samples', exist_ok=True)
    async with aiofiles.open(f"/tmp/samples/{sha256_hex}", 'wb') as f:
        await f.write(contents)
    
    # Submit multi-engine scan task
    if CELERY_AVAILABLE:
        try:
            # Use orchestrator for comprehensive multi-engine scanning
            celery_app.send_task('orchestrator.scan_file', args=[sha256_hex, contents])
        except Exception:
            # Fallback to mock scanning for local development
            await _mock_scan_file(sha256_hex)
    else:
        # Mock scanning when Celery is not available
        await _mock_scan_file(sha256_hex)
    
    return {
        "sha256": sha256_hex, 
        "status": "queued", 
        "scan_type": "multi-engine",
        "engines": ["simulated", "clamav", "yara"],
        "message": "File submitted for comprehensive multi-engine analysis"
    }

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
