from common.celery_app import celery_app
from common.db import SessionLocal, Sample
from sqlalchemy import select
import pyclamd
import os
import tempfile
import subprocess
import logging

logger = logging.getLogger(__name__)

@celery_app.task(name='clamav.scan_file')
def scan_file(sha256: str, file_content: bytes = None):
    """
    Scan a file using ClamAV engine
    """
    logger.info(f"Starting ClamAV scan for file {sha256}")
    
    try:
        # Start clamd if not running
        subprocess.run(['clamd'], check=False)
        
        # Connect to ClamAV daemon
        cd = pyclamd.ClamdUnixSocket()
        
        # Test connection
        if not cd.ping():
            logger.error("Could not connect to ClamAV daemon")
            result = {
                'verdict': 'error',
                'engine': 'clamav',
                'score': 0,
                'details': 'ClamAV daemon connection failed'
            }
        else:
            if file_content:
                # Scan file content directly
                scan_result = cd.scan_stream(file_content)
                if scan_result is None:
                    verdict = 'clean'
                    details = 'No threats detected by ClamAV'
                    score = 0
                else:
                    verdict = 'malicious'
                    details = f"ClamAV detected: {scan_result}"
                    score = 1
            else:
                # If no file content provided, mark as error
                verdict = 'error'
                details = 'No file content provided for scanning'
                score = 0
            
            result = {
                'verdict': verdict,
                'engine': 'clamav',
                'score': score,
                'details': details,
                'database_version': cd.version()
            }
            
    except Exception as e:
        logger.error(f"ClamAV scan error: {str(e)}")
        result = {
            'verdict': 'error',
            'engine': 'clamav',
            'score': 0,
            'details': f'Scan error: {str(e)}'
        }
    
    # Update database
    import asyncio
    async def update():
        async with SessionLocal() as session:
            stmt = select(Sample).where(Sample.sha256 == sha256)
            res = await session.execute(stmt)
            sample = res.scalar_one_or_none()
            if sample:
                # Update or merge with existing scan results
                existing_result = sample.scan_result or {}
                if isinstance(existing_result, dict):
                    existing_result['clamav'] = result
                else:
                    existing_result = {'clamav': result}
                
                sample.scan_result = existing_result
                sample.scan_status = 'finished'
                await session.commit()
                logger.info(f"Updated scan result for {sha256}")
    
    asyncio.run(update())
    return result

@celery_app.task(name='clamav.ping')  
def ping():
    """Health check task for ClamAV scanner"""
    try:
        import pyclamd
        cd = pyclamd.ClamdUnixSocket()
        if cd.ping():
            return {'status': 'healthy', 'engine': 'clamav', 'version': cd.version()}
        else:
            return {'status': 'unhealthy', 'engine': 'clamav', 'error': 'daemon not responding'}
    except Exception as e:
        return {'status': 'unhealthy', 'engine': 'clamav', 'error': str(e)}