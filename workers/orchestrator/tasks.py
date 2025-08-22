from common.celery_app import celery_app
from common.db import SessionLocal, Sample
from sqlalchemy import select
from celery import group
import logging
import os

logger = logging.getLogger(__name__)

@celery_app.task(name='orchestrator.scan_file')
def scan_file_multi_engine(sha256: str, file_content: bytes = None):
    """
    Orchestrate scanning across multiple AV engines
    """
    logger.info(f"Starting multi-engine scan for file {sha256}")
    
    # List of available scanning engines
    engines = [
        'tasks.scan_file',        # Original simulated scanner
        'clamav.scan_file',       # ClamAV scanner
        'yara.scan_file',         # Yara scanner
    ]
    
    try:
        # Create a group of scan tasks for parallel execution
        scan_tasks = []
        for engine in engines:
            if file_content:
                task = celery_app.send_task(engine, args=[sha256, file_content])
            else:
                task = celery_app.send_task(engine, args=[sha256])
            scan_tasks.append(task)
        
        # Wait for all tasks to complete
        results = {}
        for i, task in enumerate(scan_tasks):
            try:
                result = task.get(timeout=300)  # 5 minute timeout per engine
                engine_name = engines[i].split('.')[-1].replace('_file', '')
                results[engine_name] = result
                logger.info(f"Engine {engine_name} completed for {sha256}")
            except Exception as e:
                engine_name = engines[i].split('.')[-1].replace('_file', '')
                logger.error(f"Engine {engine_name} failed for {sha256}: {str(e)}")
                results[engine_name] = {
                    'verdict': 'error',
                    'engine': engine_name,
                    'score': 0,
                    'details': f'Engine timeout or error: {str(e)}'
                }
        
        # Aggregate results
        total_score = sum(r.get('score', 0) for r in results.values())
        max_score = len([r for r in results.values() if r.get('score', 0) > 0])
        
        # Determine overall verdict
        if total_score == 0:
            overall_verdict = 'clean'
        elif total_score >= max_score * 0.5:  # If majority agree it's malicious
            overall_verdict = 'malicious'
        else:
            overall_verdict = 'suspicious'
        
        aggregated_result = {
            'verdict': overall_verdict,
            'total_score': total_score,
            'max_possible_score': max_score,
            'engines': results,
            'scan_summary': f"Scanned by {len(results)} engines, {sum(1 for r in results.values() if r.get('verdict') == 'malicious')} detected threats"
        }
        
    except Exception as e:
        logger.error(f"Multi-engine scan orchestration failed for {sha256}: {str(e)}")
        aggregated_result = {
            'verdict': 'error',
            'total_score': 0,
            'max_possible_score': 0,
            'engines': {},
            'error': str(e)
        }
    
    # Update database with aggregated results
    import asyncio
    async def update():
        async with SessionLocal() as session:
            stmt = select(Sample).where(Sample.sha256 == sha256)
            res = await session.execute(stmt)
            sample = res.scalar_one_or_none()
            if sample:
                sample.scan_result = aggregated_result
                sample.scan_status = 'finished'
                await session.commit()
                logger.info(f"Updated aggregated scan result for {sha256}")
    
    asyncio.run(update())
    return aggregated_result

@celery_app.task(name='orchestrator.health_check')
def health_check():
    """Check health of all scanning engines"""
    engines = ['tasks.scan_file', 'clamav.scan_file', 'yara.scan_file']
    health_status = {}
    
    for engine in engines:
        try:
            # Send a ping task to check if engine is responsive
            task = celery_app.send_task(f"{engine.split('.')[0]}.ping", args=[])
            result = task.get(timeout=10)
            health_status[engine] = 'healthy'
        except Exception as e:
            health_status[engine] = f'unhealthy: {str(e)}'
    
    return health_status