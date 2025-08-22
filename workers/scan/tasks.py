from common.celery_app import celery_app
from common.db import SessionLocal, Sample
from sqlalchemy import select
import random

@celery_app.task(name='tasks.scan_file')
def scan_file(sha256: str):
    # Simulated scan: randomly decide malicious/clean
    verdict = random.choice(['clean', 'malicious'])
    result = {'verdict': verdict, 'engine': 'simulated', 'score': 1 if verdict=='malicious' else 0}
    import asyncio
    async def update():
        async with SessionLocal() as session:
            stmt = select(Sample).where(Sample.sha256==sha256)
            res = await session.execute(stmt)
            sample = res.scalar_one_or_none()
            if sample:
                sample.scan_status = 'finished'
                sample.scan_result = result
                await session.commit()
    asyncio.run(update())
    return result
