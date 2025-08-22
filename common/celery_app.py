from celery import Celery
from .config import settings

celery_app = Celery(
    'virusjaeger',
    broker=settings.rabbitmq_url,
    backend='rpc://',  # use lightweight RPC backend suitable for simple result needs
)

__all__ = ["celery_app"]
