try:
    from pydantic_settings import BaseSettings  # pydantic v2
except ImportError:  # fallback for pydantic v1
    from pydantic import BaseSettings  # type: ignore

class Settings(BaseSettings):
    postgres_dsn: str = "postgresql+asyncpg://virus:virus@postgres:5432/virus"
    rabbitmq_url: str = "amqp://guest:guest@rabbitmq:5672//"
    opensearch_url: str = "http://opensearch:9200"
    s3_endpoint: str = "http://minio:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket: str = "samples"
    max_file_size_mb: int = 64

settings = Settings()  # type: ignore[arg-type]
