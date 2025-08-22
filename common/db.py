from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, DateTime, LargeBinary, JSON
from datetime import datetime

from .config import settings

engine = create_async_engine(settings.postgres_dsn, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class Sample(Base):
    __tablename__ = 'samples'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    size: Mapped[int] = mapped_column(Integer)
    filename: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scan_status: Mapped[str] = mapped_column(String(32), default='pending')
    scan_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)

__all__ = ["Base", "Sample", "SessionLocal", "engine"]
