"""Base database model and engine setup."""

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncAttrs, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from cve_mcp.config import get_settings

# Naming convention for constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(AsyncAttrs, DeclarativeBase):
    """Base class for all database models."""

    metadata = MetaData(naming_convention=convention)


def get_async_engine():
    """Create async database engine."""
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.log_level == "DEBUG",
        pool_size=10,
        max_overflow=20,
    )


def get_async_session_maker():
    """Create async session maker."""
    engine = get_async_engine()
    return async_sessionmaker(engine, expire_on_commit=False)


# Async session maker for dependency injection
AsyncSessionLocal = get_async_session_maker()
