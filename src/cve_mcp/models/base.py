"""Base database model and engine setup."""

from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
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


def get_async_engine() -> AsyncEngine:
    """Create async database engine."""
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.log_level == "DEBUG",
        pool_size=10,
        max_overflow=20,
    )


def get_async_session_maker() -> Callable[[], AsyncSession]:
    """Create async session maker."""
    engine = get_async_engine()
    return async_sessionmaker(engine, expire_on_commit=False)


# Async session maker for FastAPI dependency injection (persistent event loop)
AsyncSessionLocal = get_async_session_maker()


@asynccontextmanager
async def get_task_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh async session for use in Celery tasks.

    Creates a new engine per invocation to avoid event loop mismatch
    issues with Celery's prefork worker pool. Each asyncio.run() call
    in a Celery task gets a new event loop, but module-level engines
    hold connections bound to the old loop, causing InterfaceError.

    The engine is disposed after use to prevent connection leaks.
    """
    settings = get_settings()
    engine = create_async_engine(
        settings.database_url,
        echo=settings.log_level == "DEBUG",
        pool_size=5,
        max_overflow=10,
    )
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:
            yield session
    finally:
        await engine.dispose()
