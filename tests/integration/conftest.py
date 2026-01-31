"""Pytest fixtures for integration tests.

Provides prerequisite checking for semantic search integration tests:
- Database connectivity
- OpenAI API key configuration
- ATT&CK data presence
"""

import os

import pytest
from sqlalchemy import select, text

from cve_mcp.models.attack import AttackGroup, AttackTechnique
from cve_mcp.services.database import db_service


@pytest.fixture(scope="session")
async def check_prerequisites():
    """Check prerequisites for integration tests.

    Verifies:
    1. OPENAI_API_KEY is configured
    2. Database is accessible
    3. ATT&CK data exists in database (techniques and groups)

    Raises:
        RuntimeError: If prerequisites are not met
    """
    errors = []

    # Check 1: OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        errors.append(
            "OPENAI_API_KEY environment variable not set. "
            "Semantic search requires OpenAI API access for embedding generation."
        )

    # Check 2: Database connectivity and data
    try:
        async with db_service.session() as session:
            # Test database connection
            await session.execute(text("SELECT 1"))

            # Check for ATT&CK techniques
            tech_count_stmt = select(AttackTechnique).limit(1)
            tech_result = await session.execute(tech_count_stmt)
            if not tech_result.scalar_one_or_none():
                errors.append(
                    "No ATT&CK techniques found in database. "
                    "Run 'python -m cve_mcp.tasks.sync_attack' to populate data."
                )

            # Check for ATT&CK groups
            group_count_stmt = select(AttackGroup).limit(1)
            group_result = await session.execute(group_count_stmt)
            if not group_result.scalar_one_or_none():
                errors.append(
                    "No ATT&CK groups found in database. "
                    "Run 'python -m cve_mcp.tasks.sync_attack' to populate data."
                )
    except Exception as e:
        errors.append(
            f"Database connectivity failed: {e}. "
            "Ensure PostgreSQL is running and DATABASE_URL is configured correctly."
        )

    # Raise error if any prerequisite failed
    if errors:
        error_msg = (
            "\n\n=== Integration Test Prerequisites Not Met ===\n\n"
            + "\n\n".join(f"  {i+1}. {err}" for i, err in enumerate(errors))
            + "\n\n"
            "These are REAL integration tests that require:"
            "\n  - PostgreSQL database with pgvector extension"
            "\n  - ATT&CK data synced with embeddings"
            "\n  - OpenAI API key for query embedding generation"
            "\n\nPlease resolve the issues above before running integration tests."
        )
        raise RuntimeError(error_msg)

    return True


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default event loop policy for session-scoped async fixtures."""
    import asyncio
    return asyncio.get_event_loop_policy()
