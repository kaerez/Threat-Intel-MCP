#!/usr/bin/env python3
"""CLI script to sync MITRE ATLAS data with semantic embeddings.

Downloads STIX bundle from MITRE ATLAS repository, parses techniques/tactics/case studies,
generates OpenAI embeddings, and populates the database.

Usage:
    python scripts/sync_atlas_data.py                  # Full sync with embeddings
    python scripts/sync_atlas_data.py --no-embeddings  # Skip embedding generation
    python scripts/sync_atlas_data.py --force          # Force fresh download

Requirements:
    - Install dependencies: pip install -e .
    - Set OPENAI_API_KEY in .env file (for embeddings)
    - Database must be running and migrated
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def setup_logging(verbose: bool = False) -> None:
    """Configure logging.

    Args:
        verbose: Enable verbose (DEBUG) logging
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


async def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Sync MITRE ATLAS data with semantic embeddings")
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Skip semantic embedding generation (faster, no OpenAI API calls)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("/tmp/atlas-bundles"),
        help="Directory to cache STIX bundle (default: /tmp/atlas-bundles)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force fresh download even if cached",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("MITRE ATLAS Data Sync")
    logger.info("=" * 60)

    try:
        # Import here to avoid dependency issues in help mode
        from cve_mcp.tasks.sync_atlas import sync_atlas_data

        # Run sync
        stats = await sync_atlas_data(
            cache_dir=args.cache_dir,
            generate_embeddings=not args.no_embeddings,
            force_download=args.force,
        )

        # Print summary
        logger.info("=" * 60)
        logger.info("Sync Summary:")
        logger.info(f"  Techniques:   {stats['techniques']}")
        logger.info(f"  Tactics:      {stats['tactics']}")
        logger.info(f"  Case Studies: {stats['case_studies']}")
        logger.info("=" * 60)
        logger.info("Sync completed successfully!")

    except Exception as e:
        logger.error(f"Sync failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
