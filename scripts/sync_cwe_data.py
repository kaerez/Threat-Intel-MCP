#!/usr/bin/env python3
"""CLI script to sync MITRE CWE data with semantic embeddings.

Downloads CWE XML from MITRE, parses weaknesses/categories/views,
generates OpenAI embeddings, and populates the database.

Usage:
    python scripts/sync_cwe_data.py                  # Full sync with embeddings
    python scripts/sync_cwe_data.py --no-embeddings  # Skip embedding generation
    python scripts/sync_cwe_data.py --force          # Force fresh download

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
    parser = argparse.ArgumentParser(
        description="Sync MITRE CWE data with semantic embeddings"
    )
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Skip semantic embedding generation (faster, no OpenAI API calls)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path.home() / ".cache" / "cve-mcp" / "cwe",
        help="Directory to cache CWE XML (default: ~/.cache/cve-mcp/cwe)",
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
    logger.info("MITRE CWE Data Sync")
    logger.info("=" * 60)

    try:
        # Import here to avoid dependency issues in help mode
        from cve_mcp.tasks.sync_cwe import sync_cwe_full

        # Run sync
        stats = await sync_cwe_full(
            cache_dir=args.cache_dir,
            force_download=args.force,
            generate_embeddings=not args.no_embeddings,
        )

        # Print summary
        logger.info("=" * 60)
        logger.info("Sync Summary:")
        logger.info(f"  Views:             {stats['views']}")
        logger.info(f"  Categories:        {stats['categories']}")
        logger.info(f"  Weaknesses:        {stats['weaknesses']}")
        logger.info(f"  External Mappings: {stats['external_mappings']}")
        logger.info(f"  CAPEC Links:       {stats['capec_links']}")
        logger.info("=" * 60)
        logger.info("Sync completed successfully!")

    except Exception as e:
        logger.error(f"Sync failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
