#!/usr/bin/env python3
"""CLI script to sync D3FEND data.

Downloads D3FEND data from MISP Galaxy, parses defensive techniques,
generates OpenAI embeddings, validates ATT&CK mappings, and populates the database.

Usage:
    python scripts/sync_d3fend_data.py                  # Full sync with embeddings
    python scripts/sync_d3fend_data.py --no-embeddings  # Skip embedding generation
    python scripts/sync_d3fend_data.py -v               # Verbose output

Requirements:
    - Install dependencies: pip install -e .
    - Set OPENAI_API_KEY in .env file (for embeddings)
    - Database must be running and migrated
    - ATT&CK data should be synced first for FK validation
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


async def main(args: argparse.Namespace) -> int:
    """Main entry point.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("MITRE D3FEND Data Sync")
    logger.info("=" * 60)

    try:
        # Import here to avoid dependency issues in help mode
        from cve_mcp.models.base import AsyncSessionLocal
        from cve_mcp.tasks.sync_d3fend import sync_d3fend_data

        # Run sync with database session
        async with AsyncSessionLocal() as session:
            result = await sync_d3fend_data(
                session=session,
                generate_embeddings=not args.no_embeddings,
                verbose=args.verbose,
            )

        # Print summary
        logger.info("=" * 60)
        print("\nSync complete:")
        print(f"  Tactics:            {result['tactics']}")
        print(f"  Techniques:         {result['techniques']}")
        print(f"  ATT&CK mappings:    {result['attack_mappings']}")
        print(f"  Skipped mappings:   {result['skipped_mappings']}")
        print(f"  Failed embeddings:  {result.get('failed_embeddings', 0)}")
        logger.info("=" * 60)
        logger.info("Sync completed successfully!")

        return 0

    except Exception as e:
        logger.error(f"Sync failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sync D3FEND defensive countermeasures data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                    # Full sync with embeddings
    %(prog)s --no-embeddings    # Skip embedding generation (faster)
    %(prog)s -v                 # Verbose output for debugging

Note:
    ATT&CK data should be synced first to properly validate D3FEND->ATT&CK mappings.
    Run: python scripts/sync_attack_data.py
        """,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Skip semantic embedding generation (faster, no OpenAI API calls)",
    )

    args = parser.parse_args()
    sys.exit(asyncio.run(main(args)))
