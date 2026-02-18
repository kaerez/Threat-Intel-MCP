#!/usr/bin/env python3
"""CLI script to sync OWASP LLM Top 10 data.

Loads OWASP LLM Top 10 v1.1 (2023) vulnerability definitions into the database.

Usage:
    python scripts/sync_owasp_llm_data.py

Requirements:
    - Install dependencies: pip install -e .
    - Database must be running and migrated
"""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


async def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Sync OWASP LLM Top 10 data")
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
    logger.info("OWASP LLM Top 10 Data Sync")
    logger.info("=" * 60)

    try:
        from cve_mcp.services.database import db_service
        from sqlalchemy import text

        # Load data from JSON file
        data_file = Path(__file__).parent / "owasp_llm_data.json"
        if not data_file.exists():
            logger.error(f"Data file not found: {data_file}")
            return 1

        with open(data_file, "r") as f:
            vulnerabilities = json.load(f)

        logger.info(f"Loaded {len(vulnerabilities)} OWASP LLM Top 10 vulnerabilities")

        # Insert into database
        async with db_service.session() as session:
            # Clear existing data
            await session.execute(text("DELETE FROM owasp_llm_top10"))
            logger.info("Cleared existing OWASP LLM Top 10 data")

            # Insert new data
            for vuln in vulnerabilities:
                query = text("""
                    INSERT INTO owasp_llm_top10 (
                        llm_id, name, description,
                        common_examples, prevention_strategies, example_attack_scenarios,
                        related_techniques, url, version, data_last_updated
                    ) VALUES (
                        :llm_id, :name, :description,
                        :common_examples, :prevention_strategies, :example_attack_scenarios,
                        :related_techniques, :url, :version, :data_last_updated
                    )
                """)

                await session.execute(
                    query,
                    {
                        "llm_id": vuln["llm_id"],
                        "name": vuln["name"],
                        "description": vuln["description"],
                        "common_examples": vuln["common_examples"],
                        "prevention_strategies": vuln["prevention_strategies"],
                        "example_attack_scenarios": vuln["example_attack_scenarios"],
                        "related_techniques": json.dumps(vuln["related_techniques"]),
                        "url": vuln["url"],
                        "version": vuln.get("version", "1.1"),
                        "data_last_updated": datetime.utcnow(),
                    },
                )

            await session.commit()
            logger.info(f"Successfully inserted {len(vulnerabilities)} vulnerabilities")

            # Update sync metadata
            await session.execute(
                text("""
                    INSERT INTO sync_metadata (source, last_sync_time, records_synced, last_sync_status)
                    VALUES ('owasp_llm_top10', :last_sync_time, :records_synced, 'success')
                    ON CONFLICT (source) DO UPDATE SET
                        last_sync_time = :last_sync_time,
                        records_synced = :records_synced,
                        last_sync_status = 'success'
                """),
                {
                    "last_sync_time": datetime.utcnow(),
                    "records_synced": len(vulnerabilities),
                },
            )
            await session.commit()

        logger.info("=" * 60)
        logger.info("✓ Sync completed successfully")
        logger.info(f"  Total vulnerabilities: {len(vulnerabilities)}")
        logger.info("=" * 60)

        return 0

    except Exception as e:
        logger.exception(f"Fatal error during sync: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
