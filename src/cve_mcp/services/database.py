"""Database service for CVE MCP server."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from packaging.version import InvalidVersion, Version
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models import (
    CISAKEV,
    CVE,
    CVECPEMapping,
    CVEReference,
    CWEData,
    EPSSScore,
    ExploitReference,
    QueryAuditLog,
    SyncMetadata,
)
from cve_mcp.models.base import AsyncSessionLocal


class DatabaseService:
    """Database service for CVE queries and operations."""

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session."""
        async with AsyncSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def search_cves(
        self,
        session: AsyncSession,
        keyword: str | None = None,
        cvss_min: float | None = None,
        cvss_max: float | None = None,
        severity: list[str] | None = None,
        has_kev: bool | None = None,
        has_exploit: bool | None = None,
        epss_min: float | None = None,
        published_after: datetime | None = None,
        published_before: datetime | None = None,
        cwe_ids: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Search CVEs with filters."""
        # Build query
        query = (
            select(
                CVE.cve_id,
                CVE.published_date,
                CVE.cvss_v3_score,
                CVE.cvss_v3_severity,
                CVE.description,
                CVE.has_kev_entry,
                CVE.has_exploit,
                CISAKEV.date_added.label("kev_date_added"),
                EPSSScore.epss_score,
                func.count(ExploitReference.id.distinct()).label("exploit_count"),
            )
            .outerjoin(CISAKEV, CVE.cve_id == CISAKEV.cve_id)
            .outerjoin(EPSSScore, CVE.cve_id == EPSSScore.cve_id)
            .outerjoin(ExploitReference, CVE.cve_id == ExploitReference.cve_id)
            .group_by(
                CVE.cve_id,
                CISAKEV.date_added,
                EPSSScore.epss_score,
            )
        )

        # Apply filters
        if keyword:
            # Use full-text search when tsvector is populated, with ILIKE fallback
            query = query.where(
                or_(
                    CVE.description_vector.op("@@")(func.plainto_tsquery("english", keyword)),
                    and_(
                        CVE.description_vector.is_(None),
                        CVE.description.ilike(f"%{keyword}%"),
                    ),
                )
            )

        if cvss_min is not None:
            query = query.where(CVE.cvss_v3_score >= cvss_min)

        if cvss_max is not None:
            query = query.where(CVE.cvss_v3_score <= cvss_max)

        if severity:
            query = query.where(CVE.cvss_v3_severity.in_(severity))

        if has_kev is not None:
            query = query.where(CVE.has_kev_entry == has_kev)

        if has_exploit is not None:
            query = query.where(CVE.has_exploit == has_exploit)

        if epss_min is not None:
            query = query.where(EPSSScore.epss_score >= epss_min)

        if published_after:
            query = query.where(CVE.published_date >= published_after)

        if published_before:
            query = query.where(CVE.published_date <= published_before)

        if cwe_ids:
            query = query.where(CVE.cwe_ids.overlap(cwe_ids))

        # Get total count (without limit/offset)
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await session.execute(count_query)
        total_count = total_result.scalar() or 0

        # Apply ordering and pagination
        query = query.order_by(CVE.cvss_v3_score.desc().nulls_last(), CVE.published_date.desc())
        query = query.limit(limit).offset(offset)

        # Execute query
        result = await session.execute(query)
        rows = result.all()

        cves = []
        for row in rows:
            cves.append({
                "cve_id": row.cve_id,
                "published_date": row.published_date.isoformat() if row.published_date else None,
                "cvss_v3_score": float(row.cvss_v3_score) if row.cvss_v3_score else None,
                "cvss_v3_severity": row.cvss_v3_severity,
                "description": (row.description or "")[:500] + ("..." if row.description and len(row.description) > 500 else ""),
                "has_kev_entry": row.has_kev_entry,
                "has_exploit": row.has_exploit,
                "kev_date_added": row.kev_date_added.isoformat() if row.kev_date_added else None,
                "epss_score": float(row.epss_score) if row.epss_score else None,
                "exploit_count": row.exploit_count,
            })

        return cves, total_count

    async def get_cve_details(
        self,
        session: AsyncSession,
        cve_id: str,
        include_references: bool = True,
        include_cpe: bool = True,
        include_exploits: bool = True,
    ) -> dict[str, Any] | None:
        """Get complete CVE details."""
        # Get CVE record
        result = await session.execute(select(CVE).where(CVE.cve_id == cve_id))
        cve = result.scalar_one_or_none()

        if not cve:
            return None

        # Build response
        data: dict[str, Any] = {
            "cve_id": cve.cve_id,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "last_modified_date": cve.last_modified_date.isoformat() if cve.last_modified_date else None,
            "description": cve.description,
            "cwe_ids": cve.cwe_ids or [],
        }

        # CVSS v3 data
        if cve.cvss_v3_score:
            data["cvss_v3"] = {
                "score": float(cve.cvss_v3_score),
                "vector": cve.cvss_v3_vector,
                "severity": cve.cvss_v3_severity,
                "exploitability_score": float(cve.cvss_v3_exploitability_score) if cve.cvss_v3_exploitability_score else None,
                "impact_score": float(cve.cvss_v3_impact_score) if cve.cvss_v3_impact_score else None,
            }

        # CVSS v2 data (legacy)
        if cve.cvss_v2_score:
            data["cvss_v2"] = {
                "score": float(cve.cvss_v2_score),
                "vector": cve.cvss_v2_vector,
                "severity": cve.cvss_v2_severity,
            }

        # KEV status
        kev_result = await session.execute(select(CISAKEV).where(CISAKEV.cve_id == cve_id))
        kev = kev_result.scalar_one_or_none()
        if kev:
            data["kev_status"] = {
                "in_kev": True,
                "date_added": kev.date_added.isoformat() if kev.date_added else None,
                "vulnerability_name": kev.vulnerability_name,
                "required_action": kev.required_action,
                "due_date": kev.due_date.isoformat() if kev.due_date else None,
                "known_ransomware_use": kev.known_ransomware_use,
                "notes": kev.notes,
            }
        else:
            data["kev_status"] = {"in_kev": False}

        # EPSS score
        epss_result = await session.execute(select(EPSSScore).where(EPSSScore.cve_id == cve_id))
        epss = epss_result.scalar_one_or_none()
        if epss:
            data["epss"] = {
                "score": float(epss.epss_score),
                "percentile": float(epss.epss_percentile),
                "date_scored": epss.date_scored.isoformat() if epss.date_scored else None,
            }

        # References
        if include_references:
            refs_result = await session.execute(
                select(CVEReference).where(CVEReference.cve_id == cve_id)
            )
            refs = refs_result.scalars().all()
            data["references"] = [
                {
                    "url": ref.url,
                    "source": ref.source,
                    "tags": ref.tags or [],
                }
                for ref in refs
            ]

        # CPE mappings
        if include_cpe:
            cpe_result = await session.execute(
                select(CVECPEMapping).where(CVECPEMapping.cve_id == cve_id)
            )
            cpes = cpe_result.scalars().all()
            data["cpe_mappings"] = [
                {
                    "cpe_uri": cpe.cpe_uri,
                    "vendor": cpe.cpe_vendor,
                    "product": cpe.cpe_product,
                    "version": cpe.cpe_version,
                    "version_start": cpe.version_start,
                    "version_start_type": cpe.version_start_type,
                    "version_end": cpe.version_end,
                    "version_end_type": cpe.version_end_type,
                    "vulnerable": cpe.vulnerable,
                }
                for cpe in cpes
            ]

        # Exploits
        if include_exploits:
            exploits_result = await session.execute(
                select(ExploitReference).where(ExploitReference.cve_id == cve_id)
            )
            exploits = exploits_result.scalars().all()
            data["exploits"] = [
                {
                    "type": exp.exploit_type,
                    "url": exp.exploit_url,
                    "title": exp.exploit_title,
                    "maturity": exp.exploit_maturity,
                    "verified": exp.verified,
                    "requires_authentication": exp.requires_authentication,
                    "requires_user_interaction": exp.requires_user_interaction,
                    "exploit_complexity": exp.exploit_complexity,
                    "published_date": exp.exploit_published_date.isoformat() if exp.exploit_published_date else None,
                }
                for exp in exploits
            ]

        return data

    async def check_kev_status(self, session: AsyncSession, cve_id: str) -> dict[str, Any]:
        """Check if CVE is in CISA KEV catalog."""
        result = await session.execute(select(CISAKEV).where(CISAKEV.cve_id == cve_id))
        kev = result.scalar_one_or_none()

        if not kev:
            return {"cve_id": cve_id, "in_kev": False}

        return {
            "cve_id": cve_id,
            "in_kev": True,
            "kev_details": {
                "date_added": kev.date_added.isoformat() if kev.date_added else None,
                "vulnerability_name": kev.vulnerability_name,
                "short_description": kev.short_description,
                "required_action": kev.required_action,
                "due_date": kev.due_date.isoformat() if kev.due_date else None,
                "known_ransomware_use": kev.known_ransomware_use,
                "notes": kev.notes,
            },
        }

    async def get_epss_score(self, session: AsyncSession, cve_id: str) -> dict[str, Any]:
        """Get EPSS score for a CVE."""
        result = await session.execute(select(EPSSScore).where(EPSSScore.cve_id == cve_id))
        epss = result.scalar_one_or_none()

        if not epss:
            return {"cve_id": cve_id, "found": False}

        percentile = float(epss.epss_percentile)
        interpretation = f"Top {int((1 - percentile) * 100)}% most likely to be exploited in next 30 days"

        return {
            "cve_id": cve_id,
            "found": True,
            "epss_score": float(epss.epss_score),
            "epss_percentile": percentile,
            "date_scored": epss.date_scored.isoformat() if epss.date_scored else None,
            "interpretation": interpretation,
        }

    def _compare_versions(self, cpe_version: str | None, target_version: str, operator: str) -> bool:
        """Compare semantic versions using the specified operator.

        Args:
            cpe_version: The version from the CPE mapping (can be None or empty)
            target_version: The version to compare against
            operator: One of 'eq', 'lt', 'lte', 'gt', 'gte'

        Returns:
            True if the comparison matches, False otherwise
        """
        if not cpe_version:
            return False

        try:
            cpe_ver = Version(cpe_version)
            target_ver = Version(target_version)
        except InvalidVersion:
            # If version parsing fails, fall back to string comparison
            if operator == "eq":
                return cpe_version == target_version
            # For other operators with invalid versions, return False
            return False

        if operator == "eq":
            return cpe_ver == target_ver
        elif operator == "lt":
            return cpe_ver < target_ver
        elif operator == "lte":
            return cpe_ver <= target_ver
        elif operator == "gt":
            return cpe_ver > target_ver
        elif operator == "gte":
            return cpe_ver >= target_ver
        else:
            return False

    async def search_by_product(
        self,
        session: AsyncSession,
        product_name: str,
        vendor: str | None = None,
        version: str | None = None,
        version_operator: str | None = None,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], int]:
        """Find CVEs affecting a specific product."""
        # Build query
        query = (
            select(
                CVE.cve_id,
                CVE.cvss_v3_score,
                CVE.cvss_v3_severity,
                CVE.description,
                CVE.has_kev_entry,
                CVE.has_exploit,
                CVECPEMapping.cpe_uri,
                CVECPEMapping.cpe_vendor,
                CVECPEMapping.cpe_product,
                CVECPEMapping.cpe_version,
                CVECPEMapping.vulnerable,
            )
            .join(CVECPEMapping, CVE.cve_id == CVECPEMapping.cve_id)
            .where(CVECPEMapping.cpe_product.ilike(f"%{product_name}%"))
        )

        if vendor:
            query = query.where(CVECPEMapping.cpe_vendor.ilike(f"%{vendor}%"))

        if version and not version_operator:
            # Simple exact version matching when no operator specified (backward compatibility)
            query = query.where(CVECPEMapping.cpe_version == version)

        # Apply ordering (but not limit yet if we need version filtering)
        query = query.order_by(CVE.cvss_v3_score.desc().nulls_last())

        # If version operator is specified, we need to filter in Python after fetching
        if version and version_operator:
            # Fetch all results for version comparison
            result = await session.execute(query)
            all_rows = result.all()

            # Filter by version comparison
            filtered_rows = []
            for row in all_rows:
                if self._compare_versions(row.cpe_version, version, version_operator):
                    filtered_rows.append(row)

            rows = filtered_rows[:limit]
            total_count = len(filtered_rows)
        else:
            # Original path: apply limit at SQL level
            # Get count
            count_query = select(func.count(func.distinct(CVE.cve_id))).select_from(query.subquery())
            total_result = await session.execute(count_query)
            total_count = total_result.scalar() or 0

            # Apply limit
            query = query.limit(limit)
            result = await session.execute(query)
            rows = list(result.all())

        # Group by CVE
        cves_dict: dict[str, dict] = {}
        for row in rows:
            if row.cve_id not in cves_dict:
                cves_dict[row.cve_id] = {
                    "cve_id": row.cve_id,
                    "cvss_v3_score": float(row.cvss_v3_score) if row.cvss_v3_score else None,
                    "cvss_v3_severity": row.cvss_v3_severity,
                    "description": (row.description or "")[:300] + ("..." if row.description and len(row.description) > 300 else ""),
                    "has_kev_entry": row.has_kev_entry,
                    "has_exploit": row.has_exploit,
                    "cpe_matches": [],
                }
            cves_dict[row.cve_id]["cpe_matches"].append({
                "cpe_uri": row.cpe_uri,
                "vendor": row.cpe_vendor,
                "product": row.cpe_product,
                "version": row.cpe_version,
                "vulnerable": row.vulnerable,
            })

        return list(cves_dict.values()), total_count

    async def get_exploits(
        self,
        session: AsyncSession,
        cve_id: str,
        verified_only: bool = False,
    ) -> dict[str, Any]:
        """Get exploit references for a CVE."""
        query = select(ExploitReference).where(ExploitReference.cve_id == cve_id)

        if verified_only:
            query = query.where(ExploitReference.verified == True)  # noqa: E712

        result = await session.execute(query)
        exploits = result.scalars().all()

        functional_count = sum(1 for e in exploits if e.exploit_maturity == "functional")

        return {
            "cve_id": cve_id,
            "exploits": [
                {
                    "type": exp.exploit_type,
                    "url": exp.exploit_url,
                    "title": exp.exploit_title,
                    "description": exp.exploit_description,
                    "maturity": exp.exploit_maturity,
                    "verified": exp.verified,
                    "requires_authentication": exp.requires_authentication,
                    "requires_user_interaction": exp.requires_user_interaction,
                    "exploit_complexity": exp.exploit_complexity,
                    "exploitdb_id": exp.exploitdb_id,
                    "metasploit_module": exp.metasploit_module,
                    "github_repo": exp.github_repo,
                    "published_date": exp.exploit_published_date.isoformat() if exp.exploit_published_date else None,
                }
                for exp in exploits
            ],
            "total_exploits": len(exploits),
            "functional_exploits": functional_count,
        }

    async def get_cwe_details(self, session: AsyncSession, cwe_id: str) -> dict[str, Any] | None:
        """Get CWE weakness information."""
        result = await session.execute(select(CWEData).where(CWEData.cwe_id == cwe_id))
        cwe = result.scalar_one_or_none()

        if not cwe:
            return None

        return {
            "cwe_id": cwe.cwe_id,
            "name": cwe.name,
            "description": cwe.description,
            "extended_description": cwe.extended_description,
            "weakness_type": cwe.weakness_type,
            "abstraction": cwe.abstraction,
            "parent_cwe_ids": cwe.parent_cwe_ids or [],
            "child_cwe_ids": cwe.child_cwe_ids or [],
            "related_attack_patterns": cwe.related_attack_patterns or [],
        }

    async def batch_search(
        self,
        session: AsyncSession,
        cve_ids: list[str],
        include_kev: bool = True,
        include_epss: bool = True,
    ) -> dict[str, Any]:
        """Get details for multiple CVEs."""
        query = select(
            CVE.cve_id,
            CVE.cvss_v3_score,
            CVE.cvss_v3_severity,
            CVE.has_kev_entry,
            CVE.has_exploit,
        ).where(CVE.cve_id.in_(cve_ids))

        if include_kev:
            query = query.add_columns(CISAKEV.date_added.label("kev_date_added"))
            query = query.outerjoin(CISAKEV, CVE.cve_id == CISAKEV.cve_id)

        if include_epss:
            query = query.add_columns(EPSSScore.epss_score)
            query = query.outerjoin(EPSSScore, CVE.cve_id == EPSSScore.cve_id)

        result = await session.execute(query)
        rows = result.all()

        found_ids = set()
        cves = []
        for row in rows:
            found_ids.add(row.cve_id)
            cve_data = {
                "cve_id": row.cve_id,
                "cvss_v3_score": float(row.cvss_v3_score) if row.cvss_v3_score else None,
                "cvss_v3_severity": row.cvss_v3_severity,
                "has_kev_entry": row.has_kev_entry,
                "has_exploit": row.has_exploit,
            }
            if include_kev and hasattr(row, "kev_date_added"):
                cve_data["kev_date_added"] = row.kev_date_added.isoformat() if row.kev_date_added else None
            if include_epss and hasattr(row, "epss_score"):
                cve_data["epss_score"] = float(row.epss_score) if row.epss_score else None
            cves.append(cve_data)

        not_found = [cve_id for cve_id in cve_ids if cve_id not in found_ids]

        return {
            "cves": cves,
            "requested": len(cve_ids),
            "found": len(cves),
            "not_found": not_found,
        }

    async def get_sync_metadata(self, session: AsyncSession) -> dict[str, Any]:
        """Get sync metadata for all sources."""
        result = await session.execute(select(SyncMetadata))
        metadata = result.scalars().all()

        return {
            m.source: {
                "last_sync": m.last_sync_time.isoformat() if m.last_sync_time else None,
                "status": m.last_sync_status,
                "records_synced": m.records_synced,
                "error": m.error_message,
            }
            for m in metadata
        }

    async def get_database_stats(self, session: AsyncSession) -> dict[str, Any]:
        """Get database statistics."""
        cve_count = await session.execute(select(func.count(CVE.cve_id)))
        kev_count = await session.execute(select(func.count(CISAKEV.cve_id)))
        epss_count = await session.execute(select(func.count(EPSSScore.cve_id)))
        exploit_count = await session.execute(select(func.count(ExploitReference.id)))

        return {
            "cve_count": cve_count.scalar() or 0,
            "kev_count": kev_count.scalar() or 0,
            "epss_count": epss_count.scalar() or 0,
            "exploit_count": exploit_count.scalar() or 0,
        }

    async def log_query(
        self,
        session: AsyncSession,
        tool_name: str,
        query_params: dict[str, Any],
        result_count: int,
        query_time_ms: int,
        cache_hit: bool = False,
        client_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Log a query for audit purposes."""
        log_entry = QueryAuditLog(
            tool_name=tool_name,
            query_params=query_params,
            result_count=result_count,
            match_found=result_count > 0,
            query_time_ms=query_time_ms,
            cache_hit=cache_hit,
            client_id=client_id,
            request_id=request_id,
        )
        session.add(log_entry)


# Global database service instance
db_service = DatabaseService()
