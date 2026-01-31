"""Tests for version comparison logic in DatabaseService."""

import pytest
from cve_mcp.services.database import DatabaseService


@pytest.fixture
def db_service():
    """Create a DatabaseService instance for testing."""
    return DatabaseService()


class TestVersionComparison:
    """Tests for the _compare_versions helper method."""

    def test_compare_versions_eq_match(self, db_service):
        """Test equality operator with matching versions."""
        assert db_service._compare_versions("2.4.50", "2.4.50", "eq") is True

    def test_compare_versions_eq_no_match(self, db_service):
        """Test equality operator with non-matching versions."""
        assert db_service._compare_versions("2.4.49", "2.4.50", "eq") is False

    def test_compare_versions_lt(self, db_service):
        """Test less than operator."""
        assert db_service._compare_versions("2.4.49", "2.4.50", "lt") is True
        assert db_service._compare_versions("2.4.50", "2.4.50", "lt") is False
        assert db_service._compare_versions("2.4.51", "2.4.50", "lt") is False

    def test_compare_versions_lte(self, db_service):
        """Test less than or equal operator."""
        assert db_service._compare_versions("2.4.49", "2.4.50", "lte") is True
        assert db_service._compare_versions("2.4.50", "2.4.50", "lte") is True
        assert db_service._compare_versions("2.4.51", "2.4.50", "lte") is False

    def test_compare_versions_gt(self, db_service):
        """Test greater than operator."""
        assert db_service._compare_versions("2.4.51", "2.4.50", "gt") is True
        assert db_service._compare_versions("2.4.50", "2.4.50", "gt") is False
        assert db_service._compare_versions("2.4.49", "2.4.50", "gt") is False

    def test_compare_versions_gte(self, db_service):
        """Test greater than or equal operator."""
        assert db_service._compare_versions("2.4.51", "2.4.50", "gte") is True
        assert db_service._compare_versions("2.4.50", "2.4.50", "gte") is True
        assert db_service._compare_versions("2.4.49", "2.4.50", "gte") is False

    def test_compare_versions_none_cpe_version(self, db_service):
        """Test with None CPE version returns False."""
        assert db_service._compare_versions(None, "2.4.50", "eq") is False
        assert db_service._compare_versions(None, "2.4.50", "lt") is False

    def test_compare_versions_empty_cpe_version(self, db_service):
        """Test with empty string CPE version returns False."""
        assert db_service._compare_versions("", "2.4.50", "eq") is False

    def test_compare_versions_invalid_version_eq_fallback(self, db_service):
        """Test invalid version falls back to string comparison for eq."""
        # Invalid semantic versions should use string comparison for eq
        assert db_service._compare_versions("2.4.x", "2.4.x", "eq") is True
        assert db_service._compare_versions("2.4.x", "2.4.y", "eq") is False

    def test_compare_versions_invalid_version_non_eq_returns_false(self, db_service):
        """Test invalid version returns False for non-eq operators."""
        assert db_service._compare_versions("2.4.x", "2.4.50", "lt") is False
        assert db_service._compare_versions("invalid", "2.4.50", "gt") is False

    def test_compare_versions_invalid_operator(self, db_service):
        """Test invalid operator returns False."""
        assert db_service._compare_versions("2.4.50", "2.4.50", "invalid") is False

    def test_compare_versions_semantic_ordering(self, db_service):
        """Test that semantic versioning correctly orders multi-part versions."""
        # 2.4.10 > 2.4.9 (not "2.4.10" < "2.4.9" as strings)
        assert db_service._compare_versions("2.4.10", "2.4.9", "gt") is True
        assert db_service._compare_versions("2.4.9", "2.4.10", "lt") is True

        # 2.10.0 > 2.9.0
        assert db_service._compare_versions("2.10.0", "2.9.0", "gt") is True

        # 3.0.0 > 2.99.99
        assert db_service._compare_versions("3.0.0", "2.99.99", "gt") is True
