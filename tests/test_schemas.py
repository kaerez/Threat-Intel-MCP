"""Tests for API schemas."""

import pytest
from cve_mcp.api.schemas import (
    BatchSearchRequest,
    CheckKEVStatusRequest,
    GetCVEDetailsRequest,
    SearchCVERequest,
)
from pydantic import ValidationError


def test_search_cve_request_valid():
    """Test valid SearchCVERequest."""
    request = SearchCVERequest(
        keyword="sql injection",
        cvss_min=7.0,
        severity=["CRITICAL", "HIGH"],
        has_kev=True,
        limit=10,
    )
    assert request.keyword == "sql injection"
    assert request.cvss_min == 7.0
    assert request.severity == ["CRITICAL", "HIGH"]
    assert request.has_kev is True
    assert request.limit == 10


def test_search_cve_request_defaults():
    """Test SearchCVERequest defaults."""
    request = SearchCVERequest()
    assert request.keyword is None
    assert request.cvss_min is None
    assert request.limit == 50
    assert request.offset == 0


def test_search_cve_request_invalid_cvss():
    """Test SearchCVERequest with invalid CVSS score."""
    with pytest.raises(ValidationError):
        SearchCVERequest(cvss_min=15.0)  # Max is 10


def test_get_cve_details_request_valid():
    """Test valid GetCVEDetailsRequest."""
    request = GetCVEDetailsRequest(cve_id="CVE-2024-1234")
    assert request.cve_id == "CVE-2024-1234"
    assert request.include_references is True
    assert request.include_cpe is True
    assert request.include_exploits is True


def test_get_cve_details_request_invalid_pattern():
    """Test GetCVEDetailsRequest with invalid CVE ID pattern."""
    with pytest.raises(ValidationError):
        GetCVEDetailsRequest(cve_id="invalid-cve-id")


def test_check_kev_status_request_valid():
    """Test valid CheckKEVStatusRequest."""
    request = CheckKEVStatusRequest(cve_id="CVE-2021-44228")
    assert request.cve_id == "CVE-2021-44228"


def test_batch_search_request_valid():
    """Test valid BatchSearchRequest."""
    request = BatchSearchRequest(
        cve_ids=["CVE-2024-0001", "CVE-2024-0002"],
        include_kev=True,
        include_epss=True,
    )
    assert len(request.cve_ids) == 2
    assert request.include_kev is True
    assert request.include_epss is True


def test_batch_search_request_too_many():
    """Test BatchSearchRequest with too many CVE IDs."""
    with pytest.raises(ValidationError):
        BatchSearchRequest(cve_ids=["CVE-2024-" + str(i).zfill(4) for i in range(101)])
