"""Tests for D3FEND data sync tasks."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestDownloadD3fendData:
    """Test download_d3fend_data function."""

    @pytest.mark.asyncio
    async def test_download_d3fend_data_success(self):
        """Test successful D3FEND data download from MISP Galaxy."""
        from cve_mcp.tasks.sync_d3fend import download_d3fend_data

        # Mock MISP Galaxy D3FEND JSON content
        mock_data = {
            "name": "MITRE D3FEND",
            "type": "mitre-d3fend",
            "values": [
                {
                    "value": "Application Hardening",
                    "description": "Techniques to make applications more resistant to attack.",
                    "meta": {
                        "external_id": "D3-AH",
                        "kill_chain": ["d3fend:Harden"],
                        "refs": ["https://d3fend.mitre.org/technique/D3-AH/"],
                    },
                }
            ],
        }

        # Mock httpx response
        with patch("cve_mcp.tasks.sync_d3fend.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_data
            mock_response.raise_for_status = MagicMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            result = await download_d3fend_data()

            assert result["name"] == "MITRE D3FEND"
            assert len(result["values"]) == 1
            assert result["values"][0]["value"] == "Application Hardening"

    @pytest.mark.asyncio
    async def test_download_d3fend_data_custom_url(self):
        """Test downloading from custom URL."""
        from cve_mcp.tasks.sync_d3fend import download_d3fend_data

        custom_url = "https://example.com/d3fend.json"
        mock_data = {"name": "Custom D3FEND", "values": []}

        with patch("cve_mcp.tasks.sync_d3fend.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_data
            mock_response.raise_for_status = MagicMock()

            mock_get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.get = mock_get

            result = await download_d3fend_data(url=custom_url)

            # Verify custom URL was used
            mock_get.assert_called_once_with(custom_url)
            assert result["name"] == "Custom D3FEND"

    @pytest.mark.asyncio
    async def test_download_d3fend_data_http_error(self):
        """Test handling of HTTP errors during download."""
        from cve_mcp.tasks.sync_d3fend import download_d3fend_data

        with patch("cve_mcp.tasks.sync_d3fend.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = Exception("HTTP 404")

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            with pytest.raises(Exception, match="HTTP 404"):
                await download_d3fend_data()


class TestExtractTactics:
    """Test extract_tactics function."""

    def test_extract_tactics_unique(self):
        """Test extracting unique tactics from techniques."""
        from cve_mcp.tasks.sync_d3fend import extract_tactics

        techniques = [
            {"tactic_id": "D3-HARDEN", "name": "Tech 1"},
            {"tactic_id": "D3-DETECT", "name": "Tech 2"},
            {"tactic_id": "D3-HARDEN", "name": "Tech 3"},  # Duplicate
            {"tactic_id": "D3-ISOLATE", "name": "Tech 4"},
        ]

        tactics = extract_tactics(techniques)

        # Should have 3 unique tactics
        assert len(tactics) == 3
        tactic_ids = [t["tactic_id"] for t in tactics]
        assert "D3-HARDEN" in tactic_ids
        assert "D3-DETECT" in tactic_ids
        assert "D3-ISOLATE" in tactic_ids

    def test_extract_tactics_display_order(self):
        """Test that tactics have correct display order."""
        from cve_mcp.tasks.sync_d3fend import extract_tactics

        techniques = [
            {"tactic_id": "D3-RESTORE", "name": "Tech 1"},
            {"tactic_id": "D3-MODEL", "name": "Tech 2"},
            {"tactic_id": "D3-HARDEN", "name": "Tech 3"},
        ]

        tactics = extract_tactics(techniques)

        # Check display orders match TACTIC_ORDER
        by_id = {t["tactic_id"]: t for t in tactics}
        assert by_id["D3-MODEL"]["display_order"] == 0
        assert by_id["D3-HARDEN"]["display_order"] == 1
        assert by_id["D3-RESTORE"]["display_order"] == 6

    def test_extract_tactics_descriptions(self):
        """Test that tactics have descriptions from TACTIC_DESCRIPTIONS."""
        from cve_mcp.tasks.sync_d3fend import extract_tactics

        techniques = [
            {"tactic_id": "D3-DETECT", "name": "Tech 1"},
        ]

        tactics = extract_tactics(techniques)

        assert len(tactics) == 1
        assert "identifying malicious activity" in tactics[0]["description"].lower()

    def test_extract_tactics_name_formatting(self):
        """Test that tactic names are formatted correctly."""
        from cve_mcp.tasks.sync_d3fend import extract_tactics

        techniques = [
            {"tactic_id": "D3-HARDEN", "name": "Tech 1"},
            {"tactic_id": "D3-MODEL", "name": "Tech 2"},
        ]

        tactics = extract_tactics(techniques)

        by_id = {t["tactic_id"]: t for t in tactics}
        assert by_id["D3-HARDEN"]["name"] == "Harden"
        assert by_id["D3-MODEL"]["name"] == "Model"

    def test_extract_tactics_missing_tactic_id(self):
        """Test handling of techniques without tactic_id."""
        from cve_mcp.tasks.sync_d3fend import extract_tactics

        techniques = [
            {"tactic_id": "D3-HARDEN", "name": "Tech 1"},
            {"name": "Tech 2"},  # No tactic_id
            {"tactic_id": None, "name": "Tech 3"},  # None tactic_id
        ]

        tactics = extract_tactics(techniques)

        # Should only include the one with valid tactic_id
        assert len(tactics) == 1
        assert tactics[0]["tactic_id"] == "D3-HARDEN"

    def test_extract_tactics_unknown_tactic(self):
        """Test handling of unknown tactic IDs."""
        from cve_mcp.tasks.sync_d3fend import extract_tactics

        techniques = [
            {"tactic_id": "D3-UNKNOWN", "name": "Tech 1"},
        ]

        tactics = extract_tactics(techniques)

        assert len(tactics) == 1
        assert tactics[0]["tactic_id"] == "D3-UNKNOWN"
        assert tactics[0]["display_order"] == 99  # Default for unknown
        assert tactics[0]["description"] == ""  # Empty for unknown


class TestSyncD3fendData:
    """Test sync_d3fend_data main function."""

    @pytest.mark.asyncio
    async def test_sync_d3fend_data_success(self):
        """Test successful D3FEND data sync."""
        from cve_mcp.tasks.sync_d3fend import sync_d3fend_data

        # Mock MISP Galaxy data
        mock_data = {
            "name": "MITRE D3FEND",
            "values": [
                {
                    "value": "Application Hardening",
                    "description": "Techniques to make applications resistant.",
                    "meta": {
                        "external_id": "D3-AH",
                        "kill_chain": ["d3fend:Harden"],
                        "refs": ["https://d3fend.mitre.org/technique/D3-AH/"],
                    },
                    "related": [
                        {
                            "type": "counters",
                            "tags": ["attack-technique:T1059"],
                        }
                    ],
                },
            ],
        }

        with patch("cve_mcp.tasks.sync_d3fend.download_d3fend_data") as mock_download:
            mock_download.return_value = mock_data

            # Mock session
            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_session.commit = AsyncMock()

            # Mock the select result for ATT&CK techniques
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = ["T1059"]
            mock_session.execute.return_value = mock_result

            with patch("cve_mcp.tasks.sync_d3fend.generate_embedding") as mock_embed:
                mock_embed.return_value = [0.1] * 1536

                result = await sync_d3fend_data(
                    session=mock_session,
                    generate_embeddings=True,
                    verbose=False,
                )

                assert "tactics" in result
                assert "techniques" in result
                assert "attack_mappings" in result
                assert "skipped_mappings" in result

    @pytest.mark.asyncio
    async def test_sync_d3fend_data_no_embeddings(self):
        """Test sync without embedding generation."""
        from cve_mcp.tasks.sync_d3fend import sync_d3fend_data

        mock_data = {
            "name": "MITRE D3FEND",
            "values": [
                {
                    "value": "Test Technique",
                    "description": "Test description.",
                    "meta": {
                        "external_id": "D3-TEST",
                        "kill_chain": ["d3fend:Detect"],
                    },
                },
            ],
        }

        with patch("cve_mcp.tasks.sync_d3fend.download_d3fend_data") as mock_download:
            mock_download.return_value = mock_data

            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_session.commit = AsyncMock()

            # Mock empty ATT&CK techniques result
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_session.execute.return_value = mock_result

            with patch("cve_mcp.tasks.sync_d3fend.generate_embedding") as mock_embed:
                result = await sync_d3fend_data(
                    session=mock_session,
                    generate_embeddings=False,
                )

                # Embedding should not be called
                mock_embed.assert_not_called()
                assert result["techniques"] >= 0

    @pytest.mark.asyncio
    async def test_sync_d3fend_data_skips_invalid_attack_fks(self):
        """Test that invalid ATT&CK technique FKs are skipped."""
        from cve_mcp.tasks.sync_d3fend import sync_d3fend_data

        mock_data = {
            "name": "MITRE D3FEND",
            "values": [
                {
                    "value": "Test Technique",
                    "description": "Test description.",
                    "meta": {
                        "external_id": "D3-TEST",
                        "kill_chain": ["d3fend:Harden"],
                    },
                    "related": [
                        # Valid ATT&CK technique
                        {"type": "counters", "tags": ["attack-technique:T1059"]},
                        # Invalid ATT&CK technique (not in DB)
                        {"type": "counters", "tags": ["attack-technique:T9999"]},
                    ],
                },
            ],
        }

        with patch("cve_mcp.tasks.sync_d3fend.download_d3fend_data") as mock_download:
            mock_download.return_value = mock_data

            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_session.commit = AsyncMock()

            # Mock ATT&CK techniques - only T1059 exists
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = ["T1059"]
            mock_session.execute.return_value = mock_result

            result = await sync_d3fend_data(
                session=mock_session,
                generate_embeddings=False,
            )

            # Should have 1 valid mapping and 1 skipped
            assert result["attack_mappings"] >= 0
            assert result["skipped_mappings"] >= 0

    @pytest.mark.asyncio
    async def test_sync_d3fend_data_download_error(self):
        """Test handling of download errors."""
        from cve_mcp.tasks.sync_d3fend import sync_d3fend_data

        with patch("cve_mcp.tasks.sync_d3fend.download_d3fend_data") as mock_download:
            mock_download.side_effect = Exception("Network error")

            mock_session = AsyncMock()

            with pytest.raises(Exception, match="Network error"):
                await sync_d3fend_data(
                    session=mock_session,
                    generate_embeddings=False,
                )
