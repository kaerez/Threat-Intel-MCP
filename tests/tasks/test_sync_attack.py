"""Tests for ATT&CK data sync tasks."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestDownloadStixBundle:
    """Test download_stix_bundle function."""

    @pytest.mark.asyncio
    async def test_download_stix_bundle_success(self, tmp_path):
        """Test successful STIX bundle download."""
        from cve_mcp.tasks.sync_attack import download_stix_bundle

        # Mock STIX bundle content
        mock_bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "objects": []
        }

        # Mock httpx response
        with patch("cve_mcp.tasks.sync_attack.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_bundle
            mock_response.raise_for_status = MagicMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)

            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            result_path = await download_stix_bundle(url, tmp_path)

            assert result_path.exists()
            assert result_path.suffix == ".json"

            # Verify downloaded content
            with open(result_path) as f:
                content = json.load(f)
            assert content["type"] == "bundle"

    @pytest.mark.asyncio
    async def test_download_stix_bundle_cached(self, tmp_path):
        """Test that cached bundle is reused."""
        from cve_mcp.tasks.sync_attack import download_stix_bundle

        # Create a cached file
        cached_file = tmp_path / "enterprise-attack.json"
        cached_file.write_text('{"type": "bundle", "cached": true}')

        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

        # Should not make HTTP request if cache exists
        result_path = await download_stix_bundle(url, tmp_path)

        assert result_path == cached_file
        with open(result_path) as f:
            content = json.load(f)
        assert content.get("cached") is True


class TestImportStixBundle:
    """Test import_stix_bundle function."""

    @pytest.mark.asyncio
    async def test_import_stix_bundle_techniques(self, tmp_path):
        """Test importing techniques from STIX bundle."""
        from cve_mcp.tasks.sync_attack import import_stix_bundle

        # Create test STIX bundle
        bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--test1",
                    "created": "2020-03-11T14:26:15.113Z",
                    "modified": "2021-10-17T16:31:52.968Z",
                    "name": "Test Technique",
                    "description": "Test description",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T0001"
                        }
                    ],
                    "x_mitre_platforms": ["Windows"],
                    "x_mitre_version": "1.0",
                }
            ]
        }

        bundle_path = tmp_path / "test-bundle.json"
        bundle_path.write_text(json.dumps(bundle))

        # Mock database session
        with patch("cve_mcp.tasks.sync_attack.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.merge = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_maker.return_value = mock_session

            # Mock embedding generation
            with patch("cve_mcp.tasks.sync_attack.generate_embeddings_batch") as mock_embed:
                mock_embed.return_value = [[0.1] * 1536]

                stats = await import_stix_bundle(
                    bundle_path,
                    framework="enterprise",
                    generate_embeddings=True
                )

                assert stats["techniques"] == 1
                assert stats["groups"] == 0
                assert stats["tactics"] == 0
                assert mock_session.merge.called

    @pytest.mark.asyncio
    async def test_import_stix_bundle_groups(self, tmp_path):
        """Test importing groups from STIX bundle."""
        from cve_mcp.tasks.sync_attack import import_stix_bundle

        bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "objects": [
                {
                    "type": "intrusion-set",
                    "id": "intrusion-set--test1",
                    "created": "2017-05-31T21:31:43.540Z",
                    "modified": "2021-10-12T20:04:52.596Z",
                    "name": "Test APT",
                    "description": "Test APT description",
                    "aliases": ["APT-TEST"],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "G0001"
                        }
                    ],
                }
            ]
        }

        bundle_path = tmp_path / "test-bundle.json"
        bundle_path.write_text(json.dumps(bundle))

        with patch("cve_mcp.tasks.sync_attack.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.merge = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_maker.return_value = mock_session

            with patch("cve_mcp.tasks.sync_attack.generate_embeddings_batch") as mock_embed:
                mock_embed.return_value = [[0.1] * 1536]

                stats = await import_stix_bundle(
                    bundle_path,
                    framework="enterprise",
                    generate_embeddings=True
                )

                assert stats["groups"] == 1

    @pytest.mark.asyncio
    async def test_import_stix_bundle_no_embeddings(self, tmp_path):
        """Test importing without generating embeddings."""
        from cve_mcp.tasks.sync_attack import import_stix_bundle

        bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--test1",
                    "created": "2020-03-11T14:26:15.113Z",
                    "modified": "2021-10-17T16:31:52.968Z",
                    "name": "Test Technique",
                    "description": "Test description",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T0001"
                        }
                    ],
                }
            ]
        }

        bundle_path = tmp_path / "test-bundle.json"
        bundle_path.write_text(json.dumps(bundle))

        with patch("cve_mcp.tasks.sync_attack.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.merge = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_maker.return_value = mock_session

            with patch("cve_mcp.tasks.sync_attack.generate_embeddings_batch") as mock_embed:
                stats = await import_stix_bundle(
                    bundle_path,
                    framework="enterprise",
                    generate_embeddings=False
                )

                # Should not call embedding generation
                mock_embed.assert_not_called()


class TestProcessRelationships:
    """Test process_relationships function."""

    @pytest.mark.asyncio
    async def test_process_relationships_group_techniques(self):
        """Test processing group->technique relationships."""
        from cve_mcp.tasks.sync_attack import process_relationships

        relationships = [
            {
                "type": "relationship",
                "id": "relationship--test1",
                "created": "2020-03-11T14:26:15.113Z",
                "modified": "2021-10-17T16:31:52.968Z",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--group1",
                "target_ref": "attack-pattern--tech1",
            }
        ]

        # Mock objects with STIX ID -> external ID mapping
        stix_id_map = {
            "intrusion-set--group1": ("group", "G0001"),
            "attack-pattern--tech1": ("technique", "T1566"),
        }

        with patch("cve_mcp.tasks.sync_attack.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            # Mock query results
            mock_group = MagicMock()
            mock_group.techniques_used = []
            mock_result = MagicMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=mock_group)
            mock_session.execute = AsyncMock(return_value=mock_result)

            mock_session_maker.return_value = mock_session

            await process_relationships(relationships, stix_id_map)

            # Should add technique to group
            assert "T1566" in mock_group.techniques_used


class TestSyncAttackData:
    """Test sync_attack_data main function."""

    @pytest.mark.asyncio
    async def test_sync_attack_data_all_frameworks(self, tmp_path):
        """Test syncing all ATT&CK frameworks."""
        from cve_mcp.tasks.sync_attack import sync_attack_data

        with patch("cve_mcp.tasks.sync_attack.download_stix_bundle") as mock_download:
            with patch("cve_mcp.tasks.sync_attack.import_stix_bundle") as mock_import:
                with patch("cve_mcp.tasks.sync_attack.process_relationships") as mock_process:
                    # Mock download paths
                    mock_download.return_value = tmp_path / "test.json"
                    (tmp_path / "test.json").write_text('{"type": "bundle", "objects": []}')

                    # Mock import stats
                    mock_import.return_value = {
                        "techniques": 10,
                        "groups": 5,
                        "tactics": 2,
                        "software": 3,
                        "mitigations": 1,
                    }

                    stats = await sync_attack_data(tmp_path, generate_embeddings=True)

                    # Should download 3 frameworks (enterprise, mobile, ics)
                    assert mock_download.call_count == 3
                    assert mock_import.call_count == 3

                    # Stats should be aggregated
                    assert stats["techniques"] == 30  # 10 * 3 frameworks
                    assert stats["groups"] == 15

    @pytest.mark.asyncio
    async def test_sync_attack_data_no_embeddings(self, tmp_path):
        """Test syncing without embeddings."""
        from cve_mcp.tasks.sync_attack import sync_attack_data

        with patch("cve_mcp.tasks.sync_attack.download_stix_bundle") as mock_download:
            with patch("cve_mcp.tasks.sync_attack.import_stix_bundle") as mock_import:
                with patch("cve_mcp.tasks.sync_attack.process_relationships"):
                    mock_download.return_value = tmp_path / "test.json"
                    (tmp_path / "test.json").write_text('{"type": "bundle", "objects": []}')
                    mock_import.return_value = {"techniques": 0, "groups": 0, "tactics": 0, "software": 0, "mitigations": 0}

                    await sync_attack_data(tmp_path, generate_embeddings=False)

                    # Verify generate_embeddings=False passed through
                    assert mock_import.call_count == 3  # Three frameworks
                    for call in mock_import.call_args_list:
                        # import_stix_bundle(bundle_path, framework, generate_embeddings)
                        # Third argument should be False
                        assert call[0][2] is False or call.kwargs.get("generate_embeddings") is False
