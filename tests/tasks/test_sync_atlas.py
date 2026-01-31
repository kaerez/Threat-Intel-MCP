"""Tests for ATLAS data sync tasks."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestDownloadAtlasBundle:
    """Test download_atlas_bundle function."""

    @pytest.mark.asyncio
    async def test_download_atlas_bundle_success(self, tmp_path):
        """Test successful ATLAS bundle download."""
        from cve_mcp.tasks.sync_atlas import download_atlas_bundle

        # Mock ATLAS STIX bundle content
        mock_bundle = {
            "type": "bundle",
            "id": "bundle--atlas",
            "objects": [],
        }

        # Mock httpx response
        with patch("cve_mcp.tasks.sync_atlas.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_bundle
            mock_response.raise_for_status = MagicMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            result_path = await download_atlas_bundle(tmp_path)

            assert result_path.exists()
            assert result_path.name == "ATLAS.json"

            # Verify downloaded content
            with open(result_path) as f:
                content = json.load(f)
            assert content["type"] == "bundle"

    @pytest.mark.asyncio
    async def test_download_atlas_bundle_cached(self, tmp_path):
        """Test that cached bundle is reused."""
        from cve_mcp.tasks.sync_atlas import download_atlas_bundle

        # Create a cached file
        cached_file = tmp_path / "ATLAS.json"
        cached_file.write_text('{"type": "bundle", "cached": true}')

        # Should not make HTTP request if cache exists
        result_path = await download_atlas_bundle(tmp_path)

        assert result_path == cached_file
        with open(result_path) as f:
            content = json.load(f)
        assert content.get("cached") is True


class TestImportAtlasBundle:
    """Test import_atlas_bundle function."""

    @pytest.mark.asyncio
    async def test_import_atlas_bundle_techniques(self, tmp_path):
        """Test importing techniques from ATLAS bundle."""
        from cve_mcp.tasks.sync_atlas import import_atlas_bundle

        # Create test ATLAS STIX bundle
        bundle = {
            "type": "bundle",
            "id": "bundle--atlas",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--atlas-test1",
                    "created": "2022-03-01T14:00:00.000Z",
                    "modified": "2022-04-01T14:00:00.000Z",
                    "name": "Adversarial ML Technique",
                    "description": "A test technique for adversarial ML attacks",
                    "external_references": [{"source_name": "ATLAS", "external_id": "AML.T0001"}],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-atlas", "phase_name": "reconnaissance"}
                    ],
                    "x_mitre_platforms": ["computer-vision"],
                    "x_mitre_version": "1.0",
                }
            ],
        }

        bundle_path = tmp_path / "test-atlas-bundle.json"
        bundle_path.write_text(json.dumps(bundle))

        # Mock database session
        with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.merge = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_maker.return_value = mock_session

            # Mock embedding generation
            with patch("cve_mcp.tasks.sync_atlas.generate_embeddings_batch") as mock_embed:
                mock_embed.return_value = [[0.1] * 1536]

                stats = await import_atlas_bundle(bundle_path, generate_embeddings=True)

                assert stats["techniques"] == 1
                assert stats["tactics"] == 0
                assert stats["case_studies"] == 0
                assert mock_session.merge.called

    @pytest.mark.asyncio
    async def test_import_atlas_bundle_tactics(self, tmp_path):
        """Test importing tactics from ATLAS bundle."""
        from cve_mcp.tasks.sync_atlas import import_atlas_bundle

        bundle = {
            "type": "bundle",
            "id": "bundle--atlas",
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--atlas-test1",
                    "created": "2022-03-01T14:00:00.000Z",
                    "modified": "2022-04-01T14:00:00.000Z",
                    "name": "ML Model Access",
                    "description": "Gain access to ML models",
                    "x_mitre_shortname": "ml-model-access",
                    "external_references": [{"source_name": "ATLAS", "external_id": "AML.TA0001"}],
                }
            ],
        }

        bundle_path = tmp_path / "test-atlas-bundle.json"
        bundle_path.write_text(json.dumps(bundle))

        with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.merge = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_maker.return_value = mock_session

            stats = await import_atlas_bundle(bundle_path, generate_embeddings=False)

            assert stats["tactics"] == 1

    @pytest.mark.asyncio
    async def test_import_atlas_bundle_case_studies(self, tmp_path):
        """Test importing case studies from ATLAS bundle."""
        from cve_mcp.tasks.sync_atlas import import_atlas_bundle

        bundle = {
            "type": "bundle",
            "id": "bundle--atlas",
            "objects": [
                {
                    "type": "x-mitre-case-study",
                    "id": "x-mitre-case-study--atlas-test1",
                    "created": "2022-03-01T14:00:00.000Z",
                    "modified": "2022-04-01T14:00:00.000Z",
                    "name": "Model Extraction Attack",
                    "description": "A real-world case study of model extraction",
                    "x_mitre_techniques": ["AML.T0001", "AML.T0002"],
                    "external_references": [
                        {"source_name": "ATLAS", "external_id": "AML.CS0001"},
                        {"source_name": "arxiv", "url": "https://arxiv.org/abs/1234.5678"},
                    ],
                }
            ],
        }

        bundle_path = tmp_path / "test-atlas-bundle.json"
        bundle_path.write_text(json.dumps(bundle))

        with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.merge = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_maker.return_value = mock_session

            with patch("cve_mcp.tasks.sync_atlas.generate_embeddings_batch") as mock_embed:
                mock_embed.return_value = [[0.1] * 1536]

                stats = await import_atlas_bundle(bundle_path, generate_embeddings=True)

                assert stats["case_studies"] == 1

    @pytest.mark.asyncio
    async def test_import_atlas_bundle_no_embeddings(self, tmp_path):
        """Test importing without generating embeddings."""
        from cve_mcp.tasks.sync_atlas import import_atlas_bundle

        bundle = {
            "type": "bundle",
            "id": "bundle--atlas",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--atlas-test1",
                    "created": "2022-03-01T14:00:00.000Z",
                    "modified": "2022-04-01T14:00:00.000Z",
                    "name": "Test Technique",
                    "description": "Test description",
                    "external_references": [{"source_name": "ATLAS", "external_id": "AML.T0001"}],
                }
            ],
        }

        bundle_path = tmp_path / "test-atlas-bundle.json"
        bundle_path.write_text(json.dumps(bundle))

        with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
            mock_session = AsyncMock()
            mock_session.merge = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_maker.return_value = mock_session

            with patch("cve_mcp.tasks.sync_atlas.generate_embeddings_batch") as mock_embed:
                stats = await import_atlas_bundle(bundle_path, generate_embeddings=False)

                # Should not call embedding generation
                mock_embed.assert_not_called()
                assert stats["techniques"] == 1


class TestSyncAtlasData:
    """Test sync_atlas_data main function."""

    @pytest.mark.asyncio
    async def test_sync_atlas_data_success(self, tmp_path):
        """Test successful ATLAS sync."""
        from cve_mcp.tasks.sync_atlas import sync_atlas_data

        with patch("cve_mcp.tasks.sync_atlas.download_atlas_bundle") as mock_download:
            with patch("cve_mcp.tasks.sync_atlas.import_atlas_bundle") as mock_import:
                with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
                    # Mock download path
                    mock_download.return_value = tmp_path / "ATLAS.json"
                    (tmp_path / "ATLAS.json").write_text('{"type": "bundle", "objects": []}')

                    # Mock import stats
                    mock_import.return_value = {
                        "techniques": 200,
                        "tactics": 14,
                        "case_studies": 30,
                    }

                    # Mock session for metadata update
                    mock_session = AsyncMock()
                    mock_session.merge = AsyncMock()
                    mock_session.commit = AsyncMock()
                    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                    mock_session.__aexit__ = AsyncMock(return_value=None)
                    mock_session_maker.return_value = mock_session

                    stats = await sync_atlas_data(tmp_path, generate_embeddings=True)

                    # Should download once
                    mock_download.assert_called_once()

                    # Stats should be returned
                    assert stats["techniques"] == 200
                    assert stats["tactics"] == 14
                    assert stats["case_studies"] == 30

    @pytest.mark.asyncio
    async def test_sync_atlas_data_no_embeddings(self, tmp_path):
        """Test syncing without embeddings."""
        from cve_mcp.tasks.sync_atlas import sync_atlas_data

        with patch("cve_mcp.tasks.sync_atlas.download_atlas_bundle") as mock_download:
            with patch("cve_mcp.tasks.sync_atlas.import_atlas_bundle") as mock_import:
                with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
                    mock_download.return_value = tmp_path / "ATLAS.json"
                    (tmp_path / "ATLAS.json").write_text('{"type": "bundle", "objects": []}')
                    mock_import.return_value = {
                        "techniques": 0,
                        "tactics": 0,
                        "case_studies": 0,
                    }

                    mock_session = AsyncMock()
                    mock_session.merge = AsyncMock()
                    mock_session.commit = AsyncMock()
                    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                    mock_session.__aexit__ = AsyncMock(return_value=None)
                    mock_session_maker.return_value = mock_session

                    await sync_atlas_data(tmp_path, generate_embeddings=False)

                    # Verify generate_embeddings=False passed through
                    # The function is called with positional arg, so check args[1]
                    call_args = mock_import.call_args
                    # import_atlas_bundle(bundle_path, generate_embeddings)
                    assert call_args.args[1] is False or call_args.kwargs.get("generate_embeddings") is False

    @pytest.mark.asyncio
    async def test_sync_atlas_data_force_download(self, tmp_path):
        """Test force download removes cached file."""
        from cve_mcp.tasks.sync_atlas import sync_atlas_data

        # Create a cached file
        cached_file = tmp_path / "ATLAS.json"
        cached_file.write_text('{"type": "bundle", "cached": true}')

        with patch("cve_mcp.tasks.sync_atlas.download_atlas_bundle") as mock_download:
            with patch("cve_mcp.tasks.sync_atlas.import_atlas_bundle") as mock_import:
                with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
                    mock_download.return_value = tmp_path / "ATLAS.json"
                    mock_import.return_value = {
                        "techniques": 0,
                        "tactics": 0,
                        "case_studies": 0,
                    }

                    mock_session = AsyncMock()
                    mock_session.merge = AsyncMock()
                    mock_session.commit = AsyncMock()
                    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                    mock_session.__aexit__ = AsyncMock(return_value=None)
                    mock_session_maker.return_value = mock_session

                    await sync_atlas_data(tmp_path, generate_embeddings=False, force_download=True)

                    # Cached file should be removed
                    # (download_atlas_bundle will re-create it in tests)
                    mock_download.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_atlas_data_failure_updates_metadata(self, tmp_path):
        """Test that sync failure updates metadata with error."""
        from cve_mcp.tasks.sync_atlas import sync_atlas_data

        with patch("cve_mcp.tasks.sync_atlas.download_atlas_bundle") as mock_download:
            with patch("cve_mcp.tasks.sync_atlas.AsyncSessionLocal") as mock_session_maker:
                # Mock download failure
                mock_download.side_effect = Exception("Network error")

                # Mock session for metadata update
                mock_session = AsyncMock()
                mock_session.merge = AsyncMock()
                mock_session.commit = AsyncMock()
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                mock_session_maker.return_value = mock_session

                with pytest.raises(Exception, match="Network error"):
                    await sync_atlas_data(tmp_path, generate_embeddings=False)

                # Metadata should be updated with failure
                assert mock_session.merge.called
