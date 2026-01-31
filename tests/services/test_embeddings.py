"""Tests for embedding service."""

import os

import pytest

# Skip all tests in this module if OPENAI_API_KEY is not set
pytestmark = pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not configured - skipping embedding tests"
)


@pytest.mark.asyncio
async def test_generate_embedding_basic():
    """Test basic embedding generation."""
    from cve_mcp.services.embeddings import generate_embedding

    text = "Adversaries may send spearphishing emails with malicious attachments"
    embedding = await generate_embedding(text)

    assert isinstance(embedding, list)
    assert len(embedding) == 1536  # text-embedding-3-small dimension
    assert all(isinstance(x, float) for x in embedding)
    assert -1.0 <= embedding[0] <= 1.0  # Normalized vector


@pytest.mark.asyncio
async def test_generate_embeddings_batch():
    """Test batch embedding generation."""
    from cve_mcp.services.embeddings import generate_embeddings_batch

    texts = [
        "SQL injection vulnerability",
        "Cross-site scripting attack",
        "Remote code execution",
    ]

    embeddings = await generate_embeddings_batch(texts)

    assert len(embeddings) == 3
    assert all(len(emb) == 1536 for emb in embeddings)


@pytest.mark.asyncio
async def test_embedding_similarity():
    """Test that similar texts have similar embeddings."""
    from cve_mcp.services.embeddings import generate_embedding, cosine_similarity

    emb1 = await generate_embedding("SQL injection in login form")
    emb2 = await generate_embedding("SQL injection vulnerability in authentication")
    emb3 = await generate_embedding("Buffer overflow in network daemon")

    sim_similar = cosine_similarity(emb1, emb2)
    sim_different = cosine_similarity(emb1, emb3)

    # Similar texts should have higher similarity
    assert sim_similar > sim_different
    assert sim_similar > 0.7  # High similarity threshold
