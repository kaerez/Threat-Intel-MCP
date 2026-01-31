"""OpenAI embedding service for semantic search."""

import asyncio
import logging
from typing import Any

import numpy as np
from openai import AsyncOpenAI

from cve_mcp.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# Initialize OpenAI client
client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY) if settings.OPENAI_API_KEY else None


async def generate_embedding(text: str, model: str = "text-embedding-3-small") -> list[float]:
    """Generate embedding for a single text.

    Args:
        text: Text to embed
        model: OpenAI embedding model

    Returns:
        1536-dimensional embedding vector

    Raises:
        ValueError: If OpenAI API key not configured
        Exception: If API call fails
    """
    if not client:
        raise ValueError("OPENAI_API_KEY not configured")

    # Truncate to 8000 characters (safe limit for embedding model)
    text = text[:8000]

    try:
        response = await client.embeddings.create(input=text, model=model, encoding_format="float")

        embedding = response.data[0].embedding

        logger.debug(f"Generated embedding for text of length {len(text)}")

        return embedding

    except Exception as e:
        logger.error(f"Failed to generate embedding: {e}")
        raise


async def generate_embeddings_batch(
    texts: list[str], model: str = "text-embedding-3-small", batch_size: int = 100
) -> list[list[float]]:
    """Generate embeddings for multiple texts in batches.

    Args:
        texts: List of texts to embed
        model: OpenAI embedding model
        batch_size: Max texts per API call (OpenAI limit: 2048)

    Returns:
        List of embedding vectors
    """
    if not client:
        raise ValueError("OPENAI_API_KEY not configured")

    embeddings = []

    # Process in batches to stay within API limits
    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        # Truncate each text
        batch = [text[:8000] for text in batch]

        try:
            response = await client.embeddings.create(input=batch, model=model, encoding_format="float")

            batch_embeddings = [item.embedding for item in response.data]
            embeddings.extend(batch_embeddings)

            logger.info(f"Generated {len(batch_embeddings)} embeddings (batch {i // batch_size + 1})")

            # Rate limiting: small delay between batches
            if i + batch_size < len(texts):
                await asyncio.sleep(0.1)

        except Exception as e:
            logger.error(f"Failed to generate embeddings for batch {i // batch_size + 1}: {e}")
            raise

    return embeddings


def cosine_similarity(vec1: list[float], vec2: list[float]) -> float:
    """Calculate cosine similarity between two vectors.

    Args:
        vec1: First embedding vector
        vec2: Second embedding vector

    Returns:
        Cosine similarity score (-1 to 1, higher = more similar)
    """
    arr1 = np.array(vec1)
    arr2 = np.array(vec2)

    # Cosine similarity: dot(A, B) / (||A|| * ||B||)
    dot_product = np.dot(arr1, arr2)
    norm_a = np.linalg.norm(arr1)
    norm_b = np.linalg.norm(arr2)

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return float(dot_product / (norm_a * norm_b))


async def embed_technique(technique_data: dict[str, Any]) -> list[float]:
    """Generate embedding for ATT&CK technique.

    Combines technique name and description for rich semantic representation.

    Args:
        technique_data: Dictionary with 'name' and 'description' keys

    Returns:
        Embedding vector
    """
    # Combine name and description for richer context
    text = f"{technique_data['name']}: {technique_data['description']}"

    return await generate_embedding(text)


async def embed_group(group_data: dict[str, Any]) -> list[float]:
    """Generate embedding for threat actor group.

    Combines group name, aliases, and description.

    Args:
        group_data: Dictionary with 'name', 'aliases', and 'description' keys

    Returns:
        Embedding vector
    """
    aliases = ", ".join(group_data.get("aliases", []))
    text = f"{group_data['name']} (aka {aliases}): {group_data['description']}"

    return await generate_embedding(text)
