"""Tests for embedding multilingual model dimension detection."""

from mnemosyne.core import embeddings


def test_get_embedding_dim_english_models():
    """English BGE models have correct dimensions."""
    assert embeddings._get_embedding_dim("BAAI/bge-small-en-v1.5") == 384
    assert embeddings._get_embedding_dim("BAAI/bge-base-en-v1.5") == 768
    assert embeddings._get_embedding_dim("BAAI/bge-large-en-v1.5") == 1024


def test_get_embedding_dim_chinese_models():
    """Chinese BGE models have correct dimensions (different from English!)."""
    assert embeddings._get_embedding_dim("BAAI/bge-small-zh-v1.5") == 512
    assert embeddings._get_embedding_dim("BAAI/bge-base-zh-v1.5") == 768
    assert embeddings._get_embedding_dim("BAAI/bge-large-zh-v1.5") == 1024


def test_get_embedding_dim_multilingual_models():
    """Multilingual embedding models have correct dimensions."""
    assert embeddings._get_embedding_dim("intfloat/multilingual-e5-small") == 384
    assert embeddings._get_embedding_dim("intfloat/multilingual-e5-base") == 768
    assert embeddings._get_embedding_dim("intfloat/multilingual-e5-large") == 1024
    assert embeddings._get_embedding_dim("BAAI/bge-m3") == 1024


def test_get_embedding_dim_env_override():
    """MNEMOSYNE_EMBEDDING_DIM env var overrides model-based detection."""
    import os
    os.environ["MNEMOSYNE_EMBEDDING_DIM"] = "768"
    try:
        assert embeddings._get_embedding_dim("BAAI/bge-small-en-v1.5") == 768
        assert embeddings._get_embedding_dim("unknown-model") == 768
    finally:
        del os.environ["MNEMOSYNE_EMBEDDING_DIM"]


def test_get_embedding_dim_unknown_model_fallback():
    """Unknown models fall back to 384 (bge-small default)."""
    assert embeddings._get_embedding_dim("some/unknown-model") == 384
    assert embeddings._get_embedding_dim("") == 384


def test_get_embedding_dim_openai_models():
    """OpenAI API embedding models have correct dimensions."""
    assert embeddings._get_embedding_dim("openai/text-embedding-3-small") == 1536
    assert embeddings._get_embedding_dim("openai/text-embedding-3-large") == 3072
    assert embeddings._get_embedding_dim("text-embedding-3-small") == 1536
