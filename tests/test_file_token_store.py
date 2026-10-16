"""BlockWill fork — the encrypted file token store (TOKEN_STORE_DIR)."""

import asyncio

import pytest
from key_value.aio.errors.wrappers import DecryptionError

from plane_mcp.storage import build_file_store, build_token_store

REDIS_ENV = ("REDIS_URL", "REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "ELASTICACHE_SECRET_ARN")


@pytest.fixture
def no_redis(monkeypatch):
    for name in REDIS_ENV:
        monkeypatch.delenv(name, raising=False)


def test_round_trip_survives_a_new_store_and_is_encrypted_on_disk(tmp_path):
    async def scenario():
        first = build_file_store(str(tmp_path), "key-one")
        await first.put(key="client-1", value={"upstream_token": "plane_oat_SECRET"}, collection="tokens")
        # A fresh process (new store object, same directory and key) reads it back.
        second = build_file_store(str(tmp_path), "key-one")
        return await second.get(key="client-1", collection="tokens")

    assert asyncio.run(scenario()) == {"upstream_token": "plane_oat_SECRET"}
    on_disk = "".join(p.read_text() for p in tmp_path.rglob("*.json"))
    assert on_disk and "plane_oat_SECRET" not in on_disk


def test_wrong_key_cannot_read(tmp_path):
    async def scenario():
        await build_file_store(str(tmp_path), "key-one").put(key="k", value={"v": 1}, collection="c")
        return await build_file_store(str(tmp_path), "key-two").get(key="k", collection="c")

    with pytest.raises(DecryptionError):
        asyncio.run(scenario())


def test_selected_by_env_and_key_required(tmp_path, monkeypatch, no_redis):
    monkeypatch.setenv("TOKEN_STORE_DIR", str(tmp_path / "store"))
    monkeypatch.delenv("TOKEN_STORE_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="TOKEN_STORE_ENCRYPTION_KEY"):
        build_token_store()

    monkeypatch.setenv("TOKEN_STORE_ENCRYPTION_KEY", "k")
    store = build_token_store()
    assert type(store).__name__ == "FernetEncryptionWrapper"
    assert (tmp_path / "store").is_dir()
