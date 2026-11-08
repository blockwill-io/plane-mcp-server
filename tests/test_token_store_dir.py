"""The token store directory must be writable by the server's own user (the image runs as uid 10001)."""

import os

import pytest

from plane_mcp.storage import build_file_store


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_an_unwritable_directory_fails_at_start(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o555)
    try:
        with pytest.raises(RuntimeError, match="not writable"):
            build_file_store(str(locked), "k" * 64)
    finally:
        locked.chmod(0o755)
