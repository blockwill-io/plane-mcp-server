"""Logging defaults: what reaches container logs when nothing is configured."""

import os
import subprocess
import sys


def _log_payloads(env_value: str | None) -> str:
    env = {k: v for k, v in os.environ.items() if k != "LOG_PAYLOADS"}
    if env_value is not None:
        env["LOG_PAYLOADS"] = env_value
    # A fresh interpreter: the flag is read once, at import.
    result = subprocess.run(
        [sys.executable, "-c", "import plane_mcp.server as s; print(s.LOG_PAYLOADS)"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip().splitlines()[-1]


def test_payloads_are_not_logged_by_default():
    assert _log_payloads(None) == "False"


def test_payload_logging_can_be_turned_on():
    assert _log_payloads("true") == "True"
