"""Actions that talk to BlockWill-fork-only endpoints over raw HTTP.

The SDK has no resource for these, so `_fork_request` is swapped for a
recorder and each action is checked for the method, path and body it sends.
No network is touched.
"""

from __future__ import annotations

import pytest

from plane_mcp.tools import workitem

P1 = "11111111-1111-4111-8111-111111111111"
P2 = "22222222-2222-4222-8222-222222222222"
W1 = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def fork(monkeypatch, spy):
    calls: list[tuple[str, str, dict | None]] = []

    def record(method, path, json=None):
        calls.append((method, path, json))
        return {"ok": True}

    monkeypatch.setattr(workitem, "_fork_request", record)
    return calls


def test_move_posts_the_target_project(registered, fork):
    registered["workitem"].fn(action="move", project_id=P1, workitem_id=W1, target_project_id=P2)
    assert fork == [("POST", f"workspaces/acme/projects/{P1}/work-items/{W1}/move/", {"target_project_id": P2})]


def test_list_agent_assigned_defaults_to_startupos(registered, fork):
    registered["workitem"].fn(action="list_agent_assigned")
    assert fork == [("GET", "workspaces/acme/agent-assignments/?agent=startupos", None)]


def test_list_agent_assigned_honours_an_explicit_agent(registered, fork):
    registered["workitem"].fn(action="list_agent_assigned", agent="other")
    assert fork[0][1].endswith("?agent=other")


@pytest.mark.parametrize(("action", "method"), [("assign_agent", "POST"), ("unassign_agent", "DELETE")])
def test_agent_assignment_flips_one_item(registered, fork, action, method):
    registered["workitem"].fn(action=action, project_id=P1, workitem_id=W1)
    path = f"workspaces/acme/projects/{P1}/work-items/{W1}/agent-assignment/"
    assert fork == [(method, path, {"agent": "startupos"})]


@pytest.mark.parametrize("action", ["assign_agent", "unassign_agent"])
def test_agent_assignment_needs_a_work_item(registered, fork, action):
    result = registered["workitem"].fn(action=action, project_id=P1)
    assert isinstance(result, str) and result.startswith("Error:")
    assert not fork


def test_a_failed_fork_call_is_reported_not_raised(registered, monkeypatch, spy):
    monkeypatch.setattr(workitem, "_fork_request", lambda *a, **k: "Error: GET failed with HTTP 404: nope")
    result = registered["workitem"].fn(action="list_agent_assigned")
    assert result.startswith("Error:")


@pytest.mark.parametrize(
    ("action", "extra"),
    [("move", {"target_project_id": P2}), ("assign_agent", {}), ("unassign_agent", {})],
)
@pytest.mark.parametrize("bad", ["w1", f"{W1}/../../", f"{W1}?x=1", ""])
def test_ids_that_are_not_uuids_never_reach_the_path(registered, fork, action, extra, bad):
    result = registered["workitem"].fn(action=action, project_id=P1, workitem_id=bad, **extra)
    assert isinstance(result, str) and result.startswith("Error:")
    assert not fork


def test_the_agent_name_is_encoded_into_the_query(registered, fork):
    registered["workitem"].fn(action="list_agent_assigned", agent="a&b=c")
    assert fork[0][1].endswith("?agent=a%26b%3Dc")


# ── Credentials: _fork_request itself, with the HTTP call recorded ──────────


@pytest.fixture
def sent(monkeypatch):
    """Headers of the one request _fork_request makes."""
    import httpx

    captured: dict = {}

    def request(method, url, json=None, headers=None, timeout=None):
        captured.update(headers or {})
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(httpx, "request", request)
    return captured


def _caller(monkeypatch, token: str | None, auth_method: str = "oauth"):
    from fastmcp.server import dependencies
    from fastmcp.server.auth.auth import AccessToken

    stored = None
    if token:
        stored = AccessToken(token=token, client_id="c", scopes=[], claims={"auth_method": auth_method})
    monkeypatch.setattr(dependencies, "get_access_token", lambda: stored)


def test_an_oauth_caller_uses_its_own_token_even_with_a_server_key(monkeypatch, sent):
    monkeypatch.setenv("PLANE_API_KEY", "server-key")
    _caller(monkeypatch, "user-oauth-token")

    workitem._fork_request("GET", "workspaces/acme/agent-assignments/")

    assert sent["Authorization"] == "Bearer user-oauth-token"
    assert "x-api-key" not in sent


def test_a_header_api_key_caller_uses_its_own_key(monkeypatch, sent):
    monkeypatch.setenv("PLANE_API_KEY", "server-key")
    _caller(monkeypatch, "user-pat", auth_method="api_key_header")

    workitem._fork_request("GET", "workspaces/acme/agent-assignments/")

    assert sent["x-api-key"] == "user-pat"
    assert "Authorization" not in sent


def test_the_server_key_is_used_only_without_a_caller(monkeypatch, sent):
    monkeypatch.setenv("PLANE_API_KEY", "server-key")
    _caller(monkeypatch, None)

    workitem._fork_request("GET", "workspaces/acme/agent-assignments/")

    assert sent["x-api-key"] == "server-key"
