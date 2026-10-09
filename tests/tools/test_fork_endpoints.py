"""Actions that talk to BlockWill-fork-only endpoints over raw HTTP.

The SDK has no resource for these, so `_fork_request` is swapped for a
recorder and each action is checked for the method, path and body it sends.
No network is touched.
"""

from __future__ import annotations

import pytest

from plane_mcp.tools import workitem


@pytest.fixture
def fork(monkeypatch, spy):
    calls: list[tuple[str, str, dict | None]] = []

    def record(method, path, json=None):
        calls.append((method, path, json))
        return {"ok": True}

    monkeypatch.setattr(workitem, "_fork_request", record)
    return calls


def test_move_posts_the_target_project(registered, fork):
    registered["workitem"].fn(action="move", project_id="p1", workitem_id="w1", target_project_id="p2")
    assert fork == [("POST", "workspaces/acme/projects/p1/work-items/w1/move/", {"target_project_id": "p2"})]


def test_list_agent_assigned_defaults_to_startupos(registered, fork):
    registered["workitem"].fn(action="list_agent_assigned")
    assert fork == [("GET", "workspaces/acme/agent-assignments/?agent=startupos", None)]


def test_list_agent_assigned_honours_an_explicit_agent(registered, fork):
    registered["workitem"].fn(action="list_agent_assigned", agent="other")
    assert fork[0][1].endswith("?agent=other")


@pytest.mark.parametrize(("action", "method"), [("assign_agent", "POST"), ("unassign_agent", "DELETE")])
def test_agent_assignment_flips_one_item(registered, fork, action, method):
    registered["workitem"].fn(action=action, project_id="p1", workitem_id="w1")
    assert fork == [(method, "workspaces/acme/projects/p1/work-items/w1/agent-assignment/", {"agent": "startupos"})]


@pytest.mark.parametrize("action", ["assign_agent", "unassign_agent"])
def test_agent_assignment_needs_a_work_item(registered, fork, action):
    result = registered["workitem"].fn(action=action, project_id="p1")
    assert isinstance(result, str) and result.startswith("Error:")
    assert not fork


def test_a_failed_fork_call_is_reported_not_raised(registered, monkeypatch, spy):
    monkeypatch.setattr(workitem, "_fork_request", lambda *a, **k: "Error: GET failed with HTTP 404: nope")
    result = registered["workitem"].fn(action="list_agent_assigned")
    assert result.startswith("Error:")
