"""
Integration tests: real DaemonServer + DaemonCapabilityClient over a Unix socket.
No subprocess — both run in the same test event loop for simplicity.
"""

from __future__ import annotations

import os
import pytest

from axor_core.capability.executor import ToolHandler
from axor_core.capability.daemon_client import DaemonCapabilityClient
from axor_core.contracts.envelope import Capabilities
from axor_core.contracts.intent import Intent, IntentKind
from axor_core.contracts.policy import (
    ChildMode,
    CompressionMode,
    ContextMode,
    ExecutionPolicy,
    ExportMode,
    TaskComplexity,
    ToolPolicy,
)
from axor_core.errors.exceptions import DaemonUnavailableError, ToolNotAllowedError

from axor_daemon.enforcer import DaemonEnforcer
from axor_daemon.server import DaemonServer


# ── Fixtures ───────────────────────────────────────────────────────────────────

class _ReadHandler(ToolHandler):
    @property
    def name(self) -> str:
        return "read"

    async def execute(self, args: dict) -> str:
        return f"contents:{args.get('path', '')}"


def _readonly_policy() -> ExecutionPolicy:
    return ExecutionPolicy(
        name="focused_readonly",
        derived_from=TaskComplexity.FOCUSED,
        context_mode=ContextMode.MINIMAL,
        compression_mode=CompressionMode.AGGRESSIVE,
        child_mode=ChildMode.DENIED,
        max_child_depth=0,
        tool_policy=ToolPolicy(allow_read=True, allow_bash=False),
        export_mode=ExportMode.SUMMARY,
    )


def _make_intent(tool: str, args: dict) -> Intent:
    return Intent(
        kind=IntentKind.TOOL_CALL,
        payload={"tool": tool, "args": args},
        node_id="test_node",
        sequence=0,
    )


def _make_capabilities(allowed: set[str]) -> Capabilities:
    return Capabilities(
        allowed_tools=frozenset(allowed),
        allow_children=False,
        allow_nested_children=False,
        allow_context_expansion=False,
        allow_export=True,
        allow_mutation=False,
        max_child_depth=0,
    )


@pytest.fixture
async def daemon_socket(tmp_path):
    """Start a real DaemonServer on a temp socket; yield socket path; stop server."""
    socket_path = str(tmp_path / "test_daemon.sock")
    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _ReadHandler()},
    )
    server = DaemonServer(enforcer=enforcer)
    await server.start(socket_path)

    yield socket_path

    await server.stop()


# ── Tests ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_approved_read_call(daemon_socket):
    client = DaemonCapabilityClient(socket_path=daemon_socket)
    intent = _make_intent("read", {"path": "app.py"})
    caps = _make_capabilities({"read"})

    result = await client.execute(intent, caps)

    assert result == "contents:app.py"
    await client.aclose()


@pytest.mark.asyncio
async def test_bash_denied_by_operator_policy(daemon_socket):
    """Operator policy is focused_readonly → bash denied even when client allows it."""
    client = DaemonCapabilityClient(socket_path=daemon_socket)
    intent = _make_intent("bash", {"cmd": "ls"})
    caps = _make_capabilities({"bash", "read"})

    with pytest.raises(ToolNotAllowedError):
        await client.execute(intent, caps)

    await client.aclose()


@pytest.mark.asyncio
async def test_session_grant_roundtrip(daemon_socket, monkeypatch):
    """With a session key, the legit client attaches a grant and the call works."""
    monkeypatch.setenv("AXOR_DAEMON_SESSION_KEY", "shared-secret")
    client = DaemonCapabilityClient(socket_path=daemon_socket)
    result = await client.execute(
        _make_intent("read", {"path": "a.py"}), _make_capabilities({"read"})
    )
    assert result == "contents:a.py"
    await client.aclose()


@pytest.mark.asyncio
async def test_missing_grant_denied_when_key_set(daemon_socket, monkeypatch):
    """A client without the key (no grant) is denied when the daemon requires one."""
    monkeypatch.setenv("AXOR_DAEMON_SESSION_KEY", "shared-secret")
    # Simulate a rogue same-user process that cannot mint a grant.
    monkeypatch.setattr(
        "axor_core.capability.daemon_client.issue_grant", lambda *a, **k: None
    )
    client = DaemonCapabilityClient(socket_path=daemon_socket)
    with pytest.raises(ToolNotAllowedError):
        await client.execute(
            _make_intent("read", {"path": "a.py"}), _make_capabilities({"read"})
        )
    await client.aclose()


@pytest.mark.asyncio
async def test_tool_not_in_client_capabilities_denied(daemon_socket):
    """Client did not include read in allowed_tools → denied."""
    client = DaemonCapabilityClient(socket_path=daemon_socket)
    intent = _make_intent("read", {"path": "secret.txt"})
    caps = _make_capabilities(set())  # empty

    with pytest.raises(ToolNotAllowedError):
        await client.execute(intent, caps)

    await client.aclose()


@pytest.mark.asyncio
async def test_connection_reused_across_calls(daemon_socket):
    """Multiple calls share one connection — verified by checking socket not re-opened."""
    client = DaemonCapabilityClient(socket_path=daemon_socket)
    caps = _make_capabilities({"read"})

    for i in range(3):
        result = await client.execute(
            _make_intent("read", {"path": f"file{i}.py"}), caps
        )
        assert f"file{i}.py" in result

    await client.aclose()


@pytest.mark.asyncio
async def test_post_callbacks_fired(daemon_socket):
    calls = []

    async def _cb(tool, args, result):
        calls.append((tool, result))

    client = DaemonCapabilityClient(socket_path=daemon_socket)
    client.register_post_callback(_cb)

    await client.execute(_make_intent("read", {"path": "x.py"}), _make_capabilities({"read"}))

    assert len(calls) == 1
    assert calls[0][0] == "read"
    assert "x.py" in calls[0][1]
    await client.aclose()


@pytest.mark.asyncio
async def test_socket_permissions(tmp_path):
    """Daemon socket must be created with mode 0o600."""
    socket_path = str(tmp_path / "perm_test.sock")
    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _ReadHandler()},
    )
    server = DaemonServer(enforcer=enforcer)
    await server.start(socket_path)

    mode = oct(os.stat(socket_path).st_mode & 0o777)
    await server.stop()

    assert mode == oct(0o600), f"expected 0o600, got {mode}"


@pytest.mark.asyncio
async def test_start_refuses_to_unlink_regular_file(tmp_path):
    """Daemon startup must not delete a non-socket file at socket_path."""
    socket_path = tmp_path / "not_a_socket.sock"
    socket_path.write_text("keep me", encoding="utf-8")
    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _ReadHandler()},
    )
    server = DaemonServer(enforcer=enforcer)

    with pytest.raises(FileExistsError):
        await server.start(str(socket_path))

    assert socket_path.read_text(encoding="utf-8") == "keep me"
    await server.stop()


@pytest.mark.asyncio
async def test_daemon_unavailable_raises(tmp_path):
    """No daemon running → DaemonUnavailableError (fail-closed)."""
    client = DaemonCapabilityClient(
        socket_path=str(tmp_path / "nonexistent.sock"),
        connect_timeout=0.5,
    )
    intent = _make_intent("read", {"path": "x.py"})
    caps = _make_capabilities({"read"})

    with pytest.raises(DaemonUnavailableError):
        await client.execute(intent, caps)
