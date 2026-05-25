"""Unit tests for DaemonEnforcer — policy validation + tool execution."""

from __future__ import annotations

import asyncio
import pytest

from axor_core.capability.executor import ToolHandler
from axor_core.contracts.policy import (
    ChildMode,
    CompressionMode,
    ContextMode,
    ExecutionPolicy,
    ExportMode,
    TaskComplexity,
    ToolPolicy,
)

from axor_daemon.enforcer import DaemonEnforcer


class _EchoHandler(ToolHandler):
    @property
    def name(self) -> str:
        return "read"

    async def execute(self, args: dict) -> str:
        return f"content of {args.get('path', '?')}"


class _BashHandler(ToolHandler):
    @property
    def name(self) -> str:
        return "bash"

    async def execute(self, args: dict) -> str:
        return "bash output"


def _readonly_policy() -> ExecutionPolicy:
    return ExecutionPolicy(
        name="focused_readonly",
        derived_from=TaskComplexity.FOCUSED,
        context_mode=ContextMode.MINIMAL,
        compression_mode=CompressionMode.AGGRESSIVE,
        child_mode=ChildMode.DENIED,
        max_child_depth=0,
        tool_policy=ToolPolicy(allow_read=True, allow_write=False, allow_bash=False),
        export_mode=ExportMode.SUMMARY,
    )


def _make_enforcer(policy=None, extra_handlers=None) -> DaemonEnforcer:
    handlers = {"read": _EchoHandler()}
    if extra_handlers:
        handlers.update(extra_handlers)
    return DaemonEnforcer(
        operator_policy=policy or _readonly_policy(),
        handlers=handlers,
    )


@pytest.mark.asyncio
async def test_approved_tool_returns_result():
    enforcer = _make_enforcer()
    decision, result, reason = await enforcer.execute(
        call_id="c1",
        tool="read",
        args={"path": "src/main.py"},
        client_allowed_tools=frozenset(["read"]),
    )
    assert decision == "approved"
    assert "src/main.py" in result
    assert reason is None


@pytest.mark.asyncio
async def test_operator_ceiling_denies_bash():
    """operator_policy=focused_readonly → bash denied even if client allows it."""
    enforcer = _make_enforcer(extra_handlers={"bash": _BashHandler()})
    decision, result, reason = await enforcer.execute(
        call_id="c2",
        tool="bash",
        args={"cmd": "ls"},
        client_allowed_tools=frozenset(["bash"]),  # client says ok
    )
    assert decision == "denied"
    assert result is None
    assert "operator policy" in reason


@pytest.mark.asyncio
async def test_client_denied_tool_is_blocked():
    """Client did not include 'read' in allowed_tools — denied regardless of operator policy."""
    enforcer = _make_enforcer()
    decision, result, reason = await enforcer.execute(
        call_id="c3",
        tool="read",
        args={"path": "secret.txt"},
        client_allowed_tools=frozenset(),  # client excluded read
    )
    assert decision == "denied"
    assert "session allowed_tools" in reason


@pytest.mark.asyncio
async def test_path_traversal_normalized():
    """args["path"] with ../ sequences is normalized before handler sees it."""
    seen = {}

    class _CapturingHandler(ToolHandler):
        @property
        def name(self) -> str:
            return "read"

        async def execute(self, args: dict) -> str:
            seen["path"] = args.get("path")
            return "ok"

    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _CapturingHandler()},
    )
    await enforcer.execute(
        call_id="p1",
        tool="read",
        args={"path": "/home/user/project/../../etc/passwd"},
        client_allowed_tools=frozenset(["read"]),
    )
    # os.path.normpath resolves ../ sequences — no raw traversal reaches the handler
    import os as _os
    assert seen["path"] == _os.path.normpath("/home/user/project/../../etc/passwd")
    assert ".." not in seen["path"]


@pytest.mark.asyncio
async def test_sandbox_root_denies_parent_traversal(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _EchoHandler()},
        sandbox_root=str(sandbox),
    )

    decision, result, reason = await enforcer.execute(
        call_id="p2",
        tool="read",
        args={"path": "../outside.txt"},
        client_allowed_tools=frozenset(["read"]),
    )

    assert decision == "denied"
    assert result is None
    assert "outside daemon sandbox root" in reason


@pytest.mark.asyncio
async def test_sandbox_root_denies_prefix_sibling(tmp_path):
    sandbox = tmp_path / "sandbox"
    sibling = tmp_path / "sandbox-secret"
    sandbox.mkdir()
    sibling.mkdir()
    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _EchoHandler()},
        sandbox_root=str(sandbox),
    )

    decision, result, reason = await enforcer.execute(
        call_id="p3",
        tool="read",
        args={"path": str(sibling / "secret.txt")},
        client_allowed_tools=frozenset(["read"]),
    )

    assert decision == "denied"
    assert result is None
    assert "outside daemon sandbox root" in reason


@pytest.mark.asyncio
async def test_sandbox_root_resolves_safe_relative_path(tmp_path):
    seen = {}
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    class _CapturingHandler(ToolHandler):
        @property
        def name(self) -> str:
            return "read"

        async def execute(self, args: dict) -> str:
            seen["path"] = args.get("path")
            return "ok"

    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _CapturingHandler()},
        sandbox_root=str(sandbox),
    )

    decision, result, reason = await enforcer.execute(
        call_id="p4",
        tool="read",
        args={"path": "src/main.py"},
        client_allowed_tools=frozenset(["read"]),
    )

    assert decision == "approved"
    assert result == "ok"
    assert reason is None
    assert seen["path"] == str(sandbox / "src" / "main.py")


@pytest.mark.asyncio
async def test_handler_timeout_denies():
    """Handler that exceeds exec_timeout is denied, not silently hung."""

    class _SlowHandler(ToolHandler):
        @property
        def name(self) -> str:
            return "read"

        async def execute(self, args: dict) -> str:
            await asyncio.sleep(10)
            return "never"

    enforcer = DaemonEnforcer(
        operator_policy=_readonly_policy(),
        handlers={"read": _SlowHandler()},
        exec_timeout=0.05,
    )
    decision, result, reason = await enforcer.execute(
        call_id="t1",
        tool="read",
        args={"path": "file.py"},
        client_allowed_tools=frozenset(["read"]),
    )
    assert decision == "denied"
    assert "exec_timeout" in reason


@pytest.mark.asyncio
async def test_no_handler_registered_denies():
    """Tool allowed by both policies but no handler registered → denied."""
    from axor_core.contracts.policy import ToolPolicy
    policy_with_search = ExecutionPolicy(
        name="test_search",
        derived_from=TaskComplexity.FOCUSED,
        context_mode=ContextMode.MINIMAL,
        compression_mode=CompressionMode.AGGRESSIVE,
        child_mode=ChildMode.DENIED,
        max_child_depth=0,
        tool_policy=ToolPolicy(allow_read=True, allow_search=True),
        export_mode=ExportMode.SUMMARY,
    )
    # enforcer has only "read" handler — "search" has no handler
    enforcer = _make_enforcer(policy=policy_with_search)
    decision, result, reason = await enforcer.execute(
        call_id="c4",
        tool="search",
        args={"query": "x"},
        client_allowed_tools=frozenset(["search"]),
    )
    assert decision == "denied"
    assert "no handler" in reason
