"""
DaemonEnforcer — validates tool calls against policy and executes approved ones.

Two-ceiling enforcement:
  1. client_allowed_tools  — derived by GovernedSession from session policy
  2. operator_allowed_tools — derived from operator_policy set at daemon startup

Tool executes only when approved by both. Operator ceiling cannot be escalated
by the client — it is set once at daemon start and never modified per-connection.

Args are never trusted raw from the client:
  - tool name is validated against both ceilings before handler is called
  - path-like string args are normalized independently, and when sandbox_root is
    set they must resolve inside that root before handler execution
  - handler execution is bounded by exec_timeout to prevent runaway tools
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from axor_core.capability.executor import ToolHandler
from axor_core.capability.resolver import CapabilityResolver
from axor_core.contracts.policy import ExecutionPolicy

_log = logging.getLogger("axor.daemon.enforcer")

# Path-like args the enforcer normalizes (and sandbox-validates) independently.
# Must stay aligned with axor-core's path-extraction aliases so a handler reading
# e.g. file_path cannot receive an un-normalized, sandbox-escaping value.
_PATH_ARG_KEYS = frozenset({
    "path", "file", "file_path", "filepath", "filename", "target",
    "dir", "directory", "dest", "destination", "output", "src", "source",
})

# Default max seconds any single handler.execute() may run.
_DEFAULT_EXEC_TIMEOUT = 60.0


class DaemonEnforcer:
    def __init__(
        self,
        operator_policy: ExecutionPolicy,
        handlers: dict[str, ToolHandler],
        exec_timeout: float = _DEFAULT_EXEC_TIMEOUT,
        sandbox_root: str | None = None,
    ) -> None:
        self._operator_policy = operator_policy
        self._handlers = handlers
        self._exec_timeout = exec_timeout
        self._sandbox_root = (
            Path(sandbox_root).expanduser().resolve(strict=False)
            if sandbox_root else None
        )
        resolver = CapabilityResolver()
        caps = resolver.resolve(operator_policy)
        self._operator_allowed: frozenset[str] = caps.allowed_tools

    async def execute(
        self,
        call_id: str,
        tool: str,
        args: dict[str, Any],
        client_allowed_tools: frozenset[str],
    ) -> tuple[str, Any, str | None]:
        """
        Validate and execute a tool call.

        Returns (decision, result, denial_reason):
          decision: "approved" | "denied"
          result:   tool output or None
          denial_reason: str if denied, else None
        """
        # ceiling check — operator policy wins, evaluated daemon-side
        if tool not in self._operator_allowed:
            reason = f"tool '{tool}' not permitted by operator policy"
            _log.info("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
            return "denied", None, reason

        # client check — session policy reported by client
        if tool not in client_allowed_tools:
            reason = f"tool '{tool}' not in session allowed_tools"
            _log.info("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
            return "denied", None, reason

        handler = self._handlers.get(tool)
        if handler is None:
            reason = f"no handler registered for tool '{tool}'"
            _log.warning("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
            return "denied", None, reason

        try:
            safe_args = _normalize_path_args(args, sandbox_root=self._sandbox_root)
        except ValueError as exc:
            reason = str(exc)
            _log.info("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
            return "denied", None, reason

        try:
            result = await asyncio.wait_for(
                handler.execute(safe_args), timeout=self._exec_timeout
            )
        except asyncio.TimeoutError:
            reason = f"handler '{tool}' exceeded exec_timeout ({self._exec_timeout}s)"
            _log.error("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
            return "denied", None, reason

        _log.debug("APPROVED call_id=%s tool=%s", call_id, tool)
        return "approved", result, None


def _normalize_path_args(
    args: dict[str, Any],
    sandbox_root: Path | None = None,
) -> dict[str, Any]:
    """
    Return a copy of args with known path-like string values normalized.
    Non-string values and unrecognized keys are passed through unchanged.
    """
    result = {}
    for key, value in args.items():
        if key in _PATH_ARG_KEYS and isinstance(value, str):
            result[key] = _normalize_path(value, sandbox_root=sandbox_root)
        else:
            result[key] = value
    return result


def _normalize_path(value: str, sandbox_root: Path | None) -> str:
    if sandbox_root is None:
        return os.path.normpath(value)
    path = Path(value).expanduser()
    candidate = path if path.is_absolute() else sandbox_root / path
    resolved = candidate.resolve(strict=False)
    if resolved == sandbox_root:
        return str(resolved)
    try:
        resolved.relative_to(sandbox_root)
    except ValueError as exc:
        raise ValueError(
            f"path {str(path)!r} resolves outside daemon sandbox root"
        ) from exc
    return str(resolved)
