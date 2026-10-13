"""
DaemonEnforcer — validates tool calls against policy and executes approved ones.

Two-ceiling enforcement:
  1. client_allowed_tools  — derived by GovernedSession from session policy
  2. operator_allowed_tools — derived from operator_policy set at daemon startup

Tool executes only when approved by both.

Governance (optional, ``governance=GovernanceConfig``): the daemon also runs the
kernel's per-call gates itself — consequence, value policy, SSRF, positional,
carrier, per-value taint, the confidentiality floor and task-scoped grants — on a
``ToolCallGovernor`` it owns, one per connection. Every tool output passes through
the daemon, so it registers outputs into that governor's ledger itself: the agent
process can neither skip a gate nor launder a read. A grant use is reserved before
the handler runs and committed after it returns; a handler that times out leaves
the use spent (never re-run). Operator ceiling cannot be escalated
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

from dataclasses import dataclass

from axor_core.capability.executor import ToolHandler
from axor_core.capability.resolver import CapabilityResolver
from axor_core.contracts.policy import ExecutionPolicy

_log = logging.getLogger("axor.daemon.enforcer")

# Path-like args the enforcer normalizes independently.
# Handlers may have additional args — only these are path-normalized.
_PATH_ARG_KEYS = frozenset({"path", "file", "filepath", "filename", "target"})

# Default max seconds any single handler.execute() may run.
_DEFAULT_EXEC_TIMEOUT = 60.0


@dataclass
class DaemonSession:
    """Per-connection daemon state: the governor whose ledger the daemon feeds."""

    governor: Any = None


class DaemonEnforcer:
    def __init__(
        self,
        operator_policy: ExecutionPolicy,
        handlers: dict[str, ToolHandler],
        exec_timeout: float = _DEFAULT_EXEC_TIMEOUT,
        sandbox_root: str | None = None,
        governance: Any = None,
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
        # Operator GovernanceConfig, fixed at startup like operator_policy.
        self._governance = governance

    def open_session(self, task: str | None = None) -> DaemonSession:
        """State for one connection. ``task`` is the user's request as the client
        reports it; it seeds the trusted-origin index (context integrity) and the
        L1 request grants. It is client-asserted: a compromised agent process can
        lie about it, which widens L1 to whatever it claims — the operator ceiling,
        templates and the floor are unaffected."""
        if self._governance is None:
            return DaemonSession()
        from axor_core.governor import ToolCallGovernor

        g = ToolCallGovernor(**self._governance.as_governor_kwargs())
        if task:
            g.register_task(task)
            if self._governance.grant_args:
                g.grants.from_request(task)
        return DaemonSession(governor=g)

    async def execute(
        self,
        call_id: str,
        tool: str,
        args: dict[str, Any],
        client_allowed_tools: frozenset[str],
        session: DaemonSession | None = None,
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

        gov = session.governor if session is not None else None
        decision = spend = None
        if gov is not None:
            decision = gov.evaluate(tool, safe_args)
            if not decision.allowed:
                reason = f"governance ({decision.category}): {decision.reason}"
                _log.info("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
                return "denied", None, reason
            spend = gov.spend(decision, safe_args, call_key=call_id or None)
            if decision.grant_id is not None and spend is None:
                reason = "governance (grant_gate): the grant was used up concurrently"
                return "denied", None, reason

        try:
            result = await asyncio.wait_for(
                handler.execute(safe_args), timeout=self._exec_timeout
            )
        except asyncio.TimeoutError:
            reason = f"handler '{tool}' exceeded exec_timeout ({self._exec_timeout}s)"
            _log.error("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
            return "denied", None, reason  # a reserved grant use stays spent

        if gov is not None:
            if spend is not None:
                gov.grant_store.commit(spend)
            gov.register_output(decision, result if isinstance(result, str) else repr(result))

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
