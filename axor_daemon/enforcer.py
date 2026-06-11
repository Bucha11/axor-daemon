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
from axor_core.contracts.canonical import ConsequenceClass
from axor_core.contracts.policy import ExecutionPolicy
from axor_core.governor import ToolCallGovernor

_log = logging.getLogger("axor.daemon.enforcer")

# Path-like args the enforcer normalizes independently.
# Handlers may have additional args — only these are path-normalized.
_PATH_ARG_KEYS = frozenset({"path", "file", "filepath", "filename", "target"})

# Default max seconds any single handler.execute() may run.
_DEFAULT_EXEC_TIMEOUT = 60.0


class DaemonEnforcer:
    def __init__(
        self,
        operator_policy: ExecutionPolicy,
        handlers: dict[str, ToolHandler],
        exec_timeout: float = _DEFAULT_EXEC_TIMEOUT,
        sandbox_root: str | None = None,
        *,
        untrusted_sources: "set[str] | frozenset[str] | None" = None,
        sensitive_sources: "set[str] | frozenset[str] | None" = None,
        egress_sinks: "set[str] | frozenset[str] | None" = None,
        positional_sinks: "set[str] | frozenset[str] | None" = None,
        value_policies: dict | None = None,
        consequence_overrides: dict | None = None,
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

        # Operator-configured data-flow taxonomy. Set here at daemon startup — NOT
        # taken from the client — so a compromised worker cannot disable the
        # data-flow gates by declaring an empty taxonomy. Empty by default: the
        # normalizer's generic heuristics still apply to every call.
        self._governor_kwargs = dict(
            untrusted_sources=set(untrusted_sources or ()),
            sensitive_sources=set(sensitive_sources or ()),
            egress_sinks=set(egress_sinks or ()),
            positional_sinks=set(positional_sinks or ()),
            value_policies=dict(value_policies or {}),
            consequence_overrides=dict(consequence_overrides or {}),
            max_unattended_consequence=getattr(
                operator_policy, "max_unattended_consequence",
                ConsequenceClass.CONSEQUENTIAL,
            ),
        )

    def new_session_governor(self) -> ToolCallGovernor:
        """A fresh per-connection governor (its own taint ledger / floor), using
        the operator-configured taxonomy. One per session; the server holds it."""
        return ToolCallGovernor(**self._governor_kwargs)

    async def execute(
        self,
        call_id: str,
        tool: str,
        args: dict[str, Any],
        client_allowed_tools: frozenset[str],
        governor: ToolCallGovernor | None = None,
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

        # data-flow gate — evaluated daemon-side, server-side of the trust boundary.
        # This is what makes taint / confidentiality-floor / consequence enforcement
        # survive a compromised worker that sends a raw tool_call bypassing its own
        # in-process IntentLoop: the daemon re-runs the per-value gates against its
        # OWN ledger before touching the handler.
        gov_decision = None
        if governor is not None:
            gov_decision = governor.evaluate(tool, args)
            if not gov_decision.allowed:
                _log.info(
                    "DENIED call_id=%s tool=%s: data-flow gate (%s)",
                    call_id, tool, gov_decision.category,
                )
                return "denied", None, gov_decision.reason

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

        # Register the output so a later sink carrying it is gated — the daemon's
        # own per-value ledger, independent of whatever the worker tracks.
        if governor is not None and gov_decision is not None:
            governor.register_output(gov_decision, result)

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
