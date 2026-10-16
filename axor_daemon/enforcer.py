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
import copy
import logging
import os
import secrets
import signal
from pathlib import Path
from typing import Any

from dataclasses import dataclass, field

from axor_core.capability.executor import ToolHandler
from axor_core.capability.resolver import CapabilityResolver
from axor_core.contracts.policy import ExecutionPolicy

_log = logging.getLogger("axor.daemon.enforcer")

# Path-like args the enforcer normalizes independently.
# Handlers may have additional args — only these are path-normalized.
_PATH_ARG_KEYS = frozenset({"path", "file", "filepath", "filename", "target"})

_TERMINATED = "session terminated: the operator refused too many confirmations (--l4-max-refusals)"


class SessionRejected(Exception):
    """A hello the daemon will not open a session for (resume refused)."""


def _crash(point: str) -> None:
    """Fault injection for the crash tests: AXOR_DAEMON_CRASHPOINT=<point> kills the
    process with SIGKILL at that point (no cleanup, no flush). Unset: nothing."""
    if os.environ.get("AXOR_DAEMON_CRASHPOINT") == point:
        os.kill(os.getpid(), signal.SIGKILL)

# Default max seconds any single handler.execute() may run.
_DEFAULT_EXEC_TIMEOUT = 60.0


@dataclass
class DaemonSession:
    """Per-connection daemon state: the governor whose ledger the daemon feeds.

    ``lock`` serializes check -> execute -> register for the session, so a call is
    decided on the state at the moment it is sent: no other call of the session
    can register an output (a secret read arming the floor) between this call's
    check and its execution."""

    governor: Any = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    confirmer: Any = None  # the session's ThreadConfirmer (L4 limits), if any
    # --journal (journal.py, durable.py)
    session_id: str | None = None
    journaled: set = field(default_factory=set)   # grant ids already in the journal
    snapshot: dict | None = None                  # the session state last journaled
    retired: set = field(default_factory=set)     # reference names issued before a restart
    dedup: Any = None                             # DurableDedup

    @property
    def terminated(self) -> bool:
        return bool(self.confirmer is not None and self.confirmer.terminated)


class DaemonEnforcer:
    def __init__(
        self,
        operator_policy: ExecutionPolicy,
        handlers: dict[str, ToolHandler],
        exec_timeout: float = _DEFAULT_EXEC_TIMEOUT,
        sandbox_root: str | None = None,
        governance: Any = None,
        confirm: Any = None,
        operator_allowed: frozenset[str] | None = None,
        structured: Any = None,
        journal: Any = None,
        config_sha256: str = "",
    ) -> None:
        self._operator_policy = operator_policy
        # --journal: grants and the session state they depend on survive a restart
        # (journal.py). Requires governance: without a governor there is nothing to keep.
        self._journal = journal
        self._config_sha256 = config_sha256
        self._live: set[str] = set()
        if journal is not None:
            if governance is None:
                raise ValueError("--journal needs --governance")
            from axor_daemon.durable import check_kernel
            check_kernel(governance.as_governor_kwargs())
        # The platform's parser of a declared description source's output (axor-core
        # MODEL.md 9.15): (tool, result) -> structure | None. Without it the description
        # grants are never computed, as in any integration that is not given one.
        self._structured = structured
        self._handlers = handlers
        self._exec_timeout = exec_timeout
        self._sandbox_root = (
            Path(sandbox_root).expanduser().resolve(strict=False)
            if sandbox_root else None
        )
        resolver = CapabilityResolver()
        caps = resolver.resolve(operator_policy)
        # The ceiling is the policy's tool classes unless the operator names the
        # tools explicitly (e.g. every registered handler).
        self._operator_allowed: frozenset[str] = (
            caps.allowed_tools if operator_allowed is None else frozenset(operator_allowed))
        # Operator GovernanceConfig, fixed at startup like operator_policy.
        self._governance = governance
        # L4: the operator's confirmation endpoint (axor_daemon.confirm.ConfirmChannel).
        # Without it no call is ever confirmed (the grant gate stays a denial).
        self._confirm = confirm

    def open_session(self, task: str | None = None,
                     session_id: str | None = None) -> DaemonSession:
        """State for one connection. ``task`` is the user's request as the client
        reports it; it seeds the trusted-origin index (context integrity) and the
        L1 request grants. It is client-asserted: a compromised agent process can
        lie about it, which widens L1 to whatever it claims — the operator ceiling,
        templates and the floor are unaffected."""
        if self._governance is None:
            return DaemonSession()
        if self._journal is not None:
            return self._open_journaled(task, session_id)
        if session_id is not None:
            raise SessionRejected("this daemon keeps no journal: a session cannot be resumed")
        from axor_core.governor import ToolCallGovernor

        kw = self._governance.as_governor_kwargs()
        confirmer = None
        if self._confirm is not None:
            confirmer = kw["confirmer"] = self._confirm.confirmer(task)
        g = ToolCallGovernor(**kw)
        if task:
            g.register_task(task)
            if self._governance.grant_args:
                g.grants.from_request(task)
        return DaemonSession(governor=g, confirmer=confirmer)

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
        # What is checked is what runs: one private copy, decided on and executed.
        safe_args = copy.deepcopy(safe_args)

        if session is None:
            return await self._decide_and_run(call_id, tool, handler, safe_args, None)
        async with session.lock:
            if session.session_id is not None:
                return await self._decide_and_run_journaled(call_id, tool, handler, safe_args,
                                                            session)
            return await self._decide_and_run(call_id, tool, handler, safe_args, session)

    # ── --journal ───────────────────────────────────────────────────────────────
    def close_session(self, session: DaemonSession | None) -> None:
        if session is not None and session.session_id is not None:
            self._live.discard(session.session_id)

    def _governor(self, task: str | None, seed: int | None = None):
        from axor_core.governor import ToolCallGovernor

        kw = self._governance.as_governor_kwargs()
        confirmer = None
        if self._confirm is not None:
            confirmer = kw["confirmer"] = self._confirm.confirmer(task)
        if seed is not None:
            kw["references_seed"] = seed
        return ToolCallGovernor(**kw), confirmer

    def _open_journaled(self, task: str | None, session_id: str | None) -> DaemonSession:
        from axor_daemon.durable import (
            apply_state, capture, install_store, mint_rows, restore_store,
        )
        from axor_daemon.journal import DurableDedup

        J = self._journal
        if session_id is None:  # a new session: the request is minted once, here
            sid = secrets.token_hex(16)
            g, confirmer = self._governor(task)
            if task:
                g.register_task(task)
                if self._governance.grant_args:
                    g.grants.from_request(task)
            s = DaemonSession(governor=g, confirmer=confirmer, session_id=sid,
                              dedup=DurableDedup(J, sid))
            rows = mint_rows(g.grant_store, s.journaled)
            s.snapshot = capture(g, confirmer)
            J.new_session(sid, task or "", self._config_sha256, rows)  # fsync before ready
            self._live.add(sid)
            return s

        row = J.session(session_id)
        if row is None:
            raise SessionRejected("unknown session")
        if session_id in self._live:
            raise SessionRejected("session in use by another connection")
        if row["config_sha256"] != self._config_sha256:
            raise SessionRejected("the daemon's governance changed since this session started")
        if task is not None and task != row["task"]:
            raise SessionRejected("a resumed session keeps its request")
        # a new reference seed: names issued before the restart are retired, not reissued
        g, confirmer = self._governor(row["task"] or None, seed=secrets.randbits(64))
        if row["task"]:
            g.register_task(row["task"])  # trusted origin only: never from_request again
        trs = J.transitions(session_id)
        store = restore_store(trs)
        install_store(g, store)
        retired = apply_state(g, confirmer, trs)
        s = DaemonSession(governor=g, confirmer=confirmer, session_id=session_id,
                          journaled={x.id for x in store.grants()}, retired=retired,
                          dedup=DurableDedup(J, session_id))
        # an outcome left unknown by the crash: the handlers' log decides, never a retry
        settled_unknown = {b["key"] for _, k, b in trs if k == "settle" and b["outcome"] == "unknown"}
        rows = []
        for r in store.reservations():
            if r.state.value != "reserved":
                continue
            state = store.reconcile(r.key, s.dedup.executed)
            outcome = {"committed": "executed", "released": "void"}.get(state.value, "unknown")
            if outcome != "unknown" or r.key not in settled_unknown:
                rows.append(("settle", {"key": r.key, "outcome": outcome, "via": "reconcile"}))
        J.tx(session_id, rows)
        s.snapshot = capture(g, confirmer)
        self._live.add(session_id)
        return s

    def _journal_state(self, s: DaemonSession, rows: list) -> list:
        from axor_daemon.durable import capture, mint_rows, state_rows

        rows = list(rows) + mint_rows(s.governor.grant_store, s.journaled)
        cur = capture(s.governor, s.confirmer)
        rows += state_rows(s.snapshot, cur)
        s.snapshot = cur
        return rows

    async def _decide_and_run_journaled(self, call_id: str, tool: str, handler: ToolHandler,
                                        safe_args: dict[str, Any], s: DaemonSession
                                        ) -> tuple[str, Any, str | None]:
        """``_decide_and_run`` with every transition on disk before what depends on it:
        the reserve before the handler runs, the effect's start and end around it, the
        settle after, and the session state (floor_armed first) before the output
        reaches the agent."""
        from axor_core.capability.grant_store import NotRun
        from axor_daemon.durable import reservation_body, retired_reference

        J, sid, gov = self._journal, s.session_id, s.governor
        if s.terminated:
            return "denied", None, _TERMINATED
        hit = retired_reference(safe_args, s.retired)
        if hit is not None:
            return ("denied", None, f"governance (reference_unknown): reference {hit!r} was "
                                    "issued before the daemon restarted; it is not reissued")
        if self._confirm is not None:
            decision = await asyncio.to_thread(gov.evaluate, tool, safe_args)
        else:
            decision = gov.evaluate(tool, safe_args)
        rows = self._journal_state(s, [])  # an L4 grant or refusal, written files
        if not decision.allowed:
            J.tx(sid, rows)
            if s.terminated:
                return "denied", None, _TERMINATED
            return "denied", None, f"governance ({decision.category}): {decision.reason}"
        if getattr(decision, "resolved_args", None) is not None:
            safe_args = copy.deepcopy(decision.resolved_args)
        store = gov.grant_store
        if decision.grant_id is not None and call_id:
            prior = next((r for r in store.reservations() if r.call_key == call_id), None)
            if prior is not None:  # a retried call: its spend is decided, never re-run
                J.tx(sid, rows)
                return ("denied", None, f"governance (grant_gate): call {call_id!r} already holds "
                                        f"spend {prior.key} ({prior.state.value}); not run again")
        spend = gov.spend(decision, safe_args, call_key=call_id or None)
        if decision.grant_id is not None and spend is None:
            J.tx(sid, rows)
            return "denied", None, "governance (grant_gate): the grant was used up concurrently"
        if spend is not None:
            rows.append(("reserve", reservation_body(store, spend, tool, safe_args)))
        J.tx(sid, rows)                                   # reserve on disk before dispatch
        _crash("after_reserve")
        if spend is not None:
            s.dedup.started(spend, tool)                  # before the effect
        try:
            result = await asyncio.wait_for(
                handler.execute(copy.deepcopy(safe_args)), timeout=self._exec_timeout)
        except NotRun as exc:
            if spend is not None:
                s.dedup.not_run(spend)
                store.release(spend)
                J.tx(sid, [("settle", {"key": spend, "outcome": "void", "via": "handler"})])
            return "denied", None, f"handler '{tool}' did not run: {exc}"
        except Exception as exc:  # timeout or error: the outcome is unknown, never retried
            if spend is not None:
                state = store.reconcile(spend, s.dedup.executed)
                outcome = {"committed": "executed", "released": "void"}.get(state.value, "unknown")
                J.tx(sid, [("settle", {"key": spend, "outcome": outcome, "via": "reconcile"})])
            reason = (f"handler '{tool}' exceeded exec_timeout ({self._exec_timeout}s)"
                      if isinstance(exc, asyncio.TimeoutError) else
                      f"handler '{tool}' failed: {type(exc).__name__}")
            return "denied", None, reason
        if spend is not None:
            s.dedup.done(spend)                           # after the effect
        _crash("after_execute")
        if spend is not None:
            store.commit(spend)
            J.tx(sid, [("settle", {"key": spend, "outcome": "executed", "via": "handler"})])
        _crash("after_settle")

        out = result if isinstance(result, str) else repr(result)
        raw = result
        if getattr(gov, "_xrefs", None) is not None:
            result = gov.present_output(decision, out)
        else:
            gov.register_output(decision, out)
        if getattr(gov, "_delegated", None):
            gov.observe_delegated(tool, safe_args, out)
        desc = getattr(gov, "_desc", None)
        if self._structured is not None and desc is not None and tool in desc.sources:
            value = self._structured(tool, raw)
            if value is not None:
                gov.observe_structured(tool, safe_args, value)
        rows = self._journal_state(s, [])
        J.tx(sid, rows)                                   # floor_armed before the output leaves
        if any(k == "floor_armed" for k, _ in rows):
            _crash("after_floor")
        return "approved", result, None

    async def _decide_and_run(self, call_id: str, tool: str, handler: ToolHandler,
                              safe_args: dict[str, Any], session: DaemonSession | None
                              ) -> tuple[str, Any, str | None]:
        gov = session.governor if session is not None else None
        decision = spend = None
        if session is not None and session.terminated:
            return "denied", None, _TERMINATED
        if gov is not None:
            if self._confirm is not None:
                # the confirmer waits on the event loop for the operator: run the
                # (synchronous) evaluate off-loop; the session lock is still held
                decision = await asyncio.to_thread(gov.evaluate, tool, safe_args)
            else:
                decision = gov.evaluate(tool, safe_args)
            if not decision.allowed:
                if session is not None and session.terminated:
                    return "denied", None, _TERMINATED
                reason = f"governance ({decision.category}): {decision.reason}"
                _log.info("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
                return "denied", None, reason
            # MODEL.md §9: with references on, the tool runs on the resolved values; the
            # reference table never leaves this session
            if getattr(decision, "resolved_args", None) is not None:
                safe_args = copy.deepcopy(decision.resolved_args)
            spend = gov.spend(decision, safe_args, call_key=call_id or None)
            if decision.grant_id is not None and spend is None:
                reason = "governance (grant_gate): the grant was used up concurrently"
                return "denied", None, reason

        try:
            result = await asyncio.wait_for(
                handler.execute(copy.deepcopy(safe_args)), timeout=self._exec_timeout
            )
        except asyncio.TimeoutError:
            reason = f"handler '{tool}' exceeded exec_timeout ({self._exec_timeout}s)"
            _log.error("DENIED call_id=%s tool=%s: %s", call_id, tool, reason)
            return "denied", None, reason  # a reserved grant use stays spent

        if gov is not None:
            if spend is not None:
                gov.grant_store.commit(spend)
            out = result if isinstance(result, str) else repr(result)
            raw = result
            if getattr(gov, "_xrefs", None) is not None:
                result = gov.present_output(decision, out)  # the agent sees references
            else:
                gov.register_output(decision, out)
            # the same order as the in-process gate (axor_*/gate.py Gate.finish)
            if getattr(gov, "_delegated", None):
                gov.observe_delegated(tool, safe_args, out)  # MODEL.md 9.16, off unless configured
            desc = getattr(gov, "_desc", None)
            if self._structured is not None and desc is not None and tool in desc.sources:
                value = self._structured(tool, raw)
                if value is not None:
                    gov.observe_structured(tool, safe_args, value)

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
        # an empty value names no path: normpath would turn "" into "." and run a
        # different call than the agent proposed
        if key in _PATH_ARG_KEYS and isinstance(value, str) and value:
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
