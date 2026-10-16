"""Restoring a daemon session from the journal (journal.py) without touching the kernel.

A session survives a daemon restart as:

* its ``GrantStore`` — rebuilt from the ``mint`` / ``reserve`` / ``settle`` transitions;
* the session state whose loss would WEAKEN a check (journaled as flags, counters and
  sets — never tool outputs):
    floor_armed       the confidentiality floor (restored armed and sticky)
    context           the sources of the context root (taint/engine.py:110)
    ledger            the value ledger held tainted / sensitive values: restored as
                      SATURATED (taint/ledger.py:83) — every value derives untrusted,
                      fail-closed, since the fragments themselves are tool output
    written_files     the normalizer's written paths (executes_generated_code)
    desc_done / delegated_done   description / delegated grants already issued
    ref_names         every reference name the session issued: the new table gets a
                      new seed, and a call naming a retired name is refused before
                      evaluate (a new name may collide with an old one)
    l4                the operator-confirmation limits (asked, refusals, refused
                      calls as sha256, terminated)
* the request (``sessions.task``): ``register_task`` again, never ``from_request``.

State whose loss only adds refusals is not journaled (the reference values, the
trusted-origin index, ``_described``, the description observations, handles, trace).

The kernel is not changed, so this module writes a few of its private fields. They
are checked at daemon start (``check_kernel``) and the restore is tested against the
live store (tests/test_journal_restore.py).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from decimal import Decimal
from typing import Any

from axor_core.kernel.grants import (
    ArgConstraint, ConstraintKind, Grant, GrantStore, Reservation, SpendState,
)
from axor_core.kernel.handles import TrustedChannel

GRANT_FIELDS = ("id", "task", "sink", "constraints", "uses", "source", "expiry", "note",
                "call_digest", "grant_args", "call_canonical", "list_union")


def sha256(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     default=str).encode()).hexdigest()


# ── grants ─────────────────────────────────────────────────────────────────────────
def grant_to_json(g: Grant) -> dict:
    return {
        "id": g.id, "task": g.task, "sink": g.sink,
        "constraints": {a: {"kind": c.kind.value, "handle_kind": c.handle_kind,
                            "values": sorted(c.values),
                            "limit": None if c.limit is None else str(c.limit),
                            "optional": c.optional}
                        for a, c in g.constraints.items()},
        "uses": g.uses, "source": g.source.value, "expiry": g.expiry, "note": g.note,
        "call_digest": g.call_digest,
        "grant_args": None if g.grant_args is None else dict(g.grant_args),
        "call_canonical": g.call_canonical,
        "list_union": {a: sorted(v) for a, v in (g.list_union or {}).items()},
    }


def grant_from_json(d: dict) -> Grant:
    return Grant(
        id=d["id"], task=d["task"], sink=d["sink"],
        constraints={a: ArgConstraint(ConstraintKind(c["kind"]), c["handle_kind"],
                                      frozenset(c["values"]),
                                      None if c["limit"] is None else Decimal(c["limit"]),
                                      c["optional"])
                     for a, c in d["constraints"].items()},
        uses=d["uses"], source=TrustedChannel(d["source"]), expiry=d["expiry"], note=d["note"],
        call_digest=d["call_digest"], grant_args=d["grant_args"], call_canonical=d["call_canonical"],
        list_union={a: frozenset(v) for a, v in d["list_union"].items()},
    )


def reservation_body(store: GrantStore, key: str, tool: str, args: dict) -> dict:
    r = next(r for r in store.reservations() if r.key == key)
    return {"key": r.key, "grant_id": r.grant_id, "call_key": r.call_key,
            "value_key": r.value_key, "at": r.at, "tool": tool, "args_sha256": sha256(args)}


def restore_store(transitions: list[tuple[int, str, dict]]) -> GrantStore:
    """The ``GrantStore`` the journal describes: mints in issue order, every reservation
    with the use it took, every settle applied; RESERVED stays RESERVED."""
    st = GrantStore()
    for _seq, kind, b in transitions:
        if kind == "mint":
            st._issue(grant_from_json(b["grant"]))
        elif kind == "reserve":
            s = st._slots[b["grant_id"]]
            vk, g = b["value_key"], s.grant
            if vk is not None and g.uses is not None:
                s.by_value[vk] = s.by_value.get(vk, g.uses) - 1
            elif s.remaining is not None:
                s.remaining -= 1
            s.spends += 1
            if b["key"] != f"{b['grant_id']}#{s.spends}":
                raise ValueError(f"journal: reservation {b['key']} out of order")
            st._res[b["key"]] = Reservation(b["key"], b["grant_id"], b["call_key"],
                                            SpendState.RESERVED, b["at"], value_key=vk)
            if b["call_key"] is not None:
                st._by_call[b["call_key"]] = b["key"]
        elif kind == "settle":
            if st.state(b["key"]) is SpendState.RESERVED:
                if b["outcome"] == "executed":
                    st.commit(b["key"])
                elif b["outcome"] == "void":
                    st.release(b["key"])
    nums = [int(gid.rsplit("-", 1)[1]) for gid in st._order if gid.rsplit("-", 1)[-1].isdigit()]
    st._next = max(nums, default=0)
    return st


def install_store(gov: Any, store: GrantStore) -> None:
    """Replace the governor's store (the one its minter mints into) with ``store``."""
    gov._grants = store
    gov._minter.store = store


def mint_rows(store: GrantStore, journaled: set[str]) -> list:
    rows = []
    for g in store.grants():
        if g.id not in journaled:
            rows.append(("mint", {"grant": grant_to_json(g)}))
            journaled.add(g.id)
    return rows


# ── session state ───────────────────────────────────────────────────────────────────
def _ref_name(n: Any) -> list:
    return ["i", n] if isinstance(n, int) else ["s", str(n)]


def capture(gov: Any, confirmer: Any = None) -> dict:
    t = gov._taint
    any_tainted, any_sensitive = t.session_shadow()
    out = {
        "floor": bool(gov.confidentiality_floor_active()),
        "context": sorted(s.value for s in t.context_root().sources),
        "ledger": bool(any_tainted or any_sensitive),
        "written_files": sorted(gov._normalizer._written_files),
        "desc_done": sorted(json.dumps(k, default=str) for k in gov._desc_done),
        "delegated_done": sorted(json.dumps(k, default=str) for k in gov._delegated_done),
        "ref_names": sorted(json.dumps(_ref_name(n)) for n in
                            (gov._xrefs.by_name if gov._xrefs is not None else {})),
    }
    if confirmer is not None:
        out["l4"] = {"asked": confirmer.asked, "refusals": confirmer.refusals,
                     "terminated": bool(confirmer.terminated), "refused": sorted(confirmer._refused)}
    return out


_SETS = ("written_files", "desc_done", "delegated_done", "ref_names")


def state_rows(prev: dict, cur: dict) -> list:
    rows = []
    if cur["floor"] and not prev["floor"]:
        rows.append(("floor_armed", {}))
    if cur["context"] != prev["context"]:
        rows.append(("state", {"field": "context", "value": cur["context"]}))
    if cur["ledger"] and not prev["ledger"]:
        rows.append(("state", {"field": "ledger", "value": True}))
    for f in _SETS:
        new = sorted(set(cur[f]) - set(prev[f]))
        if new:
            rows.append(("state", {"field": f, "add": new}))
    if cur.get("l4") is not None and cur.get("l4") != prev.get("l4"):
        rows.append(("state", {"field": "l4", "value": cur["l4"]}))
    return rows


def _tupled(x: Any) -> Any:
    return tuple(_tupled(v) for v in x) if isinstance(x, list) else x


def apply_state(gov: Any, confirmer: Any, transitions: list[tuple[int, str, dict]]) -> set:
    """Put the journaled state back on a fresh governor; returns the retired reference
    names (as ``("i", int)`` / ``("s", str)``)."""
    from axor_core.contracts.taint import TaintSource
    from axor_core.taint.causal_root import CausalRoot

    t = gov._taint
    retired: set = set()
    for _seq, kind, b in transitions:
        if kind == "floor_armed":
            t._floor_saturated = True  # sticky: nothing in the daemon releases it
        elif kind != "state":
            continue
        elif b["field"] == "context":
            t._context_root = CausalRoot(sources=frozenset(TaintSource(v) for v in b["value"]))
        elif b["field"] == "ledger":
            t._ledger._saturated = True  # fail-closed: every value derives untrusted
        elif b["field"] == "written_files":
            gov._normalizer._written_files.update(b["add"])
        elif b["field"] == "desc_done":
            gov._desc_done.update(_tupled(json.loads(k)) for k in b["add"])
        elif b["field"] == "delegated_done":
            gov._delegated_done.update(_tupled(json.loads(k)) for k in b["add"])
        elif b["field"] == "ref_names":
            retired.update(tuple(json.loads(k)) for k in b["add"])
        elif b["field"] == "l4" and confirmer is not None:
            v = b["value"]
            confirmer.asked, confirmer.refusals = v["asked"], v["refusals"]
            confirmer.terminated = v["terminated"]
            confirmer._refused = set(v["refused"])
    return retired


def retired_reference(args: Any, retired: set) -> Any:
    """The first retired reference name the call carries, read as the kernel reads
    references (kernel/references.py ``ReferenceTable.resolve``); None if none."""
    if not retired:
        return None
    from axor_core.kernel.references import ID_KEYS, INT_RANGE, NAME

    def go(x: Any, key: str | None) -> Any:
        if isinstance(x, dict):
            for k, v in x.items():
                hit = go(v, k)
                if hit is not None:
                    return hit
        elif isinstance(x, (list, tuple)):
            for v in x:
                hit = go(v, key)
                if hit is not None:
                    return hit
        elif isinstance(x, bool) or x is None:
            return None
        elif isinstance(x, int):
            if key in ID_KEYS and INT_RANGE[0] <= x < INT_RANGE[1] and ("i", x) in retired:
                return x
        elif isinstance(x, str):
            if ("s", x) in retired:
                return x
            for m in NAME.finditer(x):
                if ("s", m.group(0)) in retired:
                    return m.group(0)
        return None
    return go(args, None)


# ── the kernel internals this module relies on ─────────────────────────────────────
def check_kernel(governor_kwargs: dict) -> None:
    """Fail at daemon start, not at the first restore, if the kernel's private shape
    this module writes has changed."""
    from axor_core.governor import ToolCallGovernor

    problems = []
    st = GrantStore()
    for a in ("_issue", "_slots", "_order", "_res", "_by_call", "_next"):
        if not hasattr(st, a):
            problems.append(f"GrantStore.{a}")
    fields = {f.name for f in dataclasses.fields(Grant)}
    if fields != set(GRANT_FIELDS):
        problems.append(f"Grant fields {sorted(fields ^ set(GRANT_FIELDS))}")
    for cls, names in ((Reservation, {"key", "grant_id", "call_key", "state", "at", "value_key"}),):
        if not names <= {f.name for f in dataclasses.fields(cls)}:
            problems.append(cls.__name__)
    kw = {k: v for k, v in governor_kwargs.items() if k != "confirmer"}
    g = ToolCallGovernor(**kw)
    checks = [(g, "_grants"), (g, "_minter"), (g, "_desc_done"), (g, "_delegated_done"),
              (g, "_normalizer"), (g, "_taint"), (g, "_xrefs")]
    for obj, a in checks:
        if not hasattr(obj, a):
            problems.append(f"ToolCallGovernor.{a}")
    if not problems:
        for obj, a in ((g._minter, "store"), (g._normalizer, "_written_files"),
                       (g._taint, "_floor_saturated"), (g._taint, "_context_root"),
                       (g._taint, "_ledger"), (g._taint._ledger, "_saturated")):
            if not hasattr(obj, a):
                problems.append(f"{type(obj).__name__}.{a}")
    if problems:
        raise RuntimeError("--journal: the installed axor-core does not have the internals the "
                           "journal restores into: " + ", ".join(problems))
