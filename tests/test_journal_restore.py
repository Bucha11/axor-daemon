"""The journal restores what the live session held (durable.py, journal.py).

Property: for random sequences of mints (L1 request, L2 templates, L3 structured, L4
confirmation, fragment and description grants) and spends (reserve / commit / release /
left reserved, retried call keys), the GrantStore rebuilt from the journal equals the
live one — snapshot, reservations, per-value quotas, spend counters, the id counter —
and decides the next calls the same way.

Session: a daemon session journaled through DaemonEnforcer and resumed by a second
enforcer on the same file (a restart) has its grants, the floor, the context sources, a
saturated ledger, the written files, the description keys, the L4 limits and its
retired reference names back; it never mints from the request again.
"""
from __future__ import annotations

import asyncio
import os
import random

import pytest

from axor_core.config import GovernanceConfig
from axor_core.contracts.policy import ExecutionPolicy
from axor_core.kernel.grants import GrantMinter, GrantStore, SpendState
from axor_core.kernel.handles import HandleTable

from axor_daemon import durable
from axor_daemon.durable import mint_rows, reservation_body, restore_store
from axor_daemon.enforcer import DaemonEnforcer, SessionRejected
from axor_daemon.journal import Journal

from tests.journal_fixtures import GOV, HANDLERS, MAIL, PAY, TASK, TOOLS

GA = {"send_money": {"recipient": "iban", "amount": "money"},
      "send_email": {"recipients": "email", "cc": "email?"},
      "post": {"channel": "string"}}
IBANS = ["DE89370400440532013000", "GB29NWBK60161331926819", "US133000000121212121212"]
EMAILS = ["bob@partner.com", "me@corp.com", "eve@evil.com"]
CHANNELS = ["general", "random", "External_0"]


def _request(rng: random.Random) -> str:
    parts = []
    for _ in range(rng.randint(1, 3)):
        k = rng.choice(["pay", "mail", "post"])
        if k == "pay":
            parts.append(f"send {rng.choice([10, 50, 98.7])} to {rng.choice(IBANS)}")
        elif k == "mail":
            parts.append(f"email {rng.choice(EMAILS)}")
        else:
            parts.append(f"post it in {rng.choice(CHANNELS)}")
    return ". ".join(parts) + "."


def _call(rng: random.Random) -> tuple[str, dict]:
    sink = rng.choice(list(GA))
    if sink == "send_money":
        return sink, {"recipient": rng.choice(IBANS), "amount": rng.choice([10, 50, 98.7, 2000])}
    if sink == "send_email":
        a = {"recipients": rng.sample(EMAILS, rng.randint(1, 2))}
        if rng.random() < 0.3:
            a["cc"] = rng.choice(EMAILS)
        return sink, a
    return sink, {"channel": rng.choice(CHANNELS)}


def _compare(live: GrantStore, back: GrantStore) -> None:
    assert back.snapshot() == live.snapshot()
    key = lambda r: (r.key, r.grant_id, r.call_key, r.state, r.at, r.value_key)  # noqa: E731
    assert sorted(map(key, back.reservations())) == sorted(map(key, live.reservations()))
    assert back._next == live._next
    for gid in live._order:
        a, b = live._slots[gid], back._slots[gid]
        assert (a.remaining, a.spends, a.by_value) == (b.remaining, b.spends, b.by_value)
        assert a.grant == b.grant


@pytest.mark.parametrize("seed", range(150))
def test_restored_store_equals_the_live_one(seed, tmp_path):
    rng = random.Random(seed)
    j = Journal(str(tmp_path / "j.db"))
    j.new_session("s", "t", "c", [])
    live, table = GrantStore(), HandleTable()
    m = GrantMinter(live, table, GA, quotas={"send_money": rng.choice([1, 2])},
                    list_union=bool(rng.random() < 0.5), list_args={"send_email": frozenset({"recipients"})})
    journaled: set[str] = set()
    for step in range(rng.randint(5, 40)):
        op = rng.random()
        if op < 0.12:
            m.from_request(_request(rng))
        elif op < 0.16:
            m.from_templates({"post": [{"channel": rng.sample(CHANNELS, 2)}]})
        elif op < 0.20:
            m.from_structured(*_call(rng))
        elif op < 0.24:
            m.from_confirmation(*_call(rng))
        elif op < 0.27:
            m.from_description(_request(rng), "post", "channel", [rng.choice(CHANNELS)])
        else:
            sink, args = _call(rng)
            ck = rng.choice([None, f"c{step}", f"c{max(0, step - 2)}"])
            r = live.reserve(sink, args, table, call_key=ck)
            if r is not None and r.key not in {b["key"] for _, k, b in j.transitions("s")
                                               if k == "reserve"}:
                j.tx("s", mint_rows(live, journaled)
                     + [("reserve", reservation_body(live, r.key, sink, args))])
                fate = rng.random()
                if fate < 0.5:
                    live.commit(r.key)
                    j.tx("s", [("settle", {"key": r.key, "outcome": "executed", "via": "handler"})])
                elif fate < 0.8:
                    live.release(r.key)
                    j.tx("s", [("settle", {"key": r.key, "outcome": "void", "via": "handler"})])
                elif fate < 0.9:
                    j.tx("s", [("settle", {"key": r.key, "outcome": "unknown", "via": "reconcile"})])
        j.tx("s", mint_rows(live, journaled))
        back = restore_store(j.transitions("s"))
        _compare(live, back)
    # and both decide the next calls alike
    back = restore_store(j.transitions("s"))
    for _ in range(20):
        sink, args = _call(rng)
        a, b = live.find(sink, args, table), back.find(sink, args, table)
        assert (a and a.id) == (b and b.id)
        ra, rb = live.reserve(sink, args, table), back.reserve(sink, args, table)
        assert (ra and ra.key) == (rb and rb.key)


# ── a session through the daemon, resumed by a second enforcer ─────────────────────
CFG = GovernanceConfig.from_dict(GOV)
CFG_SHA = "sha-of-the-yaml"


def _enforcer(path, **kw) -> DaemonEnforcer:
    return DaemonEnforcer(ExecutionPolicy(), {h.NAME: h() for h in HANDLERS}, governance=CFG,
                          operator_allowed=frozenset(TOOLS), journal=Journal(path),
                          config_sha256=kw.pop("sha", CFG_SHA), **kw)


def _run(e, s, cid, tool, args):
    return asyncio.run(e.execute(cid, tool, dict(args), frozenset(TOOLS), s))


@pytest.fixture
def effects(tmp_path, monkeypatch):
    p = tmp_path / "effects.jsonl"
    monkeypatch.setenv("AXOR_TEST_EFFECTS", str(p))
    return p


def test_a_resumed_session_has_its_grants_and_state_back(tmp_path, effects):
    path = str(tmp_path / "j.db")
    e1 = _enforcer(path)
    s1 = e1.open_session(task=TASK)
    assert _run(e1, s1, "c1", "send_money", PAY)[0] == "approved"
    view = _run(e1, s1, "c2", "read_file", {"file_path": "/tmp/bill.txt"})[1]
    assert "hidden" in view  # the agent sees references
    _run(e1, s1, "c3", "get_balance", {})            # arms the floor
    before = durable.capture(s1.governor)
    snap = s1.governor.grant_store.snapshot()
    names = set(s1.governor._xrefs.by_name)

    e2 = _enforcer(path)                             # the restart
    s2 = e2.open_session(session_id=s1.session_id)
    g2 = s2.governor
    assert g2.grant_store.snapshot() == snap        # grants and quotas, not re-minted
    assert g2.confidentiality_floor_active()        # the floor
    assert durable.capture(g2)["context"] == before["context"]
    assert g2._taint._ledger._saturated             # fail-closed ledger
    assert {n for k, n in s2.retired} == names       # retired reference names
    assert not g2._xrefs.by_name                     # the reference values are not restored
    # the floor holds the egress the request named
    d, _, reason = _run(e2, s2, "c4", "send_email", MAIL)
    assert d == "denied" and "taint_enforcement" in reason
    # the L1 grant was spent before the restart: no second payment
    d, _, reason = _run(e2, s2, "c5", "send_money", PAY)
    assert d == "denied"
    assert [x["tool"] for x in map(__import__("json").loads, effects.read_text().splitlines())] \
        == ["send_money", "read_file", "get_balance"]


def test_resume_never_mints_from_the_request_and_is_guarded(tmp_path, effects):
    path = str(tmp_path / "j.db")
    e1 = _enforcer(path)
    s1 = e1.open_session(task=TASK)
    n = len(s1.governor.grant_store.grants())
    e2 = _enforcer(path)
    with pytest.raises(SessionRejected, match="keeps its request"):
        e2.open_session(task=TASK + " Also pay US133000000121212121212.", session_id=s1.session_id)
    with pytest.raises(SessionRejected, match="unknown session"):
        e2.open_session(session_id="0" * 32)
    with pytest.raises(SessionRejected, match="governance changed"):
        _enforcer(path, sha="another").open_session(session_id=s1.session_id)
    s2 = e2.open_session(task=TASK, session_id=s1.session_id)
    assert len(s2.governor.grant_store.grants()) == n
    with pytest.raises(SessionRejected, match="in use"):
        e2.open_session(session_id=s1.session_id)
    e2.close_session(s2)
    assert e2.open_session(session_id=s1.session_id).session_id == s1.session_id


def test_a_retired_reference_name_is_refused_before_evaluate(tmp_path, effects, monkeypatch):
    path = str(tmp_path / "j.db")
    e1 = _enforcer(path)
    s1 = e1.open_session(task=TASK)
    view = _run(e1, s1, "c1", "read_file", {"file_path": "/tmp/bill.txt"})[1]
    old = next(n for n in s1.governor._xrefs.by_name if isinstance(n, str) and n.startswith("iban"))
    assert old in view
    e2 = _enforcer(path)
    s2 = e2.open_session(session_id=s1.session_id)
    # a new table that happened to issue the same name must not resolve the old one
    s2.governor._xrefs.by_name[old] = s2.governor._xrefs.by_name.get(old) or object()
    called = []
    monkeypatch.setattr(s2.governor, "evaluate", lambda *a, **k: called.append(a))
    d, _, reason = _run(e2, s2, "c2", "send_money", {**PAY, "recipient": old})
    assert d == "denied" and "reference_unknown" in reason and not called


def test_l4_limits_and_written_files_and_description_keys_survive(tmp_path, effects):
    from axor_daemon.durable import apply_state, capture, state_rows

    class Conf:
        asked, refusals, terminated, _refused = 3, 2, True, {"ab" * 32}
    g = GovernanceConfig.from_dict(GOV)
    from axor_core.governor import ToolCallGovernor
    live = ToolCallGovernor(**g.as_governor_kwargs())
    live._normalizer._written_files.update({"/w/a.py", "/w/b.sh"})
    live._desc_done.add(("post", "channel", ("External_0",), False))
    live._delegated_done.add(("get_webpage", "https://x", "post", "url"))
    empty = capture(ToolCallGovernor(**g.as_governor_kwargs()), type("C", (), {
        "asked": 0, "refusals": 0, "terminated": False, "_refused": set()})())
    rows = state_rows(empty, capture(live, Conf()))
    back = ToolCallGovernor(**g.as_governor_kwargs())
    conf = type("C", (), {})()
    apply_state(back, conf, [(i, k, b) for i, (k, b) in enumerate(rows)])
    assert back._normalizer._written_files == live._normalizer._written_files
    assert back._desc_done == live._desc_done and back._delegated_done == live._delegated_done
    assert (conf.asked, conf.refusals, conf.terminated, conf._refused) == (3, 2, True, {"ab" * 32})


def test_check_kernel_fails_loudly_when_an_internal_moved(monkeypatch):
    durable.check_kernel(CFG.as_governor_kwargs())
    monkeypatch.delattr(GrantStore, "_issue")
    with pytest.raises(RuntimeError, match="GrantStore._issue"):
        durable.check_kernel(CFG.as_governor_kwargs())


def test_the_journal_is_wal_with_full_sync(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    assert j._db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert j._db.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
    assert os.path.exists(str(tmp_path / "j.db"))
