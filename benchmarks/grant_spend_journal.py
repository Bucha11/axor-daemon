"""E4 through the daemon with --journal: does O5 hold when every spend is on disk?

The counterpart of axor-core's ``benchmarks/grant_spend.py`` (the in-process store), run
on the daemon's own path (``DaemonEnforcer.execute`` with a ``Journal``):

  race     N concurrent calls (asyncio.gather) on one session at a request grant with
           ``uses`` = k. Pass: effects == k exactly; the journal holds k reserves and k
           ``executed`` settles; no spend key reaches the handler twice.
  faults   each call's handler may refuse before any effect (NotRun), raise after the
           effect, or hang past exec_timeout. Pass: no key re-run, effects <= uses, every
           NotRun ends ``void`` (released), and an outcome nobody can report stays
           RESERVED (``unknown``) — counted, never retried.
  latency  p50 / p99 of one granted call through the enforcer, with the journal (four
           fsyncs: reserve, dedup started, dedup done, settle) and without.

    python benchmarks/grant_spend_journal.py [--quick]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import random
import sqlite3
import statistics
import sys
import tempfile
import time

from axor_core.capability.executor import ToolHandler
from axor_core.capability.grant_store import NotRun
from axor_core.config import GovernanceConfig
from axor_core.contracts.policy import ExecutionPolicy

from axor_daemon.enforcer import DaemonEnforcer
from axor_daemon.journal import Journal

IBAN = "GB29NWBK60161331926819"
CALL = {"recipient": IBAN, "amount": 100}
TOOLS = frozenset({"send_money"})


def _gov(uses: int) -> GovernanceConfig:
    return GovernanceConfig.from_dict({
        "egress_sinks": ["send_money"], "driving_args": {"send_money": ["recipient", "amount"]},
        "grant_args": {"send_money": {"recipient": "iban", "amount": "money"}},
        "grant_quotas": {"send_money": uses},
        "consequence_overrides": {"send_money": "consequential"},
    })


class Effect(ToolHandler):
    """Counts effects; with ``faults`` it may refuse (NotRun) before the effect, raise
    after it, or hang past the timeout after it."""

    def __init__(self, faults: dict[str, float] | None = None, seed: int = 0) -> None:
        self.faults, self.rng = faults or {}, random.Random(seed)
        self.effects = 0

    @property
    def name(self) -> str:
        return "send_money"

    async def execute(self, args: dict) -> str:
        roll, acc = self.rng.random(), 0.0
        fate = "ok"
        for k, p in self.faults.items():
            acc += p
            if roll < acc:
                fate = k
                break
        if fate == "refuse":
            raise NotRun("refused before any effect")
        self.effects += 1
        if fate == "after":
            raise RuntimeError("died after the effect")
        if fate == "hang":
            await asyncio.sleep(10)
        return "sent"


def _enforcer(uses: int, handler: Effect, journal_path: str | None, timeout: float = 60.0):
    j = Journal(journal_path) if journal_path else None
    e = DaemonEnforcer(ExecutionPolicy(), {"send_money": handler}, governance=_gov(uses),
                       operator_allowed=TOOLS, journal=j, config_sha256="bench",
                       exec_timeout=timeout)
    return e, j


def _rows(path: str, sid: str) -> list[tuple[str, str]]:
    with sqlite3.connect(path) as c:
        return c.execute("SELECT kind, body FROM transitions WHERE session_id=?", (sid,)).fetchall()


async def _one(trial: int, n: int, uses: int, tmp: str, faults=None, timeout=60.0) -> dict:
    path = os.path.join(tmp, f"t{trial}.db")
    h = Effect(faults, seed=trial)
    e, j = _enforcer(uses, h, path, timeout)
    s = e.open_session(task=f"send 100 to {IBAN}")
    outs = await asyncio.gather(*(e.execute(f"c{i}", "send_money", dict(CALL), TOOLS, s)
                                  for i in range(n)))
    rows = _rows(path, s.session_id)
    j.close()
    reserves = [json.loads(b)["key"] for k, b in rows if k == "reserve"]
    settles = [json.loads(b) for k, b in rows if k == "settle"]
    return {"effects": h.effects, "approved": sum(o[0] == "approved" for o in outs),
            "reserves": len(reserves), "dup_keys": len(reserves) - len(set(reserves)),
            "executed": sum(x["outcome"] == "executed" for x in settles),
            "void": sum(x["outcome"] == "void" for x in settles),
            "unknown": sum(x["outcome"] == "unknown" for x in settles),
            "states": [r.state.value for r in s.governor.grant_store.reservations()]}


def race(trials: int, n: int, uses: int) -> dict:
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for t in range(trials):
            r = asyncio.run(_one(t, n, uses, tmp))
            if not (r["effects"] == uses == r["approved"] == r["reserves"] == r["executed"]
                    and r["dup_keys"] == 0):
                bad += 1
    return {"trials": trials, "concurrent_calls": n, "uses": uses, "violations": bad}


def faults(trials: int, n: int, uses: int, p: dict[str, float]) -> dict:
    over = dup = reruns = 0
    tot = {"executed": 0, "void": 0, "unknown": 0, "effects": 0}
    with tempfile.TemporaryDirectory() as tmp:
        for t in range(trials):
            r = asyncio.run(_one(t, n, uses, tmp, faults=p, timeout=0.05))
            over += r["effects"] > uses + r["void"]  # a released use may be taken again
            dup += r["dup_keys"]
            # every reserve is settled exactly once; RESERVED only when unknown
            reruns += r["states"].count("reserved") != r["unknown"]
            for k in tot:
                tot[k] += r[k]
    return {"trials": trials, "concurrent_calls": n, "uses": uses, "fault_p": p,
            "effects_over_uses": over, "spend_key_reused": dup,
            "unknown_left_reserved_mismatch": reruns, **tot}


def latency(n: int) -> dict:
    def pct(xs, q):
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(q * len(xs)))]

    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        for label, path in (("no_journal", None), ("journal", os.path.join(tmp, "lat.db"))):
            e, j = _enforcer(n + 10, Effect(), path)
            s = e.open_session(task=f"send 100 to {IBAN}")

            async def go():
                xs = []
                for i in range(n):
                    t = time.perf_counter_ns()
                    r = await e.execute(f"c{i}", "send_money", dict(CALL), TOOLS, s)
                    xs.append(time.perf_counter_ns() - t)
                    assert r[0] == "approved", r
                return xs
            xs = asyncio.run(go())
            us = lambda v: round(v / 1000, 1)  # noqa: E731
            out[label] = {"p50_us": us(pct(xs, .5)), "p99_us": us(pct(xs, .99)),
                          "mean_us": us(statistics.mean(xs))}
            if j:
                j.close()
    return {"n": n, **out}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args(argv)
    t = 20 if a.quick else 100
    report = {
        "host": {"python": platform.python_version(), "machine": platform.machine()},
        "race": [race(t, 8, 1), race(t, 32, 1), race(t, 32, 5)],
        "faults": [faults(t, 16, 3, {"refuse": 0.1, "after": 0.1}),
                   faults(t, 16, 3, {"refuse": 0.1, "after": 0.1, "hang": 0.05})],
        "latency": latency(200 if a.quick else 2000),
    }
    print(json.dumps(report, indent=1))
    ok = (all(r["violations"] == 0 for r in report["race"])
          and all(f["effects_over_uses"] == 0 and f["spend_key_reused"] == 0
                  and f["unknown_left_reserved_mismatch"] == 0 for f in report["faults"]))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
