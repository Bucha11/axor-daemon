"""kill -9 of the daemon process at four points of a call, then a restart on the same
journal and a resume of the session (``hello.session_id``).

The daemon runs as its own process through its CLI (``--journal``); the crash is a real
SIGKILL from inside, at the point ``AXOR_DAEMON_CRASHPOINT`` names (enforcer._crash).
Effects are counted on disk by the handlers (tests/journal_fixtures.py, fsync per effect).

    after_reserve   the reserve is on disk, the handler was never dispatched
    after_execute   the effect ran and its dedup row is ``done``; no settle
    after_settle    the spend is settled; the output never reached the agent
    after_floor     a secret read armed the floor (on disk); the output never reached the agent

For each: after the restart there is at most one execution, the grant's quota is not
reset (the request is never minted again), and the same call retried — with its call id
or a new one — is refused or not executed twice. After ``after_floor``, an egress the
request itself named (outside O) is refused: the floor came back from the journal.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time

import pytest
import yaml

from tests.journal_fixtures import GOV, MAIL, PAY, TASK, Client, effects

# two uses per request grant: a retry of the crashed call meets its decided spend (not
# an exhausted grant), a new call takes the second use, and a third finds none
GOV_CRASH = {**GOV, "grant_quotas": {"send_money": 2}}
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HANDLERS = ["SendMoney", "SendEmail", "GetBalance", "ReadFile"]


class Daemon:
    def __init__(self, tmp, crash: str | None = None) -> None:
        self.sock = str(tmp / "d.sock")
        self.db = str(tmp / "journal.db")
        cfg = tmp / "governance.yaml"
        if not cfg.exists():
            cfg.write_text(yaml.safe_dump(GOV_CRASH))
        env = {**os.environ, "PYTHONPATH": REPO + os.pathsep + os.environ.get("PYTHONPATH", ""),
               "AXOR_TEST_EFFECTS": str(tmp / "effects.jsonl")}
        env.pop("AXOR_DAEMON_CRASHPOINT", None)
        if crash:
            env["AXOR_DAEMON_CRASHPOINT"] = crash
        cmd = [sys.executable, "-m", "axor_daemon", "start", "--socket", self.sock,
               "--governance", str(cfg), "--operator-tools", "handlers", "--journal", self.db,
               "--log-level", "WARNING"]
        for h in HANDLERS:
            cmd += ["--handler", f"tests.journal_fixtures:{h}"]
        if os.path.exists(self.sock):
            os.unlink(self.sock)
        self.log = open(tmp / f"daemon-{crash or 'clean'}.log", "w")
        self.proc = subprocess.Popen(cmd, env=env, cwd=REPO, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(300):
            if os.path.exists(self.sock):
                return
            if self.proc.poll() is not None:
                raise RuntimeError(open(self.log.name).read())
            time.sleep(0.05)
        raise RuntimeError("daemon did not start")

    def killed(self) -> int:
        return self.proc.wait(timeout=15)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # a client still connected
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log.close()


@pytest.fixture
def tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("AXOR_TEST_EFFECTS", str(tmp_path / "effects.jsonl"))
    return tmp_path


def _journal(db: str) -> list[tuple[str, str]]:
    with sqlite3.connect(db) as c:
        return c.execute("SELECT kind, body FROM transitions ORDER BY seq").fetchall()


def _mints(db: str, sid: str) -> int:
    with sqlite3.connect(db) as c:
        return c.execute("SELECT count(*) FROM transitions WHERE session_id=? AND kind='mint'",
                         (sid,)).fetchone()[0]


def _crash_during(tmp, point: str, tool: str, args: dict) -> str:
    """Start a crashing daemon, open a session, send the call; the process dies."""
    d = Daemon(tmp, crash=point)
    c = Client(d.sock, task=TASK)
    sid = c.session_id
    assert sid
    with pytest.raises((ConnectionError, OSError)):
        c.call("c1", tool, args)
    assert d.killed() == -9  # SIGKILL, from the crash point
    d.log.close()
    return sid


def _send_money_effects() -> int:
    return sum(1 for e in effects() if e["tool"] == "send_money")


@pytest.mark.parametrize("point,ran,outcome", [
    ("after_reserve", 0, "unknown"),   # no dedup row: the use stays RESERVED
    ("after_execute", 1, "executed"),  # dedup done: reconcile commits it
    ("after_settle", 1, "executed"),   # settled before the crash
])
def test_a_grant_spend_survives_kill_9(tmp, point, ran, outcome):
    sid = _crash_during(tmp, point, "send_money", PAY)
    assert _send_money_effects() == ran
    minted = _mints(str(tmp / "journal.db"), sid)
    assert minted >= 1
    d = Daemon(tmp)
    try:
        c = Client(d.sock, session_id=sid)
        assert c.ready["type"] == "ready" and c.session_id == sid
        # the spend's outcome, from the journal (never a retry)
        settles = [b for k, b in _journal(d.db) if k == "settle"]
        assert settles and f'"outcome":"{outcome}"' in settles[-1]
        # the same call, same call id: its spend is decided, it does not run again
        r = c.call("c1", "send_money", PAY)
        assert r["decision"] == "denied" and "already holds spend" in r["denial_reason"]
        # a new call id takes the second use; the quota was not reset, so a third has none
        assert c.call("c2", "send_money", PAY)["decision"] == "approved"
        r = c.call("c3", "send_money", PAY)
        assert r["decision"] == "denied" and "grant_gate" in r["denial_reason"]
        c.close()
        # the crashed call ran at most once (never again), the second use once
        assert _send_money_effects() == ran + 1
        # the request was minted once, when the session opened; never again on resume
        assert _mints(d.db, sid) == minted
    finally:
        d.stop()


def test_the_floor_survives_kill_9_before_the_secret_reaches_the_agent(tmp):
    sid = _crash_during(tmp, "after_floor", "get_balance", {})
    assert [e["tool"] for e in effects()] == ["get_balance"]
    assert ("floor_armed", "{}") in _journal(str(tmp / "journal.db"))
    d = Daemon(tmp)
    try:
        # control: without the secret read, the egress the request names is admitted
        fresh = Client(d.sock, task=TASK)
        assert fresh.call("m0", "send_email", MAIL)["decision"] == "approved"
        fresh.close()
        # the resumed session: the floor came back from the journal
        c = Client(d.sock, session_id=sid)
        r = c.call("m1", "send_email", MAIL)
        assert r["decision"] == "denied" and "taint_enforcement" in r["denial_reason"]
        c.close()
        assert [e["tool"] for e in effects()] == ["get_balance", "send_email"]  # the control only
    finally:
        d.stop()
