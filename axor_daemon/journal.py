"""The daemon's durable journal: task-scoped grants and the session state they depend on.

One sqlite file (``--journal PATH``), WAL with ``synchronous=FULL``: every ``COMMIT``
fsyncs the WAL, so a transition is on disk when ``tx`` returns. Nothing is ever
updated or deleted in ``transitions``; ``dedup`` is the handlers' idempotency log.

    sessions(session_id, created_at, task, config_sha256)
    transitions(seq, session_id, kind, at, body)
        mint         {grant: <the whole Grant>}
        reserve      {key, grant_id, call_key, value_key, tool, args_sha256}
        settle       {key, outcome: executed | void | unknown, via: handler | reconcile}
        floor_armed  {}
        state        {field, value}   the session state whose loss would weaken a check
    dedup(key, session_id, tool, state: started | done | not_run, started_at, finished_at)

Tool outputs are never written (not even a retried call's result: a call whose spend
is already done is refused, not answered from disk).

Order on the call path (enforcer.py): reserve committed before the handler is
dispatched; ``dedup started`` committed before the effect and ``done`` after it;
``settle`` after; ``floor_armed`` and the other state committed before the output is
returned to the agent.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  session_id    TEXT PRIMARY KEY,
  created_at    REAL NOT NULL,
  task          TEXT NOT NULL,
  config_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transitions (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(session_id),
  kind       TEXT NOT NULL CHECK (kind IN ('mint','reserve','settle','floor_armed','state')),
  at         REAL NOT NULL,
  body       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS transitions_by_session ON transitions(session_id, seq);
CREATE TABLE IF NOT EXISTS dedup (
  key         TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(session_id),
  tool        TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('started','done','not_run')),
  started_at  REAL,
  finished_at REAL
);
"""

Row = tuple[str, dict]  # (kind, body)


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class Journal:
    def __init__(self, path: str) -> None:
        self.path = path
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._lock = threading.Lock()
        mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise RuntimeError(f"journal {path}: WAL not available (got {mode!r})")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ── transactions (each COMMIT is an fsync of the WAL) ──────────────────────
    def _tx(self, fn) -> Any:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                out = fn(self._db)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
            return out

    def new_session(self, session_id: str, task: str, config_sha256: str,
                    rows: Iterable[Row]) -> None:
        rows = list(rows)

        def go(db):
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                       (session_id, time.time(), task, config_sha256))
            self._insert(db, session_id, rows)
        self._tx(go)

    def tx(self, session_id: str, rows: Iterable[Row]) -> None:
        rows = list(rows)
        if rows:
            self._tx(lambda db: self._insert(db, session_id, rows))

    @staticmethod
    def _insert(db, session_id: str, rows: list[Row]) -> None:
        now = time.time()
        db.executemany("INSERT INTO transitions(session_id, kind, at, body) VALUES (?,?,?,?)",
                       [(session_id, k, now, canonical(b)) for k, b in rows])

    # ── reads ───────────────────────────────────────────────────────────────────
    def session(self, session_id: str) -> dict | None:
        with self._lock:
            r = self._db.execute("SELECT session_id, created_at, task, config_sha256 FROM sessions "
                                 "WHERE session_id=?", (session_id,)).fetchone()
        return None if r is None else dict(zip(("session_id", "created_at", "task", "config_sha256"), r))

    def transitions(self, session_id: str) -> list[tuple[int, str, dict]]:
        with self._lock:
            rows = self._db.execute("SELECT seq, kind, body FROM transitions WHERE session_id=? "
                                    "ORDER BY seq", (session_id,)).fetchall()
        return [(s, k, json.loads(b)) for s, k, b in rows]

    # ── the handlers' idempotency log (DurableDedup) ────────────────────────────
    def dedup_get(self, key: str) -> str | None:
        with self._lock:
            r = self._db.execute("SELECT state FROM dedup WHERE key=?", (key,)).fetchone()
        return None if r is None else r[0]

    def dedup_started(self, key: str, session_id: str, tool: str) -> None:
        self._tx(lambda db: db.execute(
            "INSERT INTO dedup(key, session_id, tool, state, started_at) VALUES (?,?,?,'started',?)",
            (key, session_id, tool, time.time())))

    def dedup_finish(self, key: str, state: str) -> None:
        self._tx(lambda db: db.execute(
            "UPDATE dedup SET state=?, finished_at=? WHERE key=? AND state='started'",
            (state, time.time(), key)))


class DurableDedup:
    """The reference idempotent handler of axor-core (``capability.grant_store.DedupHandler``)
    on the journal: an effect runs at most once per spend key, and ``executed(key)``
    answers from disk — True (``done``), False (``not_run``: the handler refused before
    any effect), None (no record, or ``started`` without an end): the outcome is not
    known, the use stays RESERVED (spent, never retried)."""

    def __init__(self, journal: Journal, session_id: str) -> None:
        self.journal, self.session_id = journal, session_id

    def executed(self, key: str) -> bool | None:
        return {"done": True, "not_run": False}.get(self.journal.dedup_get(key))

    def started(self, key: str, tool: str) -> None:
        self.journal.dedup_started(key, self.session_id, tool)

    def done(self, key: str) -> None:
        self.journal.dedup_finish(key, "done")

    def not_run(self, key: str) -> None:
        self.journal.dedup_finish(key, "not_run")
