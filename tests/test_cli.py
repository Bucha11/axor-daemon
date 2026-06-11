"""Smoke tests for the daemon CLI — the parser builds and the taxonomy threads.

`main()` was never exercised by tests before, which let an `os` NameError in the
argument defaults ship undetected. These run the parser end-to-end.
"""
from __future__ import annotations

import runpy
import sys

import pytest

import axor_daemon.__main__ as cli


def test_help_builds_parser_and_exits_zero(monkeypatch):
    # argparse --help raises SystemExit(0); a build-time NameError would raise first.
    monkeypatch.setattr(sys, "argv", ["axor-daemon", "start", "--help"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_taxonomy_flags_thread_into_enforcer():
    from axor_daemon.enforcer import DaemonEnforcer

    enf = cli._build_enforcer(
        cli._build_operator_policy("focused_readonly"),
        handlers={},
        untrusted_sources={"search_docs"},
        egress_sinks={"send_email"},
    )
    assert isinstance(enf, DaemonEnforcer)
    gov = enf.new_session_governor()
    # The governor carries the operator taxonomy.
    assert gov._egress_sinks == frozenset({"send_email"})
    assert gov._untrusted_sources == frozenset({"search_docs"})
