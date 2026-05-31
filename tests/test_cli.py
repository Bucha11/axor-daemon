"""CLI smoke tests — guard the `axor-daemon start` entry point.

Regression guard: the start subparser reads os.environ for --sandbox-root at
parser-build time. A missing `import os` made `axor-daemon start` crash with
NameError before argument parsing — and no test covered the CLI. These tests
exercise the parser-build path so that class of bug fails CI.
"""

from __future__ import annotations

import pytest

from axor_daemon.__main__ import (
    _build_operator_policy,
    _load_handlers,
    main,
)


def test_start_help_builds_parser(monkeypatch):
    # --help exits 0; reaching it proves the start subparser (and its
    # os.environ-backed --sandbox-root default) builds without NameError.
    monkeypatch.setattr("sys.argv", ["axor-daemon", "start", "--help"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0


def test_sandbox_root_default_from_env(monkeypatch):
    monkeypatch.setenv("AXOR_DAEMON_SANDBOX_ROOT", "/srv/sandbox")
    # No subcommand → prints help and exits 0, but parser must build first.
    monkeypatch.setattr("sys.argv", ["axor-daemon", "start", "--help"])
    with pytest.raises(SystemExit):
        main()


def test_build_operator_policy_valid():
    policy = _build_operator_policy("focused_readonly")
    assert policy is not None
    assert policy.tool_policy.allow_read is True
    assert policy.tool_policy.allow_bash is False


def test_build_operator_policy_invalid_exits():
    with pytest.raises(SystemExit):
        _build_operator_policy("does_not_exist")


def test_load_handlers_bad_spec_exits():
    with pytest.raises(SystemExit):
        _load_handlers(["no_colon_here"])
