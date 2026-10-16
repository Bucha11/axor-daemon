"""
CLI entry point for AxorDaemon.

Usage:
    python -m axor_daemon start [--socket PATH] [--policy NAME] [--log-level LEVEL]
                                [--handler module.path:ClassName ...]
    axor-daemon start [--socket PATH] [--policy NAME]

Handlers are loaded at startup via --handler (repeatable). Each value is a
dotted module path and class name separated by ':', e.g.:
    --handler axor_claude.tools.read:ReadHandler
    --handler axor_claude.tools.bash:BashHandler

The class is instantiated with no arguments; its .name property is used as the
tool name key. axor-daemon has no direct dependency on handler packages —
they are imported dynamically at runtime.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import logging
import os
import signal
import sys

_DEFAULT_SOCKET = "~/.axor/daemon.sock"
_DEFAULT_POLICY = "focused_generative"

_POLICY_NAMES = {
    "focused_readonly",
    "focused_generative",
    "focused_mutative",
    "moderate_readonly",
    "moderate_generative",
    "moderate_mutative",
    "expansive",
}


def _build_operator_policy(policy_name: str):
    from axor_core.contracts.policy import (
        TaskSignal, TaskComplexity, TaskNature,
    )
    from axor_core.policy.selector import PolicySelector

    # Resolve name → signal → policy via PolicySelector
    _name_to_signal = {
        "focused_readonly":    (TaskComplexity.FOCUSED,   TaskNature.READONLY),
        "focused_generative":  (TaskComplexity.FOCUSED,   TaskNature.GENERATIVE),
        "focused_mutative":    (TaskComplexity.FOCUSED,   TaskNature.MUTATIVE),
        "moderate_readonly":   (TaskComplexity.MODERATE,  TaskNature.READONLY),
        "moderate_generative": (TaskComplexity.MODERATE,  TaskNature.GENERATIVE),
        "moderate_mutative":   (TaskComplexity.MODERATE,  TaskNature.MUTATIVE),
        "expansive":           (TaskComplexity.EXPANSIVE, TaskNature.MUTATIVE),
    }
    if policy_name not in _name_to_signal:
        print(f"Unknown policy '{policy_name}'. Valid: {sorted(_POLICY_NAMES)}", file=sys.stderr)
        sys.exit(1)

    complexity, nature = _name_to_signal[policy_name]
    signal = TaskSignal(
        raw_input="",
        complexity=complexity,
        nature=nature,
        estimated_scope=1,
        requires_children=False,
        requires_mutation=(nature == TaskNature.MUTATIVE),
    )
    return PolicySelector().select(signal)


def _load_handlers(specs: list[str]) -> dict:
    """
    Load ToolHandler instances from 'module.path:ClassName' spec strings.
    Each handler is instantiated with no arguments; its .name is the dict key.
    """
    handlers = {}
    for spec in specs:
        if ":" not in spec:
            print(
                f"Invalid --handler spec '{spec}'. Expected 'module.path:ClassName'.",
                file=sys.stderr,
            )
            sys.exit(1)
        module_path, class_name = spec.rsplit(":", 1)
        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            print(f"Cannot import '{module_path}': {e}", file=sys.stderr)
            sys.exit(1)
        cls = getattr(module, class_name, None)
        if cls is None:
            print(
                f"Class '{class_name}' not found in module '{module_path}'.",
                file=sys.stderr,
            )
            sys.exit(1)
        handler = cls()
        handlers[handler.name] = handler
        logging.info("Registered handler '%s' from %s", handler.name, spec)
    return handlers


def _build_enforcer(operator_policy, handlers: dict, sandbox_root: str | None = None,
                    governance_path: str | None = None, confirm=None,
                    operator_tools: str = "policy", structured_spec: str | None = None,
                    journal_path: str | None = None):
    from axor_daemon.enforcer import DaemonEnforcer
    governance = None
    config_sha256 = ""
    if governance_path:
        import hashlib
        from axor_core.config import GovernanceConfig
        governance = GovernanceConfig.from_yaml(governance_path)
        config_sha256 = hashlib.sha256(open(governance_path, "rb").read()).hexdigest()
    journal = None
    if journal_path:
        from axor_daemon.journal import Journal
        journal = Journal(os.path.expanduser(journal_path))
    return DaemonEnforcer(
        operator_policy=operator_policy,
        handlers=handlers,
        sandbox_root=sandbox_root,
        governance=governance,
        confirm=confirm,
        operator_allowed=frozenset(handlers) if operator_tools == "handlers" else None,
        structured=_load_callable(structured_spec) if structured_spec else None,
        journal=journal,
        config_sha256=config_sha256,
    )


def _load_callable(spec: str):
    """'module.path:function' -> the function (the --structured parser)."""
    import importlib
    module, sep, name = spec.partition(":")
    if not sep or not module or not name:
        raise SystemExit(f"Invalid --structured spec '{spec}'. Expected 'module.path:function'.")
    fn = getattr(importlib.import_module(module), name)
    if not callable(fn):
        raise SystemExit(f"--structured {spec} is not callable")
    return fn


async def _run(
    socket_path: str,
    policy_name: str,
    handler_specs: list[str],
    sandbox_root: str | None = None,
    governance_path: str | None = None,
    confirm_socket: str | None = None,
    operator_tools: str = "policy",
    l4_budget: int | None = None,
    l4_max_refusals: int | None = None,
    structured_spec: str | None = None,
    journal_path: str | None = None,
) -> None:
    from axor_daemon.server import DaemonServer

    operator_policy = _build_operator_policy(policy_name)
    handlers = _load_handlers(handler_specs)
    confirm = None
    if confirm_socket:
        from axor_daemon.confirm import ConfirmChannel
        confirm = ConfirmChannel(budget=l4_budget, max_refusals=l4_max_refusals)
        await confirm.start(os.path.expanduser(confirm_socket))
    enforcer = _build_enforcer(
        operator_policy,
        handlers=handlers,
        sandbox_root=sandbox_root,
        governance_path=governance_path,
        confirm=confirm,
        operator_tools=operator_tools,
        structured_spec=structured_spec,
        journal_path=journal_path,
    )
    server = DaemonServer(enforcer=enforcer)
    await server.start(socket_path)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    logging.info(
        "AxorDaemon started — policy=%s socket=%s handlers=%s sandbox_root=%s governance=%s",
        policy_name, socket_path, sorted(handlers), sandbox_root or "<none>",
        governance_path or "<none>",
    )

    await stop_event.wait()
    await server.stop()
    if confirm is not None:
        await confirm.stop()
    logging.info("AxorDaemon stopped")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="axor-daemon",
        description="AxorDaemon — process-isolated capability executor",
    )
    sub = parser.add_subparsers(dest="command")

    start_p = sub.add_parser("start", help="Start the daemon")
    start_p.add_argument(
        "--socket", default=_DEFAULT_SOCKET,
        help=f"Unix socket path (default: {_DEFAULT_SOCKET})",
    )
    start_p.add_argument(
        "--policy", default=_DEFAULT_POLICY,
        help=f"Operator policy ceiling (default: {_DEFAULT_POLICY}). "
             f"Valid: {sorted(_POLICY_NAMES)}",
    )
    start_p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    start_p.add_argument(
        "--handler", dest="handlers", action="append", default=[],
        metavar="MODULE:CLASS",
        help=(
            "Register a ToolHandler. Repeatable. Format: 'module.path:ClassName'. "
            "Example: --handler axor_claude.tools.read:ReadHandler"
        ),
    )
    start_p.add_argument(
        "--sandbox-root",
        default=os.environ.get("AXOR_DAEMON_SANDBOX_ROOT"),
        help=(
            "Optional filesystem root for daemon-side path args. "
            "Also configurable via AXOR_DAEMON_SANDBOX_ROOT."
        ),
    )

    start_p.add_argument(
        "--governance",
        default=os.environ.get("AXOR_DAEMON_GOVERNANCE"),
        metavar="CONFIG.yaml",
        help=(
            "Operator GovernanceConfig (axor-core YAML). When set, the daemon runs "
            "the kernel gates and task-scoped grants itself, per connection. Also "
            "configurable via AXOR_DAEMON_GOVERNANCE."
        ),
    )

    start_p.add_argument(
        "--confirm-socket",
        default=os.environ.get("AXOR_DAEMON_CONFIRM_SOCKET"),
        metavar="PATH",
        help=(
            "Operator confirmation endpoint (L4), a Unix socket separate from the "
            "agent's. Without it nothing is ever confirmed. Also "
            "AXOR_DAEMON_CONFIRM_SOCKET."
        ),
    )
    start_p.add_argument(
        "--operator-tools", choices=["policy", "handlers"], default="policy",
        help=(
            "Operator ceiling: the policy's tool classes (default) or exactly the "
            "registered handlers' names."
        ),
    )

    start_p.add_argument(
        "--structured", default=os.environ.get("AXOR_DAEMON_STRUCTURED"), metavar="module:function",
        help=(
            "The platform's parser of a description source's output (axor-core MODEL.md "
            "9.15): function(tool, result) -> structure or None. Without it no description "
            "grant is computed. Also AXOR_DAEMON_STRUCTURED."
        ),
    )
    start_p.add_argument(
        "--journal", default=os.environ.get("AXOR_DAEMON_JOURNAL"), metavar="PATH",
        help=(
            "Durable grants (sqlite, WAL, synchronous=FULL): every grant, spend and the "
            "session state they depend on is journaled, and a session survives a daemon "
            "restart (hello with its session_id). Needs --governance. Also AXOR_DAEMON_JOURNAL."
        ),
    )
    start_p.add_argument("--l4-budget", type=int, default=None, metavar="N",
                         help="At most N confirmation questions per session (default: no limit).")
    start_p.add_argument("--l4-max-refusals", type=int, default=None, metavar="K",
                         help="Terminate a session after K operator refusals (default: never).")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    asyncio.run(_run(args.socket, args.policy, args.handlers, args.sandbox_root,
                     args.governance, args.confirm_socket, args.operator_tools,
                     args.l4_budget, args.l4_max_refusals, args.structured, args.journal))


if __name__ == "__main__":
    main()
