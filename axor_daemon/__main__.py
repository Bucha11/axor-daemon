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


def _build_enforcer(operator_policy, handlers: dict, sandbox_root: str | None = None):
    from axor_daemon.enforcer import DaemonEnforcer
    return DaemonEnforcer(
        operator_policy=operator_policy,
        handlers=handlers,
        sandbox_root=sandbox_root,
    )


async def _run(
    socket_path: str,
    policy_name: str,
    handler_specs: list[str],
    sandbox_root: str | None = None,
) -> None:
    from axor_daemon.server import DaemonServer

    operator_policy = _build_operator_policy(policy_name)
    handlers = _load_handlers(handler_specs)
    enforcer = _build_enforcer(
        operator_policy,
        handlers=handlers,
        sandbox_root=sandbox_root,
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
        "AxorDaemon started — policy=%s socket=%s handlers=%s sandbox_root=%s",
        policy_name, socket_path, sorted(handlers), sandbox_root or "<none>",
    )

    await stop_event.wait()
    await server.stop()
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
            "Filesystem root for daemon-side path args. Path args resolving "
            "outside it are denied. Also via AXOR_DAEMON_SANDBOX_ROOT. Required "
            "unless --unsafe-no-sandbox is given."
        ),
    )
    start_p.add_argument(
        "--unsafe-no-sandbox",
        action="store_true",
        help=(
            "Run without a filesystem sandbox root. Path containment then depends "
            "entirely on handlers and the operator policy. Not recommended."
        ),
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # Fail-closed: a missing sandbox root must be an explicit, acknowledged choice.
    if args.command == "start" and not args.sandbox_root and not args.unsafe_no_sandbox:
        print(
            "Refusing to start without a filesystem sandbox: pass --sandbox-root PATH "
            "(or AXOR_DAEMON_SANDBOX_ROOT), or --unsafe-no-sandbox to opt out.",
            file=sys.stderr,
        )
        sys.exit(2)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    asyncio.run(_run(args.socket, args.policy, args.handlers, args.sandbox_root))


if __name__ == "__main__":
    main()
