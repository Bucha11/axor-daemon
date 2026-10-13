"""Full-path latency through the daemon: client socket -> daemon check (kernel gates
+ grant) -> handler -> output registered -> reply. One connection, sequential calls,
a no-op handler, so the number is the daemon's overhead on a tool call.

    python benchmarks/latency_daemon.py
"""
from __future__ import annotations

import asyncio
import os
import platform
import tempfile
import time

from axor_core.capability.daemon_client import DaemonCapabilityClient
from axor_core.capability.executor import ToolHandler
from axor_core.config import GovernanceConfig
from axor_core.contracts.envelope import Capabilities
from axor_core.contracts.intent import Intent, IntentKind
from axor_core.contracts.policy import (ChildMode, CompressionMode, ContextMode, ExecutionPolicy,
                                        ExportMode, TaskComplexity, ToolPolicy)

from axor_daemon.enforcer import DaemonEnforcer
from axor_daemon.server import DaemonServer

IBAN = "GB29NWBK60161331926819"


class Noop(ToolHandler):
    def __init__(self, name):
        self._n = name

    @property
    def name(self):
        return self._n

    async def execute(self, args):
        return "ok"


def policy():
    return ExecutionPolicy(name="expansive", derived_from=TaskComplexity.EXPANSIVE,
                           context_mode=ContextMode.MINIMAL, compression_mode=CompressionMode.AGGRESSIVE,
                           child_mode=ChildMode.DENIED, max_child_depth=0,
                           tool_policy=ToolPolicy(allow_read=True, allow_write=True, allow_bash=True),
                           export_mode=ExportMode.SUMMARY)


async def run(governance, n=5000, warm=300):
    handlers = {"send_money": Noop("send_money")}
    e = DaemonEnforcer(policy(), handlers, governance=governance)
    e._operator_allowed = frozenset(handlers)
    d = tempfile.mkdtemp()
    sock = os.path.join(d, "d.sock")
    server = DaemonServer(enforcer=e)
    await server.start(sock)
    caps = Capabilities(allowed_tools=frozenset(handlers), allow_children=False, allow_nested_children=False,
                        allow_context_expansion=False, allow_export=True, allow_mutation=True, max_child_depth=0)
    client = DaemonCapabilityClient(socket_path=sock, task=f"pay rent 1800 to {IBAN}")
    intent = Intent(kind=IntentKind.TOOL_CALL, payload={"tool": "send_money",
                    "args": {"recipient": IBAN, "amount": 1800}}, node_id="n", sequence=0)
    for _ in range(warm):
        await client.execute(intent, caps)
    s = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        await client.execute(intent, caps)
        s.append(time.perf_counter_ns() - t0)
    await client.aclose()
    await server.stop()
    s.sort()
    return s[len(s) // 2] / 1000, s[int(0.99 * len(s))] / 1000


def main():
    print(f"host: {platform.processor() or 'x86_64'} | CPython {platform.python_version()}")
    base = {"egress_sinks": ["send_money"], "driving_args": {"send_money": ["recipient"]},
            "integrity_default": "context", "integrity_origins": "request-only"}
    grants = {**base, "grant_args": {"send_money": {"recipient": "iban", "amount": "money"}},
              "grant_quotas": {"send_money": 10 ** 6}}
    for label, gov in (("names only (no governance)", None),
                       ("kernel gates", GovernanceConfig.from_dict(base)),
                       ("kernel gates + grant", GovernanceConfig.from_dict(grants))):
        p50, p99 = asyncio.run(run(gov))
        print(f"  {label:28} p50={p50:7.1f}  p99={p99:7.1f}  µs  (socket -> check -> handler -> register -> reply)")


if __name__ == "__main__":
    main()
