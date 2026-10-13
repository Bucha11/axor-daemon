"""L4 through the daemon: confirmations go to the operator socket, never the agent's.

A call every gate admits but no grant covers is confirmable; the daemon asks the
operator connection and only ``approve: true`` turns it into a grant. No operator,
a refusal or a dropped operator is a denial (fail closed).
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from axor_core.config import GovernanceConfig
from axor_core.contracts.daemon import encode_message, read_message

from axor_daemon.confirm import ConfirmChannel
from axor_daemon.enforcer import DaemonEnforcer
from axor_daemon.server import DaemonServer

from tests.test_governance import _Tool, _policy

BOB = "GB33BUKB20201555555555"
GOV = {
    "egress_sinks": ["send_money"],
    "driving_args": {"send_money": ["recipient"]},
    "integrity_default": "context",
    "integrity_origins": "any-trusted",
    "grant_args": {"send_money": {"recipient": "iban"}},
}


async def _setup(tmp, answer):
    """Daemon with a confirm endpoint; ``answer`` is the operator (None: none connected)."""
    confirm = ConfirmChannel(timeout=2.0)
    await confirm.start(os.path.join(tmp, "c.sock"))
    send = _Tool("send_money")
    e = DaemonEnforcer(_policy(), {"send_money": send}, governance=GovernanceConfig.from_dict(GOV),
                       confirm=confirm, operator_allowed=frozenset({"send_money"}))
    server = DaemonServer(enforcer=e)
    await server.start(os.path.join(tmp, "d.sock"))
    seen: list[dict] = []
    op = None
    if answer is not None:
        r, w = await asyncio.open_unix_connection(os.path.join(tmp, "c.sock"))
        w.write(encode_message({"type": "operator"}))
        await w.drain()
        assert (await read_message(r))["type"] == "ready"

        async def loop():
            try:
                while True:
                    m = await read_message(r)
                    seen.append(m)
                    w.write(encode_message({"type": "confirm_response", "id": m["id"],
                                            "approve": answer(m)}))
                    await w.drain()
            except asyncio.IncompleteReadError:
                pass
        op = asyncio.create_task(loop())
    return server, confirm, send, seen, op


async def _agent_call(tmp, task, args):
    r, w = await asyncio.open_unix_connection(os.path.join(tmp, "d.sock"))
    w.write(encode_message({"type": "hello", "mode": "production", "task": task}))
    await w.drain()
    assert (await read_message(r))["type"] == "ready"
    w.write(encode_message({"type": "tool_call", "call_id": "c1", "tool": "send_money",
                            "args": args, "allowed_tools": ["send_money"]}))
    await w.drain()
    res = await read_message(r)
    w.close()
    return res


async def _run(answer, args):
    with tempfile.TemporaryDirectory() as tmp:
        server, confirm, send, seen, op = await _setup(tmp, answer)
        try:
            res = await _agent_call(tmp, "pay my friend 10", args)
        finally:
            if op:
                op.cancel()
            await server.stop()
            await confirm.stop()
        return res, send, seen


def test_operator_approval_admits_the_call():
    res, send, seen = asyncio.run(_run(lambda m: True, {"recipient": BOB, "amount": 10}))
    assert res["decision"] == "approved" and send.calls == 1
    assert len(seen) == 1 and seen[0]["sink"] == "send_money" and seen[0]["args"]["recipient"] == BOB
    assert BOB in seen[0]["text"] and seen[0]["task"] == "pay my friend 10"


def test_operator_refusal_denies():
    res, send, seen = asyncio.run(_run(lambda m: False, {"recipient": BOB, "amount": 10}))
    assert res["decision"] == "denied" and "grant" in res["denial_reason"] and send.calls == 0
    assert len(seen) == 1


def test_no_operator_fails_closed():
    res, send, _ = asyncio.run(_run(None, {"recipient": BOB, "amount": 10}))
    assert res["decision"] == "denied" and send.calls == 0


def test_agent_connection_cannot_answer():
    """A confirm_response sent on the agent's own socket is ignored."""
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            server, confirm, send, _, _ = await _setup(tmp, None)
            r, w = await asyncio.open_unix_connection(os.path.join(tmp, "d.sock"))
            w.write(encode_message({"type": "hello", "mode": "production", "task": "pay 10"}))
            await w.drain()
            await read_message(r)
            for i in range(1, 4):
                w.write(encode_message({"type": "confirm_response", "id": i, "approve": True}))
            w.write(encode_message({"type": "tool_call", "call_id": "c1", "tool": "send_money",
                                    "args": {"recipient": BOB}, "allowed_tools": ["send_money"]}))
            await w.drain()
            res = await read_message(r)
            w.close()
            await server.stop()
            await confirm.stop()
            return res, send
    res, send = asyncio.run(go())
    assert res["decision"] == "denied" and send.calls == 0
