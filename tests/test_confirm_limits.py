"""L4 limits per daemon session: budget, dedup of refused calls, termination after K refusals."""
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

from tests.test_confirm import GOV
from tests.test_governance import _Tool, _policy

IBANS = [f"GB33BUKB2020155555555{i}" for i in range(6)]


async def _session(calls, answer, **limits):
    """Run ``calls`` (list of recipient IBANs) in one agent session; operator answers
    with ``answer(request)``. Returns (results, operator requests, executions)."""
    with tempfile.TemporaryDirectory() as tmp:
        confirm = ConfirmChannel(timeout=2.0, **limits)
        await confirm.start(os.path.join(tmp, "c.sock"))
        send = _Tool("send_money")
        e = DaemonEnforcer(_policy(), {"send_money": send}, governance=GovernanceConfig.from_dict(GOV),
                           confirm=confirm, operator_allowed=frozenset({"send_money"}))
        server = DaemonServer(enforcer=e)
        await server.start(os.path.join(tmp, "d.sock"))
        r, w = await asyncio.open_unix_connection(os.path.join(tmp, "c.sock"))
        w.write(encode_message({"type": "operator"}))
        await w.drain()
        await read_message(r)
        seen = []

        async def op():
            try:
                while True:
                    m = await read_message(r)
                    seen.append(m)
                    w.write(encode_message({"type": "confirm_response", "id": m["id"], "approve": answer(m)}))
                    await w.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
        opt = asyncio.create_task(op())
        ar, aw = await asyncio.open_unix_connection(os.path.join(tmp, "d.sock"))
        aw.write(encode_message({"type": "hello", "mode": "production", "task": "pay my friends"}))
        await aw.drain()
        await read_message(ar)
        results = []
        for i, iban in enumerate(calls):
            try:
                aw.write(encode_message({"type": "tool_call", "call_id": f"c{i}", "tool": "send_money",
                                         "args": {"recipient": iban, "amount": 10},
                                         "allowed_tools": ["send_money"]}))
                await aw.drain()
                results.append(await read_message(ar))
            except (asyncio.IncompleteReadError, ConnectionError):
                results.append("closed")
        aw.close()
        w.close()
        opt.cancel()
        await server.stop()
        await confirm.stop()
        return results, seen, send.calls


def test_budget_stops_asking():
    res, seen, ran = asyncio.run(_session(IBANS[:4], lambda m: True, budget=2))
    assert len(seen) == 2 and ran == 2
    assert [x["decision"] for x in res] == ["approved", "approved", "denied", "denied"]


def test_refused_call_is_not_asked_again_but_approved_one_is():
    res, seen, ran = asyncio.run(_session([IBANS[0], IBANS[0], IBANS[1], IBANS[1]],
                                          lambda m: m["args"]["recipient"] == IBANS[1]))
    # IBANS[0] refused once, the repeat is refused without asking; IBANS[1] is asked each time
    assert [m["args"]["recipient"] for m in seen] == [IBANS[0], IBANS[1], IBANS[1]]
    assert [x["decision"] for x in res] == ["denied", "denied", "approved", "approved"] and ran == 2


def test_session_terminated_after_k_refusals():
    res, seen, ran = asyncio.run(_session(IBANS[:5], lambda m: False, max_refusals=2))
    assert len(seen) == 2 and ran == 0
    assert res[0]["decision"] == res[1]["decision"] == "denied"
    assert "terminated" in res[1]["denial_reason"]
    assert res[2] == "closed"  # the daemon ended the session


def test_unlimited_by_default():
    res, seen, ran = asyncio.run(_session(IBANS[:5], lambda m: True))
    assert len(seen) == 5 and ran == 5


def test_limits_validated():
    with pytest.raises(ValueError):
        ConfirmChannel(budget=0)
    with pytest.raises(ValueError):
        ConfirmChannel(max_refusals=-1)
