"""
ConfirmChannel — the operator's confirmation endpoint (L4), separate from the agent.

A governing daemon asks for a confirmation when a call passes every gate but no
grant covers it (the kernel's grant gate is confirmable). The question goes to an
operator connection on its own socket (``--confirm-socket``), never back over the
agent's connection: the agent process cannot answer its own confirmation.

Operator protocol (same framing as the agent protocol, axor_core.contracts.daemon):
  1. Operator → {"v": 1, "type": "operator"}
  2. Daemon   → {"v": 1, "type": "ready"}
  3. Per confirmation:
     Daemon   → {"v": 1, "type": "confirm_request", "id": int, "task": str|None,
                 "sink": str, "args": {...}, "text": <the rendered action>}
     Operator → {"v": 1, "type": "confirm_response", "id": int, "approve": bool}

Fail closed: no operator connected, a timeout, a dropped connection or any answer
other than ``approve: true`` is a refusal. One operator connection at a time; a new
one replaces the old.

The kernel calls a confirmer synchronously from ``evaluate``. The daemon runs that
``evaluate`` in a worker thread (under the session lock) and the confirmer waits on
the event loop for the operator's answer.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from typing import Any, Mapping

from axor_core.contracts.daemon import encode_message, read_message

_log = logging.getLogger("axor.daemon.confirm")

_DEFAULT_TIMEOUT = 30.0


class ConfirmChannel:
    def __init__(self, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._writer: asyncio.StreamWriter | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._ids = itertools.count(1)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self.asked = 0

    async def start(self, socket_path: str) -> None:
        import os
        import stat

        self._loop = asyncio.get_running_loop()
        try:
            st = os.lstat(socket_path)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(st.st_mode):
                raise FileExistsError(f"refusing to remove non-socket path: {socket_path}")
            os.unlink(socket_path)
        self._server = await asyncio.start_unix_server(self._operator, path=socket_path)
        os.chmod(socket_path, 0o600)
        _log.info("confirm endpoint listening on %s (mode 600)", socket_path)

    async def stop(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        self._fail_pending()

    def _fail_pending(self) -> None:
        for fut in self._pending.values():
            if not fut.done():
                fut.set_result(False)
        self._pending.clear()

    async def _operator(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            hello = await read_message(reader)
            if hello.get("type") != "operator":
                writer.write(encode_message({"type": "rejected", "reason": "expected operator"}))
                await writer.drain()
                return
            if self._writer is not None:  # a new operator replaces the old one
                self._fail_pending()
                self._writer.close()
            self._writer = writer
            writer.write(encode_message({"type": "ready"}))
            await writer.drain()
            while True:
                msg = await read_message(reader)
                if msg.get("type") != "confirm_response":
                    continue
                fut = self._pending.pop(msg.get("id"), None)
                if fut is not None and not fut.done():
                    fut.set_result(msg.get("approve") is True)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._tasks.discard(task)
            if self._writer is writer:
                self._writer = None
                self._fail_pending()
            try:
                writer.close()
            except Exception:
                pass

    async def ask(self, task: str | None, sink: str, args: Mapping[str, Any], text: str) -> bool:
        self.asked += 1
        writer = self._writer
        if writer is None:
            return False
        cid = next(self._ids)
        fut = asyncio.get_running_loop().create_future()
        self._pending[cid] = fut
        try:
            writer.write(encode_message({"type": "confirm_request", "id": cid, "task": task,
                                         "sink": sink, "args": dict(args), "text": text}))
            await writer.drain()
            return await asyncio.wait_for(fut, timeout=self._timeout)
        except (asyncio.TimeoutError, ConnectionError):
            return False
        finally:
            self._pending.pop(cid, None)

    def confirmer(self, task: str | None) -> "ThreadConfirmer":
        """A kernel confirmer for one session (``confirm(action, call) -> bool``)."""
        if self._loop is None:
            raise RuntimeError("ConfirmChannel.start() first")
        return ThreadConfirmer(self, self._loop, task)


class ThreadConfirmer:
    """Called by the kernel from a worker thread; blocks on the operator's answer."""

    def __init__(self, channel: ConfirmChannel, loop: asyncio.AbstractEventLoop, task: str | None) -> None:
        self._channel, self._loop, self._task = channel, loop, task

    def confirm(self, action: Any, call: tuple[str, Mapping[str, Any]]) -> bool:
        sink, args = call
        fut = asyncio.run_coroutine_threadsafe(
            self._channel.ask(self._task, sink, args, action.text()), self._loop)
        try:
            return bool(fut.result(timeout=self._channel._timeout + 5))
        except Exception:
            return False
