"""
DaemonServer — asyncio Unix socket server.

One connection = one session. The server handles multiple concurrent
connections; each runs in its own coroutine.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
from typing import Any

from axor_core.contracts.daemon import encode_message, read_message, PROTOCOL_VERSION
from axor_core.capability.session_grant import session_key_configured, verify_grant

from axor_daemon.enforcer import DaemonEnforcer

_log = logging.getLogger("axor.daemon.server")

_ALLOWED_MODES = {"library", "production", "strict"}

# Seconds to wait for the next message from a connected client.
# Prevents a stalled/malicious client from holding a session open indefinitely.
_READ_TIMEOUT = 30.0

# Max concurrent connections. Each connection is a coroutine; this caps memory.
_MAX_CONNECTIONS = 64


class DaemonServer:
    def __init__(self, enforcer: DaemonEnforcer) -> None:
        self._enforcer = enforcer
        self._server: asyncio.Server | None = None
        self._active_connections: set[asyncio.Task] = set()

    async def start(self, socket_path: str) -> None:
        socket_path = os.path.expanduser(socket_path)
        os.makedirs(os.path.dirname(socket_path) or ".", exist_ok=True)

        # Remove stale socket from a previous crash
        try:
            existing = os.lstat(socket_path)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(existing.st_mode):
                raise FileExistsError(
                    f"refusing to remove non-socket daemon path: {socket_path}"
                )
            os.unlink(socket_path)

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=socket_path
        )

        # Restrict socket to owner only — any local process can connect otherwise.
        os.chmod(socket_path, 0o600)

        _log.info("AxorDaemon listening on %s (mode 600)", socket_path)

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("call start() before serve_forever()")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for task in list(self._active_connections):
            task.cancel()

    # ── Per-connection handler ─────────────────────────────────────────────────

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if len(self._active_connections) >= _MAX_CONNECTIONS:
            _log.warning("max connections (%d) reached — rejecting", _MAX_CONNECTIONS)
            writer.write(encode_message({"type": "rejected", "reason": "server at capacity"}))
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass
            return

        peer = writer.get_extra_info("peername") or "unix"
        task = asyncio.current_task()
        self._active_connections.add(task)
        _log.debug("connection from %s (active=%d)", peer, len(self._active_connections))
        try:
            await self._session(reader, writer)
        except asyncio.IncompleteReadError:
            pass  # client disconnected mid-message
        except asyncio.TimeoutError:
            _log.info("session timed out: %s", peer)
        except Exception as exc:
            _log.warning("session error from %s: %s", peer, exc)
        finally:
            self._active_connections.discard(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            _log.debug("connection closed: %s", peer)

    async def _session(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # ── Handshake ──────────────────────────────────────────────────────────
        hello = await asyncio.wait_for(read_message(reader), timeout=_READ_TIMEOUT)

        client_version = hello.get("v")
        if client_version != PROTOCOL_VERSION:
            writer.write(encode_message({
                "type": "rejected",
                "reason": f"protocol version mismatch: client={client_version} server={PROTOCOL_VERSION}",
            }))
            await writer.drain()
            return

        if hello.get("type") != "hello":
            writer.write(encode_message({
                "type": "rejected",
                "reason": f"expected hello, got {hello.get('type')!r}",
            }))
            await writer.drain()
            return

        mode = hello.get("mode", "library")
        if mode not in _ALLOWED_MODES:
            writer.write(encode_message({
                "type": "rejected",
                "reason": f"unknown mode {mode!r}",
            }))
            await writer.drain()
            return

        writer.write(encode_message({"type": "ready"}))
        await writer.drain()

        # ── Request loop ───────────────────────────────────────────────────────
        while True:
            msg = await asyncio.wait_for(read_message(reader), timeout=_READ_TIMEOUT)
            msg_type = msg.get("type")

            if msg_type == "bye":
                break

            if msg_type != "tool_call":
                _log.warning("unexpected message type: %r", msg_type)
                continue

            call_id: str = msg.get("call_id", "")
            tool: str = msg.get("tool", "")
            args: dict[str, Any] = msg.get("args", {})

            # Derive the session ceiling. When a session key is configured the
            # daemon trusts only a verified, signed grant — never the plaintext
            # allowed_tools claim (which any same-user process could inflate).
            if session_key_configured():
                grant = verify_grant(msg.get("grant"))
                if grant is None:
                    writer.write(encode_message({
                        "type": "tool_result",
                        "call_id": call_id,
                        "decision": "denied",
                        "result": None,
                        "denial_reason": "invalid or missing session grant",
                    }))
                    await writer.drain()
                    continue
                client_allowed = frozenset(grant.get("allowed_tools", []))
            else:
                client_allowed = frozenset(msg.get("allowed_tools", []))

            decision, result, denial_reason = await self._enforcer.execute(
                call_id=call_id,
                tool=tool,
                args=args,
                client_allowed_tools=client_allowed,
            )

            response = {
                "type": "tool_result",
                "call_id": call_id,
                "decision": decision,
                "result": result,
                "denial_reason": denial_reason,
            }
            writer.write(encode_message(response))
            await writer.drain()
