# axor-daemon

[![CI](https://github.com/Bucha11/axor-daemon/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Bucha11/axor-daemon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/axor-daemon?cacheSeconds=300)](https://pypi.org/project/axor-daemon/)
[![Python](https://img.shields.io/pypi/pyversions/axor-daemon?cacheSeconds=300)](https://pypi.org/project/axor-daemon/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Process-isolated capability executor for [axor-core](https://github.com/Bucha11/axor-core).**

axor-core governs what agents are *allowed* to do. axor-daemon enforces it from *outside the agent process*.

---

## The Problem with Library-Only Governance

When governance runs as a library in the same process as the agent, the enforcement boundary is Python-level. A compromised dependency, a monkey-patched import, or a hostile extension can bypass `CapabilityExecutor` without touching the governance logic at all.

axor-daemon moves tool execution across a process boundary:

```
Agent process                      AxorDaemon process
────────────────────────────       ─────────────────────────────────
GovernedSession                    DaemonServer (mode 0600 socket)
IntentLoop                           DaemonEnforcer
DaemonCapabilityClient  ──────►        operator_policy (ceiling)
  (no tool impls here)   socket         path normalization
                        ◄──────        exec timeout per handler
                                       approved result | DENIED
```

Tool implementations live only in the daemon. The agent process cannot call them directly — it has no code to do so. The Unix socket is the only path, and it is only accessible to the process owner.

---

## Enforcement Model

Every tool call passes independent checks in the daemon:

**1. Socket access** — the socket is created `0600`. Only the owner process may connect. Any other local process is rejected by the OS before the handshake begins.

**2. Protocol version** — the handshake validates `PROTOCOL_VERSION` on both sides. A version mismatch is rejected immediately with an explicit error, not a silent protocol confusion.

**3. Operator ceiling** — `operator_policy` is set at daemon startup by the operator and never modified per-connection. The daemon derives allowed tools from it independently — it does not trust the client's claim.

**4. Client ceiling** — `allowed_tools` reported by the client's `GovernedSession`. Both the operator ceiling and the client ceiling must approve the tool. The client can only narrow below the operator ceiling, never escalate above it.

**5. Arg normalization** — path-like args (`path`, `file`, `target`, etc.) are normalized with `os.path.normpath` by the daemon independently before being passed to any handler. A `../` traversal sequence in a client-supplied path cannot reach a handler unnormalized.

**6. Exec timeout** — every handler execution is bounded by `exec_timeout` (default: 60s). A handler that exceeds the timeout returns `DENIED` — it does not hang the daemon session.

```
Client sends: tool="bash", allowed_tools=["bash", "read"]

Operator policy = focused_readonly (allow_bash=False)
  → DENIED  operator ceiling  "bash not permitted by operator policy"

Client sends: tool="read", args={"path": "../../etc/passwd"}, allowed_tools=["read"]
Operator policy = focused_readonly (allow_read=True)
  → daemon normalizes path → "/etc/passwd"
  → handler receives normalized args, never raw client string

Client sends: tool="read", allowed_tools=[]   ← excluded read
  → DENIED  session ceiling  "read not in session allowed_tools"
```

A client that sends an inflated `allowed_tools` list or crafted path args cannot bypass or escalate — both checks are evaluated daemon-side on independently derived state.

---

## Installation

```bash
pip install axor-daemon
```

Requires `axor-core >= 0.5.0, < 0.6`. Zero additional dependencies — stdlib `asyncio` only.

---

## Quick Start

**1. Start the daemon**

```bash
axor-daemon start --policy focused_generative
```

The daemon loads the operator policy, creates `~/.axor/daemon.sock` with permissions `0600`, and begins accepting connections.

**2. Use `DaemonCapabilityClient` instead of `CapabilityExecutor`**

```python
from axor_core.capability.daemon_client import DaemonCapabilityClient
import axor_claude

session = axor_claude.make_session(
    api_key="sk-ant-...",
    capability_executor=DaemonCapabilityClient(
        socket_path="~/.axor/daemon.sock",
        mode="production",
    ),
)

result = await session.run("Write tests for the auth module")
```

No other changes. `DaemonCapabilityClient` exposes the same interface as `CapabilityExecutor`.

---

## Operator Policies

The operator policy is the capability ceiling. Clients cannot exceed it.

```bash
axor-daemon start --policy focused_readonly     # read + search only, no writes
axor-daemon start --policy focused_generative   # read + write, no bash (default)
axor-daemon start --policy focused_mutative     # read + write + bash
axor-daemon start --policy moderate_mutative    # broad context, bash, shallow children
axor-daemon start --policy expansive            # full capability surface
```

| Policy | read | write | bash | search | children |
|--------|------|-------|------|--------|----------|
| `focused_readonly` | ✓ | — | — | ✓ | — |
| `focused_generative` | ✓ | ✓ | — | ✓ | — |
| `focused_mutative` | ✓ | ✓ | ✓ | ✓ | — |
| `moderate_mutative` | ✓ | ✓ | ✓ | ✓ | shallow |
| `expansive` | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## CLI Reference

```
axor-daemon start [options]

  --socket PATH      Unix socket path (default: ~/.axor/daemon.sock)
  --policy NAME      Operator policy ceiling (default: focused_generative)
  --log-level LEVEL  DEBUG | INFO | WARNING | ERROR (default: INFO)
```

---

## Wire Protocol

Communication is length-prefixed JSON over a Unix domain socket. Every message carries a protocol version field `"v"`. Version mismatches are rejected at handshake — there is no silent fallback.

```
Client → {"v": 1, "type": "hello", "mode": "production"}
Server → {"v": 1, "type": "ready"}

Client → {"v": 1, "type": "tool_call", "call_id": "a1b2c3", "tool": "read",
           "args": {"path": "auth.py"}, "allowed_tools": ["read", "search"]}
Server → {"v": 1, "type": "tool_result", "call_id": "a1b2c3",
           "decision": "approved", "result": "...", "denial_reason": null}

Client → {"v": 1, "type": "bye"}
```

**Framing:** 4-byte big-endian unsigned int (payload length) + JSON bytes. Maximum message size: 8 MB.

**Backpressure:** the server enforces a maximum of 64 concurrent connections. Connections beyond this limit receive an immediate `rejected` response. Each connection has a `30s` read timeout — a stalled client does not hold a session indefinitely.

One connection per session. If the connection is lost mid-session, `DaemonCapabilityClient` raises `DaemonUnavailableError` — fail-closed by design.

---

## Fail-Closed Guarantee

If the daemon is unreachable, `DaemonCapabilityClient.execute()` raises `DaemonUnavailableError`. Execution stops. It never silently falls back to direct tool execution.

```python
from axor_core.errors.exceptions import DaemonUnavailableError

try:
    result = await session.run("audit the auth module")
except DaemonUnavailableError as e:
    # daemon not running — do not proceed
    raise
```

---

## Registering Tool Handlers

Tool handlers live in the daemon, not in the client. Extend the daemon at startup:

```python
from axor_daemon.enforcer import DaemonEnforcer
from axor_daemon.server import DaemonServer

enforcer = DaemonEnforcer(
    operator_policy=operator_policy,
    exec_timeout=30.0,          # seconds per handler call, default 60
    handlers={
        "read":   MyReadHandler(),
        "write":  MyWriteHandler(),
        "bash":   MyBashHandler(),
        "search": MySearchHandler(),
    },
)
server = DaemonServer(enforcer=enforcer)
await server.start("~/.axor/daemon.sock")
await server.serve_forever()
```

`axor-claude` ships ready-made handlers for Claude tool use. Register them with the daemon at startup — not with the session.

---

## Known Limitations

**Socket access is OS-level, not cryptographic.** Any process running as the same OS user may connect to the socket. For multi-user or container environments, run the agent in a separate OS user or apply additional access controls (e.g., systemd socket activation with `User=`).

**Path normalization is not an allowlist.** `os.path.normpath` resolves `../` sequences so handlers always receive clean paths. It does not enforce which paths are allowed — that remains the handler's or operator's responsibility. Use `CapabilityLease` with `allowed_paths` for path allowlists.

**Exec timeout kills slow handlers, not hanging syscalls.** `asyncio.wait_for` cancels the coroutine. If a handler blocks on a non-async call (e.g., a synchronous subprocess), the cancel will not interrupt it immediately. Use `asyncio.create_subprocess_exec` for shell commands inside handlers.

**Trace is client-side.** Audit traces are written by the agent process, not the daemon. A compromised worker could suppress or mutate trace writes. Daemon-side audit logging is planned for a future release.

For stronger guarantees, combine axor-daemon with OS-level sandboxing (seccomp, Landlock, container isolation) to restrict what the agent process can do even beyond the governance boundary. That is Level 2.

---

## Requirements

- Python 3.11+
- [`axor-core`](https://github.com/Bucha11/axor-core) >= 0.5.0
- No additional dependencies — stdlib `asyncio` only

---

## Ecosystem

| Package | Role |
|---------|------|
| [`axor-core`](https://github.com/Bucha11/axor-core) | Governance kernel — defines the contracts axor-daemon implements |
| [`axor-daemon`](https://github.com/Bucha11/axor-daemon) | Process-isolated capability executor — this package |
| [`axor-claude`](https://github.com/Bucha11/axor-claude) | Claude / Claude Code adapter — provides tool handlers |
| [`axor-cli`](https://github.com/Bucha11/axor-cli) | Governed terminal runtime |
| [`axor-memory-sqlite`](https://github.com/Bucha11/axor-memory-sqlite) | Cross-session memory (SQLite) |
| [`axor-classifier-simple`](https://github.com/Bucha11/axor-classifier-simple) | ML task signal derivation (optional) |
| [`axor-benchmarks`](https://github.com/Bucha11/axor-benchmarks) | Governance proof layer |

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
