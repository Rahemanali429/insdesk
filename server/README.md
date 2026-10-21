# InsDesk Server (Express.js relay)

The InsDesk **relay / rendezvous server**. Both InsDesk peers — the host (the
machine being controlled) and the controller (the one doing the controlling) —
are *clients* of this server. The server's only jobs are:

1. let a host publish a numeric **device ID**, and
2. pair an incoming controller with that host and then forward **opaque,
   end-to-end-encrypted** bytes between the two.

It never holds any encryption keys and cannot read session content — the Noise
channel is negotiated directly between the two peers *through* the relay.

## Two listeners

| Port (default) | Protocol | Purpose |
|---|---|---|
| `9510` | raw TCP | the relay itself: rendezvous + opaque byte forwarding (this is what the Rust `client/` peers connect to) |
| `9520` | HTTP (Express.js) | health & status API (`/`, `/healthz`, `/status`) |

The TCP framing and the rendezvous messages are byte-for-byte compatible with
the Rust client (`client/crates/insdesk-proto`): a 4-byte big-endian length
prefix, and bincode-encoded control messages. See `src/rendezvous.js`.

## Run

```bash
cd server
npm install
npm start
```

Configuration (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `INSDESK_BIND` | `0.0.0.0` | bind address for both listeners |
| `INSDESK_RELAY_PORT` | `9510` | TCP relay port |
| `INSDESK_HTTP_PORT` | `9520` | Express HTTP API port |
| `INSDESK_DEBUG` | _(unset)_ | set to any value for verbose logging |

Check it is up:

```bash
curl http://localhost:9520/status
# {"service":"insdesk-relay","status":"ok","hostsWaiting":0,"waitingIds":[],"uptimeSeconds":3}
```

## Test

```bash
cd server
npm test        # runs node:test unit tests for framing + rendezvous encoding
```

## Why Express *and* raw TCP?

Express speaks HTTP, which is perfect for health/status and future web
dashboards, but the remote-desktop peers need a long-lived, low-overhead,
bidirectional byte pipe — so the actual relaying uses Node's `net` module on a
separate port. Both run in the same process and share the same waiting-host
registry.
