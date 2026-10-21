# InsDesk

A secure, **end-to-end-encrypted remote desktop** (AnyDesk/RustDesk-style). It
streams a remote screen, replays the operator's mouse and keyboard, transfers
files and clipboard text in **both directions**, and bridges Windows **UAC /
secure-desktop** prompts so an elevation dialog can be read and answered
remotely. All session traffic is end-to-end encrypted — even when routed through
the relay server.

> **Authorized use only.** Use InsDesk for remote support, administration and
> access to machines you own or are permitted to control. The host derives a
> verifiable device ID, supports a session password, and (outside unattended
> mode) decides whether to admit each session.

## Repository layout

```
insdesk/
├── server/    # Relay / rendezvous server — Express.js + TCP (Node.js)
└── client/    # The peers — Rust workspace: host agent + controller (+ shared libraries)
```

- **`server/`** is the relay. Both peers are *clients* of it: a host publishes a
  numeric device ID; a controller dials that ID; the server pairs them and then
  forwards **opaque, encrypted** bytes. It holds no keys and cannot read
  sessions. Built with **Express.js** (HTTP health/status on `:9520`) plus a raw
  TCP relay (`:9510`). See [`server/README.md`](server/README.md).
- **`client/`** is the Rust workspace containing everything that runs on a user's
  machine: the **host agent** (`insdesk-host`, the controlled machine) and the
  **controller** (`insdesk-client`, CLI + optional egui GUI), on top of shared
  crates for the protocol, crypto, transport, media codec and file transfer. See
  [`client/README.md`](client/README.md) for the architecture and security
  model.

## Features

| Capability | Where |
|---|---|
| Smooth streaming (dirty-tile delta codec, adaptive quality/FPS) | `client/crates/insdesk-media` + `insdesk-core` |
| File copy/paste, remote **and** local (SHA-256 verified) | `client/crates/insdesk-fs` |
| Full remote control (mouse + keyboard) | `client/crates/insdesk-media` (input) |
| Graphical UI + scriptable CLI | `client/crates/insdesk-client` |
| Remotely viewable/controllable Windows UAC secure desktop | `client/crates/insdesk-media` (uac) |
| End-to-end encryption (holds through the untrusted relay) | `client/crates/insdesk-crypto` |

---

# How to run it

You need **Node.js ≥ 18** (for the server) and the **Rust toolchain** (for the
client): https://rustup.rs. The default client build runs anywhere — including
headless machines — using a synthetic screen source and a recording input sink;
real capture/input/clipboard are opt-in feature flags (see below).

Use **three terminals**.

### 1 — Start the server (Express.js relay)

```bash
cd server
npm install
npm start
```

You should see it listening on `:9510` (TCP relay) and `:9520` (HTTP). Verify:

```bash
curl http://localhost:9520/status
# {"service":"insdesk-relay","status":"ok","hostsWaiting":0,...}
```

> Running on **different machines**? Start the server on a host reachable by
> both (open TCP `9510`), and pass its address with `--relay <host>:9510` below.

### 2 — Launch the desktop app on each machine

The desktop app is the AnyDesk-style window: it shows **this** machine's Device
ID + password (so others can connect to you) **and** has a box to connect out to
another machine. Build it with native backends so it captures the real screen
and injects real input:

```bash
cd client
cargo run --release -p insdesk-client --features "gui desktop" -- --gui \
    --relay 127.0.0.1:9510
```

On Linux you need the usual GUI/desktop dev libraries to build it (see
[client/README.md](client/README.md#building-the-desktop-app)); on Windows add
`uac-windows` to the feature list for the UAC secure-desktop bridge. Without a
display (or to try the UI with a synthetic screen) drop `desktop` and use just
`--features gui`.

The window shows **Your Device ID** and a **password** under *This Desk*. The
app registers with the server automatically — the `/status` endpoint from step 1
will list your ID under `hostsWaiting`.

### 3 — Connect

On the controlling machine, type the **other** machine's Device ID and its
password into the *Remote Desk* box and click **Connect**. The window switches to
a live view of that screen with full mouse/keyboard control, quality controls,
clipboard push and a remote file list. Share your own ID + password from *This
Desk* to let someone connect the other way.

### Headless / scriptable controller (no GUI)

For automation or servers without a display, the same binary without `--gui`
runs a scriptable controller — snapshot the screen, browse and move files:

```bash
cd client
cargo run --release -p insdesk-client -- \
    --relay 127.0.0.1:9510 --id <DEVICE_ID> --password <PASSWORD> \
    --ls "." \
    --download "report.pdf:/tmp/report.pdf" \
    --upload   "/tmp/patch.bin:incoming/patch.bin" \
    --snapshot /tmp/remote.png
```

A matching headless host (synthetic screen, runs anywhere) is also available as
`insdesk-host` — see [client/README.md](client/README.md).

### Direct connection (no server)

For a LAN or a port-forwarded host you can skip the relay entirely:

```bash
# host listens itself
cargo run --release -p insdesk-host   -- --listen 0.0.0.0:9511 --password hunter2
# controller dials the address directly
cargo run --release -p insdesk-client -- --connect host.example:9511 --gui
```

### Tests

```bash
cd server && npm test        # relay framing + rendezvous encoding
cd client && cargo test --workspace   # crypto, codec, file transfer, transport
```

## Security in one paragraph

Each device has a long-term Curve25519 identity key; the host's 9-digit ID is
derived from its public key. Sessions run over a Noise `XX` channel
(`25519 + ChaChaPoly + BLAKE2s`) with mutual authentication and forward secrecy.
The controller verifies the host's key matches the dialed ID (anti-MITM), and an
optional session password is checked with a proof bound to the handshake (no
replay). The server only forwards ciphertext — confidentiality and integrity are
genuinely end-to-end. Full details in [`client/README.md`](client/README.md).

## License

Dual-licensed under MIT or Apache-2.0, at your option.
