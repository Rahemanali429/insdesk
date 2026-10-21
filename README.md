# InsDesk

A secure, end-to-end-encrypted **remote desktop** in Rust — an AnyDesk/RustDesk-style
tool built as a clean, modular workspace. It streams a remote screen, replays
the operator's mouse and keyboard ("control PC"), transfers files and clipboard
text in **both directions**, and bridges Windows **UAC / secure-desktop**
prompts so an elevation dialog can be read and answered remotely. All session
traffic is end-to-end encrypted — even when it is routed through a relay.

> **Authorized use only.** InsDesk is for remote support, administration and
> access to machines you own or are permitted to control. The host always
> derives a verifiable device ID, supports a session password, and (outside
> unattended mode) makes an explicit accept decision before a session starts.

---

## Why it is structured this way

The project is split so the **security- and protocol-critical core is pure Rust
and fully testable on any machine** (including headless CI), while the
OS-specific desktop integration (screen capture, input injection, system
clipboard, Windows UAC) lives behind **feature flags** with portable fallbacks.

That means the complete pipeline — relay ⇄ host ⇄ controller, Noise handshake,
encrypted tile-delta video, file transfer, clipboard — **compiles, tests and
runs end-to-end out of the box**, and the same binaries light up real capture
and input when built on a desktop with `--features desktop`.

## Workspace layout

| Crate | What it provides |
|---|---|
| `insdesk-proto` | Wire protocol: every message type, length-prefix framing, codec descriptors. Pure data. |
| `insdesk-crypto` | End-to-end encryption: Noise `XX` channel, long-term identity keys, 9-digit device IDs, channel-bound password proofs. |
| `insdesk-net` | Async transport: framing, relay rendezvous client, and the concurrent encrypted session pipe. |
| `insdesk-media` | Tile + delta + DEFLATE video codec, screen-capture trait (+ `scrap`), input-injection trait (+ `enigo`), UAC/secure-desktop bridge. |
| `insdesk-fs` | Integrity-checked chunked file transfer (both directions) and clipboard sync. |
| `insdesk-core` | Host and controller session engines + identity keystore. |
| `insdesk-relay` | The relay / rendezvous server binary. |
| `insdesk-host` | The host agent binary (the machine being controlled). |
| `insdesk-client` | The controller binary: headless CLI + optional egui GUI. |

## Feature → implementation map

- **Smooth streaming** → `insdesk-media::codec` (dirty-tile delta encoding with
  per-tile DEFLATE / solid-color fast path) driven by an adaptive capture loop
  in `insdesk-core::host` with quality/FPS controls and frame dropping under
  backpressure.
- **File copy/paste, remote *and* local** → `insdesk-fs::transfer`
  (download = host→controller, upload = controller→host, each SHA-256 verified)
  and `insdesk-fs::clipboard` (bi-directional text sync).
- **Control PC** → `insdesk-media::input` (`enigo` backend) fed by the
  controller's mouse/keyboard events.
- **Good UI** → the egui GUI in `insdesk-client` (live texture, input
  forwarding, status bar, quality sliders, file panel, clipboard), plus a
  scriptable CLI.
- **UAC dialog controllable remotely** → `insdesk-media::uac` +
  `ElevationMsg` protocol: the host detects the secure desktop, notifies the
  controller, and (via an elevated session-0 helper on Windows) streams and
  injects into it. See [UAC / secure desktop](#uac--secure-desktop-bridge).
- **End-to-end encryption** → `insdesk-crypto`: the relay only forwards opaque
  ciphertext; see [Security model](#security-model).

---

## Build

```bash
# Core engine + all three binaries with portable backends (works anywhere,
# including headless CI — uses a synthetic capturer and a recording input sink).
cargo build --release

# Real desktop backends (needs X11+XTest / Windows / macOS dev libraries):
cargo build --release -p insdesk-host   --features desktop
cargo build --release -p insdesk-client --features gui

# On Windows, add the UAC secure-desktop bridge:
cargo build --release -p insdesk-host --features "desktop uac-windows"
```

Run the test suite (all pure-Rust, no display needed):

```bash
cargo test --workspace
```

## Quick start (three terminals)

```bash
# 1) Relay / rendezvous server
cargo run --release -p insdesk-relay -- --listen 0.0.0.0:9510

# 2) Host agent — prints its device ID on startup
cargo run --release -p insdesk-host -- \
    --relay 127.0.0.1:9510 --name my-pc --password hunter2

# 3) Controller — dial the host's device ID
cargo run --release -p insdesk-client --features gui -- \
    --relay 127.0.0.1:9510 --id <DEVICE_ID> --password hunter2 --gui
```

### Headless controller (no GUI, scriptable)

The CLI controller connects over the same encrypted channel and can snapshot the
screen and move files — handy for automation and for verifying a deployment:

```bash
cargo run --release -p insdesk-client -- \
    --relay 127.0.0.1:9510 --id <DEVICE_ID> --password hunter2 \
    --ls "." \
    --download "report.pdf:/tmp/report.pdf" \
    --upload   "/tmp/patch.bin:incoming/patch.bin" \
    --snapshot /tmp/remote.png
```

### Direct connection (no relay)

```bash
# Host listens itself:
insdesk-host   --listen 0.0.0.0:9511 --password hunter2
# Controller dials the address directly:
insdesk-client --connect host.example:9511 --gui   # add --id <ID> to verify identity
```

---

## Security model

- **Identity.** Each device has a long-term Curve25519 keypair. The host's
  **9-digit device ID is derived from its public key**, so the number a user
  dials is cryptographically bound to a specific key.
- **Channel.** Sessions run over a **Noise `XX` (`25519 + ChaChaPoly +
  BLAKE2s`)** handshake: mutual authentication of both static keys plus forward
  secrecy from the ephemeral exchange.
- **Anti-MITM.** After the handshake the controller checks that the host's
  presented key maps to the dialed device ID. A relay that cannot produce the
  host's private key is detected.
- **Password.** An optional session password is verified *inside* the encrypted
  channel using a proof **bound to the Noise handshake hash**, so it cannot be
  replayed onto another session or forged through a man-in-the-middle.
- **The relay is untrusted.** It performs rendezvous (pair a controller to a
  host by ID) and then forwards **opaque ciphertext**. It holds no keys and
  cannot read or alter session content — confidentiality and integrity are
  genuinely end-to-end.
- **Authorization.** The host enforces policy: require a password, allow or deny
  input/file transfer, confine file access to a `--file-root` jail, and (outside
  `--auto-accept`) decide whether to admit the session.

See `crates/insdesk-crypto/src/lib.rs` for the detailed rationale and tests.

## UAC / secure desktop bridge

Windows draws UAC consent prompts on an isolated **secure desktop** that an
ordinary user-session agent cannot see or click — exactly when admin work is
needed. InsDesk handles this with a privileged helper:

1. The agent installs a **Windows service** running as `LocalSystem` in session 0.
2. That service can attach to the secure desktop (`OpenInputDesktop` /
   `SetThreadDesktop`), capture it, and inject input into it.
3. `insdesk-media::uac` detects when the secure desktop becomes active, the host
   sends `ElevationMsg::SecureDesktopActive`, switches its capture to the secure
   desktop, and routes the operator's input there — so the **UAC dialog is
   visible and answerable remotely**. The person at the host keeps a hard
   kill-switch (`SetSecureDesktopControl`).

The trait and a portable no-op bridge are always compiled; the real Windows
implementation is behind `cfg(windows)` + `--features uac-windows`. See
`crates/insdesk-media/src/uac.rs`.

## Protocol in brief

```
Controller                      Relay                        Host
   | ConnectToHost{id} --------->  |  <--------- RegisterHost{id}
   |              <--- PeerConnected / PeerConnected --->     |
   | ====================== Noise XX handshake ============== |   (relay forwards opaque bytes)
   | -- Hello -->                                 <-- Hello --|
   | -- AuthRequest{proof} -->                               |
   |               <-- AuthResult / SessionDecision / VideoConfig --|
   | <====== VideoFrame (tile deltas), Clipboard, File ======|
   | ===== Input, File ops, Clipboard, Elevation ===========>|
```

Everything after `PeerConnected` is sealed by the Noise transport; the relay
only moves ciphertext.

## Platform backends

| Capability | Portable default | Real backend (feature) |
|---|---|---|
| Screen capture | animated synthetic frames | `scrap` (`capture-scrap`) |
| Input injection | recording sink (audited, no-op) | `enigo` (`input-enigo`) |
| Clipboard | in-memory | `arboard` (`clipboard-arboard`) |
| UAC / secure desktop | no-op bridge | Windows service (`uac-windows`) |

## License

Licensed under either of MIT or Apache-2.0 at your option.
