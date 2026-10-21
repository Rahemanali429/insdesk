//! # insdesk-proto
//!
//! The wire protocol shared by every InsDesk component.
//!
//! The protocol has two planes:
//!
//! * **Control plane (rendezvous):** small, routing-only messages exchanged with
//!   the relay server so a controller can find a host by its numeric ID. The
//!   relay only ever sees these routing messages and, afterwards, *opaque*
//!   encrypted blobs — it can never read session content. See [`rendezvous`].
//!
//! * **Session plane (end-to-end):** every message defined in [`Message`] is
//!   serialized, then sealed inside the peer-to-peer Noise channel
//!   (`insdesk-crypto`) before it ever touches the wire. Neither the relay nor a
//!   network observer can read or tamper with it.
//!
//! Everything here is pure data + (de)serialization so it builds on every
//! platform and is trivially unit-testable.

pub mod codec;
pub mod frame;
pub mod rendezvous;

pub use frame::FrameError;

use serde::{Deserialize, Serialize};

/// Protocol version. Bumped on any incompatible change to [`Message`] or the
/// rendezvous messages. Peers exchange this in [`Hello`] and refuse mismatches.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum plaintext size of a single session message *before* encryption.
///
/// Noise transport messages are capped at 65535 bytes, and `insdesk-net` adds a
/// small framing/overhead budget, so large payloads (video frames, file chunks)
/// are split into pieces no larger than this by the sender.
pub const MAX_PLAINTEXT_CHUNK: usize = 60 * 1024;

/// A monotonically increasing identifier for video frames.
pub type FrameSeq = u64;

/// Opaque identifier for an in-flight file transfer.
pub type TransferId = u64;

// ---------------------------------------------------------------------------
// Session-plane messages (always travel inside the E2E channel)
// ---------------------------------------------------------------------------

/// Every message exchanged between a controller and a host after the secure
/// channel is established.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Message {
    /// First message each side sends, announcing itself.
    Hello(Hello),
    /// Controller proves knowledge of the session password (if the host
    /// requires one). The proof is computed over data bound to the live
    /// Noise handshake, so it cannot be replayed on another session.
    AuthRequest { proof: Vec<u8> },
    /// Host's verdict on an [`Message::AuthRequest`].
    AuthResult { accepted: bool, reason: Option<String> },
    /// Human on the host machine accepted/declined the incoming session
    /// (AnyDesk-style "Allow" prompt). Sent by the host.
    SessionDecision { accepted: bool, reason: Option<String> },

    /// Host announces the stream geometry/format before sending frames.
    VideoConfig(VideoConfig),
    /// A (possibly partial) video frame. See [`codec`] for the payload format.
    VideoFrame(VideoFrame),
    /// Controller asks the host to send a full (non-delta) frame, e.g. after a
    /// decode error or when a new viewer attaches.
    RequestKeyframe,
    /// Controller tunes the stream at runtime (quality vs. bandwidth).
    SetQuality(QualityHint),

    /// Controller → host: an input event to inject (mouse/keyboard).
    Input(InputEvent),

    /// Bi-directional clipboard synchronization (the "copy/paste" of text and
    /// small blobs between the two machines).
    Clipboard(ClipboardData),

    /// File-manager / file-transfer operations. Works in both directions:
    /// the controller can browse & pull from the host, and push to it.
    File(FileMsg),

    /// Privilege-elevation / UAC bridge messages. Let the remote operator see
    /// and drive a UAC secure-desktop prompt on the host.
    Elevation(ElevationMsg),

    /// Keep-alive / latency probe. The receiver echoes it back unchanged.
    Ping { nonce: u64, sent_unix_millis: u64 },
    /// Response to [`Message::Ping`].
    Pong { nonce: u64, sent_unix_millis: u64 },

    /// Orderly shutdown of the session.
    Bye { reason: Option<String> },
}

impl Message {
    /// Serialize to bytes with bincode. Used by `insdesk-net` right before the
    /// bytes are handed to the Noise encryptor.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        bincode::serialize(self).map_err(|e| FrameError::Serialize(e.to_string()))
    }

    /// Deserialize bytes produced by [`Message::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        bincode::deserialize(bytes).map_err(|e| FrameError::Deserialize(e.to_string()))
    }
}

/// Which role a peer plays in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// The machine being viewed/controlled.
    Host,
    /// The machine doing the viewing/controlling.
    Controller,
}

/// Initial greeting with capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hello {
    pub protocol_version: u16,
    pub role: Role,
    /// Friendly display name (hostname, user label, …).
    pub display_name: String,
    /// Feature flags the sender supports (forward-compatible).
    pub features: Features,
}

/// Capability bitset exchanged in [`Hello`]. Unknown bits are ignored so new
/// capabilities can be added without breaking old peers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Features {
    pub clipboard: bool,
    pub file_transfer: bool,
    pub input_control: bool,
    pub elevation_bridge: bool,
    pub audio: bool,
}

impl Features {
    /// The full set this build understands.
    pub fn current() -> Self {
        Features {
            clipboard: true,
            file_transfer: true,
            input_control: true,
            elevation_bridge: true,
            audio: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Video
// ---------------------------------------------------------------------------

/// Stream geometry and pixel format announced before frames flow.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoConfig {
    pub width: u32,
    pub height: u32,
    /// Pixels are delivered as BGRA (little-endian 0xAARRGGBB) tiles.
    pub pixel_format: PixelFormat,
    /// Size of the square tile grid used by the delta codec.
    pub tile_size: u32,
}

/// Pixel formats the codec understands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PixelFormat {
    /// 4 bytes per pixel, order B, G, R, A.
    Bgra8888,
    /// 4 bytes per pixel, order R, G, B, A.
    Rgba8888,
}

impl PixelFormat {
    pub const fn bytes_per_pixel(self) -> usize {
        4
    }
}

/// A single encoded frame (full keyframe or a delta of changed tiles).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoFrame {
    pub seq: FrameSeq,
    /// `true` if this frame can be decoded without any prior frame.
    pub keyframe: bool,
    /// Capture timestamp (host clock, unix millis) for latency accounting.
    pub captured_unix_millis: u64,
    /// Encoded tile payload. Format described in [`codec`].
    pub payload: codec::EncodedFrame,
}

/// A hint the controller sends to trade quality against bandwidth.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct QualityHint {
    /// 1..=100. Lower → more aggressive compression / subsampling.
    pub quality: u8,
    /// Target maximum frames per second.
    pub max_fps: u8,
}

impl Default for QualityHint {
    fn default() -> Self {
        QualityHint { quality: 80, max_fps: 30 }
    }
}

// ---------------------------------------------------------------------------
// Input (remote control)
// ---------------------------------------------------------------------------

/// A single input action to replay on the host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InputEvent {
    /// Absolute pointer move in host pixels.
    MouseMove { x: i32, y: i32 },
    /// Pointer button transition.
    MouseButton { button: MouseButton, down: bool },
    /// Wheel scroll, in notches (+ up/right, - down/left).
    MouseScroll { dx: i32, dy: i32 },
    /// Key transition by platform-independent [`Key`].
    Key { key: Key, down: bool },
    /// A Unicode scalar to type directly (handles layout-independent text).
    Text { ch: char },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Platform-independent key identifiers. Deliberately small but covers the keys
/// a remote operator needs most, including the ones required to drive dialogs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Key {
    Enter,
    Escape,
    Backspace,
    Tab,
    Space,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    Left,
    Right,
    Up,
    Down,
    Shift,
    Control,
    Alt,
    /// The Windows / Command / Super key.
    Meta,
    CapsLock,
    F(u8),
    /// A printable character key (letters, digits, punctuation).
    Char(char),
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

/// Clipboard contents mirrored between the two machines.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClipboardData {
    #[default]
    Empty,
    Text(String),
}

// ---------------------------------------------------------------------------
// File transfer
// ---------------------------------------------------------------------------

/// All file-manager / transfer messages. Either side may send any of these;
/// `direction` on a transfer is implied by who issues [`FileMsg::DownloadRequest`]
/// vs [`FileMsg::UploadRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileMsg {
    /// List a directory on the receiving peer.
    ListDir { path: String },
    /// Reply to [`FileMsg::ListDir`].
    DirListing { path: String, entries: Vec<DirEntry>, error: Option<String> },

    /// Ask the peer to send us the file at `path` (peer → requester).
    DownloadRequest { transfer: TransferId, path: String },
    /// Ask the peer to receive a file we will push to `dest` (requester → peer).
    UploadRequest { transfer: TransferId, dest: String, size: u64 },
    /// Peer's answer to an upload/download request.
    TransferAccept { transfer: TransferId, size: u64 },
    /// Peer rejected the transfer.
    TransferReject { transfer: TransferId, reason: String },

    /// One ordered chunk of file bytes.
    Chunk { transfer: TransferId, offset: u64, data: Vec<u8> },
    /// Final message of a transfer, carrying an integrity digest.
    TransferDone { transfer: TransferId, sha256_hex: String },
    /// Abort an in-flight transfer.
    TransferAbort { transfer: TransferId, reason: String },

    /// Create a directory on the peer.
    MakeDir { path: String },
    /// Delete a file or empty directory on the peer.
    Remove { path: String },
    /// Generic acknowledgement for `MakeDir`/`Remove`.
    OpAck { ok: bool, error: Option<String> },
}

/// One entry in a directory listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Modified time as unix seconds, if known.
    pub modified_unix: Option<u64>,
}

// ---------------------------------------------------------------------------
// Elevation / UAC bridge
// ---------------------------------------------------------------------------

/// Messages that let a remote operator observe and control a privilege
/// elevation prompt (Windows UAC secure desktop, or `pkexec`/`sudo` prompts on
/// other platforms).
///
/// On Windows the UAC prompt is drawn on an isolated *secure desktop* that an
/// ordinary user-session capture cannot see. The host therefore runs an
/// elevated helper (see `insdesk-media::uac`) that captures that desktop and
/// injects input into it; these messages carry the notifications and requests
/// between the two sides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ElevationMsg {
    /// Host → controller: a UAC / secure-desktop prompt just appeared (or
    /// disappeared). While active, the host streams the secure desktop instead
    /// of the normal one, so the operator can read and answer the dialog.
    SecureDesktopActive { active: bool },
    /// Controller → host: please trigger an elevation for the given action
    /// (e.g. relaunch the agent elevated so the whole session is privileged).
    RequestElevation { reason: String },
    /// Host → controller: result / status of an elevation attempt.
    ElevationStatus { elevated: bool, detail: String },
    /// Controller → host: whether the operator is allowed to interact with the
    /// secure desktop. The human at the host can revoke this at any time.
    SetSecureDesktopControl { allowed: bool },
}
