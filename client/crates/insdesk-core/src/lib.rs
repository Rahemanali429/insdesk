//! # insdesk-core
//!
//! Session orchestration tying the crypto, transport, media and file-transfer
//! layers into two engines:
//!
//! * [`host`] — the controlled machine: authenticate the peer, stream the
//!   screen, replay input, serve files/clipboard, bridge UAC.
//! * [`controller`] — the controlling machine: verify the host's identity,
//!   decode the stream, and expose a command/event handle that any front-end
//!   (CLI or GUI) drives.
//!
//! [`keystore`] persists the long-term identity key.

pub mod controller;
pub mod host;
pub mod keystore;
pub mod session_support;

pub use controller::{ControllerCommand, ControllerConfig, ControllerEvent, ControllerHandle};
pub use host::{HostBackends, HostConfig};
pub use keystore::load_or_create;
