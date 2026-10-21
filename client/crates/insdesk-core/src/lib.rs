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

pub mod backends;
pub mod controller;
pub mod host;
pub mod keystore;
pub mod session_support;

pub use controller::{ControllerCommand, ControllerConfig, ControllerEvent, ControllerHandle};
pub use host::{HostBackends, HostConfig};
pub use keystore::load_or_create;

/// Generate a random, human-typable session password (lowercase letters and
/// digits, ambiguous characters omitted). Used by the desktop app to show a
/// fresh password that remote operators enter to connect.
pub fn random_password(len: usize) -> String {
    use rand::Rng;
    // No 0/o/1/l/i to avoid confusion when read aloud or copied by hand.
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}
