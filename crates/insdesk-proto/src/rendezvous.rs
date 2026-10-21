//! Control-plane messages exchanged with the relay / rendezvous server.
//!
//! The relay's only jobs are (1) let a host publish a short numeric ID and (2)
//! pair an incoming controller with that host and then blindly forward opaque
//! encrypted frames between them. These messages are therefore routing-only and
//! carry **no** session content — the end-to-end Noise channel is negotiated
//! *through* the relay, so the relay never holds any key material.

use serde::{Deserialize, Serialize};

/// A host's public address on the relay: a short, human-dictatable number.
pub type DeviceId = u64;

/// First message a peer sends to the relay after connecting, declaring intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RendezvousHello {
    /// A host comes online and wants to be reachable at `id`.
    ///
    /// `id` is derived from the host's long-term public key (see
    /// `insdesk-crypto::device_id_from_pubkey`) so it is stable across restarts
    /// and binds the number to a verifiable identity.
    RegisterHost { id: DeviceId },
    /// A controller wants to reach the host registered at `id`.
    ConnectToHost { id: DeviceId },
}

/// The relay's reply to a [`RendezvousHello`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RendezvousReply {
    /// Host registration succeeded; the host should now wait for peers.
    Registered { id: DeviceId },
    /// A controller asked for this host and has been paired; the next bytes on
    /// the stream are the opaque encrypted session (Noise handshake first).
    PeerConnected,
    /// The requested host id is not currently online.
    HostUnavailable { id: DeviceId },
    /// The id is already registered by another live connection.
    IdInUse { id: DeviceId },
    /// Generic failure with a human-readable reason.
    Error { reason: String },
}
