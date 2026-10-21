//! Shared connection setup for every front-end (CLI and GUI).

use anyhow::{anyhow, Result};
use insdesk_core::controller::{self, ControllerConfig, ControllerHandle};
use insdesk_net::{connect_direct, perform_handshake, relay, spawn_session, HandshakeRole};
use insdesk_proto::QualityHint;
use std::path::PathBuf;

/// Everything needed to reach and authenticate to a host.
#[derive(Clone)]
pub struct ConnectOpts {
    /// Relay address (with [`ConnectOpts::id`]) — mutually exclusive with `direct`.
    pub relay: Option<String>,
    /// Direct host address, bypassing any relay.
    pub direct: Option<String>,
    /// Target device ID (required in relay mode).
    pub id: Option<u64>,
    /// Identity key file for this controller (created if missing).
    pub key: PathBuf,
    pub name: String,
    pub password: Option<String>,
    /// Verify the host's key maps to `id` (MITM protection). Ignored without id.
    pub verify_id: bool,
    pub quality: u8,
    pub fps: u8,
}

/// Connect, run the secure handshake, and start the controller engine.
pub async fn establish(opts: &ConnectOpts) -> Result<ControllerHandle> {
    let identity = insdesk_core::load_or_create(&opts.key)?;

    let mut stream = if let Some(direct) = &opts.direct {
        tracing::info!("connecting directly to {direct}");
        connect_direct(direct).await?
    } else {
        let relay_addr = opts.relay.as_ref().ok_or_else(|| anyhow!("need --relay or --connect"))?;
        let id = opts.id.ok_or_else(|| anyhow!("--id is required in relay mode"))?;
        tracing::info!("reaching host {id} via relay {relay_addr}");
        relay::connect_to_host(relay_addr, id).await?
    };

    let established = perform_handshake(&mut stream, HandshakeRole::Initiator, &identity).await?;
    let (transport, meta) = established.into_parts();
    let session = spawn_session(stream, transport, 32);

    let cfg = ControllerConfig {
        display_name: opts.name.clone(),
        expected_id: if opts.verify_id { opts.id } else { None },
        password: opts.password.clone(),
        initial_quality: QualityHint { quality: opts.quality, max_fps: opts.fps },
    };
    controller::connect(session, &meta, cfg).await
}
