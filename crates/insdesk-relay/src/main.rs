//! InsDesk relay / rendezvous server.
//!
//! A host registers a numeric ID; a controller asks to reach that ID. The relay
//! pairs them and then copies bytes between the two sockets. Everything after
//! the pairing is the end-to-end Noise session, which the relay cannot read —
//! it only moves opaque frames. The relay therefore needs no keys and is not a
//! trusted party for confidentiality or integrity.

use anyhow::{anyhow, Result};
use clap::Parser;
use insdesk_net::frame_io::{read_frame, write_frame};
use insdesk_proto::rendezvous::{DeviceId, RendezvousHello, RendezvousReply};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};

/// Map of hosts currently waiting for a controller.
type Waiting = Arc<Mutex<HashMap<DeviceId, oneshot::Sender<TcpStream>>>>;

#[derive(Parser, Debug)]
#[command(name = "insdesk-relay", about = "InsDesk relay / rendezvous server")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:9510", env = "INSDESK_RELAY_LISTEN")]
    listen: String,
}

fn encode<T: serde::Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).expect("serialize rendezvous message")
}
fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
    bincode::deserialize(b).map_err(|e| anyhow!("decode: {e}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("INSDESK_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen).await?;
    tracing::info!("insdesk-relay listening on {}", args.listen);

    let waiting: Waiting = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };
        socket.set_nodelay(true).ok();
        let waiting = waiting.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, waiting).await {
                tracing::debug!("connection {peer} ended: {e}");
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream, waiting: Waiting) -> Result<()> {
    let hello: RendezvousHello = decode(&read_frame(&mut socket).await?)?;
    match hello {
        RendezvousHello::RegisterHost { id } => handle_host(socket, id, waiting).await,
        RendezvousHello::ConnectToHost { id } => handle_controller(socket, id, waiting).await,
    }
}

async fn handle_host(mut socket: TcpStream, id: DeviceId, waiting: Waiting) -> Result<()> {
    // Reserve the id.
    let rx = {
        let mut map = waiting.lock().await;
        if map.contains_key(&id) {
            write_frame(&mut socket, &encode(&RendezvousReply::IdInUse { id })).await?;
            return Ok(());
        }
        let (tx, rx) = oneshot::channel();
        map.insert(id, tx);
        rx
    };
    write_frame(&mut socket, &encode(&RendezvousReply::Registered { id })).await?;
    tracing::info!("host {id} registered, awaiting controller");

    // Wait for a controller to be paired in. If the socket drops first, clean up.
    let controller = tokio::select! {
        res = rx => res.map_err(|_| anyhow!("registration cancelled"))?,
        _ = wait_closed(&mut socket) => {
            waiting.lock().await.remove(&id);
            return Ok(());
        }
    };
    waiting.lock().await.remove(&id);

    // Tell both sides we're paired, then splice the raw byte streams.
    let mut controller = controller;
    write_frame(&mut socket, &encode(&RendezvousReply::PeerConnected)).await?;
    write_frame(&mut controller, &encode(&RendezvousReply::PeerConnected)).await?;
    tracing::info!("host {id} paired with controller; relaying");

    let (sent, recvd) = tokio::io::copy_bidirectional(&mut socket, &mut controller).await?;
    tracing::info!("session for {id} finished ({sent}B →, {recvd}B ←)");
    Ok(())
}

async fn handle_controller(mut socket: TcpStream, id: DeviceId, waiting: Waiting) -> Result<()> {
    let tx = { waiting.lock().await.remove(&id) };
    match tx {
        Some(tx) => {
            // Hand our socket to the waiting host task, which drives the splice.
            if tx.send(socket).is_err() {
                tracing::warn!("host {id} vanished before pairing");
            }
            Ok(())
        }
        None => {
            write_frame(&mut socket, &encode(&RendezvousReply::HostUnavailable { id })).await?;
            Ok(())
        }
    }
}

/// Resolve when the registered host socket becomes readable or closes while we
/// wait for a controller. A well-behaved host sends nothing until it is paired,
/// so `peek` simply pends until EOF; any readiness (close, stray data, or error)
/// ends the wait and lets the caller clean up the registration.
async fn wait_closed(socket: &mut TcpStream) {
    let mut buf = [0u8; 1];
    let _ = socket.peek(&mut buf).await;
}
