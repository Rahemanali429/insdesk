//! Client helpers for talking to the InsDesk relay (rendezvous) server.
//!
//! The relay exposes only the routing messages in
//! `insdesk_proto::rendezvous`. Once a host and controller are paired, the relay
//! copies opaque bytes between them; from that point the stream carries the
//! end-to-end Noise session, which the relay cannot read.

use crate::frame_io::{read_frame, write_frame};
use crate::NetError;
use insdesk_proto::rendezvous::{DeviceId, RendezvousHello, RendezvousReply};
use tokio::net::TcpStream;

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, NetError> {
    bincode::serialize(v).map_err(|e| NetError::Protocol(e.to_string()))
}
fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, NetError> {
    bincode::deserialize(b).map_err(|e| NetError::Protocol(e.to_string()))
}

/// Connect to the relay and register as a host under `id`. Returns the stream,
/// still connected and waiting for a controller to arrive.
pub async fn register_host(relay_addr: &str, id: DeviceId) -> Result<TcpStream, NetError> {
    let mut stream = TcpStream::connect(relay_addr).await?;
    stream.set_nodelay(true).ok();
    write_frame(&mut stream, &encode(&RendezvousHello::RegisterHost { id })?).await?;
    match decode::<RendezvousReply>(&read_frame(&mut stream).await?)? {
        RendezvousReply::Registered { .. } => Ok(stream),
        RendezvousReply::IdInUse { id } => Err(NetError::Rendezvous(format!("id {id} already in use"))),
        other => Err(NetError::Rendezvous(format!("unexpected reply: {other:?}"))),
    }
}

/// Block until a controller is paired with this registered host. After this
/// returns, the stream is the opaque session pipe (Noise handshake next).
pub async fn wait_for_peer(stream: &mut TcpStream) -> Result<(), NetError> {
    match decode::<RendezvousReply>(&read_frame(stream).await?)? {
        RendezvousReply::PeerConnected => Ok(()),
        other => Err(NetError::Rendezvous(format!("unexpected reply: {other:?}"))),
    }
}

/// Connect to the relay as a controller and ask to reach host `id`. After this
/// returns, the stream is the opaque session pipe (Noise handshake next).
pub async fn connect_to_host(relay_addr: &str, id: DeviceId) -> Result<TcpStream, NetError> {
    let mut stream = TcpStream::connect(relay_addr).await?;
    stream.set_nodelay(true).ok();
    write_frame(&mut stream, &encode(&RendezvousHello::ConnectToHost { id })?).await?;
    match decode::<RendezvousReply>(&read_frame(&mut stream).await?)? {
        RendezvousReply::PeerConnected => Ok(stream),
        RendezvousReply::HostUnavailable { id } => {
            Err(NetError::Rendezvous(format!("host {id} is offline")))
        }
        other => Err(NetError::Rendezvous(format!("unexpected reply: {other:?}"))),
    }
}
