//! # insdesk-net
//!
//! Async transport glue. It turns a raw byte stream (from the relay or a direct
//! TCP connection) into a concurrent, end-to-end-encrypted channel of
//! [`insdesk_proto::Message`] values.
//!
//! Pipeline, from the application's point of view:
//!
//! ```text
//!   Message ──serialize──▶ record(len||bytes) ──chunk≤60k──▶ Noise.encrypt ──▶ frame ──▶ TCP
//!   Message ◀─deserialize── record reassembly ◀─ Noise.decrypt ◀─ frame ◀── TCP
//! ```
//!
//! A single writer task owns the sending cipher and a single reader task owns
//! the receiving cipher, so per-direction Noise nonces stay strictly ordered
//! even while video streams out and input/clipboard/file traffic flow back.

pub mod frame_io;
pub mod relay;

use insdesk_crypto::{Handshake, Identity, Transport};
use insdesk_proto::{Message, MAX_PLAINTEXT_CHUNK};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

/// Largest reassembled application record we will accept from a peer, to bound
/// memory against a hostile sender. Video frames are chunked well below this by
/// the media layer.
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum NetError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("frame error: {0}")]
    Frame(#[from] insdesk_proto::FrameError),
    #[error("crypto error: {0}")]
    Crypto(#[from] insdesk_crypto::CryptoError),
    #[error("rendezvous error: {0}")]
    Rendezvous(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("record of {0} bytes exceeds maximum {MAX_RECORD_LEN}")]
    RecordTooLarge(usize),
    #[error("session closed")]
    Closed,
}

/// Which end of the handshake to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Dials out (controller). Writes the first XX message.
    Initiator,
    /// Answers (host).
    Responder,
}

/// Outcome of a completed handshake: the bulk cipher plus the metadata the
/// session engines need.
pub struct Established {
    pub transport: Transport,
    pub meta: SessionMeta,
}

/// Post-handshake metadata, separable from the (unclonable) [`Transport`] so it
/// can be handed to a session engine while the transport is moved into the
/// reader/writer tasks.
#[derive(Clone)]
pub struct SessionMeta {
    /// The peer's long-term public key (for device-ID checks / allow-listing).
    pub remote_public: Vec<u8>,
    /// Noise handshake hash, used to channel-bind the password proof.
    pub handshake_hash: Vec<u8>,
}

impl Established {
    /// Split into the transport (for [`spawn_session`]) and the metadata (for
    /// the engine).
    pub fn into_parts(self) -> (Transport, SessionMeta) {
        (self.transport, self.meta)
    }
}

/// Run the Noise `XX` handshake to completion over `stream`.
pub async fn perform_handshake<S>(
    stream: &mut S,
    role: HandshakeRole,
    identity: &Identity,
) -> Result<Established, NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = match role {
        HandshakeRole::Initiator => Handshake::new_initiator(identity)?,
        HandshakeRole::Responder => Handshake::new_responder(identity)?,
    };

    while !hs.is_finished() {
        if hs.is_my_turn() {
            let msg = hs.write_message()?;
            frame_io::write_frame(stream, &msg).await?;
        } else {
            let msg = frame_io::read_frame(stream).await?;
            hs.read_message(&msg)?;
        }
    }

    let (transport, remote_public, handshake_hash) = hs.into_transport()?;
    Ok(Established { transport, meta: SessionMeta { remote_public, handshake_hash } })
}

/// The live, encrypted session. Clone-free: hold the [`SessionSender`] to send
/// and the [`SessionReceiver`] to receive; both can be moved into separate
/// tasks.
pub struct Session {
    pub sender: SessionSender,
    pub receiver: SessionReceiver,
    _writer: JoinHandle<()>,
    _reader: JoinHandle<()>,
}

/// Send side: enqueue [`Message`] values; a background task encrypts and writes
/// them in order.
#[derive(Clone)]
pub struct SessionSender {
    tx: mpsc::Sender<Message>,
}

impl SessionSender {
    /// Queue a message for encrypted delivery. Applies backpressure.
    pub async fn send(&self, msg: Message) -> Result<(), NetError> {
        self.tx.send(msg).await.map_err(|_| NetError::Closed)
    }

    /// Try to queue without waiting; drops the oldest-friendly semantics to the
    /// caller. Returns `false` if the queue is full (useful for video frames
    /// that are fine to skip under congestion).
    pub fn try_send(&self, msg: Message) -> bool {
        self.tx.try_send(msg).is_ok()
    }

    /// Blocking variant for use from `spawn_blocking` / native threads (e.g.
    /// streaming a file off disk). Must not be called from an async context.
    pub fn blocking_send(&self, msg: Message) -> Result<(), NetError> {
        self.tx.blocking_send(msg).map_err(|_| NetError::Closed)
    }
}

/// Receive side: a background task decrypts and reassembles messages into this
/// channel.
pub struct SessionReceiver {
    rx: mpsc::Receiver<Result<Message, String>>,
}

impl SessionReceiver {
    /// Await the next decrypted message. `None` once the session is closed.
    pub async fn recv(&mut self) -> Option<Result<Message, NetError>> {
        self.rx
            .recv()
            .await
            .map(|r| r.map_err(NetError::Protocol))
    }
}

/// Spawn the reader/writer tasks for an established session over a `TcpStream`.
///
/// `send_capacity` bounds the outbound queue; a small value keeps latency low
/// and lets callers use [`SessionSender::try_send`] to shed video frames under
/// congestion.
pub fn spawn_session(
    stream: TcpStream,
    transport: Transport,
    send_capacity: usize,
) -> Session {
    let (read_half, write_half) = stream.into_split();
    let transport = Arc::new(Mutex::new(transport));

    let (out_tx, out_rx) = mpsc::channel::<Message>(send_capacity);
    let (in_tx, in_rx) = mpsc::channel::<Result<Message, String>>(send_capacity.max(16));

    let writer = tokio::spawn(writer_task(write_half, transport.clone(), out_rx));
    let reader = tokio::spawn(reader_task(read_half, transport, in_tx));

    Session {
        sender: SessionSender { tx: out_tx },
        receiver: SessionReceiver { rx: in_rx },
        _writer: writer,
        _reader: reader,
    }
}

/// Encrypt and write queued messages in order.
async fn writer_task(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    transport: Arc<Mutex<Transport>>,
    mut out_rx: mpsc::Receiver<Message>,
) {
    while let Some(msg) = out_rx.recv().await {
        let bytes = match msg.encode() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("failed to encode message: {e}");
                continue;
            }
        };
        // Inner record = 4-byte length prefix + serialized message.
        let mut record = Vec::with_capacity(4 + bytes.len());
        record.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        record.extend_from_slice(&bytes);

        // Split the record into Noise-sized units, encrypt each, and write.
        for chunk in record.chunks(MAX_PLAINTEXT_CHUNK) {
            let ciphertext = {
                let mut t = transport.lock().await;
                match t.encrypt(chunk) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("encrypt failed: {e}");
                        return;
                    }
                }
            };
            if frame_io::write_frame(&mut write_half, &ciphertext).await.is_err() {
                tracing::debug!("writer: peer closed");
                return;
            }
        }
    }
}

/// Read, decrypt, and reassemble messages.
async fn reader_task(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    transport: Arc<Mutex<Transport>>,
    in_tx: mpsc::Sender<Result<Message, String>>,
) {
    let mut inbuf: Vec<u8> = Vec::new();
    loop {
        let ciphertext = match frame_io::read_frame(&mut read_half).await {
            Ok(c) => c,
            Err(_) => break, // peer closed or protocol error
        };
        let plaintext = {
            let mut t = transport.lock().await;
            match t.decrypt(&ciphertext) {
                Ok(p) => p,
                Err(e) => {
                    let _ = in_tx.send(Err(format!("decrypt failed: {e}"))).await;
                    break;
                }
            }
        };
        inbuf.extend_from_slice(&plaintext);

        // Extract every complete record currently buffered.
        loop {
            if inbuf.len() < 4 {
                break;
            }
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&inbuf[..4]);
            let record_len = u32::from_be_bytes(len_bytes) as usize;
            if record_len > MAX_RECORD_LEN {
                let _ = in_tx
                    .send(Err(format!("record length {record_len} too large")))
                    .await;
                return;
            }
            if inbuf.len() < 4 + record_len {
                break; // wait for more chunks
            }
            let body = inbuf[4..4 + record_len].to_vec();
            inbuf.drain(..4 + record_len);
            match Message::decode(&body) {
                Ok(msg) => {
                    if in_tx.send(Ok(msg)).await.is_err() {
                        return; // receiver dropped
                    }
                }
                Err(e) => {
                    let _ = in_tx.send(Err(format!("decode failed: {e}"))).await;
                    return;
                }
            }
        }
    }
}

/// Connect directly to a listening host (no relay), returning the raw stream.
pub async fn connect_direct(addr: &str) -> Result<TcpStream, NetError> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}
