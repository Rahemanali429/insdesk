//! Controller-side session engine: the machine doing the viewing/controlling.
//!
//! [`connect`] runs the handshake (device-ID verification + channel-bound
//! password proof + accept wait), then spawns a driver task and hands back a
//! [`ControllerHandle`]. UIs (the CLI and the egui GUI) drive the session purely
//! through the handle's command channel and react to its event stream, so the
//! same engine backs every front-end.

use crate::session_support::SessionAuth;
use anyhow::{anyhow, Result};
use insdesk_crypto::verify_device_id;
use insdesk_fs::transfer::FsError;
use insdesk_fs::{FileService, InboundTransfer};
use insdesk_media::codec::Decoder;
use insdesk_net::{Session, SessionMeta, SessionReceiver, SessionSender};
use insdesk_proto::{
    ClipboardData, DirEntry, ElevationMsg, Features, FileMsg, Hello, Message, QualityHint, Role,
    TransferId, VideoConfig,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Controller configuration.
#[derive(Clone)]
pub struct ControllerConfig {
    pub display_name: String,
    /// If set, the host's presented key must map to this device ID (MITM check).
    pub expected_id: Option<u64>,
    /// Session password, if the host requires one.
    pub password: Option<String>,
    pub initial_quality: QualityHint,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        ControllerConfig {
            display_name: "insdesk-controller".into(),
            expected_id: None,
            password: None,
            initial_quality: QualityHint::default(),
        }
    }
}

/// Commands a front-end sends into a live session.
#[derive(Debug, Clone)]
pub enum ControllerCommand {
    Input(insdesk_proto::InputEvent),
    RequestKeyframe,
    SetQuality(QualityHint),
    ListDir(String),
    /// Pull `remote_path` from the host into `local_dest`.
    Download { transfer: TransferId, remote_path: String, local_dest: String },
    /// Push `local_path` to the host at `remote_dest`.
    Upload { transfer: TransferId, local_path: String, remote_dest: String },
    MakeRemoteDir(String),
    RemoveRemote(String),
    SendClipboard(ClipboardData),
    RequestElevation(String),
    SetSecureDesktopControl(bool),
    Ping,
    Disconnect,
}

/// Events the engine emits to the front-end.
#[derive(Debug, Clone)]
pub enum ControllerEvent {
    /// A fully decoded frame as tightly-packed RGBA (ready for a texture/PNG).
    Frame { width: u32, height: u32, seq: u64, rgba: Arc<Vec<u8>> },
    DirListing { path: String, entries: Vec<DirEntry>, error: Option<String> },
    TransferAccepted { transfer: TransferId, size: u64 },
    TransferRejected { transfer: TransferId, reason: String },
    TransferProgress { transfer: TransferId, received: u64, total: u64 },
    TransferCompleted { transfer: TransferId, ok: bool, detail: String },
    OpAck { ok: bool, error: Option<String> },
    Clipboard(ClipboardData),
    SecureDesktop(bool),
    ElevationStatus { elevated: bool, detail: String },
    Latency { millis: u64 },
    Disconnected { reason: Option<String> },
    Error(String),
}

/// Handle to a running controller session.
pub struct ControllerHandle {
    pub commands: mpsc::Sender<ControllerCommand>,
    pub events: mpsc::Receiver<ControllerEvent>,
    pub host_name: String,
    pub host_id: u64,
    pub width: u32,
    pub height: u32,
}

/// Perform the controller handshake and start the driver task.
pub async fn connect(
    session: Session,
    meta: &SessionMeta,
    cfg: ControllerConfig,
) -> Result<ControllerHandle> {
    let Session { sender, mut receiver, .. } = session;

    // 1. MITM check: the dialed ID must match the key the host actually used.
    if let Some(expected) = cfg.expected_id {
        verify_device_id(expected, &meta.remote_public)
            .map_err(|e| anyhow!("host identity check failed: {e}"))?;
    }
    let host_id = insdesk_crypto::device_id_from_pubkey(&meta.remote_public);

    // 2. Greetings.
    sender
        .send(Message::Hello(Hello {
            protocol_version: insdesk_proto::PROTOCOL_VERSION,
            role: Role::Controller,
            display_name: cfg.display_name.clone(),
            features: Features::current(),
        }))
        .await?;
    let host_name = match recv(&mut receiver).await? {
        Message::Hello(h) => h.display_name,
        other => return Err(anyhow!("expected host Hello, got {other:?}")),
    };

    // 3. Channel-bound password proof.
    let auth = SessionAuth { password: cfg.password.clone() };
    sender.send(Message::AuthRequest { proof: auth.make_proof(&meta.handshake_hash) }).await?;
    match recv(&mut receiver).await? {
        Message::AuthResult { accepted: true, .. } => {}
        Message::AuthResult { accepted: false, reason } => {
            return Err(anyhow!("authentication rejected: {}", reason.unwrap_or_default()));
        }
        other => return Err(anyhow!("expected AuthResult, got {other:?}")),
    }

    // 4. Wait for the host's accept decision.
    match recv(&mut receiver).await? {
        Message::SessionDecision { accepted: true, .. } => {}
        Message::SessionDecision { accepted: false, reason } => {
            return Err(anyhow!("host declined the session: {}", reason.unwrap_or_default()));
        }
        other => return Err(anyhow!("expected SessionDecision, got {other:?}")),
    }

    // 5. Stream geometry.
    let vcfg = match recv(&mut receiver).await? {
        Message::VideoConfig(c) => c,
        other => return Err(anyhow!("expected VideoConfig, got {other:?}")),
    };

    // Apply the initial quality preference up front.
    sender.send(Message::SetQuality(cfg.initial_quality)).await?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<ControllerCommand>(64);
    let (evt_tx, evt_rx) = mpsc::channel::<ControllerEvent>(256);

    let width = vcfg.width;
    let height = vcfg.height;
    tokio::spawn(driver(receiver, sender, vcfg, cmd_rx, evt_tx));

    Ok(ControllerHandle {
        commands: cmd_tx,
        events: evt_rx,
        host_name,
        host_id,
        width,
        height,
    })
}

/// The long-running driver: fan-in of inbound session messages and outbound
/// front-end commands.
async fn driver(
    mut receiver: SessionReceiver,
    sender: SessionSender,
    vcfg: VideoConfig,
    mut cmd_rx: mpsc::Receiver<ControllerCommand>,
    evt_tx: mpsc::Sender<ControllerEvent>,
) {
    let mut decoder = Decoder::new(vcfg.width, vcfg.height, vcfg.tile_size, vcfg.pixel_format);
    let files = FileService::new();
    let mut inbound: HashMap<TransferId, InboundTransfer> = HashMap::new();
    let mut pending_download: HashMap<TransferId, String> = HashMap::new();
    let mut pending_upload: HashMap<TransferId, insdesk_fs::OutboundTransfer> = HashMap::new();

    let mut disconnect_reason: Option<String> = None;

    loop {
        tokio::select! {
            incoming = receiver.recv() => {
                match incoming {
                    Some(Ok(msg)) => {
                        if !handle_incoming(
                            msg, &vcfg, &mut decoder, &files, &sender,
                            &mut inbound, &mut pending_download, &mut pending_upload, &evt_tx,
                        ).await {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        let _ = evt_tx.send(ControllerEvent::Error(e.to_string())).await;
                        break;
                    }
                    None => break,
                }
            }
            command = cmd_rx.recv() => {
                match command {
                    Some(ControllerCommand::Disconnect) | None => {
                        let _ = sender.send(Message::Bye { reason: Some("controller closed".into()) }).await;
                        disconnect_reason = Some("closed by user".into());
                        break;
                    }
                    Some(cmd) => {
                        handle_command(cmd, &sender, &files, &mut pending_download, &mut pending_upload, &evt_tx).await;
                    }
                }
            }
        }
    }

    let _ = evt_tx.send(ControllerEvent::Disconnected { reason: disconnect_reason }).await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    msg: Message,
    vcfg: &VideoConfig,
    decoder: &mut Decoder,
    _files: &FileService,
    sender: &SessionSender,
    inbound: &mut HashMap<TransferId, InboundTransfer>,
    pending_download: &mut HashMap<TransferId, String>,
    pending_upload: &mut HashMap<TransferId, insdesk_fs::OutboundTransfer>,
    evt_tx: &mpsc::Sender<ControllerEvent>,
) -> bool {
    match msg {
        Message::VideoFrame(frame) => {
            match decoder.apply(&frame.payload) {
                Ok(bgra) => {
                    let rgba = bgra_to_rgba(bgra);
                    let _ = evt_tx
                        .send(ControllerEvent::Frame {
                            width: vcfg.width,
                            height: vcfg.height,
                            seq: frame.seq,
                            rgba: Arc::new(rgba),
                        })
                        .await;
                }
                Err(e) => {
                    let _ = evt_tx.send(ControllerEvent::Error(format!("decode: {e}"))).await;
                    // Recover by asking for a fresh keyframe.
                    let _ = sender.send(Message::RequestKeyframe).await;
                }
            }
        }
        Message::Clipboard(data) => {
            let _ = evt_tx.send(ControllerEvent::Clipboard(data)).await;
        }
        Message::Elevation(ElevationMsg::SecureDesktopActive { active }) => {
            let _ = evt_tx.send(ControllerEvent::SecureDesktop(active)).await;
        }
        Message::Elevation(ElevationMsg::ElevationStatus { elevated, detail }) => {
            let _ = evt_tx.send(ControllerEvent::ElevationStatus { elevated, detail }).await;
        }
        Message::File(fmsg) => {
            return handle_incoming_file(fmsg, sender, inbound, pending_download, pending_upload, evt_tx).await;
        }
        Message::Pong { sent_unix_millis, .. } => {
            let rtt = now_millis().saturating_sub(sent_unix_millis);
            let _ = evt_tx.send(ControllerEvent::Latency { millis: rtt }).await;
        }
        Message::Bye { reason } => {
            let _ = evt_tx.send(ControllerEvent::Disconnected { reason }).await;
            return false;
        }
        other => tracing::debug!("controller ignoring {other:?}"),
    }
    true
}

async fn handle_incoming_file(
    fmsg: FileMsg,
    sender: &SessionSender,
    inbound: &mut HashMap<TransferId, InboundTransfer>,
    pending_download: &mut HashMap<TransferId, String>,
    pending_upload: &mut HashMap<TransferId, insdesk_fs::OutboundTransfer>,
    evt_tx: &mpsc::Sender<ControllerEvent>,
) -> bool {
    match fmsg {
        FileMsg::DirListing { path, entries, error } => {
            let _ = evt_tx.send(ControllerEvent::DirListing { path, entries, error }).await;
        }
        FileMsg::TransferAccept { transfer, size } => {
            let _ = evt_tx.send(ControllerEvent::TransferAccepted { transfer, size }).await;
            if let Some(dest) = pending_download.remove(&transfer) {
                // Our download was accepted → open the local destination.
                match FileService::new().open_inbound(transfer, &dest, size) {
                    Ok(inb) => {
                        inbound.insert(transfer, inb);
                    }
                    Err(e) => {
                        let _ = evt_tx
                            .send(ControllerEvent::TransferCompleted {
                                transfer,
                                ok: false,
                                detail: e.to_string(),
                            })
                            .await;
                    }
                }
            } else if let Some(out) = pending_upload.remove(&transfer) {
                // Our upload was accepted → stream the bytes out and report
                // completion back to the front-end when the stream finishes.
                stream_upload(out, sender.clone(), evt_tx.clone(), transfer);
            }
        }
        FileMsg::TransferReject { transfer, reason } => {
            pending_download.remove(&transfer);
            pending_upload.remove(&transfer);
            let _ = evt_tx.send(ControllerEvent::TransferRejected { transfer, reason }).await;
        }
        FileMsg::Chunk { transfer, offset, data } => {
            if let Some(inb) = inbound.get_mut(&transfer) {
                match inb.write_chunk(offset, &data) {
                    Ok(()) => {
                        let (received, total) = (inb.received(), inb.expected());
                        let _ = evt_tx
                            .send(ControllerEvent::TransferProgress { transfer, received, total })
                            .await;
                    }
                    Err(e) => {
                        inbound.remove(&transfer);
                        let _ = evt_tx
                            .send(ControllerEvent::TransferCompleted {
                                transfer,
                                ok: false,
                                detail: e.to_string(),
                            })
                            .await;
                    }
                }
            }
        }
        FileMsg::TransferDone { transfer, sha256_hex } => {
            if let Some(inb) = inbound.remove(&transfer) {
                let (ok, detail) = match inb.finish(&sha256_hex) {
                    Ok(()) => (true, "verified".to_string()),
                    Err(FsError::IntegrityMismatch) => (false, "integrity mismatch".to_string()),
                    Err(e) => (false, e.to_string()),
                };
                let _ = evt_tx.send(ControllerEvent::TransferCompleted { transfer, ok, detail }).await;
            }
        }
        FileMsg::OpAck { ok, error } => {
            let _ = evt_tx.send(ControllerEvent::OpAck { ok, error }).await;
        }
        _ => {}
    }
    true
}

async fn handle_command(
    cmd: ControllerCommand,
    sender: &SessionSender,
    files: &FileService,
    pending_download: &mut HashMap<TransferId, String>,
    pending_upload: &mut HashMap<TransferId, insdesk_fs::OutboundTransfer>,
    evt_tx: &mpsc::Sender<ControllerEvent>,
) {
    match cmd {
        ControllerCommand::Input(ev) => {
            let _ = sender.send(Message::Input(ev)).await;
        }
        ControllerCommand::RequestKeyframe => {
            let _ = sender.send(Message::RequestKeyframe).await;
        }
        ControllerCommand::SetQuality(q) => {
            let _ = sender.send(Message::SetQuality(q)).await;
        }
        ControllerCommand::ListDir(path) => {
            let _ = sender.send(Message::File(FileMsg::ListDir { path })).await;
        }
        ControllerCommand::MakeRemoteDir(path) => {
            let _ = sender.send(Message::File(FileMsg::MakeDir { path })).await;
        }
        ControllerCommand::RemoveRemote(path) => {
            let _ = sender.send(Message::File(FileMsg::Remove { path })).await;
        }
        ControllerCommand::Download { transfer, remote_path, local_dest } => {
            pending_download.insert(transfer, local_dest);
            let _ = sender.send(Message::File(FileMsg::DownloadRequest { transfer, path: remote_path })).await;
        }
        ControllerCommand::Upload { transfer, local_path, remote_dest } => {
            match files.open_outbound(transfer, &local_path) {
                Ok(out) => {
                    let size = out.size();
                    pending_upload.insert(transfer, out);
                    let _ = sender
                        .send(Message::File(FileMsg::UploadRequest { transfer, dest: remote_dest, size }))
                        .await;
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(ControllerEvent::TransferCompleted {
                            transfer,
                            ok: false,
                            detail: e.to_string(),
                        })
                        .await;
                }
            }
        }
        ControllerCommand::SendClipboard(data) => {
            let _ = sender.send(Message::Clipboard(data)).await;
        }
        ControllerCommand::RequestElevation(reason) => {
            let _ = sender.send(Message::Elevation(ElevationMsg::RequestElevation { reason })).await;
        }
        ControllerCommand::SetSecureDesktopControl(allowed) => {
            let _ = sender.send(Message::Elevation(ElevationMsg::SetSecureDesktopControl { allowed })).await;
        }
        ControllerCommand::Ping => {
            let _ = sender.send(Message::Ping { nonce: 0, sent_unix_millis: now_millis() }).await;
        }
        ControllerCommand::Disconnect => {}
    }
}

/// Stream an outbound upload on a blocking task, emitting a
/// [`ControllerEvent::TransferCompleted`] when the file has been fully sent so
/// the front-end can clear it from its pending set.
fn stream_upload(
    mut out: insdesk_fs::OutboundTransfer,
    sender: SessionSender,
    evt_tx: mpsc::Sender<ControllerEvent>,
    transfer: TransferId,
) {
    use insdesk_fs::transfer::OutStep;
    tokio::task::spawn_blocking(move || loop {
        match out.next(insdesk_fs::DEFAULT_CHUNK) {
            Ok(OutStep::Chunk(m)) => {
                if sender.blocking_send(Message::File(m)).is_err() {
                    let _ = evt_tx.blocking_send(ControllerEvent::TransferCompleted {
                        transfer,
                        ok: false,
                        detail: "connection closed".into(),
                    });
                    break;
                }
            }
            Ok(OutStep::Done(m)) => {
                let _ = sender.blocking_send(Message::File(m));
                let _ = evt_tx.blocking_send(ControllerEvent::TransferCompleted {
                    transfer,
                    ok: true,
                    detail: "uploaded".into(),
                });
                break;
            }
            Err(e) => {
                let _ = evt_tx.blocking_send(ControllerEvent::TransferCompleted {
                    transfer,
                    ok: false,
                    detail: e.to_string(),
                });
                break;
            }
        }
    });
}

/// Convert packed BGRA to packed RGBA (what egui textures and PNG expect).
fn bgra_to_rgba(bgra: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bgra.len()];
    for (i, px) in bgra.chunks_exact(4).enumerate() {
        let o = i * 4;
        out[o] = px[2];
        out[o + 1] = px[1];
        out[o + 2] = px[0];
        out[o + 3] = px[3];
    }
    out
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

async fn recv(receiver: &mut SessionReceiver) -> Result<Message> {
    match receiver.recv().await {
        Some(Ok(m)) => Ok(m),
        Some(Err(e)) => Err(anyhow!("session error: {e}")),
        None => Err(anyhow!("session closed during handshake")),
    }
}
