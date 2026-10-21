//! Host-side session engine: the machine being viewed and controlled.
//!
//! Given an already-established E2E [`Session`], the host:
//! 1. exchanges [`Hello`] greetings,
//! 2. verifies the controller's channel-bound password proof (if a password is
//!    configured) and makes an accept/decline decision,
//! 3. streams the screen (capture → encode → send) on a dedicated thread,
//! 4. replays the controller's input, serves file transfers and clipboard, and
//!    bridges UAC / secure-desktop notifications.

use crate::session_support::{compute_accept, SessionAuth};
use anyhow::{anyhow, Result};
use insdesk_fs::{ClipboardBackend, FileService, InboundTransfer};
use insdesk_media::capture::ScreenCapturer;
use insdesk_media::codec::Encoder;
use insdesk_media::input::InputSink;
use insdesk_media::uac::{ElevationBridge, SecureDesktopEvent};
use insdesk_net::{Session, SessionMeta, SessionSender};
use insdesk_proto::{
    ElevationMsg, Features, FileMsg, Hello, Message, PixelFormat, Role, VideoConfig, VideoFrame,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Configuration for a host session.
#[derive(Clone)]
pub struct HostConfig {
    pub display_name: String,
    /// If set, the controller must prove knowledge of this password.
    pub password: Option<String>,
    /// Accept incoming sessions without a local prompt (unattended access).
    pub auto_accept: bool,
    /// Allow the controller to inject input ("control PC").
    pub allow_input: bool,
    /// Allow file-manager / transfer operations.
    pub allow_file_transfer: bool,
    /// Allow the operator to drive a UAC secure desktop.
    pub allow_secure_desktop_control: bool,
    /// Video tile size for the delta codec.
    pub tile_size: u32,
    /// Initial quality (1..=100) and frame rate cap.
    pub quality: u8,
    pub max_fps: u8,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            display_name: "insdesk-host".into(),
            password: None,
            auto_accept: true,
            allow_input: true,
            allow_file_transfer: true,
            allow_secure_desktop_control: true,
            tile_size: 64,
            quality: 80,
            max_fps: 30,
        }
    }
}

/// Backends the host drives. Kept as trait objects so the same engine runs with
/// synthetic backends (headless/CI) or real ones (desktop builds).
pub struct HostBackends {
    pub capturer: Box<dyn ScreenCapturer>,
    pub input: Box<dyn InputSink>,
    pub clipboard: Box<dyn ClipboardBackend>,
    pub elevation: Box<dyn ElevationBridge>,
    pub files: FileService,
}

struct Shared {
    want_keyframe: AtomicBool,
    quality: AtomicU8,
    max_fps: AtomicU8,
    running: AtomicBool,
    secure_control_allowed: AtomicBool,
    elevation_requested: AtomicBool,
}

/// Run a host session to completion over `established`/`session`.
pub async fn run(
    session: Session,
    meta: &SessionMeta,
    cfg: HostConfig,
    backends: HostBackends,
) -> Result<()> {
    let Session { sender, mut receiver, .. } = session;
    let HostBackends { capturer, input, clipboard, elevation, files } = backends;

    // --- Greet + authenticate ----------------------------------------------
    sender
        .send(Message::Hello(Hello {
            protocol_version: insdesk_proto::PROTOCOL_VERSION,
            role: Role::Host,
            display_name: cfg.display_name.clone(),
            features: Features::current(),
        }))
        .await?;

    // Expect the controller's Hello first.
    match next_message(&mut receiver).await? {
        Message::Hello(h) => tracing::info!(peer = %h.display_name, "controller connected"),
        other => return Err(anyhow!("expected Hello, got {other:?}")),
    }

    // Password proof (channel-bound). If no password is configured we accept
    // any proof; otherwise it must match.
    let auth = SessionAuth { password: cfg.password.clone() };
    match next_message(&mut receiver).await? {
        Message::AuthRequest { proof } => {
            let ok = auth.verify(&meta.handshake_hash, &proof);
            sender
                .send(Message::AuthResult {
                    accepted: ok,
                    reason: if ok { None } else { Some("invalid password".into()) },
                })
                .await?;
            if !ok {
                tracing::warn!("controller failed password check");
                let _ = sender.send(Message::Bye { reason: Some("auth failed".into()) }).await;
                return Ok(());
            }
        }
        other => return Err(anyhow!("expected AuthRequest, got {other:?}")),
    }

    // Local accept decision (unattended vs prompt). The prompt itself lives in
    // the binary; here we honor the configured policy.
    let accepted = compute_accept(cfg.auto_accept);
    sender
        .send(Message::SessionDecision {
            accepted,
            reason: if accepted { None } else { Some("declined by host".into()) },
        })
        .await?;
    if !accepted {
        let _ = sender.send(Message::Bye { reason: Some("declined".into()) }).await;
        return Ok(());
    }

    // --- Start streaming ----------------------------------------------------
    let (width, height) = capturer.dimensions();
    sender
        .send(Message::VideoConfig(VideoConfig {
            width,
            height,
            pixel_format: PixelFormat::Bgra8888,
            tile_size: cfg.tile_size,
        }))
        .await?;

    let shared = Arc::new(Shared {
        want_keyframe: AtomicBool::new(true),
        quality: AtomicU8::new(cfg.quality),
        max_fps: AtomicU8::new(cfg.max_fps),
        running: AtomicBool::new(true),
        secure_control_allowed: AtomicBool::new(cfg.allow_secure_desktop_control),
        elevation_requested: AtomicBool::new(false),
    });

    // Capture/encode/elevation loop on a dedicated thread (blocking capture).
    let capture_thread = spawn_capture_thread(
        capturer,
        elevation,
        shared.clone(),
        cfg.tile_size,
        width,
        height,
        sender.clone(),
    );

    // --- Main receive loop --------------------------------------------------
    let files = Arc::new(files);
    let mut input = input;
    let mut clipboard = clipboard;
    let mut inbound: HashMap<u64, InboundTransfer> = HashMap::new();

    // Periodically push local clipboard changes to the controller.
    let clip_sender = sender.clone();

    let result = async {
        loop {
            match receiver.recv().await {
                Some(Ok(msg)) => {
                    if !handle_message(
                        msg,
                        &cfg,
                        &sender,
                        &shared,
                        input.as_mut(),
                        clipboard.as_mut(),
                        &files,
                        &mut inbound,
                    )
                    .await?
                    {
                        break; // Bye
                    }
                    // Opportunistically forward a local clipboard change.
                    if let Ok(Some(change)) = clipboard.take_change() {
                        let _ = clip_sender.send(Message::Clipboard(change)).await;
                    }
                }
                Some(Err(e)) => {
                    tracing::warn!("session error: {e}");
                    break;
                }
                None => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    shared.running.store(false, Ordering::SeqCst);
    let _ = capture_thread.join();
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_message(
    msg: Message,
    cfg: &HostConfig,
    sender: &SessionSender,
    shared: &Arc<Shared>,
    input: &mut dyn InputSink,
    clipboard: &mut dyn ClipboardBackend,
    files: &Arc<FileService>,
    inbound: &mut HashMap<u64, InboundTransfer>,
) -> Result<bool> {
    match msg {
        Message::Input(ev) => {
            if cfg.allow_input {
                if let Err(e) = input.inject(ev) {
                    tracing::debug!("input inject failed: {e}");
                }
            }
        }
        Message::RequestKeyframe => shared.want_keyframe.store(true, Ordering::SeqCst),
        Message::SetQuality(q) => {
            shared.quality.store(q.quality, Ordering::SeqCst);
            shared.max_fps.store(q.max_fps.max(1), Ordering::SeqCst);
        }
        Message::Clipboard(data) => {
            let _ = clipboard.set(&data);
        }
        Message::File(fmsg) => {
            if cfg.allow_file_transfer {
                handle_file(fmsg, sender, files, inbound).await;
            } else {
                let _ = sender
                    .send(Message::File(FileMsg::OpAck {
                        ok: false,
                        error: Some("file transfer disabled by host".into()),
                    }))
                    .await;
            }
        }
        Message::Elevation(e) => handle_elevation(e, shared),
        Message::Ping { nonce, sent_unix_millis } => {
            let _ = sender.send(Message::Pong { nonce, sent_unix_millis }).await;
        }
        Message::Bye { reason } => {
            tracing::info!(?reason, "controller ended session");
            return Ok(false);
        }
        other => tracing::debug!("ignoring unexpected host-side message: {other:?}"),
    }
    Ok(true)
}

fn handle_elevation(e: ElevationMsg, shared: &Arc<Shared>) {
    match e {
        ElevationMsg::SetSecureDesktopControl { allowed } => {
            shared.secure_control_allowed.store(allowed, Ordering::SeqCst);
        }
        ElevationMsg::RequestElevation { reason } => {
            tracing::info!(%reason, "controller requested elevation");
            shared.elevation_requested.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
}

async fn handle_file(
    fmsg: FileMsg,
    sender: &SessionSender,
    files: &Arc<FileService>,
    inbound: &mut HashMap<u64, InboundTransfer>,
) {
    match fmsg {
        FileMsg::ListDir { path } => {
            let reply = files.list_dir(&path);
            let _ = sender.send(Message::File(reply)).await;
        }
        FileMsg::MakeDir { path } => {
            let _ = sender.send(Message::File(files.make_dir(&path))).await;
        }
        FileMsg::Remove { path } => {
            let _ = sender.send(Message::File(files.remove(&path))).await;
        }
        FileMsg::DownloadRequest { transfer, path } => {
            // Controller wants to pull `path` from us → stream it out.
            match files.open_outbound(transfer, &path) {
                Ok(out) => {
                    let size = out.size();
                    let _ = sender.send(Message::File(FileMsg::TransferAccept { transfer, size })).await;
                    crate::session_support::stream_outbound(out, sender.clone());
                }
                Err(e) => {
                    let _ = sender
                        .send(Message::File(FileMsg::TransferReject { transfer, reason: e.to_string() }))
                        .await;
                }
            }
        }
        FileMsg::UploadRequest { transfer, dest, size } => {
            // Controller wants to push a file to us → open the destination.
            match files.open_inbound(transfer, &dest, size) {
                Ok(inb) => {
                    inbound.insert(transfer, inb);
                    let _ = sender.send(Message::File(FileMsg::TransferAccept { transfer, size })).await;
                }
                Err(e) => {
                    let _ = sender
                        .send(Message::File(FileMsg::TransferReject { transfer, reason: e.to_string() }))
                        .await;
                }
            }
        }
        FileMsg::Chunk { transfer, offset, data } => {
            if let Some(inb) = inbound.get_mut(&transfer) {
                if let Err(e) = inb.write_chunk(offset, &data) {
                    tracing::warn!("write chunk failed: {e}");
                    inbound.remove(&transfer);
                }
            }
        }
        FileMsg::TransferDone { transfer, sha256_hex } => {
            if let Some(inb) = inbound.remove(&transfer) {
                let ok = inb.finish(&sha256_hex).is_ok();
                let _ = sender
                    .send(Message::File(FileMsg::OpAck {
                        ok,
                        error: if ok { None } else { Some("integrity mismatch".into()) },
                    }))
                    .await;
            }
        }
        FileMsg::TransferAbort { transfer, .. } => {
            inbound.remove(&transfer);
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_capture_thread(
    mut capturer: Box<dyn ScreenCapturer>,
    mut elevation: Box<dyn ElevationBridge>,
    shared: Arc<Shared>,
    tile_size: u32,
    width: u32,
    height: u32,
    sender: SessionSender,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut encoder = Encoder::new(width, height, tile_size);
        let mut seq: u64 = 0;
        let mut first = true;
        while shared.running.load(Ordering::SeqCst) {
            let frame_start = Instant::now();
            let fps = shared.max_fps.load(Ordering::SeqCst).clamp(1, 60) as u64;
            let interval = Duration::from_millis(1000 / fps);

            // Elevation / secure-desktop handling.
            if let Some(ev) = elevation.poll() {
                let active = matches!(ev, SecureDesktopEvent::Activated);
                let _ = sender.blocking_send(Message::Elevation(ElevationMsg::SecureDesktopActive { active }));
                // A secure desktop implies the view changed entirely.
                encoder.request_keyframe();
            }
            if shared.elevation_requested.swap(false, Ordering::SeqCst) {
                let detail = match elevation.request_elevation("remote operator request") {
                    Ok(()) => "elevation triggered".to_string(),
                    Err(e) => e.to_string(),
                };
                let elevated =
                    matches!(elevation.privilege_level(), insdesk_media::uac::PrivilegeLevel::Elevated);
                let _ = sender.blocking_send(Message::Elevation(ElevationMsg::ElevationStatus { elevated, detail }));
            }

            encoder.set_quality(shared.quality.load(Ordering::SeqCst));
            let force = shared.want_keyframe.swap(false, Ordering::SeqCst) || first;

            match capturer.capture() {
                Ok(fb) => {
                    match encoder.encode(&fb, force) {
                        Ok(encoded) => {
                            let vf = VideoFrame {
                                seq,
                                keyframe: force,
                                captured_unix_millis: now_millis(),
                                payload: encoded,
                            };
                            // Drop video under backpressure to protect latency.
                            if !sender.try_send(Message::VideoFrame(vf)) {
                                tracing::trace!("video queue full; dropping frame {seq}");
                            }
                            seq += 1;
                            first = false;
                        }
                        Err(e) => tracing::warn!("encode error: {e}"),
                    }
                }
                Err(insdesk_media::capture::CaptureError::WouldBlock) => {}
                Err(e) => tracing::warn!("capture error: {e}"),
            }

            let elapsed = frame_start.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval - elapsed);
            }
        }
        tracing::debug!("capture thread exiting");
    })
}

// --- tiny helpers -----------------------------------------------------------

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

async fn next_message(receiver: &mut insdesk_net::SessionReceiver) -> Result<Message> {
    match receiver.recv().await {
        Some(Ok(m)) => Ok(m),
        Some(Err(e)) => Err(anyhow!("session error: {e}")),
        None => Err(anyhow!("session closed during handshake")),
    }
}
