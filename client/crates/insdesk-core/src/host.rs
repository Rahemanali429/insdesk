//! Host-side session engine: the machine being viewed and controlled.
//!
//! Given an already-established E2E [`Session`], the host:
//! 1. exchanges [`Hello`] greetings,
//! 2. verifies the controller's channel-bound password proof (if a password is
//!    configured) and makes an accept/decline decision,
//! 3. streams the screen (capture → encode → send) on a dedicated capture
//!    thread,
//! 4. replays the controller's input and mirrors the clipboard on a dedicated
//!    I/O thread, serves file transfers, and bridges UAC / secure-desktop
//!    notifications.
//!
//! ## Threading
//!
//! Real OS backends (`scrap` capture, `enigo` input, `arboard` clipboard) are
//! not `Send` on every platform, so each is **created and used entirely on one
//! dedicated OS thread** and never crosses a thread boundary. The async session
//! task communicates with those threads over channels:
//!
//! ```text
//!   capture thread ──VideoFrame/Elevation──▶ session sender
//!   async loop ──IoCommand(input/clipboard-set)──▶ I/O thread
//!   I/O thread ──local clipboard change──▶ session sender
//! ```
//!
//! Because the backends live behind factories (`FnOnce() -> Box<…>`), the async
//! task itself holds only `Send` state and can be freely spawned.

use crate::session_support::{compute_accept, SessionAuth};
use anyhow::{anyhow, Result};
use insdesk_fs::{ClipboardBackend, FileService, InboundTransfer};
use insdesk_media::capture::ScreenCapturer;
use insdesk_media::codec::Encoder;
use insdesk_media::input::InputSink;
use insdesk_media::uac::{ElevationBridge, SecureDesktopEvent};
use insdesk_net::{Session, SessionMeta, SessionSender};
use insdesk_proto::{
    ClipboardData, ElevationMsg, Features, FileMsg, Hello, InputEvent, Message, PixelFormat, Role,
    VideoConfig, VideoFrame,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Builds a screen capturer on the capture thread.
pub type CapturerFactory = Box<dyn FnOnce() -> Box<dyn ScreenCapturer> + Send>;
/// Builds an input sink on the I/O thread.
pub type InputFactory = Box<dyn FnOnce() -> Box<dyn InputSink> + Send>;
/// Builds a clipboard backend on the I/O thread.
pub type ClipboardFactory = Box<dyn FnOnce() -> Box<dyn ClipboardBackend> + Send>;

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

/// Backends the host drives, as thread-local factories so non-`Send` OS handles
/// are constructed on their own thread.
pub struct HostBackends {
    pub capturer: CapturerFactory,
    pub input: InputFactory,
    pub clipboard: ClipboardFactory,
    pub elevation: Box<dyn ElevationBridge>,
    pub files: FileService,
}

/// A command sent from the async loop to the dedicated I/O thread.
enum IoCommand {
    Input(InputEvent),
    ClipboardSet(ClipboardData),
}

struct Shared {
    want_keyframe: AtomicBool,
    quality: AtomicU8,
    max_fps: AtomicU8,
    running: AtomicBool,
    secure_control_allowed: AtomicBool,
    elevation_requested: AtomicBool,
}

/// Run a host session to completion.
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

    match next_message(&mut receiver).await? {
        Message::Hello(h) => tracing::info!(peer = %h.display_name, "controller connected"),
        other => return Err(anyhow!("expected Hello, got {other:?}")),
    }

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

    // --- Start the capture + I/O threads ------------------------------------
    let shared = Arc::new(Shared {
        want_keyframe: AtomicBool::new(true),
        quality: AtomicU8::new(cfg.quality),
        max_fps: AtomicU8::new(cfg.max_fps),
        running: AtomicBool::new(true),
        secure_control_allowed: AtomicBool::new(cfg.allow_secure_desktop_control),
        elevation_requested: AtomicBool::new(false),
    });

    let (dims_tx, dims_rx) = tokio::sync::oneshot::channel::<(u32, u32)>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (io_tx, io_rx) = mpsc::channel::<IoCommand>();
    let (clip_tx, clip_rx) = mpsc::channel::<ClipboardData>();

    let capture_thread =
        spawn_capture_thread(capturer, elevation, shared.clone(), cfg.tile_size, sender.clone(), dims_tx, go_rx);
    let io_thread = spawn_io_thread(input, clipboard, io_rx, clip_tx);

    // The capture thread reports the real display geometry; announce it, then
    // release the thread to start streaming.
    let (width, height) = match dims_rx.await {
        Ok(d) => d,
        Err(_) => {
            shared.running.store(false, Ordering::SeqCst);
            return Err(anyhow!("capture thread failed to initialize"));
        }
    };
    sender
        .send(Message::VideoConfig(VideoConfig {
            width,
            height,
            pixel_format: PixelFormat::Bgra8888,
            tile_size: cfg.tile_size,
        }))
        .await?;
    let _ = go_tx.send(());

    // Bridge local clipboard changes (produced on the I/O thread) to the peer.
    let clip_sender = sender.clone();
    let clip_bridge = tokio::task::spawn_blocking(move || {
        while let Ok(change) = clip_rx.recv() {
            if clip_sender.blocking_send(Message::Clipboard(change)).is_err() {
                break;
            }
        }
    });

    // --- Main receive loop --------------------------------------------------
    let files = Arc::new(files);
    let mut inbound: HashMap<u64, InboundTransfer> = HashMap::new();

    let result = async {
        loop {
            match receiver.recv().await {
                Some(Ok(msg)) => {
                    if !handle_message(msg, &cfg, &sender, &shared, &io_tx, &files, &mut inbound).await? {
                        break;
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

    // Tear down: stopping `running` ends the capture thread; dropping `io_tx`
    // ends the I/O thread, which drops `clip_tx` and ends the bridge.
    shared.running.store(false, Ordering::SeqCst);
    let _ = go_tx.send(());
    drop(io_tx);
    let _ = capture_thread.join();
    let _ = io_thread.join();
    clip_bridge.abort();
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_message(
    msg: Message,
    cfg: &HostConfig,
    sender: &SessionSender,
    shared: &Arc<Shared>,
    io_tx: &mpsc::Sender<IoCommand>,
    files: &Arc<FileService>,
    inbound: &mut HashMap<u64, InboundTransfer>,
) -> Result<bool> {
    match msg {
        Message::Input(ev) => {
            if cfg.allow_input {
                let _ = io_tx.send(IoCommand::Input(ev));
            }
        }
        Message::RequestKeyframe => shared.want_keyframe.store(true, Ordering::SeqCst),
        Message::SetQuality(q) => {
            shared.quality.store(q.quality, Ordering::SeqCst);
            shared.max_fps.store(q.max_fps.max(1), Ordering::SeqCst);
        }
        Message::Clipboard(data) => {
            let _ = io_tx.send(IoCommand::ClipboardSet(data));
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

/// The dedicated capture thread: owns the (possibly non-`Send`) capturer and
/// elevation bridge, reports the display geometry, then streams encoded frames.
fn spawn_capture_thread(
    capturer_factory: CapturerFactory,
    mut elevation: Box<dyn ElevationBridge>,
    shared: Arc<Shared>,
    tile_size: u32,
    sender: SessionSender,
    dims_tx: tokio::sync::oneshot::Sender<(u32, u32)>,
    go_rx: mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut capturer = capturer_factory();
        let (width, height) = capturer.dimensions();
        if dims_tx.send((width, height)).is_err() {
            return;
        }
        // Wait until the geometry has been announced to the peer.
        if go_rx.recv().is_err() {
            return;
        }

        let mut encoder = Encoder::new(width, height, tile_size);
        let mut seq: u64 = 0;
        let mut first = true;
        while shared.running.load(Ordering::SeqCst) {
            let frame_start = Instant::now();
            let fps = shared.max_fps.load(Ordering::SeqCst).clamp(1, 60) as u64;
            let interval = Duration::from_millis(1000 / fps);

            if let Some(ev) = elevation.poll() {
                let active = matches!(ev, SecureDesktopEvent::Activated);
                let _ = sender.blocking_send(Message::Elevation(ElevationMsg::SecureDesktopActive { active }));
                encoder.request_keyframe();
            }
            if shared.elevation_requested.swap(false, Ordering::SeqCst) {
                let detail = match elevation.request_elevation("remote operator request") {
                    Ok(()) => "elevation triggered".to_string(),
                    Err(e) => e.to_string(),
                };
                let elevated =
                    matches!(elevation.privilege_level(), insdesk_media::uac::PrivilegeLevel::Elevated);
                let _ = sender
                    .blocking_send(Message::Elevation(ElevationMsg::ElevationStatus { elevated, detail }));
            }

            encoder.set_quality(shared.quality.load(Ordering::SeqCst));
            let force = shared.want_keyframe.swap(false, Ordering::SeqCst) || first;

            match capturer.capture() {
                Ok(fb) => match encoder.encode(&fb, force) {
                    Ok(encoded) => {
                        let vf = VideoFrame {
                            seq,
                            keyframe: force,
                            captured_unix_millis: now_millis(),
                            payload: encoded,
                        };
                        if !sender.try_send(Message::VideoFrame(vf)) {
                            tracing::trace!("video queue full; dropping frame {seq}");
                        }
                        seq += 1;
                        first = false;
                    }
                    Err(e) => tracing::warn!("encode error: {e}"),
                },
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

/// The dedicated I/O thread: owns the (possibly non-`Send`) input sink and
/// clipboard, replays input commands, and reports local clipboard changes.
fn spawn_io_thread(
    input_factory: InputFactory,
    clipboard_factory: ClipboardFactory,
    io_rx: mpsc::Receiver<IoCommand>,
    clip_tx: mpsc::Sender<ClipboardData>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut input = input_factory();
        let mut clipboard = clipboard_factory();
        loop {
            match io_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(IoCommand::Input(ev)) => {
                    if let Err(e) = input.inject(ev) {
                        tracing::debug!("input inject failed: {e}");
                    }
                }
                Ok(IoCommand::ClipboardSet(data)) => {
                    let _ = clipboard.set(&data);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            // Mirror a local clipboard change to the peer.
            if let Ok(Some(change)) = clipboard.take_change() {
                if clip_tx.send(change).is_err() {
                    break;
                }
            }
        }
        tracing::debug!("io thread exiting");
    })
}

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
