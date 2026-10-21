//! InsDesk host agent.
//!
//! Registers a device ID on a relay (or listens directly), then for each
//! incoming controller runs an end-to-end-encrypted session: streaming the
//! screen, replaying input, serving files/clipboard and bridging UAC.
//!
//! Backends are chosen at build time. The default build uses portable synthetic
//! backends so it runs anywhere (including headless CI). Build with
//! `--features desktop` (and `uac-windows` on Windows) for real capture, input
//! and clipboard.

use anyhow::Result;
use clap::Parser;
use insdesk_core::host::{self, HostBackends, HostConfig};
use insdesk_fs::{ClipboardBackend, FileService, MemoryClipboard};
use insdesk_media::capture::{ScreenCapturer, SyntheticCapturer};
use insdesk_media::input::{InputSink, RecordingInputSink};
use insdesk_media::uac;
use insdesk_net::{perform_handshake, spawn_session, HandshakeRole};
use std::path::PathBuf;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "insdesk-host", about = "InsDesk host agent (viewed/controlled machine)")]
struct Args {
    /// Relay server address to register with. Omit when using --listen.
    #[arg(long, env = "INSDESK_RELAY")]
    relay: Option<String>,

    /// Listen directly for controllers on this address (no relay).
    #[arg(long)]
    listen: Option<String>,

    /// Path to the long-term identity key file (created if missing).
    #[arg(long, default_value = "insdesk-host.key")]
    key: PathBuf,

    /// Friendly name shown to the controller.
    #[arg(long, default_value = "insdesk-host")]
    name: String,

    /// Require this session password from controllers.
    #[arg(long, env = "INSDESK_PASSWORD")]
    password: Option<String>,

    /// Accept sessions automatically (unattended access).
    #[arg(long, default_value_t = true)]
    auto_accept: bool,

    /// Disallow remote input (view-only).
    #[arg(long, default_value_t = false)]
    no_input: bool,

    /// Disallow file transfer.
    #[arg(long, default_value_t = false)]
    no_files: bool,

    /// Confine file transfer to this directory.
    #[arg(long)]
    file_root: Option<PathBuf>,

    /// Synthetic capture width (used when no real capture backend is built).
    #[arg(long, default_value_t = 1280)]
    width: u32,
    /// Synthetic capture height.
    #[arg(long, default_value_t = 720)]
    height: u32,

    /// Video quality (1..=100) and frame-rate cap.
    #[arg(long, default_value_t = 80)]
    quality: u8,
    #[arg(long, default_value_t = 30)]
    fps: u8,
    #[arg(long, default_value_t = 64)]
    tile: u32,

    /// Handle only one session then exit (useful for testing).
    #[arg(long, default_value_t = false)]
    once: bool,
}

fn make_capturer(width: u32, height: u32) -> Box<dyn ScreenCapturer> {
    #[cfg(feature = "capture-scrap")]
    {
        match insdesk_media::capture::ScrapCapturer::primary() {
            Ok(c) => {
                tracing::info!("using real screen capture (scrap)");
                return Box::new(c);
            }
            Err(e) => tracing::warn!("real capture unavailable ({e}); using synthetic"),
        }
    }
    tracing::info!("using synthetic capturer {width}x{height}");
    Box::new(SyntheticCapturer::new(width, height))
}

fn make_input() -> Box<dyn InputSink> {
    #[cfg(feature = "input-enigo")]
    {
        match insdesk_media::input::EnigoInputSink::new() {
            Ok(s) => {
                tracing::info!("using real input injection (enigo)");
                return Box::new(s);
            }
            Err(e) => tracing::warn!("real input unavailable ({e}); using recording sink"),
        }
    }
    Box::new(RecordingInputSink::new())
}

fn make_clipboard() -> Box<dyn ClipboardBackend> {
    #[cfg(feature = "clipboard-arboard")]
    {
        match insdesk_fs::clipboard::SystemClipboard::new() {
            Ok(c) => return Box::new(c),
            Err(e) => tracing::warn!("system clipboard unavailable ({e}); using memory"),
        }
    }
    Box::new(MemoryClipboard::new())
}

fn build_backends(args: &Args) -> HostBackends {
    let files = match &args.file_root {
        Some(root) => FileService::with_root(root.clone()),
        None => FileService::new(),
    };
    HostBackends {
        capturer: make_capturer(args.width, args.height),
        input: make_input(),
        clipboard: make_clipboard(),
        elevation: uac::default_bridge(),
        files,
    }
}

fn host_config(args: &Args) -> HostConfig {
    HostConfig {
        display_name: args.name.clone(),
        password: args.password.clone(),
        auto_accept: args.auto_accept,
        allow_input: !args.no_input,
        allow_file_transfer: !args.no_files,
        allow_secure_desktop_control: true,
        tile_size: args.tile,
        quality: args.quality,
        max_fps: args.fps,
    }
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
    let identity = insdesk_core::load_or_create(&args.key)?;
    let device_id = identity.device_id();

    println!("==============================================");
    println!(" InsDesk host ready");
    println!("   Device ID : {device_id}");
    println!("   Public key: {}", identity.public_hex());
    if args.password.is_some() {
        println!("   Password  : (set)");
    } else {
        println!("   Password  : (none — set one with --password for security)");
    }
    println!("==============================================");

    if let Some(listen) = &args.listen {
        run_direct(listen, &args, &identity).await
    } else if let Some(relay) = &args.relay {
        run_relay(relay, device_id, &args, &identity).await
    } else {
        anyhow::bail!("specify either --relay <addr> or --listen <addr>");
    }
}

/// Direct mode: listen for controllers ourselves (LAN / port-forwarded).
async fn run_direct(listen: &str, args: &Args, identity: &insdesk_crypto::Identity) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!("listening for controllers on {listen}");
    loop {
        let (socket, peer) = listener.accept().await?;
        socket.set_nodelay(true).ok();
        tracing::info!("controller connecting from {peer}");
        if let Err(e) = serve_one(socket, args, identity).await {
            tracing::warn!("session ended: {e}");
        }
        if args.once {
            break;
        }
    }
    Ok(())
}

/// Relay mode: register our ID and handle controllers routed to us.
async fn run_relay(
    relay: &str,
    device_id: u64,
    args: &Args,
    identity: &insdesk_crypto::Identity,
) -> Result<()> {
    loop {
        let mut stream = match insdesk_net::relay::register_host(relay, device_id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("relay registration failed ({e}); retrying in 3s");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
        };
        tracing::info!("registered on relay {relay} as {device_id}; waiting for controller");
        if let Err(e) = insdesk_net::relay::wait_for_peer(&mut stream).await {
            tracing::warn!("waiting for peer failed: {e}");
            continue;
        }
        tracing::info!("controller paired; starting session");
        if let Err(e) = serve_one(stream, args, identity).await {
            tracing::warn!("session ended: {e}");
        }
        if args.once {
            break;
        }
    }
    Ok(())
}

/// Run the handshake + host engine over one already-connected stream.
async fn serve_one(
    mut stream: tokio::net::TcpStream,
    args: &Args,
    identity: &insdesk_crypto::Identity,
) -> Result<()> {
    let established = perform_handshake(&mut stream, HandshakeRole::Responder, identity).await?;
    tracing::info!("secure channel established with controller");
    let (transport, meta) = established.into_parts();
    let session = spawn_session(stream, transport, 32);
    host::run(session, &meta, host_config(args), build_backends(args)).await
}
