//! InsDesk controller.
//!
//! The default build is a headless CLI controller: it connects to a host over
//! the end-to-end-encrypted channel and can snapshot the remote screen, browse
//! the remote filesystem, and transfer files in both directions. Built with
//! `--features gui`, the `gui` subcommand launches a graphical controller that
//! renders the live stream and forwards mouse/keyboard input.

mod connect;
#[cfg(feature = "gui")]
mod gui;

use anyhow::{anyhow, Result};
use clap::Parser;
use connect::ConnectOpts;
use insdesk_core::controller::{ControllerCommand, ControllerEvent};
use insdesk_proto::ClipboardData;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "insdesk-client", about = "InsDesk controller (view/control a remote host)")]
struct Args {
    /// Relay server address (use with --id).
    #[arg(long, env = "INSDESK_RELAY")]
    relay: Option<String>,
    /// Connect directly to a host address (bypasses the relay).
    #[arg(long)]
    connect: Option<String>,
    /// Target device ID (required in relay mode).
    #[arg(long)]
    id: Option<u64>,

    /// This controller's identity key file.
    #[arg(long, default_value = "insdesk-client.key")]
    key: PathBuf,
    /// Friendly name reported to the host.
    #[arg(long, default_value = "insdesk-controller")]
    name: String,
    /// Session password, if the host requires one.
    #[arg(long, env = "INSDESK_PASSWORD")]
    password: Option<String>,
    /// Skip verifying the host key against --id (not recommended).
    #[arg(long, default_value_t = false)]
    no_verify: bool,

    #[arg(long, default_value_t = 80)]
    quality: u8,
    #[arg(long, default_value_t = 30)]
    fps: u8,

    // --- headless actions ---
    /// List a remote directory and print it.
    #[arg(long, value_name = "REMOTE_PATH")]
    ls: Option<String>,
    /// Download "REMOTE:LOCAL" (repeatable).
    #[arg(long, value_name = "REMOTE:LOCAL")]
    download: Vec<String>,
    /// Upload "LOCAL:REMOTE" (repeatable).
    #[arg(long, value_name = "LOCAL:REMOTE")]
    upload: Vec<String>,
    /// Save a PNG snapshot of the remote screen to this path.
    #[arg(long, value_name = "PATH")]
    snapshot: Option<PathBuf>,
    /// Number of frames to receive before snapshotting (lets the screen settle).
    #[arg(long, default_value_t = 15)]
    frames: u32,
    /// Overall time budget for headless actions, in seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Launch the graphical controller (requires building with --features gui).
    #[arg(long, default_value_t = false)]
    gui: bool,
}

fn parse_pair(s: &str) -> Result<(String, String)> {
    let (a, b) = s.rsplit_once(':').ok_or_else(|| anyhow!("expected A:B in '{s}'"))?;
    Ok((a.to_string(), b.to_string()))
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
    let opts = ConnectOpts {
        relay: args.relay.clone(),
        direct: args.connect.clone(),
        id: args.id,
        key: args.key.clone(),
        name: args.name.clone(),
        password: args.password.clone(),
        verify_id: !args.no_verify,
        quality: args.quality,
        fps: args.fps,
    };

    if args.gui {
        #[cfg(feature = "gui")]
        {
            return gui::run(opts);
        }
        #[cfg(not(feature = "gui"))]
        {
            anyhow::bail!("this binary was built without the `gui` feature; rebuild with --features gui");
        }
    }

    run_headless(opts, &args).await
}

/// Headless controller: connect, perform the requested actions, snapshot, exit.
async fn run_headless(opts: ConnectOpts, args: &Args) -> Result<()> {
    let mut handle = connect::establish(&opts).await?;
    println!("connected to host '{}' (id {})  {}x{}", handle.host_name, handle.host_id, handle.width, handle.height);

    // Kick off requested actions.
    let mut next_transfer: u64 = 1;
    let mut pending_transfers: HashSet<u64> = HashSet::new();
    let mut ls_pending = false;

    handle.commands.send(ControllerCommand::Ping).await.ok();

    if let Some(path) = &args.ls {
        handle.commands.send(ControllerCommand::ListDir(path.clone())).await.ok();
        ls_pending = true;
    }
    for spec in &args.download {
        let (remote, local) = parse_pair(spec)?;
        let transfer = next_transfer;
        next_transfer += 1;
        pending_transfers.insert(transfer);
        handle
            .commands
            .send(ControllerCommand::Download { transfer, remote_path: remote, local_dest: local })
            .await
            .ok();
    }
    for spec in &args.upload {
        let (local, remote) = parse_pair(spec)?;
        let transfer = next_transfer;
        next_transfer += 1;
        pending_transfers.insert(transfer);
        handle
            .commands
            .send(ControllerCommand::Upload { transfer, local_path: local, remote_dest: remote })
            .await
            .ok();
    }

    // Ask for a keyframe so the first snapshot is complete.
    handle.commands.send(ControllerCommand::RequestKeyframe).await.ok();

    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let mut frames_seen = 0u32;
    let mut latest_frame: Option<(u32, u32, std::sync::Arc<Vec<u8>>)> = None;
    let want_snapshot = args.snapshot.is_some();

    loop {
        if is_done(want_snapshot, frames_seen, args.frames, ls_pending, &pending_transfers) {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            println!("(timeout reached; finishing with what we have)");
            break;
        }
        match tokio::time::timeout(remaining, handle.events.recv()).await {
            Err(_) => {
                println!("(timeout reached)");
                break;
            }
            Ok(None) => break,
            Ok(Some(event)) => match event {
                ControllerEvent::Frame { width, height, rgba, .. } => {
                    frames_seen += 1;
                    latest_frame = Some((width, height, rgba));
                }
                ControllerEvent::DirListing { path, entries, error } => {
                    ls_pending = false;
                    match error {
                        Some(e) => println!("ls {path}: error: {e}"),
                        None => {
                            println!("ls {path}: {} entries", entries.len());
                            for e in entries.iter().take(200) {
                                let kind = if e.is_dir { "d" } else { "-" };
                                println!("  {kind} {:>12}  {}", e.size, e.name);
                            }
                        }
                    }
                }
                ControllerEvent::TransferAccepted { transfer, size } => {
                    println!("transfer {transfer} accepted ({size} bytes)");
                }
                ControllerEvent::TransferRejected { transfer, reason } => {
                    println!("transfer {transfer} rejected: {reason}");
                    pending_transfers.remove(&transfer);
                }
                ControllerEvent::TransferProgress { transfer, received, total } => {
                    tracing::debug!("transfer {transfer}: {received}/{total}");
                }
                ControllerEvent::TransferCompleted { transfer, ok, detail } => {
                    println!("transfer {transfer} {}: {detail}", if ok { "completed" } else { "FAILED" });
                    pending_transfers.remove(&transfer);
                }
                ControllerEvent::OpAck { ok, error } => {
                    println!("op ack: ok={ok} {}", error.unwrap_or_default());
                }
                ControllerEvent::Clipboard(ClipboardData::Text(t)) => {
                    println!("remote clipboard: {t:?}");
                }
                ControllerEvent::Clipboard(ClipboardData::Empty) => {}
                ControllerEvent::SecureDesktop(active) => {
                    println!("** secure desktop (UAC) {} **", if active { "ACTIVE" } else { "cleared" });
                }
                ControllerEvent::ElevationStatus { elevated, detail } => {
                    println!("elevation: elevated={elevated} ({detail})");
                }
                ControllerEvent::Latency { millis } => {
                    println!("round-trip latency: {millis} ms");
                }
                ControllerEvent::Disconnected { reason } => {
                    println!("disconnected: {}", reason.unwrap_or_else(|| "(no reason)".into()));
                    break;
                }
                ControllerEvent::Error(e) => {
                    println!("error: {e}");
                }
            },
        }
    }

    if let (Some(path), Some((w, h, rgba))) = (&args.snapshot, &latest_frame) {
        save_png(path, *w, *h, rgba)?;
        println!("saved snapshot {}x{} to {}", w, h, path.display());
    } else if want_snapshot {
        println!("no frame received to snapshot");
    }

    handle.commands.send(ControllerCommand::Disconnect).await.ok();
    Ok(())
}

fn is_done(
    want_snapshot: bool,
    frames_seen: u32,
    frames_target: u32,
    ls_pending: bool,
    pending_transfers: &HashSet<u64>,
) -> bool {
    let frames_ok = !want_snapshot || frames_seen >= frames_target;
    frames_ok && !ls_pending && pending_transfers.is_empty()
}

fn save_png(path: &std::path::Path, width: u32, height: u32, rgba: &[u8]) -> Result<()> {
    let img = image::RgbaImage::from_raw(width, height, rgba.to_vec())
        .ok_or_else(|| anyhow!("frame buffer size mismatch"))?;
    img.save(path)?;
    Ok(())
}
