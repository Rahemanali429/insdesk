//! Construction of the host's media/file backends, shared by the CLI host agent
//! and the desktop app.
//!
//! The default build returns portable backends (synthetic capturer, recording
//! input sink, in-memory clipboard) so everything runs headless. Building with
//! the `capture-scrap` / `input-enigo` / `clipboard-arboard` features swaps in
//! real OS backends.

use crate::HostBackends;
use insdesk_fs::{ClipboardBackend, FileService, MemoryClipboard};
use insdesk_media::capture::{ScreenCapturer, SyntheticCapturer};
use insdesk_media::input::{InputSink, RecordingInputSink};
use insdesk_media::uac;
use std::path::PathBuf;

/// Build a screen capturer: the real one if a capture backend is compiled in,
/// otherwise an animated synthetic source.
pub fn make_capturer(width: u32, height: u32) -> Box<dyn ScreenCapturer> {
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

/// Build an input sink: real OS injection if compiled in, else a recording sink.
pub fn make_input() -> Box<dyn InputSink> {
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

/// Build a clipboard backend: the system clipboard if compiled in, else memory.
pub fn make_clipboard() -> Box<dyn ClipboardBackend> {
    #[cfg(feature = "clipboard-arboard")]
    {
        match insdesk_fs::clipboard::SystemClipboard::new() {
            Ok(c) => return Box::new(c),
            Err(e) => tracing::warn!("system clipboard unavailable ({e}); using memory"),
        }
    }
    Box::new(MemoryClipboard::new())
}

/// Assemble a full [`HostBackends`] set. `file_root`, when given, confines file
/// transfer to that directory.
///
/// The capturer/input/clipboard are returned as factories so the real
/// (possibly non-`Send`) OS handles are constructed on their dedicated threads
/// inside the host engine, never on the caller's thread.
pub fn default_host_backends(width: u32, height: u32, file_root: Option<PathBuf>) -> HostBackends {
    let files = match file_root {
        Some(root) => FileService::with_root(root),
        None => FileService::new(),
    };
    HostBackends {
        capturer: Box::new(move || make_capturer(width, height)),
        input: Box::new(make_input),
        clipboard: Box::new(make_clipboard),
        elevation: uac::default_bridge(),
        files,
    }
}
