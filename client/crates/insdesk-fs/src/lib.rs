//! # insdesk-fs
//!
//! Data-movement features: file transfer and clipboard sync.
//!
//! * [`transfer`] — directory browsing and integrity-checked chunked file
//!   transfer in both directions ([`transfer::FileService`]).
//! * [`clipboard`] — text clipboard synchronization
//!   ([`clipboard::ClipboardBackend`]).

pub mod clipboard;
pub mod transfer;

pub use clipboard::{ClipboardBackend, MemoryClipboard};
pub use transfer::{FileService, InboundTransfer, OutStep, OutboundTransfer, DEFAULT_CHUNK};
