//! File-manager operations and integrity-checked chunked transfers.
//!
//! Both peers run a [`FileService`]. It answers directory listings and
//! create/remove requests, and it opens [`OutboundTransfer`] / [`InboundTransfer`]
//! objects that stream a file as a sequence of `insdesk_proto::FileMsg` values.
//! Every transfer ends with a SHA-256 digest so truncation or corruption on the
//! wire is always detected.
//!
//! An optional **jail root** confines all paths to a chosen directory — useful
//! when exposing only part of a machine.

use insdesk_proto::{DirEntry, FileMsg, TransferId};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;
use thiserror::Error;

/// Default transfer chunk size (fits comfortably inside one encrypted record).
pub const DEFAULT_CHUNK: usize = 48 * 1024;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("path escapes the configured root: {0}")]
    OutsideRoot(String),
    #[error("transfer integrity check failed")]
    IntegrityMismatch,
}

/// Handles filesystem requests on one peer.
pub struct FileService {
    root: Option<PathBuf>,
}

impl Default for FileService {
    fn default() -> Self {
        FileService { root: None }
    }
}

impl FileService {
    /// Unrestricted access to the whole filesystem (subject to OS permissions).
    pub fn new() -> Self {
        Self::default()
    }

    /// Confine every operation to `root` and its descendants.
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        FileService { root: Some(root.into()) }
    }

    /// Resolve a request path, enforcing the jail root if one is set.
    fn resolve(&self, path: &str) -> Result<PathBuf, FsError> {
        let requested = Path::new(path);
        match &self.root {
            None => Ok(requested.to_path_buf()),
            Some(root) => {
                // Build the path from the root, rejecting any `..` that would
                // climb above it.
                let mut out = root.clone();
                for comp in requested.components() {
                    match comp {
                        Component::Normal(c) => out.push(c),
                        Component::CurDir => {}
                        Component::RootDir | Component::Prefix(_) => {}
                        Component::ParentDir => {
                            if !out.pop() || !out.starts_with(root) {
                                return Err(FsError::OutsideRoot(path.to_string()));
                            }
                        }
                    }
                }
                if out.starts_with(root) {
                    Ok(out)
                } else {
                    Err(FsError::OutsideRoot(path.to_string()))
                }
            }
        }
    }

    /// List a directory, returning a ready-to-send [`FileMsg::DirListing`].
    pub fn list_dir(&self, path: &str) -> FileMsg {
        let resolved = match self.resolve(path) {
            Ok(p) => p,
            Err(e) => {
                return FileMsg::DirListing { path: path.into(), entries: vec![], error: Some(e.to_string()) }
            }
        };
        match self.read_entries(&resolved) {
            Ok(entries) => FileMsg::DirListing { path: path.into(), entries, error: None },
            Err(e) => FileMsg::DirListing { path: path.into(), entries: vec![], error: Some(e.to_string()) },
        }
    }

    fn read_entries(&self, dir: &Path) -> Result<Vec<DirEntry>, FsError> {
        let mut entries = Vec::new();
        for item in fs::read_dir(dir)? {
            let item = item?;
            let meta = match item.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified_unix = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            entries.push(DirEntry {
                name: item.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: meta.len(),
                modified_unix,
            });
        }
        entries.sort_by(|a, b| (b.is_dir, a.name.to_lowercase()).cmp(&(a.is_dir, b.name.to_lowercase())));
        Ok(entries)
    }

    /// Create a directory (and parents).
    pub fn make_dir(&self, path: &str) -> FileMsg {
        match self.resolve(path).and_then(|p| Ok(fs::create_dir_all(p)?)) {
            Ok(()) => FileMsg::OpAck { ok: true, error: None },
            Err(e) => FileMsg::OpAck { ok: false, error: Some(e.to_string()) },
        }
    }

    /// Remove a file or empty directory.
    pub fn remove(&self, path: &str) -> FileMsg {
        let resolved = match self.resolve(path) {
            Ok(p) => p,
            Err(e) => return FileMsg::OpAck { ok: false, error: Some(e.to_string()) },
        };
        let result = if resolved.is_dir() {
            fs::remove_dir(&resolved)
        } else {
            fs::remove_file(&resolved)
        };
        match result {
            Ok(()) => FileMsg::OpAck { ok: true, error: None },
            Err(e) => FileMsg::OpAck { ok: false, error: Some(e.to_string()) },
        }
    }

    /// Open a file to **send** to the peer (answers a download request).
    pub fn open_outbound(&self, transfer: TransferId, path: &str) -> Result<OutboundTransfer, FsError> {
        let resolved = self.resolve(path)?;
        let file = File::open(&resolved)?;
        let size = file.metadata()?.len();
        Ok(OutboundTransfer { transfer, file, offset: 0, size, hasher: Sha256::new() })
    }

    /// Open a destination file to **receive** from the peer (answers an upload
    /// request, or completes our own download request).
    pub fn open_inbound(&self, transfer: TransferId, dest: &str, size: u64) -> Result<InboundTransfer, FsError> {
        let resolved = self.resolve(dest)?;
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::create(&resolved)?;
        Ok(InboundTransfer { transfer, file, received: 0, expected: size, hasher: Sha256::new() })
    }
}

/// One step of an outbound transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutStep {
    /// A chunk to send.
    Chunk(FileMsg),
    /// The transfer is complete; send this and stop.
    Done(FileMsg),
}

/// A file being streamed out to the peer.
pub struct OutboundTransfer {
    transfer: TransferId,
    file: File,
    offset: u64,
    size: u64,
    hasher: Sha256,
}

impl OutboundTransfer {
    pub fn transfer_id(&self) -> TransferId {
        self.transfer
    }
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Produce the next [`OutStep`], reading up to `chunk_size` bytes.
    pub fn next(&mut self, chunk_size: usize) -> Result<OutStep, FsError> {
        let mut buf = vec![0u8; chunk_size];
        let n = self.file.read(&mut buf)?;
        if n == 0 {
            let digest = hex::encode(self.hasher.clone().finalize());
            return Ok(OutStep::Done(FileMsg::TransferDone { transfer: self.transfer, sha256_hex: digest }));
        }
        buf.truncate(n);
        self.hasher.update(&buf);
        let msg = FileMsg::Chunk { transfer: self.transfer, offset: self.offset, data: buf };
        self.offset += n as u64;
        Ok(OutStep::Chunk(msg))
    }
}

/// A file being written as chunks arrive from the peer.
pub struct InboundTransfer {
    transfer: TransferId,
    file: File,
    received: u64,
    expected: u64,
    hasher: Sha256,
}

impl InboundTransfer {
    pub fn transfer_id(&self) -> TransferId {
        self.transfer
    }
    pub fn received(&self) -> u64 {
        self.received
    }
    pub fn expected(&self) -> u64 {
        self.expected
    }

    /// Write one chunk at its declared offset.
    pub fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<(), FsError> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        self.hasher.update(data);
        self.received += data.len() as u64;
        Ok(())
    }

    /// Finalize and verify the SHA-256 digest sent by the peer.
    pub fn finish(mut self, sha256_hex: &str) -> Result<(), FsError> {
        self.file.flush()?;
        let digest = hex::encode(self.hasher.finalize());
        if digest.eq_ignore_ascii_case(sha256_hex) {
            Ok(())
        } else {
            Err(FsError::IntegrityMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_round_trips_with_integrity() {
        let dir = std::env::temp_dir().join(format!("insdesk-fs-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        let dst = dir.join("dst.bin");
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();

        let svc = FileService::new();
        let mut out = svc.open_outbound(1, src.to_str().unwrap()).unwrap();
        let mut inb = svc.open_inbound(1, dst.to_str().unwrap(), payload.len() as u64).unwrap();

        loop {
            match out.next(4096).unwrap() {
                OutStep::Chunk(FileMsg::Chunk { offset, data, .. }) => {
                    inb.write_chunk(offset, &data).unwrap();
                }
                OutStep::Done(FileMsg::TransferDone { sha256_hex, .. }) => {
                    inb.finish(&sha256_hex).unwrap();
                    break;
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(fs::read(&dst).unwrap(), payload);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupted_transfer_is_rejected() {
        let dir = std::env::temp_dir().join(format!("insdesk-fs-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dst = dir.join("dst.bin");
        let svc = FileService::new();
        let mut inb = svc.open_inbound(2, dst.to_str().unwrap(), 4).unwrap();
        inb.write_chunk(0, b"data").unwrap();
        // Wrong digest → integrity failure.
        assert!(matches!(inb.finish("deadbeef"), Err(FsError::IntegrityMismatch)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn jail_root_blocks_escape() {
        let svc = FileService::with_root("/tmp/insdesk-jail");
        let listing = svc.list_dir("../../../etc");
        match listing {
            FileMsg::DirListing { error, .. } => assert!(error.is_some()),
            _ => unreachable!(),
        }
    }
}
