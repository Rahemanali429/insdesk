//! Clipboard synchronization (the text "copy/paste" between the two machines).
//!
//! Each peer owns a [`ClipboardBackend`]. When the local clipboard changes, the
//! peer sends `insdesk_proto::ClipboardData`; on receipt the other peer sets its
//! local clipboard. An in-memory backend is always available; the
//! `clipboard-arboard` feature wires it to the real OS clipboard.

use insdesk_proto::ClipboardData;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("clipboard backend error: {0}")]
    Backend(String),
}

/// Read/write access to a clipboard, plus change detection so we only transmit
/// on an actual change (avoiding feedback loops between the two peers).
///
/// Driven on one dedicated I/O thread, so it need not be `Send` (the real
/// `arboard` backend is not `Send` on some platforms).
pub trait ClipboardBackend {
    /// Set the clipboard contents (applying what the peer sent).
    fn set(&mut self, data: &ClipboardData) -> Result<(), ClipboardError>;
    /// Return the current contents if they changed since the last call.
    fn take_change(&mut self) -> Result<Option<ClipboardData>, ClipboardError>;
}

/// A purely in-memory clipboard, used headless and in tests.
#[derive(Default)]
pub struct MemoryClipboard {
    current: ClipboardData,
    last_seen: Option<ClipboardData>,
}

impl MemoryClipboard {
    pub fn new() -> Self {
        // Seed `last_seen` with the current (empty) value so the first poll
        // reports "no change" rather than an empty-clipboard event.
        MemoryClipboard { current: ClipboardData::Empty, last_seen: Some(ClipboardData::Empty) }
    }

    /// Simulate a local copy (so tests/headless can drive sync).
    pub fn local_copy(&mut self, data: ClipboardData) {
        self.current = data;
    }
}

impl ClipboardBackend for MemoryClipboard {
    fn set(&mut self, data: &ClipboardData) -> Result<(), ClipboardError> {
        self.current = data.clone();
        // Record as seen so applying a peer update doesn't echo back.
        self.last_seen = Some(data.clone());
        Ok(())
    }

    fn take_change(&mut self) -> Result<Option<ClipboardData>, ClipboardError> {
        if self.last_seen.as_ref() != Some(&self.current) {
            self.last_seen = Some(self.current.clone());
            Ok(Some(self.current.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Real OS clipboard via `arboard`.
#[cfg(feature = "clipboard-arboard")]
mod arboard_backend {
    use super::*;

    pub struct SystemClipboard {
        inner: arboard::Clipboard,
        last_seen: Option<String>,
    }

    impl SystemClipboard {
        pub fn new() -> Result<Self, ClipboardError> {
            let inner = arboard::Clipboard::new().map_err(|e| ClipboardError::Backend(e.to_string()))?;
            Ok(SystemClipboard { inner, last_seen: None })
        }
    }

    impl ClipboardBackend for SystemClipboard {
        fn set(&mut self, data: &ClipboardData) -> Result<(), ClipboardError> {
            match data {
                ClipboardData::Text(t) => {
                    self.inner.set_text(t.clone()).map_err(|e| ClipboardError::Backend(e.to_string()))?;
                    self.last_seen = Some(t.clone());
                }
                ClipboardData::Empty => {}
            }
            Ok(())
        }

        fn take_change(&mut self) -> Result<Option<ClipboardData>, ClipboardError> {
            match self.inner.get_text() {
                Ok(text) => {
                    if self.last_seen.as_deref() != Some(text.as_str()) {
                        self.last_seen = Some(text.clone());
                        Ok(Some(ClipboardData::Text(text)))
                    } else {
                        Ok(None)
                    }
                }
                // An empty/unavailable clipboard is not an error.
                Err(_) => Ok(None),
            }
        }
    }
}

#[cfg(feature = "clipboard-arboard")]
pub use arboard_backend::SystemClipboard;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_local_change_once() {
        let mut cb = MemoryClipboard::new();
        assert!(cb.take_change().unwrap().is_none());
        cb.local_copy(ClipboardData::Text("hello".into()));
        assert_eq!(cb.take_change().unwrap(), Some(ClipboardData::Text("hello".into())));
        // No repeat until it changes again.
        assert!(cb.take_change().unwrap().is_none());
    }

    #[test]
    fn applying_peer_update_does_not_echo() {
        let mut cb = MemoryClipboard::new();
        cb.set(&ClipboardData::Text("from peer".into())).unwrap();
        // Applying the peer's value must not be re-emitted as a local change.
        assert!(cb.take_change().unwrap().is_none());
    }
}
