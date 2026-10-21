//! Input injection abstraction and backends (the "control PC" capability).
//!
//! The controller sends [`insdesk_proto::InputEvent`]s; on the host an
//! [`InputSink`] replays them. The always-present [`RecordingInputSink`] simply
//! records events (used headless / in tests), while the `input-enigo` feature
//! provides real OS-level injection through the cross-platform `enigo` crate.

use insdesk_proto::InputEvent;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InputError {
    #[error("input backend error: {0}")]
    Backend(String),
    #[error("input injection is disabled")]
    Disabled,
}

/// Something that can replay input events on the local machine.
pub trait InputSink: Send {
    fn inject(&mut self, event: InputEvent) -> Result<(), InputError>;
}

/// Records injected events instead of performing them. Useful for headless
/// operation, auditing, and tests.
#[derive(Default)]
pub struct RecordingInputSink {
    pub events: Vec<InputEvent>,
}

impl RecordingInputSink {
    pub fn new() -> Self {
        Self::default()
    }
}

impl InputSink for RecordingInputSink {
    fn inject(&mut self, event: InputEvent) -> Result<(), InputError> {
        tracing::debug!(?event, "recording input event");
        self.events.push(event);
        Ok(())
    }
}

/// Real OS input injection via `enigo`.
#[cfg(feature = "input-enigo")]
mod enigo_backend {
    use super::*;
    use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key as EKey, Keyboard, Mouse, Settings};
    use insdesk_proto::{Key, MouseButton};

    pub struct EnigoInputSink {
        enigo: Enigo,
    }

    impl EnigoInputSink {
        pub fn new() -> Result<Self, InputError> {
            let enigo = Enigo::new(&Settings::default()).map_err(|e| InputError::Backend(e.to_string()))?;
            Ok(EnigoInputSink { enigo })
        }
    }

    fn map_button(b: MouseButton) -> Button {
        match b {
            MouseButton::Left => Button::Left,
            MouseButton::Right => Button::Right,
            MouseButton::Middle => Button::Middle,
        }
    }

    fn map_key(k: Key) -> Option<EKey> {
        Some(match k {
            Key::Enter => EKey::Return,
            Key::Escape => EKey::Escape,
            Key::Backspace => EKey::Backspace,
            Key::Tab => EKey::Tab,
            Key::Space => EKey::Space,
            Key::Delete => EKey::Delete,
            Key::Home => EKey::Home,
            Key::End => EKey::End,
            Key::PageUp => EKey::PageUp,
            Key::PageDown => EKey::PageDown,
            Key::Left => EKey::LeftArrow,
            Key::Right => EKey::RightArrow,
            Key::Up => EKey::UpArrow,
            Key::Down => EKey::DownArrow,
            Key::Shift => EKey::Shift,
            Key::Control => EKey::Control,
            Key::Alt => EKey::Alt,
            Key::Meta => EKey::Meta,
            Key::CapsLock => EKey::CapsLock,
            Key::F(n) => EKey::F(n),
            Key::Char(c) => EKey::Unicode(c),
        })
    }

    impl InputSink for EnigoInputSink {
        fn inject(&mut self, event: InputEvent) -> Result<(), InputError> {
            let be = |e: enigo::InputError| InputError::Backend(e.to_string());
            match event {
                InputEvent::MouseMove { x, y } => {
                    self.enigo.move_mouse(x, y, Coordinate::Abs).map_err(be)?;
                }
                InputEvent::MouseButton { button, down } => {
                    let dir = if down { Direction::Press } else { Direction::Release };
                    self.enigo.button(map_button(button), dir).map_err(be)?;
                }
                InputEvent::MouseScroll { dx, dy } => {
                    if dx != 0 {
                        self.enigo.scroll(dx, Axis::Horizontal).map_err(be)?;
                    }
                    if dy != 0 {
                        self.enigo.scroll(dy, Axis::Vertical).map_err(be)?;
                    }
                }
                InputEvent::Key { key, down } => {
                    if let Some(k) = map_key(key) {
                        let dir = if down { Direction::Press } else { Direction::Release };
                        self.enigo.key(k, dir).map_err(be)?;
                    }
                }
                InputEvent::Text { ch } => {
                    self.enigo.text(&ch.to_string()).map_err(be)?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(feature = "input-enigo")]
pub use enigo_backend::EnigoInputSink;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_sink_captures_events() {
        let mut sink = RecordingInputSink::new();
        sink.inject(InputEvent::MouseMove { x: 10, y: 20 }).unwrap();
        sink.inject(InputEvent::Text { ch: 'a' }).unwrap();
        assert_eq!(sink.events.len(), 2);
    }
}
