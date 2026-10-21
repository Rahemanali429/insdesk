//! # insdesk-media
//!
//! The media layer: turning a desktop into an encrypted stream and replaying a
//! remote operator's input.
//!
//! * [`capture`] — screen capture ([`capture::ScreenCapturer`]), with a
//!   portable [`capture::SyntheticCapturer`] and an opt-in `scrap` backend.
//! * [`codec`] — the pure-Rust tile + delta + DEFLATE video codec
//!   ([`codec::Encoder`] / [`codec::Decoder`]).
//! * [`input`] — input injection ([`input::InputSink`]), with a recording sink
//!   and an opt-in `enigo` backend ("control PC").
//! * [`uac`] — the privilege-elevation / UAC secure-desktop bridge.
//! * [`frame`] — the canonical [`frame::FrameBuffer`] exchanged between them.

pub mod capture;
pub mod codec;
pub mod frame;
pub mod input;
pub mod uac;

pub use frame::FrameBuffer;
