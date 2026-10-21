//! Screen capture abstraction and backends.
//!
//! The core only depends on the [`ScreenCapturer`] trait and the always-present
//! [`SyntheticCapturer`]. Real capture is opt-in via the `capture-scrap`
//! feature, which pulls in the cross-platform `scrap` crate (X11/XCB on Linux,
//! DXGI on Windows, CoreGraphics on macOS). This keeps the engine buildable and
//! testable on headless CI while the same binaries capture a real desktop on an
//! operator's machine.

use crate::frame::FrameBuffer;
use insdesk_proto::PixelFormat;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("no display available")]
    NoDisplay,
    #[error("capture backend error: {0}")]
    Backend(String),
    #[error("frame not ready")]
    WouldBlock,
}

/// A source of screen frames.
///
/// Implementations are created and driven entirely on one dedicated capture
/// thread (see `insdesk-core::host`), so they need not be `Send` — this lets
/// real backends like `scrap`, whose handles are not `Send` on some platforms,
/// implement the trait directly.
pub trait ScreenCapturer {
    /// The capture geometry. Stable for the capturer's lifetime.
    fn dimensions(&self) -> (u32, u32);
    /// Grab the current screen contents as a packed [`FrameBuffer`].
    fn capture(&mut self) -> Result<FrameBuffer, CaptureError>;
}

/// A deterministic, animated capturer used for headless runs, demos and tests.
///
/// It renders a moving diagonal gradient plus a sweeping highlight bar, so the
/// delta codec has real motion to compress and a viewer sees the stream change
/// over time — without needing a physical display.
pub struct SyntheticCapturer {
    width: u32,
    height: u32,
    tick: u64,
}

impl SyntheticCapturer {
    pub fn new(width: u32, height: u32) -> Self {
        SyntheticCapturer { width, height, tick: 0 }
    }
}

impl ScreenCapturer for SyntheticCapturer {
    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture(&mut self) -> Result<FrameBuffer, CaptureError> {
        let mut fb = FrameBuffer::new(self.width, self.height, PixelFormat::Bgra8888);
        let t = self.tick;
        // Highlight bar sweeps horizontally; a large region stays static so
        // deltas are small (demonstrating the dirty-tile savings).
        let bar = ((t * 7) % (self.width as u64)) as u32;
        for y in 0..self.height {
            for x in 0..self.width {
                let o = fb.offset(x, y);
                let base = ((x + y + t as u32) % 256) as u8;
                let near_bar = x.abs_diff(bar) < 24;
                let (b, g, r) = if near_bar {
                    (255u8, 255u8, base)
                } else {
                    // Mostly-flat background in large bands → cheap to encode.
                    let band = ((y / 40) as u8).wrapping_mul(16);
                    (band, 48, 64)
                };
                fb.pixels[o] = b;
                fb.pixels[o + 1] = g;
                fb.pixels[o + 2] = r;
                fb.pixels[o + 3] = 0xFF;
            }
        }
        self.tick = self.tick.wrapping_add(1);
        Ok(fb)
    }
}

/// Real capture via `scrap`.
#[cfg(feature = "capture-scrap")]
mod scrap_backend {
    use super::*;
    use scrap::{Capturer, Display};

    /// Captures the primary display. Pixels arrive BGRA, matching our codec.
    pub struct ScrapCapturer {
        capturer: Capturer,
        width: u32,
        height: u32,
    }

    impl ScrapCapturer {
        pub fn primary() -> Result<Self, CaptureError> {
            let display = Display::primary().map_err(|_| CaptureError::NoDisplay)?;
            let width = display.width() as u32;
            let height = display.height() as u32;
            let capturer = Capturer::new(display).map_err(|e| CaptureError::Backend(e.to_string()))?;
            Ok(ScrapCapturer { capturer, width, height })
        }
    }

    impl ScreenCapturer for ScrapCapturer {
        fn dimensions(&self) -> (u32, u32) {
            (self.width, self.height)
        }

        fn capture(&mut self) -> Result<FrameBuffer, CaptureError> {
            let (w, h) = (self.width, self.height);
            let frame = match self.capturer.frame() {
                Ok(f) => f,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(CaptureError::WouldBlock)
                }
                Err(e) => return Err(CaptureError::Backend(e.to_string())),
            };
            // `scrap` rows are padded to `stride`; repack to width*4 BGRA.
            let stride = frame.len() / (h as usize);
            let mut fb = FrameBuffer::new(w, h, PixelFormat::Bgra8888);
            let row_bytes = (w as usize) * 4;
            for y in 0..(h as usize) {
                let src = y * stride;
                let dst = y * row_bytes;
                fb.pixels[dst..dst + row_bytes].copy_from_slice(&frame[src..src + row_bytes]);
            }
            Ok(fb)
        }
    }
}

#[cfg(feature = "capture-scrap")]
pub use scrap_backend::ScrapCapturer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_capturer_changes_over_time() {
        let mut cap = SyntheticCapturer::new(80, 60);
        assert_eq!(cap.dimensions(), (80, 60));
        let a = cap.capture().unwrap();
        let b = cap.capture().unwrap();
        assert_eq!(a.pixels.len(), a.expected_len());
        assert_ne!(a.pixels, b.pixels, "frames should animate");
    }
}
