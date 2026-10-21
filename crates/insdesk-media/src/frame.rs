//! A captured screen frame in a canonical, tightly-packed layout.

use insdesk_proto::PixelFormat;

/// A full-screen image, row-major, 4 bytes per pixel, no padding
/// (`stride == width * 4`). This is the common currency between capture
/// backends and the codec.
#[derive(Clone)]
pub struct FrameBuffer {
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    /// `width * height * 4` bytes.
    pub pixels: Vec<u8>,
}

impl FrameBuffer {
    /// Allocate a black frame of the given size.
    pub fn new(width: u32, height: u32, format: PixelFormat) -> Self {
        let mut pixels = vec![0u8; (width as usize) * (height as usize) * 4];
        // Opaque alpha so a freshly allocated frame is visible, not transparent.
        for px in pixels.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        FrameBuffer { width, height, format, pixels }
    }

    /// Byte offset of pixel `(x, y)`.
    #[inline]
    pub fn offset(&self, x: u32, y: u32) -> usize {
        ((y as usize) * (self.width as usize) + (x as usize)) * 4
    }

    /// Expected length of `pixels` for this geometry.
    pub fn expected_len(&self) -> usize {
        (self.width as usize) * (self.height as usize) * 4
    }
}
