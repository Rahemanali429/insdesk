//! Tile + delta + DEFLATE video codec.
//!
//! Encoding a frame:
//! 1. The image is cut into a grid of `tile_size`×`tile_size` tiles (edge tiles
//!    may be smaller).
//! 2. On a **keyframe** every tile is emitted; on a **delta** only tiles whose
//!    bytes changed since the previous frame are emitted.
//! 3. Each emitted tile is stored as a single solid color when possible, else
//!    DEFLATE-compressed, else raw (whichever is smallest).
//!
//! The decoder keeps a persistent canvas and patches in whatever tiles arrive,
//! so a delta frame only needs to carry motion — this is what makes the stream
//! smooth at low bandwidth.

use crate::frame::FrameBuffer;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use insdesk_proto::codec::{EncodedFrame, EncodedTile, TileEncoding};
use insdesk_proto::PixelFormat;
use std::io::{Read, Write};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("frame size {got} does not match expected {expected}")]
    SizeMismatch { got: usize, expected: usize },
    #[error("tile at ({col},{row}) is out of the {cols}x{rows} grid")]
    TileOutOfBounds { col: u32, row: u32, cols: u32, rows: u32 },
    #[error("decoded tile had {got} bytes, expected {expected}")]
    BadTileLength { got: usize, expected: usize },
    #[error("decompression failed: {0}")]
    Decompress(String),
}

/// Compute the tile-grid dimensions for an image.
pub fn grid_dims(width: u32, height: u32, tile_size: u32) -> (u32, u32) {
    let cols = (width + tile_size - 1) / tile_size;
    let rows = (height + tile_size - 1) / tile_size;
    (cols, rows)
}

/// Stateful encoder. One instance per stream; it remembers the previous frame
/// to produce deltas.
pub struct Encoder {
    width: u32,
    height: u32,
    tile_size: u32,
    prev: Option<Vec<u8>>,
    level: Compression,
}

impl Encoder {
    pub fn new(width: u32, height: u32, tile_size: u32) -> Self {
        Encoder { width, height, tile_size, prev: None, level: Compression::new(6) }
    }

    /// Set the DEFLATE compression level from a 1..=100 quality hint (higher
    /// quality → spend more CPU on better compression ratios).
    pub fn set_quality(&mut self, quality: u8) {
        let q = quality.clamp(1, 100);
        // Map 1..100 → zlib levels 1..9.
        let level = 1 + ((q as u32 - 1) * 8) / 99;
        self.level = Compression::new(level);
    }

    /// Force the next [`Encoder::encode`] to emit a full keyframe.
    pub fn request_keyframe(&mut self) {
        self.prev = None;
    }

    /// Encode `fb`. Emits a keyframe if forced or if this is the first frame.
    pub fn encode(&mut self, fb: &FrameBuffer, force_keyframe: bool) -> Result<EncodedFrame, CodecError> {
        if fb.pixels.len() != fb.expected_len() {
            return Err(CodecError::SizeMismatch {
                got: fb.pixels.len(),
                expected: fb.expected_len(),
            });
        }
        let (cols, rows) = grid_dims(self.width, self.height, self.tile_size);
        let keyframe = force_keyframe || self.prev.is_none();
        let prev = if keyframe { None } else { self.prev.as_deref() };

        let mut tiles = Vec::new();
        for row in 0..rows {
            for col in 0..cols {
                let (x0, y0, tw, th) = self.tile_rect(col, row);
                let cur = extract_tile(&fb.pixels, self.width, x0, y0, tw, th);
                let changed = match prev {
                    None => true,
                    Some(p) => {
                        let old = extract_tile(p, self.width, x0, y0, tw, th);
                        old != cur
                    }
                };
                if changed {
                    tiles.push(self.encode_tile(col, row, &cur));
                }
            }
        }

        self.prev = Some(fb.pixels.clone());
        Ok(EncodedFrame { cols, rows, tiles })
    }

    fn tile_rect(&self, col: u32, row: u32) -> (u32, u32, u32, u32) {
        let x0 = col * self.tile_size;
        let y0 = row * self.tile_size;
        let tw = self.tile_size.min(self.width - x0);
        let th = self.tile_size.min(self.height - y0);
        (x0, y0, tw, th)
    }

    fn encode_tile(&self, col: u32, row: u32, raw: &[u8]) -> EncodedTile {
        // Solid-color fast path: every pixel identical.
        if raw.len() >= 4 {
            let first = &raw[..4];
            if raw.chunks_exact(4).all(|px| px == first) {
                return EncodedTile {
                    col,
                    row,
                    encoding: TileEncoding::SolidColor,
                    data: first.to_vec(),
                };
            }
        }
        // Try DEFLATE; keep it only if it actually shrinks the tile.
        let compressed = deflate(raw, self.level);
        if compressed.len() < raw.len() {
            EncodedTile { col, row, encoding: TileEncoding::Deflate, data: compressed }
        } else {
            EncodedTile { col, row, encoding: TileEncoding::Raw, data: raw.to_vec() }
        }
    }
}

/// Stateful decoder with a persistent canvas.
pub struct Decoder {
    width: u32,
    height: u32,
    tile_size: u32,
    canvas: Vec<u8>,
    #[allow(dead_code)]
    format: PixelFormat,
}

impl Decoder {
    pub fn new(width: u32, height: u32, tile_size: u32, format: PixelFormat) -> Self {
        let mut canvas = vec![0u8; (width as usize) * (height as usize) * 4];
        for px in canvas.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        Decoder { width, height, tile_size, canvas, format }
    }

    /// Apply a frame to the canvas and return the full current image (BGRA).
    pub fn apply(&mut self, frame: &EncodedFrame) -> Result<&[u8], CodecError> {
        for tile in &frame.tiles {
            if tile.col >= frame.cols || tile.row >= frame.rows {
                return Err(CodecError::TileOutOfBounds {
                    col: tile.col,
                    row: tile.row,
                    cols: frame.cols,
                    rows: frame.rows,
                });
            }
            let x0 = tile.col * self.tile_size;
            let y0 = tile.row * self.tile_size;
            if x0 >= self.width || y0 >= self.height {
                continue;
            }
            let tw = self.tile_size.min(self.width - x0);
            let th = self.tile_size.min(self.height - y0);
            let expected = (tw as usize) * (th as usize) * 4;
            let bytes = decode_tile(tile, expected)?;
            blit_tile(&mut self.canvas, self.width, x0, y0, tw, th, &bytes);
        }
        Ok(&self.canvas)
    }

    /// The current canvas without applying anything.
    pub fn canvas(&self) -> &[u8] {
        &self.canvas
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

/// Copy a `tw`×`th` tile at `(x0,y0)` out of a full image into a packed buffer.
fn extract_tile(pixels: &[u8], width: u32, x0: u32, y0: u32, tw: u32, th: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity((tw as usize) * (th as usize) * 4);
    let row_bytes = (tw as usize) * 4;
    for y in 0..th {
        let start = (((y0 + y) as usize) * (width as usize) + (x0 as usize)) * 4;
        out.extend_from_slice(&pixels[start..start + row_bytes]);
    }
    out
}

/// Inverse of [`extract_tile`]: write a packed tile back into a full image.
fn blit_tile(pixels: &mut [u8], width: u32, x0: u32, y0: u32, tw: u32, th: u32, tile: &[u8]) {
    let row_bytes = (tw as usize) * 4;
    for y in 0..th {
        let dst = (((y0 + y) as usize) * (width as usize) + (x0 as usize)) * 4;
        let src = (y as usize) * row_bytes;
        pixels[dst..dst + row_bytes].copy_from_slice(&tile[src..src + row_bytes]);
    }
}

fn decode_tile(tile: &EncodedTile, expected: usize) -> Result<Vec<u8>, CodecError> {
    let bytes = match tile.encoding {
        TileEncoding::Raw => tile.data.clone(),
        TileEncoding::Deflate => inflate(&tile.data).map_err(|e| CodecError::Decompress(e.to_string()))?,
        TileEncoding::SolidColor => {
            if tile.data.len() != 4 {
                return Err(CodecError::BadTileLength { got: tile.data.len(), expected: 4 });
            }
            let mut out = Vec::with_capacity(expected);
            for _ in 0..(expected / 4) {
                out.extend_from_slice(&tile.data);
            }
            out
        }
    };
    if bytes.len() != expected {
        return Err(CodecError::BadTileLength { got: bytes.len(), expected });
    }
    Ok(bytes)
}

fn deflate(data: &[u8], level: Compression) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), level);
    enc.write_all(data).expect("writing to Vec never fails");
    enc.finish().expect("finishing Vec encoder never fails")
}

fn inflate(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut dec = DeflateDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkerboard(w: u32, h: u32) -> FrameBuffer {
        let mut fb = FrameBuffer::new(w, h, PixelFormat::Bgra8888);
        for y in 0..h {
            for x in 0..w {
                let o = fb.offset(x, y);
                let v = if (x / 7 + y / 7) % 2 == 0 { 220 } else { 30 };
                fb.pixels[o] = v;
                fb.pixels[o + 1] = v;
                fb.pixels[o + 2] = v;
                fb.pixels[o + 3] = 0xFF;
            }
        }
        fb
    }

    #[test]
    fn keyframe_round_trips_exactly() {
        let (w, h, ts) = (160, 120, 32);
        let fb = checkerboard(w, h);
        let mut enc = Encoder::new(w, h, ts);
        let mut dec = Decoder::new(w, h, ts, PixelFormat::Bgra8888);

        let frame = enc.encode(&fb, true).unwrap();
        assert!(frame.tiles.len() == frame.full_tile_count());
        let out = dec.apply(&frame).unwrap();
        assert_eq!(out, &fb.pixels[..]);
    }

    #[test]
    fn delta_only_sends_changed_tiles_and_reconstructs() {
        let (w, h, ts) = (160, 120, 32);
        let fb1 = checkerboard(w, h);
        let mut fb2 = fb1.clone();
        // Change a single pixel in the top-left tile.
        let o = fb2.offset(1, 1);
        fb2.pixels[o] = 0;
        fb2.pixels[o + 1] = 0;
        fb2.pixels[o + 2] = 255;

        let mut enc = Encoder::new(w, h, ts);
        let mut dec = Decoder::new(w, h, ts, PixelFormat::Bgra8888);

        let k = enc.encode(&fb1, false).unwrap();
        dec.apply(&k).unwrap();

        let d = enc.encode(&fb2, false).unwrap();
        // Only the tile containing (1,1) changed.
        assert_eq!(d.tiles.len(), 1);
        assert_eq!((d.tiles[0].col, d.tiles[0].row), (0, 0));

        let out = dec.apply(&d).unwrap();
        assert_eq!(out, &fb2.pixels[..]);
    }

    #[test]
    fn solid_tiles_compress_to_one_pixel() {
        let (w, h, ts) = (64, 64, 32);
        let fb = FrameBuffer::new(w, h, PixelFormat::Bgra8888); // all one color
        let mut enc = Encoder::new(w, h, ts);
        let frame = enc.encode(&fb, true).unwrap();
        assert!(frame
            .tiles
            .iter()
            .all(|t| t.encoding == TileEncoding::SolidColor && t.data.len() == 4));
    }

    #[test]
    fn unchanged_frame_produces_no_tiles() {
        let (w, h, ts) = (96, 96, 32);
        let fb = checkerboard(w, h);
        let mut enc = Encoder::new(w, h, ts);
        enc.encode(&fb, false).unwrap();
        let d = enc.encode(&fb, false).unwrap();
        assert!(d.tiles.is_empty());
    }
}
