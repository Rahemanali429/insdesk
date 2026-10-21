//! On-wire description of an encoded video frame.
//!
//! InsDesk uses a simple but effective **tile + delta + DEFLATE** scheme that is
//! pure Rust and needs no native codec:
//!
//! * The screen is divided into a grid of square tiles (`VideoConfig::tile_size`).
//! * A **keyframe** carries every tile. A **delta** carries only the tiles whose
//!   pixels changed since the previous frame (classic dirty-rectangle streaming),
//!   which is what keeps motion smooth at low bandwidth.
//! * Each tile's raw BGRA bytes are DEFLATE-compressed independently so a single
//!   corrupt tile can never poison the rest of the frame.
//!
//! This module only defines the *data*; the actual encode/decode lives in
//! `insdesk-media::codec` so this crate stays dependency-light.

use serde::{Deserialize, Serialize};

/// A frame as a set of (compressed) tiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodedFrame {
    /// Number of tile columns in the full image grid.
    pub cols: u32,
    /// Number of tile rows in the full image grid.
    pub rows: u32,
    /// The tiles present in *this* frame. For a keyframe this is every tile;
    /// for a delta only the changed ones.
    pub tiles: Vec<EncodedTile>,
}

/// One compressed tile plus its position in the grid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodedTile {
    /// Column index in the tile grid.
    pub col: u32,
    /// Row index in the tile grid.
    pub row: u32,
    /// How the `data` bytes are encoded.
    pub encoding: TileEncoding,
    /// Encoded pixel bytes for this tile.
    pub data: Vec<u8>,
}

/// How a tile's bytes are represented.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TileEncoding {
    /// DEFLATE-compressed raw pixels (row-major, the frame's pixel format).
    Deflate,
    /// Uncompressed raw pixels — used when compression would not help (already
    /// high-entropy tiles), avoiding wasted CPU.
    Raw,
    /// The tile is a solid single color; `data` is exactly one pixel.
    SolidColor,
}

impl EncodedFrame {
    /// Total number of tiles in a full grid of this size.
    pub fn full_tile_count(&self) -> usize {
        (self.cols as usize) * (self.rows as usize)
    }
}
