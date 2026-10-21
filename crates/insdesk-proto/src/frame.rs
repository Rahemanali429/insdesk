//! Length-prefixed framing used on every byte stream in InsDesk.
//!
//! The format is deliberately trivial: a 4-byte big-endian unsigned length
//! followed by exactly that many bytes of payload. The same framing carries
//! rendezvous messages, Noise handshake messages, and the opaque encrypted
//! blobs the relay forwards — the reader never needs to understand the payload.

use thiserror::Error;

/// Hard cap on a single frame's payload. Large enough for a Noise transport
/// message plus overhead, small enough to bound memory against a hostile peer.
pub const MAX_FRAME_LEN: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame length {0} exceeds maximum {MAX_FRAME_LEN}")]
    TooLarge(usize),
    #[error("stream closed mid-frame")]
    UnexpectedEof,
    #[error("serialize error: {0}")]
    Serialize(String),
    #[error("deserialize error: {0}")]
    Deserialize(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Encode `payload` into a freshly allocated length-prefixed frame.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parse the 4-byte length header, validating it against [`MAX_FRAME_LEN`].
pub fn parse_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_length_prefix() {
        let payload = b"hello world";
        let framed = encode_frame(payload).unwrap();
        let mut header = [0u8; 4];
        header.copy_from_slice(&framed[..4]);
        let len = parse_len(header).unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(&framed[4..], payload);
    }

    #[test]
    fn rejects_oversize() {
        let big = vec![0u8; MAX_FRAME_LEN + 1];
        assert!(matches!(encode_frame(&big), Err(FrameError::TooLarge(_))));
    }
}
