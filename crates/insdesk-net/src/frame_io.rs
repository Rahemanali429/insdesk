//! Async read/write of length-prefixed frames (see `insdesk-proto::frame`).

use insdesk_proto::frame::{self, FrameError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read exactly one length-prefixed frame from `r`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await.map_err(map_eof)?;
    let len = frame::parse_len(header)?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(map_eof)?;
    Ok(buf)
}

/// Write `payload` as one length-prefixed frame to `w` and flush.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    let framed = frame::encode_frame(payload)?;
    w.write_all(&framed).await?;
    w.flush().await?;
    Ok(())
}

fn map_eof(e: std::io::Error) -> FrameError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        FrameError::UnexpectedEof
    } else {
        FrameError::Io(e)
    }
}
