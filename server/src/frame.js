'use strict';

// Length-prefixed framing, byte-for-byte compatible with the Rust client's
// `insdesk-proto::frame`: a 4-byte big-endian unsigned length followed by that
// many payload bytes. The relay never interprets payloads beyond the first
// rendezvous frame — after pairing it forwards raw bytes.

const MAX_FRAME_LEN = 256 * 1024;

/** Wrap a payload Buffer in a length-prefixed frame. */
function encodeFrame(payload) {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/**
 * Incremental frame parser. Feed it socket chunks with `push`, then pull
 * complete frames with `next`. `leftover` exposes any still-buffered bytes so
 * they can be forwarded verbatim once the connection is spliced.
 */
class FrameReader {
  constructor() {
    this._buf = Buffer.alloc(0);
  }

  push(chunk) {
    this._buf = this._buf.length === 0 ? chunk : Buffer.concat([this._buf, chunk]);
  }

  /** Returns the next complete frame as a Buffer, or null if incomplete. */
  next() {
    if (this._buf.length < 4) return null;
    const len = this._buf.readUInt32BE(0);
    if (len > MAX_FRAME_LEN) {
      throw new Error(`frame length ${len} exceeds maximum ${MAX_FRAME_LEN}`);
    }
    if (this._buf.length < 4 + len) return null;
    const frame = this._buf.subarray(4, 4 + len);
    this._buf = this._buf.subarray(4 + len);
    return frame;
  }

  leftover() {
    return this._buf;
  }
}

module.exports = { encodeFrame, FrameReader, MAX_FRAME_LEN };
