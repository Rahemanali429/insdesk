'use strict';

// Encode/decode the rendezvous control messages exactly as the Rust client
// serializes them with bincode (v1, the crate default: fixed-width integers,
// little-endian, enum discriminant as a u32). This is the ONLY payload the
// relay parses; everything after pairing is opaque end-to-end-encrypted bytes.
//
// RendezvousHello (controller/host -> relay):
//   RegisterHost  { id: u64 }  -> tag 0, then 8-byte LE id
//   ConnectToHost { id: u64 }  -> tag 1, then 8-byte LE id
//
// RendezvousReply (relay -> controller/host):
//   Registered       { id }      -> tag 0, 8-byte LE id
//   PeerConnected                -> tag 1
//   HostUnavailable  { id }      -> tag 2, 8-byte LE id
//   IdInUse          { id }      -> tag 3, 8-byte LE id
//   Error            { reason }  -> tag 4, 8-byte LE length + UTF-8 bytes

const HELLO = Object.freeze({ RegisterHost: 0, ConnectToHost: 1 });
const REPLY = Object.freeze({
  Registered: 0,
  PeerConnected: 1,
  HostUnavailable: 2,
  IdInUse: 3,
  Error: 4,
});

/** Parse a RendezvousHello frame. Returns { type, id } with id as BigInt. */
function parseHello(buf) {
  if (buf.length < 4) throw new Error('rendezvous hello too short');
  const tag = buf.readUInt32LE(0);
  switch (tag) {
    case HELLO.RegisterHost:
      requireLen(buf, 12, 'RegisterHost');
      return { type: 'RegisterHost', id: buf.readBigUInt64LE(4) };
    case HELLO.ConnectToHost:
      requireLen(buf, 12, 'ConnectToHost');
      return { type: 'ConnectToHost', id: buf.readBigUInt64LE(4) };
    default:
      throw new Error(`unknown rendezvous hello tag ${tag}`);
  }
}

function requireLen(buf, n, what) {
  if (buf.length < n) throw new Error(`${what} frame truncated (${buf.length} < ${n})`);
}

function tagWithId(tag, id) {
  const out = Buffer.alloc(12);
  out.writeUInt32LE(tag, 0);
  out.writeBigUInt64LE(BigInt(id), 4);
  return out;
}

const reply = {
  registered: (id) => tagWithId(REPLY.Registered, id),
  peerConnected: () => {
    const out = Buffer.alloc(4);
    out.writeUInt32LE(REPLY.PeerConnected, 0);
    return out;
  },
  hostUnavailable: (id) => tagWithId(REPLY.HostUnavailable, id),
  idInUse: (id) => tagWithId(REPLY.IdInUse, id),
  error: (reason) => {
    const text = Buffer.from(String(reason), 'utf8');
    const out = Buffer.alloc(4 + 8 + text.length);
    out.writeUInt32LE(REPLY.Error, 0);
    out.writeBigUInt64LE(BigInt(text.length), 4);
    text.copy(out, 12);
    return out;
  },
};

module.exports = { parseHello, reply, HELLO, REPLY };
