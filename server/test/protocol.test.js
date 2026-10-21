'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { encodeFrame, FrameReader } = require('../src/frame');
const { parseHello, reply } = require('../src/rendezvous');

// Build a bincode-encoded RendezvousHello the way the Rust client does:
// u32 LE variant tag, then u64 LE id.
function helloBytes(tag, id) {
  const b = Buffer.alloc(12);
  b.writeUInt32LE(tag, 0);
  b.writeBigUInt64LE(BigInt(id), 4);
  return b;
}

test('frame encodes a big-endian length prefix', () => {
  const framed = encodeFrame(Buffer.from('hello'));
  assert.strictEqual(framed.readUInt32BE(0), 5);
  assert.strictEqual(framed.subarray(4).toString(), 'hello');
});

test('FrameReader reassembles frames split across chunks', () => {
  const framed = encodeFrame(Buffer.from([1, 2, 3, 4]));
  const r = new FrameReader();
  r.push(framed.subarray(0, 2));
  assert.strictEqual(r.next(), null); // header incomplete
  r.push(framed.subarray(2));
  const frame = r.next();
  assert.deepStrictEqual([...frame], [1, 2, 3, 4]);
  assert.strictEqual(r.next(), null);
});

test('parseHello decodes RegisterHost and ConnectToHost', () => {
  const reg = parseHello(helloBytes(0, 123456789));
  assert.strictEqual(reg.type, 'RegisterHost');
  assert.strictEqual(reg.id, 123456789n);

  const conn = parseHello(helloBytes(1, 987654321));
  assert.strictEqual(conn.type, 'ConnectToHost');
  assert.strictEqual(conn.id, 987654321n);
});

test('parseHello rejects unknown tags', () => {
  assert.throws(() => parseHello(helloBytes(9, 1)));
});

test('reply encoders match the Rust bincode layout', () => {
  const reg = reply.registered(42);
  assert.strictEqual(reg.readUInt32LE(0), 0);
  assert.strictEqual(reg.readBigUInt64LE(4), 42n);

  const peer = reply.peerConnected();
  assert.strictEqual(peer.length, 4);
  assert.strictEqual(peer.readUInt32LE(0), 1);

  const err = reply.error('nope');
  assert.strictEqual(err.readUInt32LE(0), 4);
  assert.strictEqual(err.readBigUInt64LE(4), 4n);
  assert.strictEqual(err.subarray(12).toString(), 'nope');
});
