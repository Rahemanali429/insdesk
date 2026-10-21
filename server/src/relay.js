'use strict';

const net = require('net');
const { encodeFrame, FrameReader } = require('./frame');
const { parseHello, reply } = require('./rendezvous');

/**
 * Create the TCP relay.
 *
 * A host registers a numeric device ID; a controller asks to reach that ID. The
 * relay pairs them, sends `PeerConnected` to both, then splices the two sockets
 * and copies raw bytes between them. Everything after pairing is the hosts'
 * end-to-end Noise session, which the relay cannot read — it holds no keys and
 * is not trusted for confidentiality or integrity.
 */
function createRelay({ logger = console } = {}) {
  /** @type {Map<string, {socket: net.Socket, id: bigint, leftover: Buffer}>} */
  const waiting = new Map();

  const server = net.createServer((socket) => handleConnection(socket));

  function handleConnection(socket) {
    socket.setNoDelay(true);
    const reader = new FrameReader();
    let settled = false;

    const onData = (chunk) => {
      reader.push(chunk);
      if (settled) return;
      let frame;
      try {
        frame = reader.next();
      } catch (err) {
        logger.warn(`[relay] framing error: ${err.message}`);
        socket.destroy();
        return;
      }
      if (!frame) return; // wait for the rest of the hello

      let hello;
      try {
        hello = parseHello(frame);
      } catch (err) {
        logger.warn(`[relay] bad rendezvous hello: ${err.message}`);
        socket.destroy();
        return;
      }

      settled = true;
      socket.removeListener('data', onData);
      const leftover = reader.leftover();

      if (hello.type === 'RegisterHost') {
        registerHost(socket, hello.id, leftover);
      } else {
        connectToHost(socket, hello.id, leftover);
      }
    };

    socket.on('data', onData);
    socket.on('error', (err) => logger.debug?.(`[relay] socket error: ${err.message}`));
  }

  function registerHost(socket, id, leftover) {
    const key = id.toString();
    if (waiting.has(key)) {
      socket.write(encodeFrame(reply.idInUse(id)));
      socket.end();
      logger.warn(`[relay] id ${key} already registered; rejecting duplicate`);
      return;
    }
    const entry = { socket, id, leftover };
    waiting.set(key, entry);
    socket.write(encodeFrame(reply.registered(id)));
    logger.info(`[relay] host ${key} registered; waiting for a controller`);

    // Clean up if the host disconnects before anyone connects.
    socket.once('close', () => {
      if (waiting.get(key) === entry) {
        waiting.delete(key);
        logger.info(`[relay] host ${key} left before pairing`);
      }
    });
  }

  function connectToHost(controller, id, controllerLeftover) {
    const key = id.toString();
    const entry = waiting.get(key);
    if (!entry) {
      controller.write(encodeFrame(reply.hostUnavailable(id)));
      controller.end();
      logger.info(`[relay] controller asked for offline host ${key}`);
      return;
    }
    waiting.delete(key);
    const host = entry.socket;
    host.removeAllListeners('close'); // drop the pre-pairing cleanup handler

    // Tell both peers the channel is up.
    host.write(encodeFrame(reply.peerConnected()));
    controller.write(encodeFrame(reply.peerConnected()));

    // Forward any bytes that were already buffered past the hello frame, then
    // splice the raw streams in both directions.
    if (entry.leftover && entry.leftover.length) controller.write(entry.leftover);
    if (controllerLeftover && controllerLeftover.length) host.write(controllerLeftover);

    host.pipe(controller);
    controller.pipe(host);

    const teardown = (why) => {
      host.destroy();
      controller.destroy();
      logger.info(`[relay] session ${key} ended${why ? ` (${why})` : ''}`);
    };
    host.on('error', () => teardown('host error'));
    controller.on('error', () => teardown('controller error'));
    host.on('close', () => teardown());
    controller.on('close', () => teardown());

    logger.info(`[relay] host ${key} paired with controller; relaying`);
  }

  return {
    server,
    listen: (port, host, cb) => server.listen(port, host, cb),
    close: (cb) => server.close(cb),
    stats: () => ({ hostsWaiting: waiting.size, ids: [...waiting.keys()] }),
  };
}

module.exports = { createRelay };
