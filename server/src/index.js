#!/usr/bin/env node
'use strict';

// InsDesk server entry point.
//
// Starts two listeners:
//   * a raw TCP relay (default :9510) that pairs hosts and controllers and
//     forwards their opaque end-to-end-encrypted traffic, and
//   * an Express.js HTTP API (default :9520) for health/status.
//
// Configuration via environment variables (or the defaults):
//   INSDESK_BIND         bind address            (default 0.0.0.0)
//   INSDESK_RELAY_PORT   TCP relay port          (default 9510)
//   INSDESK_HTTP_PORT    Express HTTP API port   (default 9520)

const { createRelay } = require('./relay');
const { createHttpApp } = require('./http');

const BIND = process.env.INSDESK_BIND || '0.0.0.0';
const RELAY_PORT = parseInt(process.env.INSDESK_RELAY_PORT || '9510', 10);
const HTTP_PORT = parseInt(process.env.INSDESK_HTTP_PORT || '9520', 10);

const logger = makeLogger();

const relay = createRelay({ logger });
relay.listen(RELAY_PORT, BIND, () => {
  logger.info(`[relay] TCP relay listening on ${BIND}:${RELAY_PORT}`);
});
relay.server.on('error', (err) => {
  logger.error(`[relay] listener error: ${err.message}`);
  process.exit(1);
});

const app = createHttpApp({ stats: relay.stats });
const httpServer = app.listen(HTTP_PORT, BIND, () => {
  logger.info(`[http]  Express API listening on http://${BIND}:${HTTP_PORT}`);
});

function shutdown(signal) {
  logger.info(`received ${signal}, shutting down`);
  relay.close(() => {});
  httpServer.close(() => {});
  // Give the sockets a moment, then exit.
  setTimeout(() => process.exit(0), 200).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

function makeLogger() {
  const ts = () => new Date().toISOString();
  return {
    info: (m) => console.log(`${ts()} INFO  ${m}`),
    warn: (m) => console.warn(`${ts()} WARN  ${m}`),
    error: (m) => console.error(`${ts()} ERROR ${m}`),
    debug: (m) => {
      if (process.env.INSDESK_DEBUG) console.log(`${ts()} DEBUG ${m}`);
    },
  };
}
