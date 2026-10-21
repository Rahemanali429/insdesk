'use strict';

const express = require('express');

/**
 * The Express.js control surface for the relay: health and status endpoints.
 *
 * This HTTP API never carries session content (that is end-to-end encrypted on
 * the TCP relay port). It only reports whether the relay is up and which device
 * IDs are currently waiting for a controller — handy for health checks, load
 * balancers and dashboards.
 */
function createHttpApp({ stats }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());

  app.get('/', (_req, res) => {
    res.json({ service: 'insdesk-relay', status: 'ok' });
  });

  app.get('/healthz', (_req, res) => {
    res.type('text/plain').send('ok');
  });

  app.get('/status', (_req, res) => {
    const s = stats();
    res.json({
      service: 'insdesk-relay',
      status: 'ok',
      hostsWaiting: s.hostsWaiting,
      waitingIds: s.ids,
      uptimeSeconds: Math.round(process.uptime()),
    });
  });

  return app;
}

module.exports = { createHttpApp };
