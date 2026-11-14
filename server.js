'use strict';
/**
 * Local dev server for the Wallet Guard agent (Node 22+, no framework).
 *
 *  POST /agent   — the agent endpoint (same handler as api/agent.js).
 *  GET  /        — health + protocol info (unsigned, for local checks).
 *
 * Env (see .env.example):
 *  PORT, AGENT_GAMES_HMAC_SECRET, ALLOW_UNSIGNED, BSC_RPC_URL, ...
 */
const http = require('node:http');
const { createHandler } = require('./lib/handler');

const PORT = Number(process.env.PORT || 3000);
const { handle } = createHandler();

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      const body = JSON.stringify({ ok: true, service: 'wallet-guard', protocolVersion: 'v1', endpoint: '/agent' });
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(body);
      return;
    }
    if (req.method === 'POST' && url.pathname === '/agent') {
      const rawBody = await readRawBody(req);
      const headers = {};
      for (const [k, v] of Object.entries(req.headers || {})) headers[String(k).toLowerCase()] = v;
      const out = await handle(rawBody, headers);
      res.statusCode = out.status;
      for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
      res.end(out.body);
      return;
    }
    res.statusCode = 404;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'not found' }));
  } catch (err) {
    res.statusCode = 500;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'internal error', detail: String(err && err.message ? err.message : err) }));
  }
});

server.listen(PORT, () => {
  console.log(`wallet-guard listening on http://localhost:${PORT} (POST /agent)`);
  console.log(`HMAC secret configured: ${Boolean(process.env.AGENT_GAMES_HMAC_SECRET)}; ALLOW_UNSIGNED=${process.env.ALLOW_UNSIGNED || 'false'}`);
});
