'use strict';
/**
 * Vercel serverless entry for the Wallet Guard agent.
 * Served at /api/agent.js natively; vercel.json rewrites /agent -> /api/agent
 * so the public competition endpoint is POST /agent.
 *
 * `bodyParser: false` is required so we can HMAC the exact raw bytes.
 */
const { createHandler } = require('../lib/handler');

const { handle } = createHandler();

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function agent(req, res) {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'method not allowed; POST only' }));
    return;
  }
  const rawBody = await readRawBody(req);
  const headers = {};
  for (const [k, v] of Object.entries(req.headers || {})) headers[String(k).toLowerCase()] = v;
  const out = await handle(rawBody, headers);
  res.statusCode = out.status;
  for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
  res.end(out.body);
}

module.exports = agent;
module.exports.config = { api: { bodyParser: false } };
