'use strict';
/**
 * HMAC-SHA256 helpers for the Agent Games endpoint contract.
 *
 * Rules (from https://agentgames.zkverify.io/build):
 *  - Incoming: verify HMAC-SHA256 over the RAW request body against the
 *    `x-agent-games-signature` header BEFORE parsing JSON.
 *  - Outgoing: every response is signed with `x-agent-games-signature`
 *    over the RAW response body.
 *
 * Signature format: lowercase hex digest. Verification also accepts an
 * optional `sha256=` prefix and mixed-case hex (be liberal in what you
 * accept, strict in what you send).
 */
const crypto = require('node:crypto');

const HEADER = 'x-agent-games-signature';

/** Compute the hex HMAC-SHA256 of a raw body (Buffer or string). */
function sign(secret, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody), 'utf8');
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

/** Normalize a presented signature: strip optional `sha256=` prefix, lowercase. */
function normalizeSignature(sig) {
  if (typeof sig !== 'string') return '';
  let s = sig.trim();
  if (s.toLowerCase().startsWith('sha256=')) s = s.slice('sha256='.length);
  return s.toLowerCase();
}

/**
 * Timing-safe verification. Returns false (never throws) on missing,
 * malformed, or mismatched signatures.
 */
function verify(secret, rawBody, presented) {
  if (!secret || typeof presented !== 'string' || !presented) return false;
  const expected = sign(secret, rawBody);
  const given = normalizeSignature(presented);
  if (!/^[0-9a-f]{64}$/.test(given)) return false;
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(given, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { HEADER, sign, verify, normalizeSignature };
