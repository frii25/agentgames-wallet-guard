'use strict';
/**
 * Shared request handler for the Wallet Guard agent endpoint.
 *
 * Used by both `api/agent.js` (Vercel serverless) and `server.js` (local
 * dev). Transport-agnostic: it takes the raw request body + headers and
 * returns { status, headers, body } where `body` is the exact string to send.
 *
 * Flow (per https://agentgames.zkverify.io/build):
 *  1. Authenticate FIRST: HMAC-SHA256 over the raw body vs the
 *     `x-agent-games-signature` header, before parsing JSON. Reject 401 on
 *     mismatch. Strict by default; unsigned requests are only accepted when
 *     the operator explicitly sets ALLOW_UNSIGNED=true (local dev only).
 *  2. Preflight: {"type":"agent-games.preflight.v1",...} ->
 *     {"ok":true,"protocolVersion":"v1"}, signed.
 *  3. Guard task: {"type":"agent-games.guard.v1","task_id":"...","input":
 *     {"wallet":"0x...","token":"0x..."}} -> a signed REPORT. The agent
 *     only advises (decision is always REPORT); it never approves a
 *     transaction and never signs anything on-chain.
 *  4. Every response (including 4xx errors) is signed over its raw body
 *     whenever a secret is configured.
 *  5. 60s hard deadline: the assessment runs under an internal deadline
 *     (default 50s, GUARD_DEADLINE_MS); on timeout or total check failure
 *     it returns a REPORT with reason_code CHECK_FAILED and whatever
 *     partial findings exist — never a crash, never a hang.
 */
const { ethers } = require('ethers');
const hmac = require('./hmac');
const { assess } = require('./guard');

const PREFLIGHT_TYPE = 'agent-games.preflight.v1';
const GUARD_TYPE = 'agent-games.guard.v1';
const PROTOCOL_VERSION = 'v1';
const DEFAULT_DEADLINE_MS = Number(process.env.GUARD_DEADLINE_MS || 50000);

function jsonBody(obj) {
  return JSON.stringify(obj);
}

/** Build a signed (when a secret is configured) response envelope. */
function respond(status, obj, secret) {
  const body = jsonBody(obj);
  const headers = { 'content-type': 'application/json' };
  if (secret) headers[hmac.HEADER] = hmac.sign(secret, body);
  return { status, headers, body };
}

function createHandler(deps = {}) {
  const getSecret = deps.getSecret || (() => process.env.AGENT_GAMES_HMAC_SECRET || '');
  const allowUnsigned = deps.allowUnsigned !== undefined
    ? deps.allowUnsigned
    : process.env.ALLOW_UNSIGNED === 'true';
  const runAssessment = deps.assess || assess;
  const deadlineMs = deps.deadlineMs || DEFAULT_DEADLINE_MS;

  /**
   * @param {Buffer} rawBody - exact raw request bytes (for HMAC).
   * @param {Object} headers - lowercased header map.
   */
  async function handle(rawBody, headers = {}) {
    const secret = getSecret();
    const presented = headers[hmac.HEADER] || headers['X-Agent-Games-Signature'.toLowerCase()] || '';

    // 1. Authenticate before parsing.
    if (secret) {
      if (!hmac.verify(secret, rawBody, presented)) {
        return respond(401, { error: 'invalid signature' }, secret);
      }
    } else if (!allowUnsigned) {
      return respond(401, { error: 'hmac secret not configured; set AGENT_GAMES_HMAC_SECRET or ALLOW_UNSIGNED=true for local dev' }, '');
    }

    // 2. Parse.
    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString('utf8'));
    } catch (_) {
      return respond(400, { error: 'invalid JSON' }, secret);
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      return respond(400, { error: 'request body must be a JSON object' }, secret);
    }

    // 3. Preflight.
    if (envelope.type === PREFLIGHT_TYPE) {
      return respond(200, { ok: true, protocolVersion: PROTOCOL_VERSION }, secret);
    }

    // 4. Guard task.
    if (envelope.type === GUARD_TYPE) {
      const input = envelope.input || {};
      const wallet = input.wallet || null;
      const token = input.token || null;
      if (!wallet && !token) {
        return respond(400, { error: 'input.wallet and/or input.token is required' }, secret);
      }
      for (const [name, addr] of [['wallet', wallet], ['token', token]]) {
        if (addr && !ethers.isAddress(addr)) {
          return respond(400, { error: `input.${name} is not a valid address: ${addr}` }, secret);
        }
      }

      let assessment;
      try {
        assessment = await Promise.race([
          runAssessment({ wallet, token }),
          new Promise((resolve) => setTimeout(() => resolve({
            subject: { wallet, token },
            chainId: 56,
            blockNumber: null,
            checkedAt: new Date().toISOString(),
            riskScore: null,
            riskBand: 'unknown',
            reasonCode: 'CHECK_FAILED',
            summary: 'Assessment timed out before completing. No conclusion can be drawn — treat this as unknown, not as safe.',
            findings: [],
            checks: { approvals: { status: 'unknown' }, token: { status: 'unknown' } },
            limitations: ['Assessment exceeded the internal deadline; results are incomplete.'],
          }), deadlineMs)),
        ]);
      } catch (err) {
        assessment = {
          subject: { wallet, token },
          chainId: 56,
          blockNumber: null,
          checkedAt: new Date().toISOString(),
          riskScore: null,
          riskBand: 'unknown',
          reasonCode: 'CHECK_FAILED',
          summary: `Assessment failed: ${err && err.message ? err.message : String(err)}. No conclusion can be drawn — treat this as unknown, not as safe.`,
          findings: [],
          checks: { approvals: { status: 'unknown' }, token: { status: 'unknown' } },
          limitations: ['Assessment errored before completing; results are incomplete.'],
        };
      }

      return respond(200, {
        decision: 'REPORT',
        reason_code: assessment.reasonCode,
        assessment,
        proof: null,
        public_signals: null,
      }, secret);
    }

    return respond(400, { error: `unknown type: ${String(envelope.type)}` }, secret);
  }

  return { handle, PREFLIGHT_TYPE, GUARD_TYPE, PROTOCOL_VERSION };
}

module.exports = { createHandler, PREFLIGHT_TYPE, GUARD_TYPE, PROTOCOL_VERSION };
