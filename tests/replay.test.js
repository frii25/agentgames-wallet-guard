'use strict';
/**
 * Replay harness (no network): replays recorded sample envelopes through
 * the real request handler with a deterministic stub assessor, and verifies
 * the endpoint contract end to end:
 *  - HMAC is verified over the raw body before any parsing;
 *  - preflight returns {ok:true, protocolVersion:"v1"} with a valid
 *    response signature;
 *  - a guard task returns a well-formed signed REPORT;
 *  - bad/missing signatures, malformed JSON, unknown types, and invalid
 *    inputs are rejected with signed 4xx responses;
 *  - an assessment that blows the deadline degrades to CHECK_FAILED
 *    instead of hanging.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const hmac = require('../lib/hmac');
const { createHandler } = require('../lib/handler');

const SECRET = 'replay-test-secret';
const FIXTURES = path.join(__dirname, 'fixtures');

function loadFixture(name) {
  return fs.readFileSync(path.join(FIXTURES, name)); // raw bytes, as received
}

function signedBody(raw) {
  return { raw, sig: hmac.sign(SECRET, raw) };
}

/** Canned assessment the stub assessor returns (deterministic, no RPC). */
function cannedAssessment(input) {
  return {
    subject: { wallet: input.wallet || null, token: input.token || null },
    chainId: 56,
    blockNumber: 60000000,
    checkedAt: '2026-11-14T15:00:00.000Z',
    riskScore: 75,
    riskBand: 'high',
    reasonCode: 'RISK_HIGH',
    summary: '1 high-severity finding — high risk.',
    findings: [{
      id: 'approval-unlimited-eoa-test', check: 'approvals', severity: 'high',
      title: 'Unlimited approval to an externally-owned account',
      detail: 'stub finding', recommendation: 'Revoke this approval immediately.',
      points: 75, capKey: null, evidence: {},
    }],
    checks: { approvals: { status: 'ok' }, token: { status: 'skipped' } },
    limitations: ['stub assessor: no live RPC'],
  };
}

function makeHandler(overrides = {}) {
  return createHandler({
    getSecret: () => SECRET,
    allowUnsigned: false,
    assess: async (input) => cannedAssessment(input),
    deadlineMs: 5000,
    ...overrides,
  });
}

test('preflight fixture: signed request -> signed {ok:true, protocolVersion:"v1"}', async () => {
  const { handle } = makeHandler();
  const { raw, sig } = signedBody(loadFixture('preflight.json'));
  const out = await handle(raw, { [hmac.HEADER]: sig });
  assert.equal(out.status, 200);
  assert.deepEqual(JSON.parse(out.body), { ok: true, protocolVersion: 'v1' });
  assert.equal(hmac.verify(SECRET, out.body, out.headers[hmac.HEADER]), true);
});

test('guard wallet fixture: signed request -> signed well-formed REPORT', async () => {
  const { handle } = makeHandler();
  const { raw, sig } = signedBody(loadFixture('guard-wallet.json'));
  const out = await handle(raw, { [hmac.HEADER]: sig });
  assert.equal(out.status, 200);
  const body = JSON.parse(out.body);
  assert.equal(body.decision, 'REPORT');
  assert.equal(body.reason_code, 'RISK_HIGH');
  assert.equal(body.proof, null);
  assert.equal(body.public_signals, null);
  assert.equal(body.assessment.riskScore, 75);
  assert.equal(body.assessment.riskBand, 'high');
  assert.equal(body.assessment.subject.wallet, '0x5bf45EfF7126D4b31707eab853702c9A081D2bF6');
  assert.equal(hmac.verify(SECRET, out.body, out.headers[hmac.HEADER]), true);
});

test('guard token fixture: signed request -> signed REPORT', async () => {
  const { handle } = makeHandler();
  const { raw, sig } = signedBody(loadFixture('guard-token.json'));
  const out = await handle(raw, { [hmac.HEADER]: sig });
  assert.equal(out.status, 200);
  const body = JSON.parse(out.body);
  assert.equal(body.decision, 'REPORT');
  assert.equal(body.assessment.subject.token, '0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82');
  assert.equal(hmac.verify(SECRET, out.body, out.headers[hmac.HEADER]), true);
});

test('bad signature -> 401 with a signed error body', async () => {
  const { handle } = makeHandler();
  const { raw } = signedBody(loadFixture('preflight.json'));
  const out = await handle(raw, { [hmac.HEADER]: '0'.repeat(64) });
  assert.equal(out.status, 401);
  assert.equal(JSON.parse(out.body).error, 'invalid signature');
  assert.equal(hmac.verify(SECRET, out.body, out.headers[hmac.HEADER]), true);
});

test('missing signature -> 401 (strict by default)', async () => {
  const { handle } = makeHandler();
  const out = await handle(loadFixture('preflight.json'), {});
  assert.equal(out.status, 401);
});

test('valid signature but malformed JSON -> 400', async () => {
  const { handle } = makeHandler();
  const raw = Buffer.from('{not json', 'utf8');
  const out = await handle(raw, { [hmac.HEADER]: hmac.sign(SECRET, raw) });
  assert.equal(out.status, 400);
  assert.equal(JSON.parse(out.body).error, 'invalid JSON');
});

test('unknown type -> 400', async () => {
  const { handle } = makeHandler();
  const raw = Buffer.from(JSON.stringify({ type: 'agent-games.nope.v1' }), 'utf8');
  const out = await handle(raw, { [hmac.HEADER]: hmac.sign(SECRET, raw) });
  assert.equal(out.status, 400);
});

test('guard task without wallet or token -> 400', async () => {
  const { handle } = makeHandler();
  const raw = Buffer.from(JSON.stringify({ type: 'agent-games.guard.v1', input: {} }), 'utf8');
  const out = await handle(raw, { [hmac.HEADER]: hmac.sign(SECRET, raw) });
  assert.equal(out.status, 400);
});

test('guard task with an invalid address -> 400', async () => {
  const { handle } = makeHandler();
  const raw = Buffer.from(JSON.stringify({ type: 'agent-games.guard.v1', input: { wallet: '0x123' } }), 'utf8');
  const out = await handle(raw, { [hmac.HEADER]: hmac.sign(SECRET, raw) });
  assert.equal(out.status, 400);
});

test('unsigned requests are accepted only with ALLOW_UNSIGNED (dev flag)', async () => {
  const { handle } = createHandler({
    getSecret: () => '',
    allowUnsigned: true,
    assess: async (input) => cannedAssessment(input),
  });
  const out = await handle(loadFixture('preflight.json'), {});
  assert.equal(out.status, 200);
  assert.equal(out.headers[hmac.HEADER], undefined); // nothing to sign with
});

test('no secret + strict mode -> 401 even for preflight', async () => {
  const { handle } = createHandler({ getSecret: () => '', allowUnsigned: false });
  const out = await handle(loadFixture('preflight.json'), {});
  assert.equal(out.status, 401);
});

test('assessment that exceeds the deadline degrades to CHECK_FAILED', async () => {
  const { handle } = createHandler({
    getSecret: () => SECRET,
    allowUnsigned: false,
    assess: async () => new Promise(() => {}), // never resolves
    deadlineMs: 50,
  });
  const { raw, sig } = signedBody(loadFixture('guard-wallet.json'));
  const out = await handle(raw, { [hmac.HEADER]: sig });
  assert.equal(out.status, 200);
  const body = JSON.parse(out.body);
  assert.equal(body.decision, 'REPORT');
  assert.equal(body.reason_code, 'CHECK_FAILED');
  assert.equal(body.assessment.riskBand, 'unknown');
  assert.equal(hmac.verify(SECRET, out.body, out.headers[hmac.HEADER]), true);
});
