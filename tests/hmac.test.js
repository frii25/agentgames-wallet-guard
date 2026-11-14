'use strict';
/** HMAC sign/verify round-trip and tamper tests (no network). */
const test = require('node:test');
const assert = require('node:assert/strict');
const hmac = require('../lib/hmac');

const SECRET = 'test-secret-please-rotate';
const BODY = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1', task_id: 'x' }), 'utf8');

test('sign produces a 64-char lowercase hex digest', () => {
  const sig = hmac.sign(SECRET, BODY);
  assert.match(sig, /^[0-9a-f]{64}$/);
});

test('verify accepts the signature it produced', () => {
  const sig = hmac.sign(SECRET, BODY);
  assert.equal(hmac.verify(SECRET, BODY, sig), true);
});

test('verify rejects a tampered body', () => {
  const sig = hmac.sign(SECRET, BODY);
  const tampered = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1', task_id: 'y' }), 'utf8');
  assert.equal(hmac.verify(SECRET, tampered, sig), false);
});

test('verify rejects a tampered signature', () => {
  const sig = hmac.sign(SECRET, BODY);
  const bad = sig.slice(0, -1) + (sig.endsWith('0') ? '1' : '0');
  assert.equal(hmac.verify(SECRET, BODY, bad), false);
});

test('verify rejects the wrong secret', () => {
  const sig = hmac.sign(SECRET, BODY);
  assert.equal(hmac.verify('different-secret', BODY, sig), false);
});

test('verify accepts an optional sha256= prefix and mixed case', () => {
  const sig = hmac.sign(SECRET, BODY);
  assert.equal(hmac.verify(SECRET, BODY, `sha256=${sig}`), true);
  assert.equal(hmac.verify(SECRET, BODY, sig.toUpperCase()), true);
});

test('verify never throws and rejects missing/malformed input', () => {
  assert.equal(hmac.verify(SECRET, BODY, ''), false);
  assert.equal(hmac.verify(SECRET, BODY, undefined), false);
  assert.equal(hmac.verify(SECRET, BODY, 'not-hex'), false);
  assert.equal(hmac.verify('', BODY, hmac.sign(SECRET, BODY)), false);
});

test('sign works with a string body as well as a Buffer', () => {
  const s = JSON.stringify({ a: 1 });
  assert.equal(hmac.sign(SECRET, s), hmac.sign(SECRET, Buffer.from(s, 'utf8')));
});
