'use strict';
/** Pure scoring tests (no network): rubric weights, caps, and bands. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreFindings, SCORE } = require('../lib/guard');

function f(points, capKey) {
  return { points, capKey: capKey || null };
}

test('empty findings score 0 and are CLEAR', () => {
  const r = scoreFindings([]);
  assert.equal(r.score, 0);
  assert.equal(r.band, 'clear');
  assert.equal(r.reasonCode, 'RISK_CLEAR');
});

test('one unlimited approval to an EOA is HIGH on its own', () => {
  const r = scoreFindings([f(SCORE.unlimitedToEoa)]);
  assert.equal(r.score, 75);
  assert.equal(r.band, 'high');
  assert.equal(r.reasonCode, 'RISK_HIGH');
});

test('one spender on the curated high-risk list is HIGH on its own', () => {
  const r = scoreFindings([f(SCORE.highRiskSpender)]);
  assert.equal(r.score, 75);
  assert.equal(r.band, 'high');
});

test('honeypot sell failure alone is MEDIUM; with thin liquidity it is HIGH', () => {
  const r = scoreFindings([f(SCORE.honeypotSellFail)]);
  assert.equal(r.score, 60);
  assert.equal(r.band, 'medium');
  assert.equal(r.reasonCode, 'RISK_MEDIUM');
  const r2 = scoreFindings([f(SCORE.honeypotSellFail), f(SCORE.thinLiquidity)]);
  assert.equal(r2.score, 75);
  assert.equal(r2.band, 'high');
});

test('honeypot plus no liquidity is HIGH', () => {
  const r = scoreFindings([f(SCORE.honeypotSellFail), f(SCORE.noLiquidity)]);
  assert.equal(r.score, 85);
  assert.equal(r.band, 'high');
});

test('no liquidity alone is LOW', () => {
  const r = scoreFindings([f(SCORE.noLiquidity)]);
  assert.equal(r.score, 25);
  assert.equal(r.band, 'low');
  assert.equal(r.reasonCode, 'RISK_LOW');
});

test('repeated limited approvals are capped at 10', () => {
  const many = Array.from({ length: 20 }, () => f(SCORE.limitedApproval, 'limitedApproval'));
  assert.equal(scoreFindings(many).score, 10);
});

test('repeated unlimited unknown-contract approvals are capped at 60', () => {
  const many = Array.from({ length: 5 }, () => f(SCORE.unlimitedToUnknownContract, 'unlimitedToUnknownContract'));
  assert.equal(scoreFindings(many).score, 60);
  assert.equal(scoreFindings(many).band, 'medium');
});

test('score never exceeds 100', () => {
  const many = [
    f(SCORE.unlimitedToEoa), f(SCORE.highRiskSpender), f(SCORE.honeypotSellFail),
    f(SCORE.noLiquidity), f(SCORE.thinLiquidity), f(SCORE.buySimFail), f(SCORE.tokenReadFail),
  ];
  assert.equal(scoreFindings(many).score, 100);
});

test('band edges: 20 LOW, 50 MEDIUM, 75 HIGH', () => {
  assert.equal(scoreFindings([f(20)]).band, 'low');
  assert.equal(scoreFindings([f(50)]).band, 'medium');
  assert.equal(scoreFindings([f(75)]).band, 'high');
  assert.equal(scoreFindings([f(19)]).band, 'clear');
  assert.equal(scoreFindings([f(49)]).band, 'low');
  assert.equal(scoreFindings([f(74)]).band, 'medium');
});
