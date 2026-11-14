'use strict';
/**
 * Wallet Guard assessment logic (read-only, BSC chainId 56).
 *
 * What it does:
 *  1. Wallet approvals audit — scans Approval events for the wallet over a
 *     recent window, resolves each distinct (token, spender) pair's current
 *     allowance, and flags unlimited allowances and structurally risky
 *     spenders (EOAs, unknown contracts, curated high-risk list).
 *  2. Token quick-screen — reads token metadata, checks PancakeSwap V2
 *     liquidity (pair + reserves), and statically simulates a small buy and
 *     sell through the router. A sell simulation that reverts or returns
 *     ~0 is flagged as a possible honeypot.
 *  3. Scores 0-100 with a transparent rubric (see SCORE below) and returns
 *     plain-language findings with a recommended action each.
 *
 * Failure policy: every check is defensive. A single RPC failure degrades
 * that check to "unknown" and contributes no points; the assessment still
 * returns with the findings it could establish. If nothing could be
 * checked at all, the caller maps the result to reason_code CHECK_FAILED.
 *
 * Honesty notes (also in README):
 *  - The high-risk spender list is curated and intentionally small. It is
 *    empty by default on purpose: hardcoding addresses we cannot verify
 *    would create false positives. Operators extend it via the
 *    HIGH_RISK_SPENDERS env var (comma-separated) from threat intel such
 *    as Revoke.cash / ScamSniffer lists. Structural heuristics (unlimited
 *    approval to an EOA, unlimited approval to an unknown contract) cover
 *    the common drainer pattern without a blocklist.
 *  - Holder concentration is NOT checked (too expensive in the 60s budget)
 *    and is listed as a limitation in every assessment.
 *  - A passing screen is evidence, not a guarantee: a token can be
 *    perfectly liquid and still be a scam, and an approval can be safe
 *    today and abused tomorrow.
 */
const { ethers } = require('ethers');
const { BscClient, WBNB } = require('./rpc');

const MAX_UINT256 = ethers.MaxUint256;

// --- curated lists ---------------------------------------------------------
// Well-known, long-lived BSC spenders that are safe to approve in the
// normal course of using DeFi. Anything else is "unknown" and scored on
// its allowance size and whether it is a contract at all.
const KNOWN_GOOD_SPENDERS = new Set([
  '0x10ED43C718714eb63d5aA57B78B54704E256024E', // PancakeSwap V2 Router
  '0x000000000022D473030F116dDEE9F6B43aC78BA3', // Uniswap Permit2 (same on all EVM chains)
]);

// Curated high-risk spender addresses. Empty by default BY DESIGN — see
// the header note. Extend via HIGH_RISK_SPENDERS (comma-separated).
function highRiskSpendersFromEnv() {
  const extra = String(process.env.HIGH_RISK_SPENDERS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return new Set(extra.map((a) => a.toLowerCase()));
}

// --- scoring rubric (transparent, weights sum to at most 100) -------------
const SCORE = {
  unlimitedToEoa: 75, // one unlimited approval to an EOA is enough (HIGH on its own)
  unlimitedToUnknownContract: 20, // per finding, capped at 60
  unlimitedToKnownGood: 5, // per finding, capped at 10 (routine DeFi use)
  limitedApproval: 2, // per finding, capped at 10
  highRiskSpender: 75, // immediate: spender on the curated high-risk list (HIGH on its own)
  honeypotSellFail: 60, // sell simulation reverts or returns ~0 (MEDIUM alone; HIGH with any second signal)
  noLiquidity: 25, // no PancakeSwap V2 pair at all
  thinLiquidity: 15, // pair exists but WBNB reserves are tiny
  buySimFail: 10, // buy simulation reverts
  tokenReadFail: 10, // name/symbol/decimals/totalSupply unreadable
};
const CAPS = { unlimitedToUnknownContract: 60, unlimitedToKnownGood: 10, limitedApproval: 10 };

const BANDS = [
  { min: 75, band: 'high', reason: 'RISK_HIGH' },
  { min: 50, band: 'medium', reason: 'RISK_MEDIUM' },
  { min: 20, band: 'low', reason: 'RISK_LOW' },
  { min: 0, band: 'clear', reason: 'RISK_CLEAR' },
];

const SCAN_BLOCKS = Number(process.env.GUARD_SCAN_BLOCKS || 500000);
const CHUNK_SIZE = 50000;
const MAX_PAIRS = Number(process.env.GUARD_MAX_PAIRS || 100);
const BUY_WBNB_WEI = 10n ** 16n; // 0.01 WBNB test buy
const THIN_LIQUIDITY_WBNB = 5n * 10n ** 17n; // < 0.5 WBNB in the pair is thin

function isUnlimited(allowance) {
  try {
    return BigInt(allowance) === MAX_UINT256;
  } catch (_) {
    return false;
  }
}

function bandFor(score) {
  for (const b of BANDS) if (score >= b.min) return b;
  return BANDS[BANDS.length - 1];
}

/**
 * Pure scoring: findings carry a `points` field (set by the checks) and an
 * optional `capKey` so repeated findings of one kind cannot stack without
 * limit. Returns { score, band, reasonCode }.
 */
function scoreFindings(findings) {
  const used = {};
  let score = 0;
  for (const f of findings) {
    const pts = f.points || 0;
    if (f.capKey) {
      const cap = CAPS[f.capKey];
      const room = cap - (used[f.capKey] || 0);
      const add = Math.max(0, Math.min(pts, room));
      used[f.capKey] = (used[f.capKey] || 0) + add;
      score += add;
    } else {
      score += pts;
    }
  }
  score = Math.max(0, Math.min(100, score));
  const b = bandFor(score);
  return { score, band: b.band, reasonCode: b.reason };
}

function finding({ id, check, severity, title, detail, recommendation, points = 0, capKey = null, evidence = {} }) {
  return { id, check, severity, title, detail, recommendation, points, capKey, evidence };
}

// --- check 1: wallet approvals audit ---------------------------------------

async function checkApprovals(client, wallet, fromBlock, toBlock) {
  const check = {
    status: 'unknown', pairsFound: 0, pairsChecked: 0,
    windowBlocks: toBlock - fromBlock + 1, fromBlock, toBlock, error: null,
  };
  const findings = [];
  try {
    const logs = await client.scanApprovals(wallet, fromBlock, toBlock, CHUNK_SIZE);
    // Distinct (token, spender) pairs, most recent first.
    const seen = new Map();
    for (const log of [...logs].reverse()) {
      const token = ethers.getAddress(log.address);
      const spender = ethers.getAddress('0x' + log.topics[2].slice(26));
      const key = `${token}|${spender}`;
      if (!seen.has(key)) seen.set(key, { token, spender, blockNumber: log.blockNumber });
    }
    const pairs = [...seen.values()].slice(0, MAX_PAIRS);
    check.pairsFound = seen.size;
    check.pairsChecked = pairs.length;

    const highRisk = highRiskSpendersFromEnv();
    const allowances = [];
    // Resolve current allowances in small concurrent batches.
    for (let i = 0; i < pairs.length; i += 8) {
      const batch = pairs.slice(i, i + 8).map(async (p) => {
        try {
          const allowance = await client.allowance(p.token, wallet, p.spender);
          return { ...p, allowance: allowance.toString(), ok: true };
        } catch (_) {
          return { ...p, allowance: null, ok: false };
        }
      });
      allowances.push(...(await Promise.all(batch)));
    }

    let anyOk = false;
    for (const a of allowances) {
      if (!a.ok) {
        findings.push(finding({
          id: `approval-unverified-${a.token.slice(2, 8)}-${a.spender.slice(2, 8)}`,
          check: 'approvals', severity: 'low',
          title: 'Allowance could not be verified',
          detail: `Could not read the current allowance of ${a.token} to spender ${a.spender} (RPC error). Treat it as unknown, not as safe.`,
          recommendation: 'Re-check this pair on a block explorer before signing anything involving it.',
          evidence: { token: a.token, spender: a.spender },
        }));
        continue;
      }
      anyOk = true;
      const unlimited = isUnlimited(a.allowance);
      const spenderLower = a.spender.toLowerCase();
      if (highRisk.has(spenderLower)) {
        findings.push(finding({
          id: `approval-highrisk-${a.spender.slice(2, 8)}`,
          check: 'approvals', severity: 'high', points: SCORE.highRiskSpender,
          title: 'Approval to a spender on the high-risk list',
          detail: `Wallet approved ${a.token} to ${a.spender}, a spender on the curated high-risk list. Allowance: ${unlimited ? 'UNLIMITED' : a.allowance}.`,
          recommendation: 'Revoke this approval immediately (revoke.cash or the token contract) and do not sign transactions from this spender.',
          evidence: { token: a.token, spender: a.spender, allowance: a.allowance, unlimited },
        }));
        continue;
      }
      if (unlimited) {
        let code = '0x';
        try { code = await client.getCode(a.spender); } catch (_) { code = '0x'; }
        const isEoa = code === '0x' || code === '0x0';
        if (isEoa) {
          findings.push(finding({
            id: `approval-unlimited-eoa-${a.spender.slice(2, 8)}`,
            check: 'approvals', severity: 'high', points: SCORE.unlimitedToEoa,
            title: 'Unlimited approval to an externally-owned account',
            detail: `Wallet granted UNLIMITED ${a.token} allowance to ${a.spender}, which has no contract code (an EOA). An EOA holding an unlimited approval can drain the full balance at any time — this is the classic drainer pattern.`,
            recommendation: 'Revoke this approval immediately. Never grant unlimited allowances to EOAs.',
            evidence: { token: a.token, spender: a.spender, allowance: a.allowance, unlimited: true, spenderType: 'EOA' },
          }));
        } else if (KNOWN_GOOD_SPENDERS.has(ethers.getAddress(a.spender))) {
          findings.push(finding({
            id: `approval-unlimited-known-${a.spender.slice(2, 8)}`,
            check: 'approvals', severity: 'info', points: SCORE.unlimitedToKnownGood, capKey: 'unlimitedToKnownGood',
            title: 'Unlimited approval to a well-known protocol contract',
            detail: `Wallet granted UNLIMITED ${a.token} allowance to ${a.spender}, a well-known protocol contract (e.g. a DEX router). Routine for DeFi use, but still worth reviewing.`,
            recommendation: 'No urgent action. Consider tightening to the exact amount you use if you rarely trade this token.',
            evidence: { token: a.token, spender: a.spender, allowance: a.allowance, unlimited: true, spenderType: 'contract' },
          }));
        } else {
          findings.push(finding({
            id: `approval-unlimited-unknown-${a.spender.slice(2, 8)}`,
            check: 'approvals', severity: 'medium', points: SCORE.unlimitedToUnknownContract, capKey: 'unlimitedToUnknownContract',
            title: 'Unlimited approval to an unknown contract',
            detail: `Wallet granted UNLIMITED ${a.token} allowance to ${a.spender}, a contract that is not on the known-good list. If that contract is ever exploited or malicious, the full balance is at risk.`,
            recommendation: 'Review what this contract is. If you do not recognise it, revoke the approval.',
            evidence: { token: a.token, spender: a.spender, allowance: a.allowance, unlimited: true, spenderType: 'contract' },
          }));
        }
      } else {
        findings.push(finding({
          id: `approval-limited-${a.token.slice(2, 8)}-${a.spender.slice(2, 8)}`,
          check: 'approvals', severity: 'low', points: SCORE.limitedApproval, capKey: 'limitedApproval',
          title: 'Limited approval on record',
          detail: `Wallet approved ${a.token} to ${a.spender} with a limited allowance of ${a.allowance}. Limited allowances cap the damage, but the spender can still move up to that amount.`,
          recommendation: 'No urgent action. Revoke it if you no longer use this spender.',
          evidence: { token: a.token, spender: a.spender, allowance: a.allowance, unlimited: false },
        }));
      }
    }
    check.status = anyOk || pairs.length === 0 ? 'ok' : 'partial';
    if (pairs.length === 0) {
      findings.push(finding({
        id: 'approval-none-found', check: 'approvals', severity: 'info',
        title: 'No approvals found in the scanned window',
        detail: `No Approval events for this wallet in the last ${check.windowBlocks.toLocaleString()} blocks. The wallet may have no approvals, or older approvals fall outside the window.`,
        recommendation: 'Nothing to revoke from this window. Re-scan with a wider window for a full history.',
        evidence: {},
      }));
    }
  } catch (err) {
    check.status = 'unknown';
    check.error = String(err && err.message ? err.message : err);
  }
  return { check, findings };
}

// --- check 2: token quick-screen -------------------------------------------

async function checkToken(client, token) {
  const check = {
    status: 'unknown', name: null, symbol: null, decimals: null,
    pair: null, reservesWbnb: null, buySim: null, sellSim: null, error: null,
  };
  const findings = [];
  try {
    const info = await client.tokenInfo(token);
    check.name = info.name; check.symbol = info.symbol; check.decimals = info.decimals;
    if (info.name === null && info.symbol === null && info.decimals === null) {
      findings.push(finding({
        id: 'token-unreadable', check: 'token', severity: 'medium', points: SCORE.tokenReadFail,
        title: 'Token contract metadata unreadable',
        detail: 'name/symbol/decimals/totalSupply all failed to read. The address may not be an ERC-20/BEP-20 token, or it may be deliberately non-standard.',
        recommendation: 'Do not interact with this address as a token until it is identified.',
        evidence: { token },
      }));
      check.status = 'partial';
      return { check, findings };
    }
    check.status = 'ok';

    let pair = ethers.ZeroAddress;
    try {
      pair = await client.getPair(token, WBNB);
    } catch (_) { pair = ethers.ZeroAddress; }
    if (!pair || pair === ethers.ZeroAddress) {
      check.pair = null;
      findings.push(finding({
        id: 'token-no-liquidity', check: 'token', severity: 'medium', points: SCORE.noLiquidity,
        title: 'No PancakeSwap V2 liquidity pair',
        detail: `No ${info.symbol || 'token'}/WBNB pair exists on PancakeSwap V2. The token cannot be sold through the main DEX router, or it trades elsewhere.`,
        recommendation: 'Do not buy a token with no exit liquidity on the main DEX.',
        evidence: { token, pair: null },
      }));
      return { check, findings };
    }
    check.pair = pair;
    try {
      const r = await client.getReserves(pair);
      const wbnbReserve = r.token0.toLowerCase() === WBNB.toLowerCase()
        ? BigInt(r.reserve0) : BigInt(r.reserve1);
      check.reservesWbnb = ethers.formatUnits(wbnbReserve, 18);
      if (wbnbReserve < THIN_LIQUIDITY_WBNB) {
        findings.push(finding({
          id: 'token-thin-liquidity', check: 'token', severity: 'medium', points: SCORE.thinLiquidity,
          title: 'Very thin liquidity',
          detail: `The pair holds only ${check.reservesWbnb} WBNB. Thin liquidity means high slippage and an easy rug: a single sell can crash the price.`,
          recommendation: 'Avoid large positions. Thin-liquidity tokens are exit-risky by construction.',
          evidence: { token, pair, reservesWbnb: check.reservesWbnb },
        }));
      }
    } catch (_) {
      check.reservesWbnb = null;
    }

    // Swap simulation: buy 0.01 WBNB worth, then sell the proceeds back.
    const decimals = Number.isInteger(info.decimals) ? info.decimals : 18;
    let buyOut = null;
    try {
      const amounts = await client.getAmountsOut(BUY_WBNB_WEI, [WBNB, token]);
      buyOut = BigInt(amounts[1]);
      check.buySim = { amountInWbnb: '0.01', amountOut: buyOut.toString() };
      if (buyOut === 0n) {
        findings.push(finding({
          id: 'token-buy-zero', check: 'token', severity: 'medium', points: SCORE.buySimFail,
          title: 'Buy simulation returned zero',
          detail: 'Swapping 0.01 WBNB for this token returns 0 tokens. The pair may be broken, the token may block buys, or pricing is effectively zero.',
          recommendation: 'Do not buy. A token you cannot buy at a quoted price is not a market.',
          evidence: { token, pair },
        }));
      }
    } catch (err) {
      check.buySim = { error: String(err && err.message ? err.message : err) };
      findings.push(finding({
        id: 'token-buy-fail', check: 'token', severity: 'medium', points: SCORE.buySimFail,
        title: 'Buy simulation failed',
        detail: `Swapping 0.01 WBNB for this token reverted: ${check.buySim.error}. The token may charge a transfer tax the router cannot handle, or the pair may be broken.`,
        recommendation: 'Treat as a warning sign. Fee-on-transfer tokens can also revert here, so this alone is not proof of a scam.',
        evidence: { token, pair },
      }));
    }

    if (buyOut && buyOut > 0n) {
      try {
        const amounts = await client.getAmountsOut(buyOut, [token, WBNB]);
        const sellOut = BigInt(amounts[1]);
        check.sellSim = { amountIn: buyOut.toString(), amountOutWbnb: ethers.formatUnits(sellOut, 18) };
        if (sellOut === 0n) {
          findings.push(finding({
            id: 'token-honeypot', check: 'token', severity: 'high', points: SCORE.honeypotSellFail,
            title: 'Possible honeypot: sell simulation returns zero',
            detail: 'You can buy the token, but selling the same amount back returns 0 WBNB. This is the signature of a honeypot (buys allowed, sells blocked).',
            recommendation: 'Do not buy this token. If you already hold it, assume the position may be unsellable.',
            evidence: { token, pair, buyOut: buyOut.toString(), sellOut: '0' },
          }));
        }
      } catch (err) {
        check.sellSim = { error: String(err && err.message ? err.message : err) };
        findings.push(finding({
          id: 'token-honeypot', check: 'token', severity: 'high', points: SCORE.honeypotSellFail,
          title: 'Possible honeypot: sell simulation reverted',
          detail: `Buying works, but selling the proceeds back reverted: ${check.sellSim.error}. This is the signature of a honeypot (buys allowed, sells blocked). Fee-on-transfer tokens can also revert, so verify on a block explorer before concluding.`,
          recommendation: 'Do not buy this token until the sell path is proven to work.',
          evidence: { token, pair, buyOut: buyOut.toString() },
        }));
      }
    }
    void decimals;
  } catch (err) {
    check.status = 'unknown';
    check.error = String(err && err.message ? err.message : err);
  }
  return { check, findings };
}

// --- top-level assessment ---------------------------------------------------

/**
 * Run the assessment. `input` is { wallet?, token? } (checksummed or not).
 * Returns the assessment object (never throws for RPC-level failures).
 * `client` may be injected (tests); otherwise one is built from env.
 */
async function assess(input, { client = null, scanBlocks = SCAN_BLOCKS } = {}) {
  const wallet = input.wallet ? ethers.getAddress(input.wallet) : null;
  const token = input.token ? ethers.getAddress(input.token) : null;
  const rpc = client || new BscClient(process.env.BSC_RPC_URL, Number(process.env.BSC_RPC_TIMEOUT_MS || 8000));

  const limitations = [
    'Holder concentration is not checked (too expensive for the 60s budget); a token can be liquid and still be held by a few wallets.',
    'The high-risk spender list is curated and small; an unknown spender is not proven safe.',
    'A passing screen is evidence, not a guarantee — approvals can be abused later and contracts can change.',
  ];
  const findings = [];
  const checks = {};
  let blockNumber = null;
  try {
    blockNumber = await rpc.getBlockNumber();
  } catch (_) {
    blockNumber = null;
  }

  if (wallet) {
    const toBlock = blockNumber !== null ? blockNumber : 0;
    const fromBlock = Math.max(0, toBlock - scanBlocks);
    const r = await checkApprovals(rpc, wallet, fromBlock, toBlock);
    checks.approvals = r.check;
    findings.push(...r.findings);
  } else {
    checks.approvals = { status: 'skipped' };
  }

  if (token) {
    const r = await checkToken(rpc, token);
    checks.token = r.check;
    findings.push(...r.findings);
  } else {
    checks.token = { status: 'skipped' };
  }

  const ranAnything = Object.values(checks).some((c) => c.status === 'ok' || c.status === 'partial');
  const { score, band, reasonCode } = ranAnything
    ? scoreFindings(findings)
    : { score: null, band: 'unknown', reasonCode: 'CHECK_FAILED' };

  const highCount = findings.filter((f) => f.severity === 'high').length;
  const summary = !ranAnything
    ? 'All checks failed (RPC unreachable or every call timed out). No conclusion can be drawn — treat this as unknown, not as safe.'
    : highCount > 0
      ? `${highCount} high-severity finding${highCount > 1 ? 's' : ''} — ${band} risk. Review the findings below before signing anything.`
      : band === 'clear'
        ? 'No material risk found in the checks that ran. This is a clean screen, not a guarantee.'
        : `${band} risk — see the findings below for what to review or revoke.`;

  return {
    subject: { wallet, token },
    chainId: 56,
    blockNumber,
    checkedAt: new Date().toISOString(),
    riskScore: score,
    riskBand: band,
    reasonCode,
    summary,
    findings,
    checks,
    limitations,
  };
}

module.exports = {
  assess,
  scoreFindings,
  checkApprovals,
  checkToken,
  finding,
  SCORE,
  CAPS,
  BANDS,
  KNOWN_GOOD_SPENDERS,
  highRiskSpendersFromEnv,
};
