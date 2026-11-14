# Wallet Guard — zkVerify Agent Games, Wildcard Track

A read-only wallet & transaction security guard for BNB Smart Chain.
It screens a wallet's token approvals and a token's risk, and returns a
plain-language risk report — before the user signs anything.

## Use case: who it helps, what it does

Approval phishing and honeypot tokens are the two most common ways BSC
users lose funds: a dApp asks for an unlimited token approval once, and
months later a malicious or compromised spender drains the balance; or a
user buys a token whose contract blocks sells. Both are invisible in a
normal wallet UI.

Wallet Guard is the check a user (or their agent) runs first:

- **Give it a wallet** → it audits every token approval that wallet
  granted recently, resolves the *current* allowance for each, and flags
  unlimited approvals — especially to EOAs (the classic drainer pattern)
  and to spenders on a curated high-risk list — each with a
  plain-language explanation and a recommended action (e.g. "revoke this
  approval").
- **Give it a token** → it reads the token's metadata, checks PancakeSwap
  V2 liquidity (pair + reserves), and statically simulates a small buy
  and sell through the router. A sell that reverts or returns ~0 is
  flagged as a possible honeypot.
- **Give it both** → one combined report with a 0–100 risk score.

The agent only ever *advises*. Its decision is always `REPORT`; it never
approves a transaction, never signs anything on-chain, and never moves
funds. It is read-only by construction: no private keys exist anywhere in
this service.

## How it works

```
POST /agent  (HMAC-signed JSON envelope)
  → verify x-agent-games-signature over the RAW body (401 on mismatch)
  → preflight? return {ok:true, protocolVersion:"v1"} (signed)
  → guard task? run the assessment under a 50s internal deadline
  → return a signed REPORT: {decision, reason_code, assessment, proof, public_signals}
```

- **Endpoint contract:** Node 22, Vercel-serverless-ready (`api/agent.js`;
  `vercel.json` rewrites `/agent` → `/api/agent`). `server.js` is the same
  handler on a plain `node:http` server for local dev. Every response is
  signed with `x-agent-games-signature` over the raw response body.
- **Chain access:** ethers v6 against public BSC RPC (chainId 56,
  default `https://bsc-dataseed.binance.org/`, overridable via
  `BSC_RPC_URL`, comma-separated for fallback). `eth_getLogs` is chunked
  at ≤ 50,000 blocks per call (public-node limit); the approvals scan
  covers the last ~500,000 blocks (~17 days).
- **Scoring rubric (0–100, higher = riskier), all weights in
  `lib/guard.js` (`SCORE`):**

  | Signal | Points |
  |---|---|
  | Unlimited approval to an EOA | 75 |
  | Approval to a curated high-risk spender | 75 |
  | Sell simulation reverts / returns ~0 (possible honeypot) | 60 |
  | No PancakeSwap V2 pair | 25 |
  | Unlimited approval to an unknown contract (each, cap 60) | 20 |
  | Very thin liquidity (< 0.5 WBNB in pair) | 15 |
  | Buy simulation fails / token metadata unreadable | 10 each |
  | Unlimited approval to a well-known protocol (each, cap 10) | 5 |
  | Limited approval (each, cap 10) | 2 |

  Bands: 0–19 `RISK_CLEAR`, 20–49 `RISK_LOW`, 50–74 `RISK_MEDIUM`,
  75–100 `RISK_HIGH`. If nothing could be checked at all, the report is
  `CHECK_FAILED` (unknown, never a false "clear").

## Key decisions

- **Fail closed, per check.** Every RPC call has a timeout and every
  check degrades independently to `"unknown"` instead of failing the
  whole assessment. A timed-out assessment returns a `CHECK_FAILED`
  report inside the 60s platform deadline — never a crash, never a hang.
- **No invented blocklists.** The curated high-risk spender list is
  intentionally empty by default: hardcoding addresses we cannot verify
  would create false positives. Operators extend it via
  `HIGH_RISK_SPENDERS` (comma-separated) from threat intel (Revoke.cash,
  ScamSniffer). Structural heuristics cover the drainer pattern without
  a blocklist: unlimited + EOA = high; unlimited + unknown contract =
  medium; unlimited + well-known protocol (PancakeSwap V2 router,
  Permit2) = info.
- **No holder-concentration check.** It is too expensive for the 60s
  budget (it needs the full holder set). It is listed as a limitation in
  every assessment instead of being faked.
- **HMAC first, parse second.** The signature is verified over the raw
  bytes before any JSON parsing, exactly as the platform requires.
  Strict by default: without a configured secret, requests are rejected
  unless the operator explicitly sets `ALLOW_UNSIGNED=true` (local dev
  only, never production).
- **No ZK proof in the response.** This agent's output is an advisory
  report, not a payment decision, so `proof` and `public_signals` are
  `null` by design. (The Wildcard track is panel-judged; the
  Proof Gatekeeper / Steal the VFY circuits do not apply to an advisory
  agent, and generating a Groth16 proof of a heuristic risk score would
  prove nothing about the underlying chain data.)

## Limitations

- Holder concentration is not checked (see above).
- The approvals scan covers the last ~500k blocks only; older approvals
  fall outside the window (configurable via `GUARD_SCAN_BLOCKS`).
- The high-risk spender list is curated and small; an unknown spender is
  not proven safe.
- Swap simulation uses static `eth_call`s: fee-on-transfer tokens can
  revert a simulation without being honeypots — the report says
  "possible honeypot" and recommends verifying on a block explorer.
- A passing screen is evidence, not a guarantee: approvals can be abused
  later and contracts can change.

## Run it locally

```bash
npm install
npm test            # unit + replay harness (no network needed)
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET for signed mode
npm start           # http://localhost:3000, POST /agent
```

## Demo (signed; replace SECRET, or run with ALLOW_UNSIGNED=true and drop the headers)

Preflight:

```bash
SECRET=your-dev-secret
BODY='{"type":"agent-games.preflight.v1","task_id":"preflight-001"}'
SIG=$(node -e "const c=require('node:crypto');process.stdout.write(c.createHmac('sha256',process.env.SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
curl -s -X POST http://localhost:3000/agent \
  -H 'content-type: application/json' \
  -H "x-agent-games-signature: $SIG" \
  -d "$BODY"
# -> {"ok":true,"protocolVersion":"v1"} + x-agent-games-signature header
```

Wallet check (approvals audit — this wallet is the demo subject):

```bash
SECRET=your-dev-secret
BODY='{"type":"agent-games.guard.v1","task_id":"demo-wallet-001","input":{"wallet":"0x5bf45EfF7126D4b31707eab853702c9A081D2bF6"}}'
SIG=$(node -e "const c=require('node:crypto');process.stdout.write(c.createHmac('sha256',process.env.SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
curl -s -X POST http://localhost:3000/agent \
  -H 'content-type: application/json' \
  -H "x-agent-games-signature: $SIG" \
  -d "$BODY"
```

Token check (CAKE on BSC):

```bash
SECRET=your-dev-secret
BODY='{"type":"agent-games.guard.v1","task_id":"demo-token-001","input":{"token":"0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"}}'
SIG=$(node -e "const c=require('node:crypto');process.stdout.write(c.createHmac('sha256',process.env.SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
curl -s -X POST http://localhost:3000/agent \
  -H 'content-type: application/json' \
  -H "x-agent-games-signature: $SIG" \
  -d "$BODY"
```

Verify a response signature (any response body + its header):

```bash
node -e "const h=require('./lib/hmac');console.log(h.verify(process.env.SECRET, process.argv[1], process.argv[2]))" '<raw-body>' '<signature>'
```

## Deploy (Vercel)

```bash
vercel deploy   # then set AGENT_GAMES_HMAC_SECRET to the platform secret
```

The public endpoint is `POST https://<your-deployment>/agent`
(`vercel.json` rewrites `/agent` to the `api/agent.js` function).
Register that URL in the Agent Games dashboard, then run preflight and
practice tasks before going live.

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | — | Required in prod; requests rejected without it (unless `ALLOW_UNSIGNED=true`). |
| `ALLOW_UNSIGNED` | `false` | Dev only: accept unsigned requests when no secret is set. |
| `BSC_RPC_URL` | `https://bsc-dataseed.binance.org/` | Comma-separated list = fallback order. |
| `BSC_RPC_TIMEOUT_MS` | `8000` | Per-call RPC timeout. |
| `GUARD_SCAN_BLOCKS` | `500000` | Approval-scan window in blocks. |
| `GUARD_MAX_PAIRS` | `100` | Max (token, spender) pairs resolved per wallet. |
| `GUARD_DEADLINE_MS` | `50000` | Internal assessment deadline (platform limit is 60s). |
| `HIGH_RISK_SPENDERS` | — | Extra high-risk spender addresses, comma-separated. |
| `PORT` | `3000` | Local dev server port. |

## Layout

```
api/agent.js        Vercel serverless entry (POST /agent)
server.js           Local dev server (same handler, plain node:http)
lib/handler.js      Request handler: HMAC verify -> preflight -> guard -> signed REPORT
lib/hmac.js         HMAC-SHA256 sign/verify (timing-safe)
lib/rpc.js          Read-only BSC client (ethers v6, fallback RPCs, timeouts)
lib/guard.js        Assessment logic + transparent scoring rubric
tests/              node:test suites (hmac, scoring, replay harness — no network)
tests/fixtures/     Sample envelopes (preflight, wallet check, token check)
```

## Security

- No private keys, no signing, no transactions — the service is
  read-only by construction.
- Secrets live in env vars only (`.env.example` documents them;
  `.gitignore` covers `.env`). Never paste a secret into an AI tool.
- HMAC is verified over raw bytes before parsing; responses are signed
  over raw bytes. Use the platform-generated secret from Rotate Secret,
  never a local placeholder, in production.
