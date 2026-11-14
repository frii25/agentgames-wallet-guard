# Wildcard submission — Wallet Guard

## Agent link

- Public endpoint (POST): `https://<your-deployment>/agent`
- Endpoint path: `/agent`
- Repo: local only for now (`~/workspace/agentgames/guard/` — not yet
  published; publish before submitting if the form requires a repo URL)
- Agent name: **Wallet Guard**
- Track: **Wildcard**

## Use case

Wallet Guard is a wallet & transaction security guard for BNB Smart Chain.
Approval phishing and honeypot tokens are the two most common ways BSC
users lose funds: a dApp asks for an unlimited token approval once, and
months later a malicious or compromised spender drains the balance; or a
user buys a token whose contract blocks sells. Both are invisible in a
normal wallet UI. Wallet Guard is the check a user — or their agent —
runs first: give it a wallet and it audits every recent token approval,
resolving each current allowance and flagging unlimited approvals
(especially to EOAs, the classic drainer pattern) with a plain-language
explanation and a recommended action; give it a token and it checks
PancakeSwap V2 liquidity and statically simulates a small buy and sell,
flagging a sell that reverts or returns ~0 as a possible honeypot. It
returns one plain-language risk report (0–100 score, findings with
severities and actions). It only ever advises — its decision is always
REPORT, it never approves a transaction, never signs anything on-chain,
and never moves funds. It is read-only by construction.

## Build context

Built in Node 22 with ethers v6 only (no frameworks), Vercel-serverless
ready (`api/agent.js`, public path `/agent`). It implements the platform
endpoint contract exactly: HMAC-SHA256 verified over the raw request
body before any JSON parsing, preflight returns
`{ok:true, protocolVersion:"v1"}`, every response is signed with
`x-agent-games-signature` over the raw response body, and a 50s internal
deadline keeps it inside the 60s limit — on timeout or total check
failure it returns a REPORT with `reason_code` `CHECK_FAILED` and
whatever partial findings exist, never a crash or a hang. Assessment is
two checks: (1) an approvals audit that scans Approval events over the
last ~500k blocks (chunked at the 50k public-node limit) and resolves
current allowances; (2) a token quick-screen (metadata, PancakeSwap V2
pair + reserves, static buy/sell simulation through the router). Scoring
is a transparent rubric documented in the README and code comments
(unlimited approval to an EOA 75, curated high-risk spender 75, possible
honeypot 60, no liquidity 25, and so on; bands CLEAR/LOW/MEDIUM/HIGH).
Key decisions: every check degrades independently to "unknown" instead
of failing the whole assessment; the high-risk spender list is
intentionally empty by default rather than guessed (operators extend it
via env from threat intel), with structural heuristics covering the
drainer pattern; holder concentration is explicitly not checked (too
expensive for 60s) and listed as a limitation rather than faked; and
`proof`/`public_signals` are null by design, because an advisory report
is not a payment decision and a ZK proof of a heuristic score would
prove nothing about the underlying chain data. Verified locally: `npm
test` passes (HMAC round-trip, scoring, and a no-network replay harness
with three sample envelopes), the server starts, preflight returns a
signed `ok:true`, and live wallet + token assessments return well-formed
signed REPORTs within the time budget.

## Demo (after deploy)

```bash
SECRET=<platform secret from Rotate Secret>
BODY='{"type":"agent-games.preflight.v1","task_id":"preflight-001"}'
SIG=$(node -e "const c=require('node:crypto');process.stdout.write(c.createHmac('sha256',process.env.SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
curl -s -X POST https://<your-deployment>/agent \
  -H 'content-type: application/json' \
  -H "x-agent-games-signature: $SIG" -d "$BODY"

BODY='{"type":"agent-games.guard.v1","task_id":"demo-wallet-001","input":{"wallet":"0x5bf45EfF7126D4b31707eab853702c9A081D2bF6"}}'
SIG=$(node -e "const c=require('node:crypto');process.stdout.write(c.createHmac('sha256',process.env.SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
curl -s -X POST https://<your-deployment>/agent \
  -H 'content-type: application/json' \
  -H "x-agent-games-signature: $SIG" -d "$BODY"
```
