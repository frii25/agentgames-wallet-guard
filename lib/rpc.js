'use strict';
/**
 * Read-only BSC client (chainId 56) built on ethers v6.
 *
 * Design notes:
 *  - Public RPC only, no API keys, no signing, no transactions. Every
 *    method is a read (eth_getLogs / eth_call / eth_getCode / eth_blockNumber).
 *  - `BSC_RPC_URL` may be a comma-separated list; each call tries the
 *    providers in order until one answers, so one flaky endpoint cannot
 *    kill an assessment. Default is the public Binance dataseed.
 *  - Every call has a hard timeout (default 8s, `BSC_RPC_TIMEOUT_MS`).
 *    A timed-out call throws, and the caller (lib/guard.js) degrades that
 *    single check to "unknown" instead of failing the whole assessment.
 *  - `eth_getLogs` is chunked by the caller at <= 50,000 blocks per call
 *    (public BSC nodes cap the range); this module enforces nothing about
 *    ranges, it just executes one call.
 *  - All contract reads go through low-level `eth_call` with an
 *    ethers.Interface, so retries/timeouts apply uniformly.
 *
 * Egress note: on hosts behind an HTTP proxy, Node's global fetch needs
 * `NODE_USE_ENV_PROXY=1`. It is set defensively here (no-op where no
 * proxy variables exist, e.g. on Vercel) and in the npm start script.
 */
if (!process.env.NODE_USE_ENV_PROXY) process.env.NODE_USE_ENV_PROXY = '1';

const { ethers } = require('ethers');

const CHAIN_ID = 56;
const DEFAULT_RPC_URLS = ['https://bsc-dataseed.binance.org/'];
const WBNB = '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c';
const PANCAKE_V2_FACTORY = '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73';
const PANCAKE_V2_ROUTER = '0x10ED43C718714eb63d5aA57B78B54704E256024E';

const ERC20_ABI = [
  'function allowance(address owner, address spender) view returns (uint256)',
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function totalSupply() view returns (uint256)',
];
const FACTORY_ABI = ['function getPair(address tokenA, address tokenB) view returns (address)'];
const PAIR_ABI = [
  'function getReserves() view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)',
  'function token0() view returns (address)',
  'function token1() view returns (address)',
];
const ROUTER_ABI = [
  'function getAmountsOut(uint256 amountIn, address[] path) view returns (uint256[] amounts)',
];

const APPROVAL_TOPIC = ethers.id('Approval(address,address,uint256)');

/** Race a promise against a timeout; on timeout throw an Error labelled `label`. */
function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout after ${ms}ms: ${label}`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function parseRpcUrls(raw) {
  const list = String(raw || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length ? list : DEFAULT_RPC_URLS;
}

class BscClient {
  constructor(urls, timeoutMs = 8000) {
    this.urls = parseRpcUrls(urls);
    this.timeoutMs = timeoutMs;
    this.providers = this.urls.map((u) => new ethers.JsonRpcProvider(u, CHAIN_ID));
  }

  /** Try `fn(provider)` on each provider in order; throw the last error if all fail. */
  async _try(fn, label) {
    let lastErr;
    for (const provider of this.providers) {
      try {
        return await withTimeout(fn(provider), this.timeoutMs, label);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr;
  }

  getBlockNumber() {
    return this._try((p) => p.getBlockNumber(), 'getBlockNumber');
  }

  getLogs(filter) {
    return this._try((p) => p.getLogs(filter), 'getLogs');
  }

  getCode(address) {
    return this._try((p) => p.getCode(address), 'getCode');
  }

  /** Raw eth_call; `tx` is { to, data }. Returns the hex result. */
  call(tx) {
    return this._try((p) => p.call(tx), `call ${tx.to}`);
  }

  // -- typed helpers (all fail-soft: they throw, the caller decides) --

  async allowance(token, owner, spender) {
    const iface = new ethers.Interface(ERC20_ABI);
    const data = iface.encodeFunctionData('allowance', [owner, spender]);
    const raw = await this.call({ to: token, data });
    return iface.decodeFunctionResult('allowance', raw)[0];
  }

  /** Read name/symbol/decimals/totalSupply; each field degrades independently. */
  async tokenInfo(token) {
    const iface = new ethers.Interface(ERC20_ABI);
    const out = { address: token, name: null, symbol: null, decimals: null, totalSupply: null };
    for (const field of ['name', 'symbol', 'decimals', 'totalSupply']) {
      try {
        const data = iface.encodeFunctionData(field, []);
        const raw = await this.call({ to: token, data });
        let value = iface.decodeFunctionResult(field, raw)[0];
        if (field === 'decimals') value = Number(value);
        if (field === 'totalSupply') value = value.toString();
        out[field] = value;
      } catch (err) {
        // Some tokens return bytes32 name/symbol or revert; try bytes32 decode.
        if (field === 'name' || field === 'symbol') {
          try {
            const data = iface.encodeFunctionData(field, []);
            const raw = await this.call({ to: token, data });
            out[field] = ethers.decodeBytes32String(raw.slice(0, 66));
          } catch (_) {
            out[field] = null;
          }
        } else {
          out[field] = null;
        }
      }
    }
    return out;
  }

  async getPair(tokenA, tokenB) {
    const iface = new ethers.Interface(FACTORY_ABI);
    const data = iface.encodeFunctionData('getPair', [tokenA, tokenB]);
    const raw = await this.call({ to: PANCAKE_V2_FACTORY, data });
    return iface.decodeFunctionResult('getPair', raw)[0];
  }

  async getReserves(pair) {
    const iface = new ethers.Interface(PAIR_ABI);
    const data = iface.encodeFunctionData('getReserves', []);
    const raw = await this.call({ to: pair, data });
    const [reserve0, reserve1] = iface.decodeFunctionResult('getReserves', raw);
    const t0 = await this.call({ to: pair, data: iface.encodeFunctionData('token0', []) })
      .then((r) => iface.decodeFunctionResult('token0', r)[0]);
    return { reserve0: reserve0.toString(), reserve1: reserve1.toString(), token0: t0 };
  }

  /** Static swap simulation via the router; reverts propagate as errors. */
  async getAmountsOut(amountIn, path) {
    const iface = new ethers.Interface(ROUTER_ABI);
    const data = iface.encodeFunctionData('getAmountsOut', [amountIn, path]);
    const raw = await this.call({ to: PANCAKE_V2_ROUTER, data });
    return iface.decodeFunctionResult('getAmountsOut', raw)[0].map((x) => x.toString());
  }

  /**
   * Scan Approval events where `owner` granted an allowance, chunked at
   * <= `chunkSize` blocks per eth_getLogs call (public nodes cap the range).
   * Returns raw log objects. `onProgress` is optional.
   */
  async scanApprovals(owner, fromBlock, toBlock, chunkSize = 50000, concurrency = 4) {
    const ownerTopic = ethers.zeroPadValue(ethers.getAddress(owner), 32);
    const ranges = [];
    for (let start = fromBlock; start <= toBlock; start += chunkSize) {
      ranges.push([start, Math.min(start + chunkSize - 1, toBlock)]);
    }
    const logs = [];
    for (let i = 0; i < ranges.length; i += concurrency) {
      const batch = ranges.slice(i, i + concurrency).map(([from, to]) =>
        this.getLogs({ fromBlock: from, toBlock: to, topics: [APPROVAL_TOPIC, ownerTopic] })
      );
      const results = await Promise.allSettled(batch);
      for (const r of results) {
        if (r.status === 'fulfilled') logs.push(...r.value);
        // A failed chunk degrades silently: the scan reports partial coverage.
      }
    }
    return logs;
  }
}

module.exports = {
  BscClient,
  CHAIN_ID,
  WBNB,
  PANCAKE_V2_FACTORY,
  PANCAKE_V2_ROUTER,
  DEFAULT_RPC_URLS,
  parseRpcUrls,
  withTimeout,
};
