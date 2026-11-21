#!/usr/bin/env node
/**
 * Runnable demo: Wrap an EIP-1193 provider with Wallet-Shield 7702 and test
 * malicious 0x05 payloads vs a safe 0x0000...0000 revocation.
 *
 * Run:
 *   node examples/firewall-provider-demo.mjs
 */

import { ZERO_ADDR, wrapProvider7702 } from "../browser/wallet-shield-firewall.js";
import { buildEip7702TupleRlpPreimage } from "../src/rlp.mjs";

const SYNTHETIC_WALLET = "0x000000000000000000000000000000000000dEaD";
const SYNTHETIC_SWEEPER = "0x000000000000000000000000000000000000bEEF";

const provider = {
  async request(payload) {
    return `0xsigned_${payload.method}`;
  },
};

wrapProvider7702(provider, { confirmFn: () => false });

const cases = [
  {
    label: "1. Wildcard chainId=0 EIP-7702 delegation",
    payload: {
      method: "wallet_signAuthorization",
      params: [{ contractAddress: SYNTHETIC_SWEEPER, chainId: 0, nonce: 1 }],
    },
  },
  {
    label: "2. Type-0x04 tx carrying sweeper authorizationList",
    payload: {
      method: "eth_sendTransaction",
      params: [
        {
          to: SYNTHETIC_WALLET,
          authorizationList: [{ address: SYNTHETIC_SWEEPER, chainId: 1, nonce: 42 }],
        },
      ],
    },
  },
  {
    label: "3. Raw 0x05 RLP blind-signing via personal_sign",
    payload: {
      method: "personal_sign",
      params: [buildEip7702TupleRlpPreimage(1, SYNTHETIC_SWEEPER, 42), SYNTHETIC_WALLET],
    },
  },
  {
    label: "4. Legitimate 0x0000...0000 null revocation",
    payload: {
      method: "wallet_signAuthorization",
      params: [{ contractAddress: ZERO_ADDR, chainId: 1, nonce: 42 }],
    },
  },
];

for (const item of cases) {
  try {
    const out = await provider.request(item.payload);
    console.log(`[ALLOWED] ${item.label} -> ${out}`);
  } catch (err) {
    console.log(`[BLOCKED] ${item.label} -> ${err.message}`);
  }
}
