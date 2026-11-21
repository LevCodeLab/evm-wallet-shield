# evm-wallet-shield

![Preview](./assets/preview.svg)

![License](https://img.shields.io/badge/license-MIT-141418?style=flat-square&color=141418&labelColor=26262E)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-141418?style=flat-square&color=141418&labelColor=26262E)
![Dependencies](https://img.shields.io/badge/dependencies-zero-141418?style=flat-square&color=141418&labelColor=26262E)
![Chains](https://img.shields.io/badge/evm_chains-7-141418?style=flat-square&color=141418&labelColor=26262E)

Made this after seeing folks lose wallets to blind signatures right after EIP-7702 went live. It is not a bug bhai, EIP-7702 literally lets an EOA wear smart contract clothes. That is great for batching legitimate transactions, and terrible when a phishing page tricks you into signing a single `0x05` tuple that turns your wallet into an automated token sweeper across seven chains at once.

`evm-wallet-shield` is a zero-dependency Node ESM toolkit, Edge API handler, and standalone browser signer firewall that scans wallets for hidden `0xef0100` delegations, checks second-hop smart-account owners, generates ascending-tuple Type-`0x04` nonce-cleaning preimages, and blocks shady `0x05` signing prompts before they hit your wallet.

---

## what is this

1. **7-Chain EIP-7702 (`0xef0100`) Scanner**: Checks `Ethereum`, `Arbitrum`, `Base`, `Optimism`, `Polygon`, `Avalanche`, and `BNB Chain` in parallel via standard JSON-RPC. Flags active `0xef0100` code pointers and inspects delegate bytecode for sweeper selectors (`0xa9059cbb`, `0x043ff9d2`).
2. **Second-Hop Smart-Account Proxy Auditor**: Even if a smart account or EIP-1967 proxy has clean bytecode, if its `getOwner()` (`0x66b46a7a`) points to a single plain EOA, an EIP-7702 hijack on that owner EOA can drain the proxy in one shot. The scanner follows that second hop automatically.
3. **Ascending-Tuple Type-`0x04` Nonce Cleaner**: Revoking a delegation normally burns just one nonce. If an attacker cached pre-signed tuples for `nonce + 1 .. nonce + K`, they can re-infect your wallet on the next block. Packing `K` null-delegation (`0x0000...0000`) tuples in strictly ascending nonce order burns all `K` nonces atomically in a single Type-`0x04` transaction.
4. **Browser `0x05` & EIP-6963 Signer Firewall**: Drop-in script that wraps `window.ethereum` and `eip6963:announceProvider` wallets to stop unauthorized `wallet_signAuthorization`, `chainId === 0` all-chain wildcard replays, non-zero Type-`0x04` `authorizationList` payloads, and raw `0x05` RLP blind-signing over `eth_sign` / `personal_sign`, while letting `0x0000000000000000000000000000000000000000` revocations pass through.

---

## run it in 60 sec

No `npm install` bloat needed. Zero external packages, pure Node `>= 18`.

```bash
git clone https://github.com/LevCodeLab/evm-wallet-shield.git
cd evm-wallet-shield

# Run instant offline 7-chain demo on synthetic wallet 0x0000...dEaD
npm run demo

# Scan any live EVM address across all 7 chains + build 15 nonce-cleaning preimages
node src/cli.mjs 0x000000000000000000000000000000000000dEaD 15

# Emit structured JSON for scripts or dashboards
node src/cli.mjs --demo --json

# Run the full unit test suite
npm test
```

---

## using the browser 0x05 firewall

Import `wrapProvider7702` or `installFirewall` before dApp scripts connect to injected wallets:

```js
import { installFirewall, wrapProvider7702 } from "evm-wallet-shield/firewall";

// Automatically wraps window.ethereum + future EIP-6963 announced wallets
installFirewall(window);

// Or wrap a specific EIP-1193 provider instance directly
wrapProvider7702(customProvider);
```

To generate ascending-tuple Type-`0x04` revocation preimages in code:

```js
import { buildAscendingNonceShredPlan } from "evm-wallet-shield/rlp";

const plan = buildAscendingNonceShredPlan(1, 42, 15);
console.log(plan.finalSafeNonce); // 57
console.log(plan.tuples[0].rlpPreimage0x05);
// 0x05d7019400000000000000000000000000000000000000002a
```

---

## how to edit and customize

Everything is small, flat, and readable in one sitting:

| Path | What lives here & how to tweak it |
| :--- | :--- |
| `src/rlp.mjs` | Zero-dep RLP uint/list encoder, `buildEip7702NullTupleRlpPreimage`, and `buildAscendingNonceShredPlan`. Edit here if you want custom max tuple counts or extra Type-`0x04` fields. |
| `src/scanner.mjs` | `EVM_CHAINS` RPC config, USDC/USDT token addresses, sweeper selector list (`SWEEPER_SELECTORS`), `0x66b46a7a` second-hop owner check, optional Solana `ProgramData` check, and offline `--demo` mock RPC transport. Swap in your own private Alchemy/Infura RPC URLs in `EVM_CHAINS` if public nodes rate-limit you. |
| `src/cli.mjs` | Terminal argument parser and ASCII matrix formatter (`--demo`, `--json`, `[shredCount]`). |
| `browser/wallet-shield-firewall.js` | Browser `0x05` & EIP-6963 signer firewall (`inspect7702Payload`, `wrapProvider7702`, `installFirewall`). Pass a custom `confirmFn` option to wire it into your own modal UI instead of `window.confirm`. |
| `api/shield.ts` | Standard Fetch / WinterCG Edge HTTP handler (`GET /api/shield?address=0x...` or `POST`). Drop into Workers, Deno, Bun, or Vercel Edge. |
| `docs/architecture.md` | Deep-dive notes on the `0x05` RLP digest, descending-nonce time bombs, second-hop MSCA drains, and atomic ascending-nonce revocation. |
| `test/wallet-shield.test.mjs` | `node:test` suite covering RLP boundaries, mocked 7-chain RPC responses, and all four browser firewall attack vectors. |

---

## license

MIT - Copyright (c) 2026 LevCodeLab. See [LICENSE](./LICENSE).
