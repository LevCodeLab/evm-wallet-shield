#!/usr/bin/env node
/**
 * Runnable demo: Build an ascending-tuple Type-0x04 nonce cleaner plan
 * to clear active 0xef0100 code delegation and burn cached future-nonce signatures.
 *
 * Run:
 *   node examples/shred-nonces-demo.mjs
 */

import { buildAscendingNonceShredPlan } from "../src/rlp.mjs";
import { DEMO_TARGET_ADDRESS, scanEvmAddress } from "../src/scanner.mjs";

const scan = await scanEvmAddress(DEMO_TARGET_ADDRESS, { demo: true, shredCount: 6 });
const ethChain = scan.chains.find((c) => c.chainId === 1);

console.log(`Scanned synthetic wallet : ${scan.address}`);
console.log(`Ethereum status          : ${ethChain.status} (delegate: ${ethChain.delegateAddress})`);
console.log(`Current Ethereum nonce   : ${ethChain.nonce}`);
console.log("");

const plan = buildAscendingNonceShredPlan(1, ethChain.nonce, 6);
console.log(`Generated Type-${plan.txType} ascending revocation plan (+${plan.count} nonces):`);

for (const tuple of plan.tuples) {
  console.log(
    `  [#${tuple.index}] nonce=${tuple.nonce} -> ${tuple.targetDelegate} | ${tuple.rlpPreimage0x05}`
  );
}

console.log("");
console.log(`Final safe wallet nonce after 1 block : ${plan.finalSafeNonce}`);
