# Contributing to evm-wallet-shield

Thanks for checking out the code! This repo stays intentionally tiny and zero-dependency so anyone auditing a suspicious wallet or integrating the `0x05` firewall can read every line in five minutes without pulling 400 transitive packages.

## local setup

You only need Node.js `>= 18`.

```bash
git clone https://github.com/LevCodeLab/evm-wallet-shield.git
cd evm-wallet-shield

# Run the offline 7-chain terminal demo
npm run demo

# Run all unit tests
npm test

# Run the hygiene check
npm run lint:brand
```

## ground rules for pull requests

1. **Zero runtime dependencies**: Stick to built-in Node ESM (`node:test`, `node:assert`, `fetch`, `BigInt`) and browser Web APIs.
2. **Use synthetic addresses in tests and docs**: Stick to `0x000000000000000000000000000000000000dEaD`, `0x000000000000000000000000000000000000bEEF`, `0x000000000000000000000000000000000000cAFE`, and `0x0000000000000000000000000000000000000000`. Do not hardcode personal wallets in test fixtures.
3. **Add unit tests for new sweeper selectors or RPC chains**: If you add a new chain to `EVM_CHAINS` or a new drainer function selector to `SWEEPER_SELECTORS` in `src/scanner.mjs`, add a mocked RPC case in `test/wallet-shield.test.mjs`.
4. **Never block `0x0000...0000` revocations**: Any change to `browser/wallet-shield-firewall.js` must still allow null-address EIP-7702 revocations and ascending-tuple Type-`0x04` nonce-cleaning transactions.

## adding a new EVM chain

Open `src/scanner.mjs` and append an entry to `EVM_CHAINS`:

```js
{
  id: 324,
  name: "ZKsync Era",
  symbol: "ETH",
  rpc: "https://mainnet.era.zksync.io",
  explorer: "https://explorer.zksync.io",
  usdc: "0x1d17cbcf0d6d143135a902365d2e5e2a16538d4",
  usdt: "0x493257fd37edb34451f62edf8d2a0c418852ba4c",
}
```

Then run `npm test` to make sure all suites pass before opening your PR.
