# Architecture & Threat Model

## 1. How EIP-7702 (`0x05` / `0xef0100`) Changes EOA Security

Under EIP-7702 (Type-`0x04` Set Code transactions), any Externally Owned Account (EOA) can attach smart contract execution logic to its own address while keeping its private key, token balances, and ERC-20 allowances intact.

To delegate code, the EOA signs an offline authorization preimage prefixed with magic byte `0x05`:

```text
signing_digest = keccak256(0x05 || RLP([chain_id, address, nonce]))
```

Once a relayer includes that signed tuple inside a Type-`0x04` transaction's `authorizationList`, the EVM writes a 23-byte delegation indicator directly into the EOA's code slot:

```text
0xef0100 || <20-byte delegate contract address>
```

From that block onward, every call to the EOA executes the delegate contract's bytecode in the context of the EOA itself. Any `transfer(address,uint256)` (`0xa9059cbb`) or batch sweeper function (`0x043ff9d2`) inside that delegate can move native gas tokens and approved/held ERC-20 balances without needing another signature.

---

## 2. Three Post-Delegation Hazards in the Wild

### Hazard A: Dormant Future-Nonce Tuples & `chainId = 0` Wildcards

A standard revocation sets `address = 0x0000000000000000000000000000000000000000`, clearing the `0xef0100` code pointer back to `0x` and consuming **1** nonce.

Drainer kits exploit two subtleties here:
1. **Descending or pre-signed future nonces**: If a victim was tricked into signing tuples for `nonce`, `nonce + 1`, ..., `nonce + K` (or if an attacker packs tuples in descending nonce order so only the current nonce executes while higher nonces stay unspent off-chain), revoking a single nonce increments the wallet to `nonce + 1` - which immediately makes the attacker's cached `nonce + 1` tuple valid on the very next block.
2. **Cross-chain wildcard replay (`chain_id = 0`)**: Under EIP-7702, `chain_id = 0` makes a single signature valid on Ethereum, Arbitrum, Base, Optimism, Polygon, Avalanche, and BNB Chain at the same time whenever the EOA's nonce matches.

### Hazard B: Second-Hop Smart-Account Proxy Drain (`getOwner` `0x66b46a7a`)

Many treasury and smart-account setups hold funds inside an EIP-1967 or modular smart contract account (MSCA) proxy whose `eth_getCode` is standard proxy bytecode (not `0xef0100`). A naive scanner marks that contract safe.

However, if `getOwner()` (`0x66b46a7a`) on that proxy resolves to a single plain EOA, hijacking that owner EOA via EIP-7702 lets the sweeper contract execute calls where `msg.sender == ownerEOA`. One transaction on the owner EOA drains the second-hop smart account without ever modifying the proxy's own bytecode.

### Hazard C: Single-EOA Solana `ProgramData` Upgrade Authorities

On Solana, `BPFLoaderUpgradeab1e` programs store their mutable bytecode pointer in a `ProgramData` account. When `UpgradeAuthority` points to a plain `0B` `SystemProgram` wallet instead of a multisig PDA (or revoked `null`), compromising that single key hands full program upgrade power to an attacker. `src/scanner.mjs` includes an optional Solana audit path for multi-chain teams checking both EVM and Solana keys.

---

## 3. Ascending-Tuple Type-`0x04` Nonce Cleaner

To defeat cached future-nonce signatures without sending 20 separate self-transfers, `src/rlp.mjs` flips the descending-nonce trick upside down.

`buildAscendingNonceShredPlan(chainId, startNonce, count)` packs `K` null-delegation tuples (`address = 0x0000000000000000000000000000000000000000`) in **strictly ascending** nonce order `[n, n+1, n+2, ..., n+K-1]` inside one single Type-`0x04` transaction:

1. **Tuple `0` (`nonce = n`)**: Matches the EOA's current nonce `n`, clears any active `0xef0100` sweeper indicator back to `0x`, and increments the EOA nonce to `n + 1` mid-transaction.
2. **Tuple `1` (`nonce = n + 1`)**: Immediately matches the freshly incremented nonce `n + 1` during the same authorization loop and increments it to `n + 2`.
3. **Tuple `K - 1` (`nonce = n + K - 1`)**: Advances the final EOA nonce to `n + K` in the same block.

Every cached attacker signature in `[n, n + K - 1]` becomes permanently unplayable in one atomic inclusion.

---

## 4. Browser `0x05` & EIP-6963 Signer Firewall

`browser/wallet-shield-firewall.js` wraps EIP-1193 (`request`) and legacy (`send`, `sendAsync`) wallet providers plus dynamic multi-wallet discovery events (`eip6963:announceProvider`):

| Vector | RPC Method | Firewall Action |
| :--- | :--- | :--- |
| Direct `0x05` delegation | `wallet_signAuthorization`, `eth_signAuthorization` | Blocks or alerts when target is non-zero; flags `chainId === 0` wildcard replay |
| Type-`0x04` sweeper tx | `eth_sendTransaction`, `eth_signTransaction` | Inspects `authorizationList` / `authorization_list` for non-zero delegates |
| Raw `0x05` RLP blind-sign | `eth_sign`, `personal_sign` | Hard-blocks hex payloads matching `^0x05[c-f][0-9a-f]` |
| Null revocation (`0x00..00`) | `wallet_signAuthorization`, `eth_sendTransaction` | Allowed cleanly so users can revoke and shred nonces |
