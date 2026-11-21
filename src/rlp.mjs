/**
 * Zero-dependency RLP encoder and EIP-7702 Type-0x04 ascending-tuple nonce cleaner.
 * Encodes 0x05 || RLP([chain_id, address, nonce]) preimages per EIP-7702.
 */

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * Encodes a non-negative integer as an RLP byte-string (without 0x prefix).
 * Per RLP rules, scalar 0 encodes as empty byte-string 0x80.
 *
 * @param {bigint | number | string} value
 * @returns {string}
 */
export function rlpEncodeUint(value) {
  const big = typeof value === "bigint" ? value : BigInt(value);
  if (big < 0n) {
    throw new RangeError("RLP uint value cannot be negative");
  }
  if (big === 0n) {
    return "80";
  }

  let hex = big.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }

  const byteLen = hex.length / 2;
  if (byteLen === 1 && parseInt(hex, 16) < 0x80) {
    return hex;
  }

  if (byteLen < 56) {
    return (0x80 + byteLen).toString(16) + hex;
  }

  let lenHex = byteLen.toString(16);
  if (lenHex.length % 2 !== 0) {
    lenHex = "0" + lenHex;
  }
  return (0xb7 + lenHex.length / 2).toString(16) + lenHex + hex;
}

/**
 * Wraps concatenated RLP item hex (without 0x prefix) in an RLP list header.
 *
 * @param {string} payloadHex
 * @returns {string}
 */
export function rlpEncodeListHex(payloadHex) {
  const payloadByteLen = payloadHex.length / 2;
  if (payloadByteLen < 56) {
    return (0xc0 + payloadByteLen).toString(16) + payloadHex;
  }
  let lenHex = payloadByteLen.toString(16);
  if (lenHex.length % 2 !== 0) {
    lenHex = "0" + lenHex;
  }
  return (0xf7 + lenHex.length / 2).toString(16) + lenHex + payloadHex;
}

/**
 * Builds the EIP-7702 signing preimage: 0x05 || RLP([chain_id, address, nonce]).
 * Passing keccak256 over these bytes yields the authorization signing digest.
 *
 * @param {bigint | number} chainId
 * @param {string} delegateAddress
 * @param {bigint | number} nonce
 * @returns {string}
 */
export function buildEip7702TupleRlpPreimage(chainId, delegateAddress, nonce) {
  const cleanAddr = String(delegateAddress || "").trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(cleanAddr)) {
    throw new TypeError(`Invalid 20-byte EVM address: ${delegateAddress}`);
  }
  const cHex = rlpEncodeUint(chainId);
  const addrHex = "94" + cleanAddr.slice(2);
  const nHex = rlpEncodeUint(nonce);
  return "0x05" + rlpEncodeListHex(cHex + addrHex + nHex);
}

/**
 * Builds the EIP-7702 null-delegation revocation preimage targeting 0x0000...0000:
 * 0x05 || RLP([chain_id, 0x0000000000000000000000000000000000000000, nonce]).
 *
 * @param {bigint | number} chainId
 * @param {bigint | number} nonce
 * @returns {string}
 */
export function buildEip7702NullTupleRlpPreimage(chainId, nonce) {
  return buildEip7702TupleRlpPreimage(chainId, ZERO_ADDRESS, nonce);
}

/**
 * Generates an ascending-nonce Type-0x04 revocation plan that clears active
 * 0xef0100 code delegation and burns [startNonce .. startNonce + count - 1]
 * atomically in a single block so off-chain pre-signed future-nonce tuples expire.
 *
 * @param {number} chainId
 * @param {number} startNonce
 * @param {number} [count=15]
 */
export function buildAscendingNonceShredPlan(chainId, startNonce, count = 15) {
  const numericChainId = Number(chainId);
  const baseNonce = Math.max(0, Math.trunc(Number(startNonce) || 0));
  const safeCount = Math.min(Math.max(Math.trunc(Number(count) || 15), 1), 100);

  if (!Number.isInteger(numericChainId) || numericChainId < 0) {
    throw new RangeError(`Invalid chainId: ${chainId}`);
  }

  const tuples = Array.from({ length: safeCount }, (_, i) => {
    const tupleNonce = baseNonce + i;
    return {
      index: i,
      chainId: numericChainId,
      address: ZERO_ADDRESS,
      targetDelegate: ZERO_ADDRESS,
      nonce: tupleNonce,
      rlpPreimage0x05: buildEip7702NullTupleRlpPreimage(numericChainId, tupleNonce),
    };
  });

  return {
    txType: "0x04",
    chainId: numericChainId,
    startNonce: baseNonce,
    count: safeCount,
    finalSafeNonce: baseNonce + safeCount,
    targetDelegate: ZERO_ADDRESS,
    tuples,
  };
}
