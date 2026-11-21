/**
 * Multi-chain EIP-7702 (0xef0100) sweeper scanner, second-hop MSCA owner auditor,
 * ERC-20 stablecoin exposure reader, and optional Solana ProgramData inspector.
 */

import { buildAscendingNonceShredPlan } from "./rlp.mjs";

export const DEMO_TARGET_ADDRESS = "0x000000000000000000000000000000000000dEaD";
export const DEMO_SWEEPER_DELEGATE = "0x000000000000000000000000000000000000beef";
export const DEMO_MSCA_OWNER = "0x000000000000000000000000000000000000cafe";

export const SWEEPER_SELECTORS = [
  { hex: "a9059cbb", name: "transfer(address,uint256)" },
  { hex: "043ff9d2", name: "sweepBatch(address[],uint256[])" },
];

export const EVM_CHAINS = [
  {
    id: 1,
    name: "Ethereum",
    symbol: "ETH",
    rpc: "https://ethereum-rpc.publicnode.com",
    explorer: "https://etherscan.io",
    usdc: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    usdt: "0xdac17f958d2ee523a2206206994597c13d831ec7",
  },
  {
    id: 42161,
    name: "Arbitrum",
    symbol: "ETH",
    rpc: "https://arbitrum-one-rpc.publicnode.com",
    explorer: "https://arbiscan.io",
    usdc: "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
    usdt: "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
  },
  {
    id: 8453,
    name: "Base",
    symbol: "ETH",
    rpc: "https://base-rpc.publicnode.com",
    explorer: "https://basescan.org",
    usdc: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    usdt: null,
  },
  {
    id: 10,
    name: "Optimism",
    symbol: "ETH",
    rpc: "https://optimism-rpc.publicnode.com",
    explorer: "https://optimistic.etherscan.io",
    usdc: "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
    usdt: "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
  },
  {
    id: 137,
    name: "Polygon",
    symbol: "POL",
    rpc: "https://polygon-bor-rpc.publicnode.com",
    explorer: "https://polygonscan.com",
    usdc: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    usdt: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
  },
  {
    id: 43114,
    name: "Avalanche",
    symbol: "AVAX",
    rpc: "https://avalanche-c-chain-rpc.publicnode.com",
    explorer: "https://snowtrace.io",
    usdc: "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
    usdt: "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7",
  },
  {
    id: 56,
    name: "BNB Chain",
    symbol: "BNB",
    rpc: "https://bsc-rpc.publicnode.com",
    explorer: "https://bscscan.com",
    usdc: "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
    usdt: "0x55d398326f99059ff775485246999027b3197955",
  },
];

export const DEFAULT_SOLANA_RPC = "https://solana-rpc.publicnode.com";

/**
 * Default JSON-RPC HTTP caller with AbortController timeout.
 *
 * @param {string} rpcUrl
 * @param {string} method
 * @param {unknown[]} params
 * @param {number} [timeoutMs=4500]
 */
export async function defaultRpcCall(rpcUrl, method, params, timeoutMs = 4500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: controller.signal,
    });
    const json = await res.json();
    return json?.result ?? null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function toHexWei(ethAmount) {
  return "0x" + BigInt(Math.round(ethAmount * 1e6) * 10n ** 12n > 0 ? BigInt(Math.round(ethAmount * 1e6)) * 10n ** 12n : 0n).toString(16);
}

function toHexUnits6(amount) {
  return "0x" + BigInt(Math.round(amount * 1e6)).toString(16).padStart(64, "0");
}

/**
 * Creates a deterministic offline mock JSON-RPC transport for `--demo` mode and unit tests.
 */
export function createDemoRpcTransport() {
  const proxy209Bytes = "0x363d3d373d3d3d363d73" + "11".repeat(199);
  const contract612Bytes = "0x6080604052" + "22".repeat(607);
  const sweeperBytecode = "0x608060405263a9059cbb63043ff9d200";
  const ownerSlotEncoded = "0x" + DEMO_MSCA_OWNER.slice(2).padStart(64, "0");

  return async function demoRpcCall(rpcUrl, method, params) {
    if (rpcUrl.includes("solana")) {
      const pubkey = String(params?.[0] || "");
      if (pubkey === "DemoProgramData1111111111111111111111111111") {
        return {
          value: {
            owner: "BPFLoaderUpgradeab1e11111111111111111111111",
            lamports: 15000000,
            executable: false,
            space: 45,
            data: {
              parsed: {
                info: {
                  authority: "DemoSingleEoaAuth11111111111111111111111111",
                  slot: 312000000,
                },
              },
            },
          },
        };
      }
      if (pubkey === "DemoSingleEoaAuth11111111111111111111111111") {
        return {
          value: {
            owner: "11111111111111111111111111111111",
            lamports: 2500000000,
            executable: false,
            space: 0,
          },
        };
      }
      return {
        value: {
          owner: "BPFLoaderUpgradeab1e11111111111111111111111",
          lamports: 1141440,
          executable: true,
          space: 36,
          data: {
            parsed: {
              info: {
                programData: "DemoProgramData1111111111111111111111111111",
              },
            },
          },
        },
      };
    }

    const chain = EVM_CHAINS.find((c) => c.rpc === rpcUrl);
    const target = String(params?.[0]?.to || params?.[0] || "").toLowerCase();
    const callData = String(params?.[0]?.data || "").toLowerCase();

    if (!chain) return null;

    if (method === "eth_getCode") {
      if (target === DEMO_SWEEPER_DELEGATE) return sweeperBytecode;
      if (target === DEMO_MSCA_OWNER) return "0x";
      if (chain.id === 1) return "0xef0100" + DEMO_SWEEPER_DELEGATE.slice(2);
      if (chain.id === 42161) return proxy209Bytes;
      if (chain.id === 43114) return contract612Bytes;
      return "0x";
    }

    if (method === "eth_getTransactionCount") {
      if (target === DEMO_MSCA_OWNER) return "0x9";
      const nonces = { 1: 42, 42161: 18, 8453: 7, 10: 3, 137: 11, 43114: 1, 56: 0 };
      return "0x" + (nonces[chain.id] ?? 0).toString(16);
    }

    if (method === "eth_getBalance") {
      const balances = { 1: 1.25, 42161: 0.4, 8453: 0.185, 10: 0.05, 137: 145, 43114: 4.5, 56: 0.82 };
      const wei = BigInt(Math.round((balances[chain.id] ?? 0) * 1e6)) * 10n ** 12n;
      return "0x" + wei.toString(16);
    }

    if (method === "eth_call") {
      if (callData === "0x66b46a7a") {
        return chain.id === 42161 ? ownerSlotEncoded : "0x";
      }
      if (callData.startsWith("0x70a08231")) {
        const holder = "0x" + callData.slice(-40);
        if (holder === DEMO_MSCA_OWNER && chain.id === 42161 && target === chain.usdc) {
          return toHexUnits6(25000);
        }
        if (chain.usdc && target === chain.usdc) {
          const usdcMap = { 1: 4500, 42161: 12000, 8453: 850, 10: 0, 137: 0, 43114: 0, 56: 0 };
          return toHexUnits6(usdcMap[chain.id] ?? 0);
        }
        if (chain.usdt && target === chain.usdt) {
          const usdtMap = { 1: 0, 42161: 0, 10: 0, 137: 320, 43114: 0, 56: 100 };
          return toHexUnits6(usdtMap[chain.id] ?? 0);
        }
      }
      return "0x";
    }

    return null;
  };
}

/**
 * Inspects delegate contract bytecode for known token-sweeper function selectors.
 *
 * @param {string | null | undefined} bytecode
 */
export function inspectDelegateBytecode(bytecode) {
  const clean = typeof bytecode === "string" ? bytecode.toLowerCase() : "0x";
  const matchedSelectors = SWEEPER_SELECTORS.filter((sel) => clean.includes(sel.hex)).map(
    (sel) => `0x${sel.hex}`
  );
  return {
    hasSweeperOpcodes: matchedSelectors.length > 0,
    matchedSelectors,
  };
}

/**
 * Scans an EVM 0x address across 7 chains for active EIP-7702 (0xef0100) delegations,
 * sweeper selectors, second-hop MSCA single-EOA owners (0x66b46a7a), and stablecoin balances.
 *
 * @param {string} address
 * @param {object} [options]
 * @param {number} [options.shredCount=15]
 * @param {boolean} [options.demo=false]
 * @param {Function} [options.rpcCall]
 * @param {number} [options.timeoutMs=4500]
 * @param {typeof EVM_CHAINS} [options.chains]
 * @param {Record<string, { label: string, severity?: string }>} [options.flaggedDelegates]
 * @param {Record<string, string>} [options.flaggedEoas]
 */
export async function scanEvmAddress(address, options = {}) {
  const cleanAddr = String(address || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(cleanAddr)) {
    throw new TypeError(`Invalid EVM address: ${address}`);
  }

  const shredCount = Math.min(Math.max(Math.trunc(Number(options.shredCount) || 15), 1), 100);
  const chains = options.chains || EVM_CHAINS;
  const timeoutMs = options.timeoutMs ?? 4500;
  const flaggedDelegates = options.flaggedDelegates || {};
  const flaggedEoas = options.flaggedEoas || {};
  const caller = options.demo
    ? createDemoRpcTransport()
    : options.rpcCall || ((url, method, params) => defaultRpcCall(url, method, params, timeoutMs));

  const padAddr = cleanAddr.slice(2).toLowerCase().padStart(64, "0");

  const chainResults = await Promise.all(
    chains.map(async (chain) => {
      const [code, balHex, nonceHex, usdcHex, usdtHex] = await Promise.all([
        caller(chain.rpc, "eth_getCode", [cleanAddr, "latest"]),
        caller(chain.rpc, "eth_getBalance", [cleanAddr, "latest"]),
        caller(chain.rpc, "eth_getTransactionCount", [cleanAddr, "latest"]),
        chain.usdc
          ? caller(chain.rpc, "eth_call", [{ to: chain.usdc, data: "0x70a08231" + padAddr }, "latest"])
          : Promise.resolve(null),
        chain.usdt
          ? caller(chain.rpc, "eth_call", [{ to: chain.usdt, data: "0x70a08231" + padAddr }, "latest"])
          : Promise.resolve(null),
      ]);

      const rawCode = typeof code === "string" && code.startsWith("0x") ? code : "0x";
      const lowerCode = rawCode.toLowerCase();
      const nativeBalance = balHex && balHex !== "0x" ? Number(BigInt(balHex)) / 1e18 : 0;
      const nonce = nonceHex && nonceHex !== "0x" ? parseInt(nonceHex, 16) : 0;
      const usdcBalance = usdcHex && usdcHex !== "0x" ? Number(BigInt(usdcHex)) / 1e6 : 0;
      const usdtBalance = usdtHex && usdtHex !== "0x" ? Number(BigInt(usdtHex)) / 1e6 : 0;

      const isEip7702 = lowerCode.startsWith("0xef0100") && lowerCode.length >= 48;
      const isPlainEoa = lowerCode === "0x";
      const codeBytes = lowerCode.length > 2 ? (lowerCode.length - 2) / 2 : 0;

      let delegateAddress = null;
      let delegateLabel = null;
      let delegateHasSweeperOpcodes = false;
      let sweeperSelectors = [];
      let mscaOwner = null;
      let mscaOwnerIsPlainEoa = false;
      let mscaOwnerLabel = null;
      let mscaOwnerNonce = 0;
      let mscaOwnerStableUsd = 0;

      if (isEip7702) {
        delegateAddress = "0x" + lowerCode.slice(8, 48);
        const flagged = flaggedDelegates[delegateAddress];
        delegateLabel = flagged ? flagged.label : "Unverified EIP-7702 Delegate Contract";
        const delCode = await caller(chain.rpc, "eth_getCode", [delegateAddress, "latest"]);
        const inspection = inspectDelegateBytecode(delCode);
        delegateHasSweeperOpcodes = inspection.hasSweeperOpcodes;
        sweeperSelectors = inspection.matchedSelectors;
      } else if (!isPlainEoa) {
        const ownerRes = await caller(
          chain.rpc,
          "eth_call",
          [{ to: cleanAddr, data: "0x66b46a7a" }, "latest"]
        );
        if (
          typeof ownerRes === "string" &&
          ownerRes.length >= 66 &&
          !ownerRes.endsWith("0".repeat(40))
        ) {
          mscaOwner = "0x" + ownerRes.slice(-40).toLowerCase();
          mscaOwnerLabel = flaggedEoas[mscaOwner] || null;
          const padOwner = mscaOwner.slice(2).padStart(64, "0");
          const [ownerCode, ownerNonceHex, ownerUsdcHex, ownerUsdtHex] = await Promise.all([
            caller(chain.rpc, "eth_getCode", [mscaOwner, "latest"]),
            caller(chain.rpc, "eth_getTransactionCount", [mscaOwner, "latest"]),
            chain.usdc
              ? caller(chain.rpc, "eth_call", [{ to: chain.usdc, data: "0x70a08231" + padOwner }, "latest"])
              : Promise.resolve(null),
            chain.usdt
              ? caller(chain.rpc, "eth_call", [{ to: chain.usdt, data: "0x70a08231" + padOwner }, "latest"])
              : Promise.resolve(null),
          ]);
          mscaOwnerIsPlainEoa = !ownerCode || ownerCode === "0x";
          mscaOwnerNonce = ownerNonceHex && ownerNonceHex !== "0x" ? parseInt(ownerNonceHex, 16) : 0;
          const oUsdc = ownerUsdcHex && ownerUsdcHex !== "0x" ? Number(BigInt(ownerUsdcHex)) / 1e6 : 0;
          const oUsdt = ownerUsdtHex && ownerUsdtHex !== "0x" ? Number(BigInt(ownerUsdtHex)) / 1e6 : 0;
          mscaOwnerStableUsd = oUsdc + oUsdt;
        }
      }

      const shredPlan = buildAscendingNonceShredPlan(chain.id, nonce, shredCount);

      let status = "PLAIN_EOA_EXPOSED";
      if (isEip7702) {
        status = "INFECTED_7702";
      } else if (mscaOwner && (mscaOwnerIsPlainEoa || mscaOwnerLabel)) {
        status = "MSCA_SECOND_HOP_RISK";
      } else if (!isPlainEoa) {
        status = "CONTRACT_IMMUNE";
      }

      return {
        chainId: chain.id,
        chainName: chain.name,
        symbol: chain.symbol,
        explorer: chain.explorer,
        status,
        isEip7702,
        isPlainEoa,
        codeBytes,
        rawCodePrefix: rawCode.slice(0, 50),
        nonce,
        nativeBalance,
        usdcBalance,
        usdtBalance,
        delegateAddress,
        delegateLabel,
        delegateHasSweeperOpcodes,
        sweeperSelectors,
        mscaOwner,
        mscaOwnerIsPlainEoa,
        mscaOwnerLabel,
        mscaOwnerNonce,
        mscaOwnerStableUsd,
        shredPreview: shredPlan.tuples.slice(0, 5),
        totalShredNonces: shredPlan.count,
        finalNonceAfterShred: shredPlan.finalSafeNonce,
      };
    })
  );

  const knownWalletLabel = flaggedEoas[cleanAddr.toLowerCase()] || null;
  const infectedChains = chainResults.filter((c) => c.status === "INFECTED_7702").length;
  const secondHopChains = chainResults.filter((c) => c.status === "MSCA_SECOND_HOP_RISK").length;

  return {
    type: "EVM",
    mode: options.demo ? "demo" : "live",
    address: cleanAddr,
    knownWalletLabel,
    summary: {
      infectedChains,
      secondHopChains,
      overallRisk:
        infectedChains > 0
          ? "CRITICAL: ACTIVE EIP-7702 (0xef0100) DELEGATION DETECTED"
          : secondHopChains > 0 || knownWalletLabel
          ? "HIGH: SECOND-HOP SINGLE-EOA MSCA OR DORMANT NONCE HAZARD"
          : "EXPOSED EOA: VULNERABLE TO 0x05 BLIND-SIGNING UNLESS GUARDED",
    },
    chains: chainResults,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Audits a Solana base58 account or BPF upgradeable program for unexpected
 * account owners or single-EOA ProgramData UpgradeAuthority risks.
 *
 * @param {string} address
 * @param {object} [options]
 * @param {boolean} [options.demo=false]
 * @param {Function} [options.rpcCall]
 * @param {string} [options.solanaRpc]
 * @param {number} [options.timeoutMs=4500]
 */
export async function scanSolanaAddress(address, options = {}) {
  const cleanAddr = String(address || "").trim();
  const solRpc = options.solanaRpc || DEFAULT_SOLANA_RPC;
  const timeoutMs = options.timeoutMs ?? 4500;
  const caller = options.demo
    ? createDemoRpcTransport()
    : options.rpcCall || ((url, method, params) => defaultRpcCall(url, method, params, timeoutMs));

  const info = await caller(solRpc, "getAccountInfo", [cleanAddr, { encoding: "jsonParsed" }]);
  const val = info?.value;

  const owner = val?.owner || "11111111111111111111111111111111";
  const lamports = val?.lamports || 0;
  const solBalance = lamports / 1e9;
  const executable = Boolean(val?.executable);
  const space = val?.space || 0;

  let programDataAddress = null;
  let upgradeAuthority = null;
  let upgradeAuthorityOwner = null;
  let upgradeAuthoritySol = 0;
  let upgradeAuthorityIsPlainEoa = false;
  let lastDeployedSlot = null;

  if (executable && val?.data?.parsed?.info?.programData) {
    programDataAddress = val.data.parsed.info.programData;
    const pData = await caller(solRpc, "getAccountInfo", [
      programDataAddress,
      { encoding: "jsonParsed" },
    ]);
    upgradeAuthority = pData?.value?.data?.parsed?.info?.authority || null;
    lastDeployedSlot = pData?.value?.data?.parsed?.info?.slot || null;
    if (upgradeAuthority) {
      const authInfo = await caller(solRpc, "getAccountInfo", [
        upgradeAuthority,
        { encoding: "jsonParsed" },
      ]);
      upgradeAuthorityOwner = authInfo?.value?.owner || "11111111111111111111111111111111";
      upgradeAuthoritySol = (authInfo?.value?.lamports || 0) / 1e9;
      upgradeAuthorityIsPlainEoa = upgradeAuthorityOwner === "11111111111111111111111111111111";
    }
  }

  const isHijackedWalletOwner =
    !executable &&
    owner !== "11111111111111111111111111111111" &&
    owner !== "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" &&
    owner !== "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

  return {
    type: "SOLANA",
    mode: options.demo ? "demo" : "live",
    address: cleanAddr,
    owner,
    solBalance,
    executable,
    space,
    isHijackedWalletOwner,
    programAudit: executable
      ? {
          programDataAddress,
          upgradeAuthority,
          upgradeAuthorityOwner,
          upgradeAuthoritySol,
          upgradeAuthorityIsPlainEoa,
          lastDeployedSlot,
          verdict: upgradeAuthorityIsPlainEoa
            ? "CRITICAL SINGLE-POINT-OF-FAILURE: UpgradeAuthority is a 1-of-1 SystemProgram EOA"
            : upgradeAuthority
            ? "MULTISIG OR CUSTOM AUTHORITY PDA"
            : "IMMUTABLE PROGRAM (UpgradeAuthority Revoked)",
        }
      : null,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Auto-dispatches EVM (0x...) vs Solana base58 address scanning.
 *
 * @param {string} address
 * @param {object} [options]
 */
export async function scanAddress(address, options = {}) {
  const cleanAddr = String(address || "").trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(cleanAddr)) {
    return scanEvmAddress(cleanAddr, options);
  }
  return scanSolanaAddress(cleanAddr, options);
}
