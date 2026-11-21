#!/usr/bin/env node
/**
 * EVM Wallet Shield CLI
 * Zero-dependency 7-chain EIP-7702 (0xef0100) scanner & ascending-tuple Type-0x04 nonce cleaner.
 *
 * Usage:
 *   node src/cli.mjs --demo
 *   node src/cli.mjs <0xAddress_or_SolanaPubkey> [shredCount]
 *   node src/cli.mjs 0x000000000000000000000000000000000000dEaD 15
 */

import { realpathSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { DEMO_TARGET_ADDRESS, scanAddress } from "./scanner.mjs";

export function printUsage(write = console.log) {
  write("evm-wallet-shield - 7-chain EIP-7702 (0xef0100) scanner & Type-0x04 nonce cleaner");
  write("");
  write("Usage:");
  write("  wallet-shield --demo [shredCount]");
  write("  wallet-shield <0xAddress_or_SolanaPubkey> [shredCount] [--json]");
  write("");
  write("Examples:");
  write("  node src/cli.mjs --demo");
  write("  node src/cli.mjs 0x000000000000000000000000000000000000dEaD 15");
  write("  node src/cli.mjs 0x000000000000000000000000000000000000bEEF 20 --json");
}

/**
 * Formats an EVM or Solana scan result into a readable terminal report.
 *
 * @param {Awaited<ReturnType<typeof scanAddress>>} result
 * @returns {string}
 */
export function formatScanReport(result) {
  const lines = [];
  lines.push("================================================================================");
  lines.push(
    ` EVM WALLET SHIELD - 7-CHAIN EIP-7702 SCANNER & NONCE CLEANER (${result.mode.toUpperCase()})`
  );
  lines.push("================================================================================");
  lines.push(`Target Address : ${result.address}`);

  if (result.type === "EVM") {
    lines.push(`Overall Risk   : ${result.summary.overallRisk}`);
    lines.push("");
    lines.push("[1] 7-CHAIN EVM CODE, NONCE & SECOND-HOP OWNERSHIP MATRIX:");

    for (const r of result.chains) {
      let stateText = "PLAIN EOA (0B)";
      if (r.isEip7702) {
        const selNote =
          r.sweeperSelectors.length > 0 ? ` [sweeper: ${r.sweeperSelectors.join(",")}]` : "";
        stateText = `[!] ACTIVE 0xef0100 -> ${r.delegateAddress}${selNote}`;
      } else if (r.codeBytes > 0) {
        stateText = `CONTRACT (${r.codeBytes}B)`;
      }

      const stables = [];
      if (r.usdcBalance > 0) stables.push(`${r.usdcBalance.toFixed(2)} USDC`);
      if (r.usdtBalance > 0) stables.push(`${r.usdtBalance.toFixed(2)} USDT`);
      const stableNote = stables.length > 0 ? ` | ${stables.join(", ")}` : "";

      const ownerNote = r.mscaOwner
        ? ` | getOwner(0x66b46a7a): ${r.mscaOwner} [${
            r.mscaOwnerIsPlainEoa ? "PLAIN EOA OWNER" : "CONTRACT OWNER"
          }]`
        : "";

      lines.push(
        `  - ${r.chainName.padEnd(10)} (#${String(r.chainId).padEnd(5)}): ${stateText} | Nonce: ${
          r.nonce
        } | ${r.nativeBalance.toFixed(4)} ${r.symbol}${stableNote}${ownerNote}`
      );
    }

    const ethRow = result.chains[0];
    if (ethRow) {
      lines.push("");
      lines.push(
        `[2] ASCENDING-TUPLE TYPE-0x04 NONCE CLEANER (${ethRow.chainName} ChainID=${ethRow.chainId}, +${ethRow.totalShredNonces} Nonces):`
      );
      for (const t of ethRow.shredPreview) {
        lines.push(
          `  Tuple #${t.index} [nonce=${t.nonce}] -> 0x0000...0000 | RLP(0x05): ${t.rlpPreimage0x05}`
        );
      }
      if (ethRow.totalShredNonces > ethRow.shredPreview.length) {
        lines.push(
          `  ... (+${ethRow.totalShredNonces} sequential nonces burned in 1 atomic Type-0x04 tx -> Final Safe Nonce: ${ethRow.finalNonceAfterShred})`
        );
      }
    }
  } else {
    lines.push("");
    lines.push("[1] SOLANA ACCOUNT & PROGRAMDATA AUTHORITY AUDIT:");
    lines.push(`  - Owner Program : ${result.owner}`);
    lines.push(`  - Balance       : ${result.solBalance.toFixed(4)} SOL`);
    lines.push(`  - Executable    : ${result.executable}`);
    if (result.isHijackedWalletOwner) {
      lines.push("  - Warning       : [!] Non-executable wallet owned by custom program");
    }
    if (result.programAudit) {
      lines.push(`  - ProgramData   : ${result.programAudit.programDataAddress}`);
      lines.push(
        `  - UpgradeAuth   : ${result.programAudit.upgradeAuthority || "Immutable (None)"}`
      );
      lines.push(`  - Verdict       : ${result.programAudit.verdict}`);
    }
  }

  return lines.join("\n");
}

/**
 * Parses CLI flags and executes the wallet scan.
 *
 * @param {string[]} argv
 * @param {{ log?: Function, error?: Function }} [io]
 */
export async function runCli(argv = process.argv.slice(2), io = {}) {
  const log = io.log || console.log;
  const err = io.error || console.error;

  const args = [...argv];
  if (args.includes("--help") || args.includes("-h")) {
    printUsage(log);
    return { exitCode: 0 };
  }

  const demo = args.includes("--demo");
  const jsonOutput = args.includes("--json");
  const positional = args.filter((a) => !a.startsWith("-"));

  let target = "";
  let shredRaw = "15";

  if (demo) {
    if (positional[0] && /^\d+$/.test(positional[0])) {
      target = DEMO_TARGET_ADDRESS;
      shredRaw = positional[0];
    } else {
      target = positional[0] || DEMO_TARGET_ADDRESS;
      shredRaw = positional[1] || "15";
    }
  } else {
    target = positional[0] || "";
    shredRaw = positional[1] || "15";
  }

  if (!target) {
    printUsage(err);
    return { exitCode: 1 };
  }

  const shredCount = Math.min(Math.max(parseInt(shredRaw, 10) || 15, 1), 50);
  const result = await scanAddress(target, { demo, shredCount });

  if (jsonOutput) {
    log(JSON.stringify(result, null, 2));
  } else {
    log(formatScanReport(result));
  }

  return { exitCode: 0, result };
}

const isDirectRun = (() => {
  if (!process.argv[1]) return false;
  try {
    const resolvedArg = realpathSync(path.resolve(process.argv[1]));
    const resolvedSelf = realpathSync(new URL(import.meta.url));
    return pathToFileURL(resolvedArg).href === pathToFileURL(resolvedSelf).href;
  } catch {
    return pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
  }
})();

if (isDirectRun) {
  runCli().then(({ exitCode }) => {
    if (exitCode !== 0) process.exitCode = exitCode;
  });
}
