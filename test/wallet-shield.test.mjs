import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ZERO_ADDR,
  installFirewall,
  inspect7702Payload,
  wrapProvider7702,
} from "../browser/wallet-shield-firewall.js";
import { runCli } from "../src/cli.mjs";
import {
  ZERO_ADDRESS,
  buildAscendingNonceShredPlan,
  buildEip7702NullTupleRlpPreimage,
  buildEip7702TupleRlpPreimage,
  rlpEncodeUint,
} from "../src/rlp.mjs";
import {
  DEMO_MSCA_OWNER,
  DEMO_SWEEPER_DELEGATE,
  DEMO_TARGET_ADDRESS,
  EVM_CHAINS,
  inspectDelegateBytecode,
  scanAddress,
  scanEvmAddress,
  scanSolanaAddress,
} from "../src/scanner.mjs";

const SYNTHETIC_WALLET = "0x000000000000000000000000000000000000dEaD";
const SYNTHETIC_SWEEPER = "0x000000000000000000000000000000000000bEEF";
const SYNTHETIC_OWNER = "0x000000000000000000000000000000000000cAFE";

describe("RLP & EIP-7702 Type-0x04 Nonce Cleaner", () => {
  it("encodes RLP unsigned integers across boundary conditions", () => {
    assert.equal(rlpEncodeUint(0), "80");
    assert.equal(rlpEncodeUint(1), "01");
    assert.equal(rlpEncodeUint(127), "7f");
    assert.equal(rlpEncodeUint(128), "8180");
    assert.equal(rlpEncodeUint(255), "81ff");
    assert.equal(rlpEncodeUint(256), "820100");
    assert.equal(rlpEncodeUint(42161), "82a4b1");
    assert.throws(() => rlpEncodeUint(-1), RangeError);
  });

  it("builds exact 0x05 null-delegation RLP preimages", () => {
    assert.equal(
      buildEip7702NullTupleRlpPreimage(1, 0),
      "0x05d70194000000000000000000000000000000000000000080"
    );
    assert.equal(
      buildEip7702NullTupleRlpPreimage(1, 42),
      "0x05d7019400000000000000000000000000000000000000002a"
    );
    assert.equal(
      buildEip7702NullTupleRlpPreimage(0, 42),
      "0x05d7809400000000000000000000000000000000000000002a"
    );
    assert.equal(
      buildEip7702TupleRlpPreimage(8453, SYNTHETIC_SWEEPER, 7),
      "0x05d982210594000000000000000000000000000000000000beef07"
    );
  });

  it("generates strictly ascending sequential nonce shredder plans", () => {
    const plan = buildAscendingNonceShredPlan(1, 42, 15);
    assert.equal(plan.txType, "0x04");
    assert.equal(plan.chainId, 1);
    assert.equal(plan.startNonce, 42);
    assert.equal(plan.count, 15);
    assert.equal(plan.finalSafeNonce, 57);
    assert.equal(plan.tuples.length, 15);

    plan.tuples.forEach((tuple, idx) => {
      assert.equal(tuple.index, idx);
      assert.equal(tuple.nonce, 42 + idx);
      assert.equal(tuple.targetDelegate, ZERO_ADDRESS);
      assert.ok(tuple.rlpPreimage0x05.startsWith("0x05d70194"));
    });
  });
});

describe("7-Chain EVM & Solana Scanner", () => {
  it("runs deterministic offline 7-chain demo scan in milliseconds", async () => {
    const res = await scanEvmAddress(DEMO_TARGET_ADDRESS, { demo: true, shredCount: 12 });
    assert.equal(res.type, "EVM");
    assert.equal(res.mode, "demo");
    assert.equal(res.chains.length, 7);
    assert.equal(res.summary.infectedChains, 1);
    assert.equal(res.summary.secondHopChains, 1);

    const eth = res.chains.find((c) => c.chainId === 1);
    assert.equal(eth.status, "INFECTED_7702");
    assert.equal(eth.delegateAddress, DEMO_SWEEPER_DELEGATE);
    assert.equal(eth.delegateHasSweeperOpcodes, true);
    assert.deepEqual(eth.sweeperSelectors, ["0xa9059cbb", "0x043ff9d2"]);
    assert.equal(eth.nonce, 42);
    assert.equal(eth.finalNonceAfterShred, 54);

    const arb = res.chains.find((c) => c.chainId === 42161);
    assert.equal(arb.status, "MSCA_SECOND_HOP_RISK");
    assert.equal(arb.mscaOwner, DEMO_MSCA_OWNER);
    assert.equal(arb.mscaOwnerIsPlainEoa, true);
    assert.equal(arb.mscaOwnerStableUsd, 25000);

    const avax = res.chains.find((c) => c.chainId === 43114);
    assert.equal(avax.status, "CONTRACT_IMMUNE");
  });

  it("detects active 0xef0100 sweeper, second-hop MSCA owner, and plain EOA with custom mocked RPC", async () => {
    const mockRpc = async (rpcUrl, method, params) => {
      const target = String(params?.[0]?.to || params?.[0] || "").toLowerCase();
      const data = String(params?.[0]?.data || "").toLowerCase();

      if (rpcUrl === EVM_CHAINS[0].rpc) {
        if (method === "eth_getCode") {
          if (target === SYNTHETIC_SWEEPER.toLowerCase()) return "0x600063043ff9d200";
          return "0xef0100" + SYNTHETIC_SWEEPER.slice(2).toLowerCase();
        }
        if (method === "eth_getTransactionCount") return "0x10";
        if (method === "eth_getBalance") return "0xde0b6b3a7640000";
      }

      if (rpcUrl === EVM_CHAINS[2].rpc) {
        if (method === "eth_getCode") {
          if (target === SYNTHETIC_OWNER.toLowerCase()) return "0x";
          return "0x363d3d373d3d3d363d73" + "aa".repeat(40);
        }
        if (method === "eth_call" && data === "0x66b46a7a") {
          return "0x" + SYNTHETIC_OWNER.slice(2).toLowerCase().padStart(64, "0");
        }
        if (method === "eth_getTransactionCount") return "0x5";
      }

      if (method === "eth_getCode") return "0x";
      if (method === "eth_getTransactionCount") return "0x0";
      if (method === "eth_getBalance") return "0x0";
      return "0x";
    };

    const report = await scanEvmAddress(SYNTHETIC_WALLET, { rpcCall: mockRpc, shredCount: 10 });
    assert.equal(report.chains.length, 7);
    assert.equal(report.summary.infectedChains, 1);
    assert.equal(report.summary.secondHopChains, 1);

    const baseRow = report.chains.find((c) => c.chainId === 8453);
    assert.equal(baseRow.status, "MSCA_SECOND_HOP_RISK");
    assert.equal(baseRow.mscaOwner, SYNTHETIC_OWNER.toLowerCase());
    assert.equal(baseRow.mscaOwnerIsPlainEoa, true);

    const optRow = report.chains.find((c) => c.chainId === 10);
    assert.equal(optRow.status, "PLAIN_EOA_EXPOSED");
  });

  it("classifies plain EOA across all 7 chains when no delegation exists", async () => {
    const plainRpc = async (_url, method) => {
      if (method === "eth_getCode") return "0x";
      if (method === "eth_getTransactionCount") return "0x3";
      if (method === "eth_getBalance") return "0x0";
      return "0x";
    };
    const report = await scanAddress(SYNTHETIC_WALLET, { rpcCall: plainRpc });
    assert.equal(report.summary.infectedChains, 0);
    assert.equal(report.summary.secondHopChains, 0);
    assert.match(report.summary.overallRisk, /EXPOSED EOA/);
  });

  it("audits Solana executable ProgramData single-EOA UpgradeAuthority", async () => {
    const solReport = await scanSolanaAddress("So11111111111111111111111111111111111111112", {
      demo: true,
    });
    assert.equal(solReport.type, "SOLANA");
    assert.equal(solReport.executable, true);
    assert.equal(solReport.programAudit.upgradeAuthorityIsPlainEoa, true);
    assert.match(solReport.programAudit.verdict, /SINGLE-POINT-OF-FAILURE/);
  });

  it("inspects delegate bytecode selectors accurately", () => {
    assert.deepEqual(inspectDelegateBytecode("0x608063a9059cbb00"), {
      hasSweeperOpcodes: true,
      matchedSelectors: ["0xa9059cbb"],
    });
    assert.deepEqual(inspectDelegateBytecode("0x6080604052"), {
      hasSweeperOpcodes: false,
      matchedSelectors: [],
    });
  });

  it("executes CLI --demo and handles missing address cleanly", async () => {
    const logs = [];
    const ok = await runCli(["--demo", "8"], { log: (line) => logs.push(line) });
    assert.equal(ok.exitCode, 0);
    assert.match(logs.join("\n"), /ACTIVE 0xef0100/);

    const errs = [];
    const missing = await runCli([], { error: (line) => errs.push(line) });
    assert.equal(missing.exitCode, 1);
  });
});

describe("Browser 0x05 & EIP-6963 Signer Firewall", () => {
  it("wraps provider idempotently and blocks all 4 EIP-7702 attack vectors", async () => {
    const prompts = [];
    const calls = [];
    const mockProvider = {
      request: async (payload) => {
        calls.push(payload.method);
        return "0xok";
      },
      sendAsync(payload, cb) {
        cb(null, { result: payload.method });
      },
      send(methodOrPayload, params) {
        return { methodOrPayload, params };
      },
    };

    wrapProvider7702(mockProvider, {
      confirmFn: (msg) => {
        prompts.push(msg);
        return false;
      },
    });
    assert.equal(mockProvider.__walletShield7702Installed, true);

    // Vector 1: Unauthorized wallet_signAuthorization to sweeper contract
    await assert.rejects(
      () =>
        mockProvider.request({
          method: "wallet_signAuthorization",
          params: [{ contractAddress: SYNTHETIC_SWEEPER, chainId: 1, nonce: 4 }],
        }),
      /Unauthorized EIP-7702 \(0x05\) code delegation rejected/
    );
    assert.match(prompts.at(-1), /\[WALLET-SHIELD 7702 ALERT\]/);

    // Vector 2: Cross-chain wildcard replay tuple (chainId === 0)
    await assert.rejects(
      () =>
        mockProvider.request({
          method: "eth_signAuthorization",
          params: [{ address: SYNTHETIC_SWEEPER, chainId: 0, nonce: 0 }],
        }),
      /Cross-chain wildcard \(chainId=0\)/
    );
    assert.match(prompts.at(-1), /WILDCARD ALL-CHAIN REPLAY RISK/);

    // Vector 3: Type-0x04 transaction carrying non-zero authorizationList
    await assert.rejects(
      () =>
        mockProvider.request({
          method: "eth_sendTransaction",
          params: [
            {
              to: SYNTHETIC_WALLET,
              authorizationList: [{ address: SYNTHETIC_SWEEPER, chainId: 8453, nonce: 2 }],
            },
          ],
        }),
      /Type-0x04 sweeper delegation rejected/
    );

    // Vector 4: Raw 0x05 RLP preimage blind-signing via personal_sign and eth_sign
    const rawPreimage = buildEip7702TupleRlpPreimage(1, SYNTHETIC_SWEEPER, 5);
    await assert.rejects(
      () =>
        mockProvider.request({
          method: "personal_sign",
          params: [rawPreimage, SYNTHETIC_WALLET],
        }),
      /Raw 0x05 EIP-7702 RLP preimage blind-signing blocked/
    );

    assert.throws(
      () => mockProvider.send("eth_sign", [SYNTHETIC_WALLET, "0x05c80194"]),
      /Raw 0x05 EIP-7702 RLP preimage blind-signing blocked/
    );

    let asyncErr = null;
    mockProvider.sendAsync(
      { method: "eth_sign", params: [SYNTHETIC_WALLET, rawPreimage] },
      (err) => {
        asyncErr = err;
      }
    );
    assert.match(asyncErr?.message || "", /blind-signing blocked/);
    assert.equal(calls.length, 0);
  });

  it("permits 0x0000000000000000000000000000000000000000 null-delegation revocations", async () => {
    const mockProvider = {
      request: async () => "0xsigned_revocation",
    };
    wrapProvider7702(mockProvider, { confirmFn: () => false });

    const sig = await mockProvider.request({
      method: "wallet_signAuthorization",
      params: [{ contractAddress: ZERO_ADDR, chainId: 1, nonce: 42 }],
    });
    assert.equal(sig, "0xsigned_revocation");

    const shredTx = await mockProvider.request({
      method: "eth_sendTransaction",
      params: [
        {
          to: SYNTHETIC_WALLET,
          authorizationList: [
            { address: ZERO_ADDR, chainId: 1, nonce: 42 },
            { address: ZERO_ADDR, chainId: 1, nonce: 43 },
          ],
        },
      ],
    });
    assert.equal(shredTx, "0xsigned_revocation");
  });

  it("hooks EIP-6963 multi-injected providers via installFirewall", () => {
    const listeners = {};
    const primaryProvider = { request: async () => "ok" };
    const announcedProvider = { request: async () => "ok" };
    const fakeWindow = {
      ethereum: primaryProvider,
      addEventListener(eventName, handler) {
        listeners[eventName] = handler;
      },
    };

    installFirewall(fakeWindow, { confirmFn: () => false });
    assert.equal(primaryProvider.__walletShield7702Installed, true);
    assert.equal(typeof listeners["eip6963:announceProvider"], "function");

    listeners["eip6963:announceProvider"]({ detail: { provider: announcedProvider } });
    assert.equal(announcedProvider.__walletShield7702Installed, true);
    assert.equal(typeof fakeWindow.WalletShield7702.inspect7702Payload, "function");
  });
});
