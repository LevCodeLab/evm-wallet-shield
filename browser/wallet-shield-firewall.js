/**
 * Wallet-Shield 7702 - Standalone Browser 0x05 & EIP-6963 Signer Firewall
 * License: MIT
 *
 * Guards injected EVM providers (MetaMask, Rabby, Coinbase Wallet, Phantom, Frame) against:
 *  1. Unauthorized EIP-7702 (0x05) code delegations (wallet_signAuthorization / eth_signAuthorization)
 *  2. Cross-chain wildcard replay tuples (chainId === 0 valid across every EVM chain simultaneously)
 *  3. Type-0x04 transactions carrying non-zero authorizationList / authorization_list sweeper targets
 *  4. Raw 0x05 RLP preimage blind-signing via eth_sign / personal_sign
 *  5. Multi-injected wallet bypasses announced over EIP-6963 (eip6963:announceProvider)
 */

export const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

function resolveConfirmFn(options) {
  if (options && typeof options.confirmFn === "function") {
    return options.confirmFn;
  }
  if (typeof window !== "undefined" && typeof window.confirm === "function") {
    return window.confirm.bind(window);
  }
  return () => false;
}

/**
 * Inspects a JSON-RPC signing or transaction payload and throws when an
 * unauthorized EIP-7702 delegation or raw 0x05 blind-signature is detected.
 * Null-address (0x0000...0000) revocations are permitted automatically.
 *
 * @param {{ method?: string, params?: unknown[] }} payload
 * @param {{ confirmFn?: (message: string) => boolean }} [options]
 */
export function inspect7702Payload(payload, options = {}) {
  const method = String(payload?.method || "");
  const params = Array.isArray(payload?.params) ? payload.params : [];
  const confirmPrompt = resolveConfirmFn(options);

  // 1. Direct EIP-7702 Authorization Signing
  if (method === "wallet_signAuthorization" || method === "eth_signAuthorization") {
    const auth = params[0] || {};
    const target = String(auth.contractAddress || auth.address || "").toLowerCase();
    const rawChainId = auth.chainId ?? auth.chain_id ?? 1;
    const cId = Number(rawChainId);

    if (target && target !== ZERO_ADDR) {
      const chainNote = cId === 0 ? "0 (WILDCARD ALL-CHAIN REPLAY RISK!)" : String(cId);
      const allow = confirmPrompt(
        `[WALLET-SHIELD 7702 ALERT]\n\n` +
          `A dApp is requesting an EIP-7702 (0x05) Code Delegation that hands execution control of your EOA to contract:\n` +
          `${target}\n` +
          `Chain ID: ${chainNote}\n\n` +
          `Press Cancel to BLOCK this delegation.`
      );
      if (!allow) {
        const reason =
          cId === 0
            ? "Cross-chain wildcard (chainId=0) EIP-7702 code delegation rejected."
            : "Unauthorized EIP-7702 (0x05) code delegation rejected.";
        throw new Error(`Blocked by Wallet-Shield 7702: ${reason}`);
      }
    }
  }

  // 2. Type-0x04 Transaction Carrying Non-Zero authorizationList
  if ((method === "eth_sendTransaction" || method === "eth_signTransaction") && params[0]) {
    const tx = params[0];
    const authList = tx.authorizationList || tx.authorization_list;
    if (Array.isArray(authList) && authList.length > 0) {
      const nonZero = authList.find((entry) => {
        const addr = String(entry?.address || entry?.contractAddress || "").toLowerCase();
        return Boolean(addr) && addr !== ZERO_ADDR;
      });
      if (nonZero) {
        const addr = String(nonZero.address || nonZero.contractAddress);
        const cId = Number(nonZero.chainId ?? nonZero.chain_id ?? 1);
        const chainNote = cId === 0 ? "0 (WILDCARD ALL-CHAIN REPLAY RISK!)" : String(cId);
        const allow = confirmPrompt(
          `[WALLET-SHIELD 7702 ALERT]\n\n` +
            `Type-0x04 Transaction contains an EIP-7702 authorizationList delegating your wallet to:\n${addr}\n` +
            `Chain ID: ${chainNote}\n\n` +
            `Press Cancel to BLOCK this sweeper delegation.`
        );
        if (!allow) {
          throw new Error("Blocked by Wallet-Shield 7702: Type-0x04 sweeper delegation rejected.");
        }
      }
    }
  }

  // 3. Raw 0x05 RLP Preimage Blind-Signing via eth_sign / personal_sign
  if (method === "eth_sign" || method === "personal_sign") {
    for (const p of params) {
      const rawHex = String(p || "").toLowerCase();
      if (/^0x05[c-f][0-9a-f]/.test(rawHex)) {
        throw new Error(
          "Blocked by Wallet-Shield 7702: Raw 0x05 EIP-7702 RLP preimage blind-signing blocked."
        );
      }
    }
  }
}

/**
 * Wraps an EIP-1193 / legacy Ethereum provider (`request`, `sendAsync`, `send`)
 * with Wallet-Shield 7702 payload inspection. Idempotent via `__walletShield7702Installed`.
 *
 * @param {Record<string, any>} prov
 * @param {{ confirmFn?: (message: string) => boolean }} [options]
 */
export function wrapProvider7702(prov, options = {}) {
  if (!prov || prov.__walletShield7702Installed) return prov;
  prov.__walletShield7702Installed = true;

  if (typeof prov.request === "function") {
    const origRequest = prov.request.bind(prov);
    prov.request = async function (payload) {
      inspect7702Payload(payload, options);
      return origRequest(payload);
    };
  }

  if (typeof prov.sendAsync === "function") {
    const origSendAsync = prov.sendAsync.bind(prov);
    prov.sendAsync = function (payload, cb) {
      try {
        inspect7702Payload(payload, options);
      } catch (err) {
        if (typeof cb === "function") return cb(err, null);
        throw err;
      }
      return origSendAsync(payload, cb);
    };
  }

  if (typeof prov.send === "function") {
    const origSend = prov.send.bind(prov);
    prov.send = function (methodOrPayload, paramsOrCb) {
      if (typeof methodOrPayload === "string") {
        inspect7702Payload({ method: methodOrPayload, params: paramsOrCb }, options);
      } else {
        inspect7702Payload(methodOrPayload, options);
      }
      return origSend(methodOrPayload, paramsOrCb);
    };
  }

  return prov;
}

/**
 * Installs Wallet-Shield 7702 on `window.ethereum`, `window.ethereum.providers`,
 * and any EIP-6963 providers announced via `eip6963:announceProvider`.
 *
 * @param {any} [targetWindow]
 * @param {{ confirmFn?: (message: string) => boolean }} [options]
 */
export function installFirewall(
  targetWindow = typeof window !== "undefined" ? window : undefined,
  options = {}
) {
  if (!targetWindow) return false;

  const sweepProviders = () => {
    if (targetWindow.ethereum) {
      wrapProvider7702(targetWindow.ethereum, options);
      if (Array.isArray(targetWindow.ethereum.providers)) {
        targetWindow.ethereum.providers.forEach((p) => wrapProvider7702(p, options));
      }
    }
  };

  sweepProviders();

  if (typeof targetWindow.addEventListener === "function" && !targetWindow.__walletShield6963Bound) {
    targetWindow.__walletShield6963Bound = true;
    targetWindow.addEventListener("eip6963:announceProvider", (ev) => {
      if (ev?.detail?.provider) {
        wrapProvider7702(ev.detail.provider, options);
      }
    });
  }

  targetWindow.WalletShield7702 = {
    ZERO_ADDR,
    inspect7702Payload,
    wrapProvider7702,
    installFirewall,
  };

  return true;
}

if (typeof window !== "undefined") {
  installFirewall(window);
  if (typeof setTimeout === "function") {
    setTimeout(() => installFirewall(window), 1000);
  }
}
