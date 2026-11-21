/**
 * Standard Fetch / WinterCG Edge HTTP Handler for `evm-wallet-shield`.
 * Exposes `handleShieldRequest(request)` (`default.fetch`) and `onRequest(context)`
 * for serverless and edge runtimes without external dependencies.
 */

import { DEMO_TARGET_ADDRESS, scanAddress } from "../src/scanner.mjs";

export interface ShieldRequestPayload {
  address?: string;
  shredCount?: number;
  demo?: boolean;
}

export interface EdgeContext {
  request: Request;
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
};

export async function handleShieldRequest(
  request: Request,
  options: { rpcCall?: (...args: unknown[]) => Promise<unknown> } = {}
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  try {
    let address = "";
    let shredCount = 15;
    let demo = false;

    if (request.method === "POST") {
      const body = (await request.json().catch(() => ({}))) as ShieldRequestPayload;
      address = String(body?.address || "").trim();
      shredCount = Number(body?.shredCount || 15);
      demo = Boolean(body?.demo);
    } else {
      const url = new URL(request.url);
      address = (url.searchParams.get("address") || "").trim();
      shredCount = parseInt(url.searchParams.get("shredCount") || "15", 10);
      demo = url.searchParams.get("demo") === "1" || url.searchParams.get("demo") === "true";
    }

    if (!address && demo) {
      address = DEMO_TARGET_ADDRESS;
    }

    if (!address) {
      return new Response(
        JSON.stringify({ error: "Provide an EVM (0x...) or Solana address, or pass demo=1" }),
        { status: 400, headers: CORS_HEADERS }
      );
    }

    const clampedCount = Math.min(Math.max(Number.isFinite(shredCount) ? shredCount : 15, 1), 50);
    const result = await scanAddress(address, {
      shredCount: clampedCount,
      demo,
      rpcCall: options.rpcCall,
    });

    return new Response(JSON.stringify(result), { status: 200, headers: CORS_HEADERS });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Scan failed";
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}

export async function onRequest(context: EdgeContext): Promise<Response> {
  return handleShieldRequest(context.request);
}

export default {
  fetch: handleShieldRequest,
};
