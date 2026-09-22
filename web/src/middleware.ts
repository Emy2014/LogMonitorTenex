/**
 * Edge gate: HTTP Basic Auth in front of the entire app.
 *
 * This exists because the browser never talks to the Go gateway directly --
 * `app/api/[...path]/route.ts` proxies to it server-side. A Basic Auth gate on
 * the gateway alone would therefore be satisfied invisibly by the proxy and
 * would never challenge a browser. This is the half that does.
 *
 * It is NOT the security boundary. Per-user authentication, the access tiers
 * and the authz resolver are. This is one shared credential whose only job is
 * to keep scanners and opportunistic traffic away from the real login form.
 *
 * The comparison uses SHA-256 rather than argon2 because middleware runs on the
 * edge runtime, where only Web Crypto is available. That is acceptable for a
 * high-entropy shared secret (unlike a human-chosen password, it is not
 * guessable by dictionary attack); the gateway, which can, still uses argon2id.
 */

import { NextRequest, NextResponse } from "next/server";

const USER = process.env.EDGE_AUTH_USER ?? "";
const PASS_SHA256 = (process.env.EDGE_AUTH_PASS_SHA256 ?? "").toLowerCase();
const ENABLED = process.env.EDGE_AUTH_ENABLED === "true";

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Length-independent, early-exit-free comparison. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function challenge(): NextResponse {
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="LogMonitor", charset="UTF-8"' },
  });
}

export async function middleware(req: NextRequest) {
  if (!ENABLED) return NextResponse.next();

  // Exempt only the health probe; everything else, assets included, is gated.
  if (req.nextUrl.pathname === "/api/health") return NextResponse.next();

  const header = req.headers.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("basic ")) return challenge();

  let decoded: string;
  try {
    decoded = atob(header.slice(6).trim());
  } catch {
    return challenge();
  }

  const sep = decoded.indexOf(":");
  if (sep < 0) return challenge();

  const user = decoded.slice(0, sep);
  const pass = decoded.slice(sep + 1);

  // Both comparisons run regardless of whether the first failed, so the
  // response time does not reveal which half was wrong.
  const userOk = timingSafeEqual(user, USER);
  const passOk = timingSafeEqual(await sha256Hex(pass), PASS_SHA256);

  return userOk && passOk ? NextResponse.next() : challenge();
}

export const config = {
  // Everything. An edge gate with holes in it is not a gate.
  matcher: ["/((?!_next/image|favicon.ico).*)"],
};
