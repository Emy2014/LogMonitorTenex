/**
 * Runtime proxy to the FastAPI backend.
 *
 * Why a route handler instead of next.config.ts `rewrites`: Next.js resolves
 * rewrite destinations at BUILD time into routes-manifest.json. In a container
 * build the API address is not known yet, so the build bakes in whatever
 * `API_URL` happened to be (or the default) and ignores the real value at
 * runtime. This handler reads `process.env.API_URL` per request, so the same
 * image runs unchanged against docker-compose (http://api:8000) and Cloud Run
 * (an https service URL).
 *
 * Keeping the browser on a single origin means no CORS configuration and a
 * first-party session cookie.
 */

import { NextRequest, NextResponse } from "next/server";

const API_URL = () => process.env.API_URL ?? "http://localhost:8000";

// Hop-by-hop and host-specific headers must not be forwarded.
//
// `expect` is included because undici (Node's fetch) rejects it outright with
// UND_ERR_NOT_SUPPORTED. curl adds `Expect: 100-continue` automatically for
// larger request bodies, so without this a big file upload fails while a small
// one succeeds.
const STRIP = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "expect",
]);

async function proxy(req: NextRequest, path: string[]) {
  const target = new URL(`/api/${path.join("/")}`, API_URL());
  target.search = req.nextUrl.search;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    if (!STRIP.has(key.toLowerCase())) headers.set(key, value);
  });

  const hasBody = req.method !== "GET" && req.method !== "HEAD";

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: req.method,
      headers,
      // Stream the body through, so large uploads are not buffered twice.
      body: hasBody ? req.body : undefined,
      // Required by undici whenever a stream is used as the body.
      ...(hasBody ? { duplex: "half" } : {}),
      redirect: "manual",
    } as RequestInit);
  } catch (err) {
    console.error(`proxy ${req.method} ${target.toString()} failed:`, err);
    return NextResponse.json({ detail: "Backend unavailable" }, { status: 502 });
  }

  const response = new NextResponse(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
  });

  upstream.headers.forEach((value, key) => {
    if (key.toLowerCase() !== "set-cookie" && !STRIP.has(key.toLowerCase())) {
      response.headers.set(key, value);
    }
  });

  // set-cookie can legitimately appear more than once, so it needs the
  // multi-value accessor rather than headers.get().
  for (const cookie of upstream.headers.getSetCookie()) {
    response.headers.append("set-cookie", cookie);
  }

  return response;
}

type Ctx = { params: Promise<{ path: string[] }> };

async function handler(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return proxy(req, path);
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;

// Never cache proxied API responses.
export const dynamic = "force-dynamic";
