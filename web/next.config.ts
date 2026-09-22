import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Traces only the files actually needed -- takes the runtime image from
  // ~1GB to ~150MB.
  output: "standalone",

  // NOTE: /api/* is proxied to FastAPI by src/app/api/[...path]/route.ts,
  // not by a rewrite here. Rewrite destinations are resolved at build time,
  // which cannot work when the API address is only known at runtime.
};

export default nextConfig;
