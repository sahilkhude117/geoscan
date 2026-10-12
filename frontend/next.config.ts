import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: { proxyTimeout: 65_000, useTypeScriptCli: false },
  async rewrites() {
    const backend = (process.env.GEOSCAN_API_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
    return [{ source: "/api/v1/:path*", destination: `${backend}/api/v1/:path*` }];
  },
};

export default nextConfig;
