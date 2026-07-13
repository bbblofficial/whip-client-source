import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  experimental: {
    // Binary uploads (scan-leak watermark forensics) can be large.
    serverActions: {
      bodySizeLimit: "64mb",
    },
  },
};

export default nextConfig;
