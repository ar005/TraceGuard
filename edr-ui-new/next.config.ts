import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: [
    "0.0.0.0",
    "100.123.224.3",
    "100.94.38.92",
    "traceedr.ianimesh.com",
  ],
};

export default nextConfig;