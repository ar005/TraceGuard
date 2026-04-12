import type { NextConfig } from "next";

// Dev origins should be set via EDR_DEV_ORIGINS env var (comma-separated), not hardcoded.
const devOrigins = process.env.EDR_DEV_ORIGINS
  ? process.env.EDR_DEV_ORIGINS.split(",").map((s) => s.trim())
  : [];

const nextConfig: NextConfig = {
  ...(devOrigins.length > 0 ? { allowedDevOrigins: devOrigins } : {}),
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.BACKEND_URL ?? "http://localhost:8080"}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;