import type { NextConfig } from "next";

// Dev origins should be set via EDR_DEV_ORIGINS env var (comma-separated), not hardcoded.
const devOrigins = process.env.EDR_DEV_ORIGINS
  ? process.env.EDR_DEV_ORIGINS.split(",").map((s) => s.trim())
  : [];

const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8080";

// CSP connect-src includes the backend origin so fetch() calls are allowed.
const backendOrigin = (() => {
  try { return new URL(backendUrl).origin; } catch { return backendUrl; }
})();

const securityHeaders = [
  { key: "X-Frame-Options",           value: "DENY" },
  { key: "X-Content-Type-Options",    value: "nosniff" },
  { key: "Referrer-Policy",           value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy",        value: "geolocation=(), microphone=(), camera=()" },
  { key: "X-XSS-Protection",         value: "1; mode=block" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",   // Next.js requires unsafe-inline for hydration
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data: https://fonts.gstatic.com",
      `connect-src 'self' ${backendOrigin}`,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  ...(devOrigins.length > 0 ? { allowedDevOrigins: devOrigins } : {}),
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
