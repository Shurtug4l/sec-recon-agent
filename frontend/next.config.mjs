/** @type {import('next').NextConfig} */
const nextConfig = {
  // Slim Docker images: bundles only the files actually used at runtime.
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  experimental: {
    // Allow SSE / streaming response from API routes without the App Router
    // wrapping them.
    proxyTimeout: 600_000,
  },
};

export default nextConfig;
