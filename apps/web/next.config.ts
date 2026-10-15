import type { NextConfig } from "next";
import { fileURLToPath } from "node:url";

const monorepoRoot = fileURLToPath(new URL("../..", import.meta.url));

const nextConfig: NextConfig = {
  transpilePackages: ["@botguard/core"],
  // The Solidity compiler and EVM are large Node-only packages; load them at runtime instead of bundling.
  serverExternalPackages: ["solc", "@ethereumjs/evm", "@ethereumjs/util"],
  outputFileTracingRoot: monorepoRoot,
  turbopack: { root: monorepoRoot },
};

export default nextConfig;
