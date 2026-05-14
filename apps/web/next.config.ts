import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@athome/sdk", "@athome/protocol"],
  webpack(config) {
    config.resolve.extensionAlias = {
      ".js": [".ts", ".tsx", ".js", ".jsx"],
      ".jsx": [".tsx", ".jsx"],
    };
    return config;
  },
};

export default nextConfig;
