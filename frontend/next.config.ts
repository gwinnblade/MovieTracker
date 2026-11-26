import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  cacheComponents: true,
  partialPrefetching: true,
  images: { unoptimized: true },
  async redirects() {
    return [
      { source: "/index", destination: "/", permanent: true },
      { source: "/my_list", destination: "/entries", permanent: true },
      { source: "/lists", destination: "/collections", permanent: true },
      {
        source: "/lists/:id",
        destination: "/collections/:id",
        permanent: true,
      },
    ];
  },
};
export default nextConfig;
