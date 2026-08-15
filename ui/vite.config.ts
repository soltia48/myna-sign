import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

// Nothing is fetched at run time, so the bundle has to be self-contained: no CDN, no remote fonts.
// `assetsInlineLimit: 0` keeps assets as files rather than data URLs, which the CSP is happier with.
export default defineConfig({
  plugins: [preact()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: { target: "es2022", sourcemap: true },
});
