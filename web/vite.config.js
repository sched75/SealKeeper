// =============================================================================
// SealKeeper — JS bundle build (Vite, UMD output)
// =============================================================================
// PRD: module A §6.1 — bundle exposes the global `window.SealKeeper.Generation`
// namespace. We ship a single UMD file so the reveal page (served as static
// HTML by the Go backend) can <script src="...">it without a module loader.
//
// Output:
//   web/dist/sealkeeper-generation.umd.js   (consumed by the Go binary at /static)
//   web/dist/sealkeeper-generation.umd.js.map
//
// The Dockerfile copies web/dist into /app/web inside the image.
// =============================================================================

import { defineConfig } from "vite";

export default defineConfig({
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    // Vite 8 dropped esbuild from its required deps in favour of oxc (Rolldown
    // pipeline). Using "oxc" keeps the install lean and removes the GHSA
    // chain we picked up on esbuild as a transitive of Vite 6.
    minify: "oxc",
    lib: {
      entry: "src/index.js",
      name: "SealKeeperGeneration",
      formats: ["umd"],
      fileName: () => "sealkeeper-generation.umd.js",
    },
    rollupOptions: {
      output: {
        // Exposes as a global on the page. The library's index.js also
        // attaches itself to `window.SealKeeper.Generation` directly so both
        // import paths (UMD global + module re-export) work in tests.
        extend: true,
        // The default export is also exposed under the namespace; the named
        // exports are the real API and we want them at the top level.
        exports: "named",
      },
    },
  },
});
