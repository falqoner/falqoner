import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [
    react(),
    {
      // Core's notices for the Falcon-1024 WebAssembly it embeds, beside the page.
      name: 'falcon-notices',
      generateBundle() {
        this.emitFile({
          type: 'asset',
          fileName: 'THIRD_PARTY_NOTICES.md',
          source: readFileSync(new URL('../../packages/core/THIRD_PARTY_NOTICES.md', import.meta.url)),
        });
      },
    },
  ],
  resolve: {
    // Use the core package's TypeScript sources so the app and the engine
    // stay in lockstep without a build step between them.
    alias: { '@falqoner/core': new URL('../../packages/core/src/index.ts', import.meta.url).pathname },
  },
  server: { port: 5173 },
  // Bundled packages' own license texts, beside THIRD_PARTY_NOTICES.md.
  build: { license: { fileName: 'THIRD_PARTY_LICENSES.md' } },
});
