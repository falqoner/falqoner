import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    // Use the core package's TypeScript sources so the app and the engine
    // stay in lockstep without a build step between them.
    alias: { '@falqoner/core': new URL('../../packages/core/src/index.ts', import.meta.url).pathname },
  },
  server: { port: 5173 },
  // Bundled packages' own license texts, beside public/THIRD_PARTY_NOTICES.md.
  build: { license: { fileName: 'THIRD_PARTY_LICENSES.md' } },
});
