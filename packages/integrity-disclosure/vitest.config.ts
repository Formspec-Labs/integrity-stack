/** @filedesc Vitest configuration for the TypeScript integrity disclosure package. */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    // Needs a server-written fixture; run through vitest.server.config.ts.
    exclude: ['src/server-presentation.test.ts', 'node_modules/**'],
  },
});
