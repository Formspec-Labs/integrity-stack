/** @filedesc Vitest configuration for the TypeScript integrity canonical handoff package. */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
  },
});
