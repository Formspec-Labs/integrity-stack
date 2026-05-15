/** @filedesc Vitest configuration for the TypeScript integrity COSE package. */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
  },
});
