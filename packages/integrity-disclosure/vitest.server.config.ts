/** @filedesc Vitest configuration for the formspec-server presentation interop proof. */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/server-presentation.test.ts'],
  },
});
