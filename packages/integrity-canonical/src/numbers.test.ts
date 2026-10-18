import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { canonicalJsonBytes } from './index.js';

const { rawJSON } = JSON as unknown as { rawJSON(text: string): unknown };
const vectors: { valid: [string, string][]; invalid: string[] } = JSON.parse(
  readFileSync(new URL('../../../tests/fixtures/canonical-numbers/vectors.json', import.meta.url), 'utf8'),
);
const text = (value: unknown) => new TextDecoder().decode(canonicalJsonBytes(value));

describe('shared number vectors (tests/fixtures/canonical-numbers)', () => {
  it('lays out every valid number exactly as the oracle does', () => {
    for (const [input, expected] of vectors.valid) expect(text(rawJSON(input)), input).toBe(expected);
  });
  it('refuses every invalid number', () => {
    for (const input of vectors.invalid) expect(() => text(rawJSON(input)), input).toThrow();
  });
});
