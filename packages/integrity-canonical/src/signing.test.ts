import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalResponseHandoffBytes, canonicalResponseSignedPayloadBytes, parseJsonExact } from './index.js';
const hex = (bytes: Uint8Array): string => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const fixture = JSON.parse(readFileSync(new URL('../../../tests/fixtures/response-signing/vectors.json', import.meta.url), 'utf8'));
describe('independent shared signing profile vectors', () => {
  for (const vector of fixture.valid) {
    it(vector.name, async () => {
      for (const raw of vector.inputJson) {
        const response = parseJsonExact(raw);
        const before = JSON.stringify(response);
        const bytes = canonicalResponseSignedPayloadBytes(response);
        expect(hex(bytes)).toBe(vector.bytesHex);
        expect(new TextDecoder().decode(bytes)).toBe(`formspec.response.signed-payload.v1\0${vector.canonicalJson}`);
        expect(hex(new Uint8Array(await webcrypto.subtle.digest('SHA-256', bytes)))).toBe(vector.sha256);
        expect(JSON.stringify(response)).toBe(before);
      }
    });
  }
  for (const vector of fixture.invalid) {
    it(`refuses ${vector.name}`, () => expect(() => canonicalResponseSignedPayloadBytes(parseJsonExact(vector.inputJson))).toThrow());
  }
  it('preserves all other emitted fields including nested signature names', () => {
    const vector = fixture.valid.find((v: { name: string }) => v.name === 'retained-members-and-cosignature-stability');
    const base = JSON.parse(vector.inputJson[0]);
    for (const field of Object.keys(base)) {
      const changed = { ...base, [field]: { changed: true } };
      expect(hex(canonicalResponseSignedPayloadBytes(changed))).not.toBe(vector.bytesHex);
    }
    const changed = structuredClone(base);
    changed.extensions.authoredSignatures = ['changed'];
    expect(hex(canonicalResponseSignedPayloadBytes(changed))).not.toBe(vector.bytesHex);
  });
  it('uses a distinct domain even without signatures', () => {
    const response = { data: null };
    expect(canonicalResponseSignedPayloadBytes(response)).not.toEqual(canonicalResponseHandoffBytes(response));
  });
  it('validates the omitted subtree without invoking its accessor', () => {
    let calls = 0;
    const response = { get authoredSignatures() { calls++; return []; } };
    expect(() => canonicalResponseSignedPayloadBytes(response)).toThrow(TypeError);
    expect(calls).toBe(0);
    for (const invalid of [undefined, NaN, 1n, () => 1, new Date(0), Array(2)]) {
      expect(() => canonicalResponseSignedPayloadBytes({ authoredSignatures: invalid })).toThrow(TypeError);
    }
  });
});
