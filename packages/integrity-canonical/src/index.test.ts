import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalResponseHandoffBytes, canonicalResponseSignedPayloadBytes } from './index.js';

interface Vector {
  name: string;
  inputJson: string[];
  canonicalJson: string;
  bytesHex: string;
  sha256: string;
}
const vectors: { valid: Vector[]; invalid: { name: string; inputJson: string }[] } = JSON.parse(
  readFileSync(new URL('../../../tests/fixtures/response-handoff/vectors.json', import.meta.url), 'utf8'),
);
const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

describe('shared Rust / TS handoff wire vectors', () => {
  for (const vector of vectors.valid) {
    it(vector.name, async () => {
      for (const input of vector.inputJson) {
        const bytes = canonicalResponseHandoffBytes(JSON.parse(input));
        expect(hex(bytes)).toBe(vector.bytesHex);
        expect(new TextDecoder().decode(bytes)).toBe(`formspec.response.handoff.v1\0${vector.canonicalJson}`);
        const digest = await webcrypto.subtle.digest('SHA-256', bytes);
        expect(hex(new Uint8Array(digest))).toBe(vector.sha256);
      }
    });
  }
  for (const vector of vectors.invalid) {
    it(`refuses ${vector.name}`, () => {
      expect(() => canonicalResponseHandoffBytes(JSON.parse(vector.inputJson))).toThrow();
    });
  }
  it('signature content changes the full-Response handoff', () => {
    const signed = vectors.valid.find((vector) => vector.name === 'full-response-with-signature')!;
    const unsigned = vectors.valid.find((vector) => vector.name === 'same-response-without-signature')!;
    expect(signed.sha256).not.toBe(unsigned.sha256);
    const response = JSON.parse(signed.inputJson[0]);
    response.authoredSignatures[0].signatureValue = 'changed';
    expect(hex(canonicalResponseHandoffBytes(response))).not.toBe(signed.bytesHex);
  });
});

for (const produceBytes of [canonicalResponseHandoffBytes, canonicalResponseSignedPayloadBytes]) {
  describe(`${produceBytes.name} runtime JSON admission without lossy normalization`, () => {
    const cases: [string, unknown][] = [
      ['undefined property', { data: undefined }], ['undefined array value', { data: [undefined] }],
      ['function', { data: () => 1 }], ['function in array', { data: [() => 1] }],
      ['symbol value', { data: Symbol('data') }], ['symbol array value', { data: [Symbol('data')] }],
      ['bigint', { data: 1n }], ['NaN', { data: NaN }], ['infinity', { data: Infinity }],
      ['sparse array', { data: Array(2) }], ['date', { data: new Date(0) }],
      ['boxed number', { data: new Number(1) }], ['custom toJSON', { data: { toJSON: () => 'changed' } }],
      ['symbol key', { [Symbol('data')]: 1 }], ['nonenumerable property', Object.defineProperty({}, 'data', { value: 1 })],
    ];
    for (const [name, value] of cases) {
      it(`refuses ${name}`, () => expect(() => produceBytes(value)).toThrow(TypeError));
    }
    for (const [name, prototype, response] of [
      ['Object.prototype', Object.prototype, { data: 1 }],
      ['Array.prototype', Array.prototype, { data: [1] }],
    ] as const) {
      for (const accessor of [false, true]) {
        it(`refuses inherited ${name} toJSON ${accessor ? 'accessor' : 'function'}`, () => {
          const original = Object.getOwnPropertyDescriptor(prototype, 'toJSON');
          let calls = 0;
          const hook = () => { calls += 1; return null; };
          Object.defineProperty(prototype, 'toJSON', accessor
            ? { configurable: true, get: () => { calls += 1; return hook; } }
            : { configurable: true, value: hook });
          let error: unknown;
          try {
            produceBytes(response);
          } catch (caught) {
            error = caught;
          } finally {
            if (original) Object.defineProperty(prototype, 'toJSON', original);
            else Reflect.deleteProperty(prototype, 'toJSON');
          }
          expect(error).toBeInstanceOf(TypeError);
          expect(calls).toBe(0);
        });
      }
    }
    it('does not execute accessors', () => {
      let calls = 0;
      const value = { get data() { calls += 1; return 'not JSON'; } };
      expect(() => produceBytes(value)).toThrow(TypeError);
      expect(calls).toBe(0);
    });
    it('refuses cycles but allows repeated acyclic references', () => {
      const cyclic: Record<string, unknown> = {};
      cyclic.self = cyclic;
      expect(() => produceBytes(cyclic)).toThrow(TypeError);
      const child = { a: 1 };
      expect(produceBytes({ a: child, b: child })).toEqual(
        produceBytes({ a: { a: 1 }, b: { a: 1 } }),
      );
    });
    it('allows null-prototype JSON objects and explicit null values', () => {
      const response = Object.assign(Object.create(null), { data: null });
      expect(new TextDecoder().decode(produceBytes(response))).toBe(
        `${produceBytes === canonicalResponseHandoffBytes ? 'formspec.response.handoff.v1' : 'formspec.response.signed-payload.v1'}\0{"data":null}`,
      );
    });
    it('refuses array properties which JSON serialization would discard', () => {
      const array = [1];
      Object.assign(array, { extra: 2 });
      expect(() => produceBytes({ data: array })).toThrow(TypeError);
    });
    it('does not depend on cryptographic availability', () => {
      const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
      Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
      try {
        expect(produceBytes({ data: 1 })).toBeInstanceOf(Uint8Array);
      } finally {
        if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor);
        else Reflect.deleteProperty(globalThis, 'crypto');
      }
    });
  });
}
