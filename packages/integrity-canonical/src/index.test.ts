import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalJsonBytes, canonicalResponseHandoffBytes, canonicalResponseSignedPayloadBytes, parseJsonExact } from './index.js';

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
        const bytes = canonicalResponseHandoffBytes(parseJsonExact(input));
        expect(hex(bytes)).toBe(vector.bytesHex);
        expect(new TextDecoder().decode(bytes)).toBe(`formspec.response.handoff.v1\0${vector.canonicalJson}`);
        const digest = await webcrypto.subtle.digest('SHA-256', bytes);
        expect(hex(new Uint8Array(digest))).toBe(vector.sha256);
      }
    });
  }
  for (const vector of vectors.invalid) {
    it(`refuses ${vector.name}`, () => {
      expect(() => canonicalResponseHandoffBytes(parseJsonExact(vector.inputJson))).toThrow();
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
    it('serializes descriptor-admitted snapshots without Proxy value or toJSON reads', () => {
    let reads = 0;
    const nested = new Proxy({ value: 1 }, {
      get(_target, key) { reads++; return key === 'toJSON' ? () => ({ replaced: true }) : undefined; },
    });
    const root = new Proxy({ data: nested }, {
      get(_target, key) { reads++; return key === 'toJSON' ? () => ({ replaced: true }) : undefined; },
    });
    expect(produceBytes(root)).toEqual(produceBytes({ data: { value: 1 } }));
    expect(reads).toBe(0);
  });
  it('uses admitted array length and elements rather than Proxy value reads', () => {
    let reads = 0;
    const array = new Proxy([1, 2], { get() { reads++; return 99; } });
    expect(produceBytes({ data: array })).toEqual(produceBytes({ data: [1, 2] }));
    expect(reads).toBe(0);
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

describe('canonicalJsonBytes generic JCS', () => {
  it('serializes any JSON root with sorted keys and ES6 numbers, no framing', () => {
    const text = (value: unknown) => new TextDecoder().decode(canonicalJsonBytes(value));
    expect(text({ b: 1, a: [1e21, 4.5e-7, -0, 1.0, 9007199254740993] })).toBe('{"a":[1e+21,4.5e-7,0,1,9007199254740992],"b":1}');
    expect(text('x')).toBe('"x"');
    expect(text(null)).toBe('null');
  });
  it('refuses malformed Unicode and non-JSON values', () => {
    expect(() => canonicalJsonBytes('\ud800')).toThrow(TypeError);
    expect(() => canonicalJsonBytes(undefined)).toThrow(TypeError);
    expect(() => canonicalJsonBytes({ a: 1n })).toThrow(TypeError);
  });
});

describe('exact decimal numbers', () => {
  const { rawJSON } = JSON as unknown as { rawJSON(text: string): unknown };
  const text = (value: unknown) => new TextDecoder().decode(canonicalJsonBytes(value));
  it('keeps every digit of a number a double cannot hold, and keeps plain numbers plain', () => {
    const parsed = parseJsonExact('{"amount":1234567890.123456789,"rate":0.1,"big":9007199254740993}') as Record<string, unknown>;
    expect(parsed.rate).toBe(0.1);
    expect(typeof parsed.amount).toBe('object');
    expect(text(parsed)).toBe('{"amount":1234567890.123456789,"big":9007199254740993,"rate":0.1}');
    expect(text(JSON.parse('{"amount":1234567890.123456789}'))).toBe('{"amount":1234567890.1234567}');
  });
  it('lays out raw numbers like Number::toString and agrees with JS numbers a double holds', () => {
    for (const [raw, expected] of [
      ['-0.000e5', '0'], ['4.50', '4.5'], ['123e-2', '1.23'], ['0.000001', '0.000001'], ['1e-7', '1e-7'],
      ['1e20', '100000000000000000000'], ['1E30', '1e+30'], ['1e21', '1e+21'], ['5e-324', '5e-324'],
      ['-1.0000000000000000001', '-1.0000000000000000001'], ['1234567890123456789012', '1.234567890123456789012e+21'],
      ['0.0000001234567890123456789', '1.234567890123456789e-7'],
    ]) {
      expect(text(rawJSON(raw)), raw).toBe(expected);
    }
    for (const value of [0.1, 4.5e-7, 1e21, 123.456, -(2 ** 60), 5e-324]) {
      expect(text(rawJSON(String(value)))).toBe(text(value));
    }
  });
  it('refuses raw values that are not numbers or lie outside the binary64 range', () => {
    for (const raw of ['1e400', '-1e-400', '"x"', 'true', 'null']) {
      expect(() => canonicalJsonBytes({ data: rawJSON(raw) }), raw).toThrow(TypeError);
    }
    expect(() => canonicalResponseHandoffBytes(rawJSON('1'))).toThrow(TypeError);
  });
});
