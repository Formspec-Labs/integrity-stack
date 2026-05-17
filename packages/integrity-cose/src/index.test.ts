/** @filedesc Unit tests for the TypeScript integrity COSE package. */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  COSE_LABEL_ARTIFACT_TYPE,
  COSE_LABEL_METHOD_URI,
  MAX_METHOD_URI_LEN,
  decodeCoseSign1,
  decodeCoseSign1WithMethodUri,
  deriveKid,
  detachedSignatureProtectedHeader,
  encodeCoseSign1,
  extractMethodUri,
  protectedHeaderBytesForAlg,
  protectedHeaderBytesWithSuiteId,
  resolvePayload,
  sigStructureBytes,
  substrateProtectedHeader,
} from './index';

const __dirname = dirname(fileURLToPath(import.meta.url));
const stackRoot = resolve(__dirname, '../../../..');
const adr0109TamperRoot = resolve(stackRoot, 'trellis/fixtures/vectors/tamper');
const hasAdr0109TamperFixtures = existsSync(adr0109TamperRoot);
const adr0109FixtureIt = hasAdr0109TamperFixtures ? it : it.skip;

describe('COSE_Sign1 helpers', () => {
  function retiredDispatchProtectedHeader(): Uint8Array {
    return new Uint8Array([
      0xa4, 0x01, 0x27, 0x04, 0x50, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x3a,
      0x00, 0x01, 0x00, 0x00, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x01,
    ]);
  }

  it('decodes detached COSE_Sign1 with alg and kid', () => {
    const protectedHeader = protectedHeaderBytesForAlg(-8, new Uint8Array([1, 2, 3]));
    const signature = new Uint8Array(64).fill(7);
    const encoded = encodeCoseSign1(protectedHeader, null, signature);

    const decoded = decodeCoseSign1(encoded);

    expect(decoded.alg).toBe(-8);
    expect(decoded.kid).toEqual(new Uint8Array([1, 2, 3]));
    expect(decoded.artifactType).toBeNull();
    expect(decoded.payload).toBeNull();
    expect(decoded.signature).toEqual(signature);
    expect(resolvePayload(decoded, new Uint8Array([9]))).toEqual(new Uint8Array([9]));
  });

  it('emits suite protected-header bytes matching the Rust golden vector', () => {
    const protectedHeader = protectedHeaderBytesWithSuiteId(new Uint8Array(16).fill(0x11), 1);

    expect(Array.from(protectedHeader)).toEqual([
      0xa4, 0x01, 0x27, 0x04, 0x50, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x3a, 0x00, 0x01,
      0x00, 0x00, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x01, 0x65, 0x65, 0x76, 0x65,
      0x6e, 0x74,
    ]);
  });

  it('round-trips substrate artifact_type', () => {
    const protectedHeader = substrateProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x22),
      1,
      'checkpoint',
    );
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    const decoded = decodeCoseSign1(encoded);

    expect(decoded.suiteId).toBe(1);
    expect(decoded.artifactType).toBe('checkpoint');
    expect(decoded.protectedHeader.get(COSE_LABEL_ARTIFACT_TYPE)).toBe('checkpoint');
  });

  it('rejects embedded payload mismatch', () => {
    const protectedHeader = protectedHeaderBytesForAlg(-8);
    const encoded = encodeCoseSign1(
      protectedHeader,
      new Uint8Array([1]),
      new Uint8Array([2]),
    );
    const decoded = decodeCoseSign1(encoded);
    expect(() => resolvePayload(decoded, new Uint8Array([3]))).toThrow(
      /embedded COSE payload does not match/,
    );
  });

  it('decodeCoseSign1 rejects the retired dispatch label', () => {
    const protectedHeader = retiredDispatchProtectedHeader();
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    expect(() => decodeCoseSign1(encoded)).toThrow(/RetiredDispatchLabelPresent/);
  });

  adr0109FixtureIt('classifies the committed unknown artifact_type tamper fixture', () => {
    const encoded = readFileSync(
      resolve(adr0109TamperRoot, '053-unknown-artifact-type/input-tampered-event.cbor'),
    );
    const decoded = decodeCoseSign1(encoded);

    expect(decoded.artifactType).toBe('x-adr0109-unknown');
    expect(new Set(['event', 'checkpoint', 'manifest']).has(decoded.artifactType ?? '')).toBe(
      false,
    );
  });

  adr0109FixtureIt('rejects the committed retired dispatch-label tamper fixture', () => {
    const encoded = readFileSync(
      resolve(adr0109TamperRoot, '054-retired-dispatch-label/input-tampered-event.cbor'),
    );

    expect(() => decodeCoseSign1(encoded)).toThrow(/RetiredDispatchLabelPresent/);
  });

  it('rejects duplicate protected-header labels', () => {
    const protectedHeader = new Uint8Array([0xa2, 0x01, 0x27, 0x01, 0x26]);
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array([1, 2, 3]));
    expect(() => decodeCoseSign1(encoded)).toThrow(/duplicate protected-header label/);
  });

  it('builds expected Sig_structure shape', () => {
    expect(
      Array.from(sigStructureBytes(new Uint8Array([0xa1, 0x01, 0x27]), new Uint8Array([1, 2]))),
    ).toEqual([
      0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
      0x43, 0xa1, 0x01, 0x27, 0x40, 0x42, 0x01, 0x02,
    ]);
  });

  it('derives a deterministic 16-byte kid', async () => {
    const kid = await deriveKid(1, new Uint8Array(32).fill(0x11));

    expect(Array.from(kid)).toEqual([
      0xc2, 0xad, 0x0a, 0x99, 0x77, 0x51, 0xe0, 0x40, 0x66, 0x91, 0x2f, 0xa4,
      0x90, 0xa9, 0x97, 0x6d,
    ]);
  });
});

describe('consumer detached-signature envelopes (ADR 0109)', () => {
  const SIG_METHOD_URI = 'urn:formspec:sig-method:ed25519-cose-sign1@1';
  const RECEIPT_METHOD_URI = 'urn:formspec:receipt-method:ed25519-cose-sign1@1';
  const SIG_PREFIX = 'urn:formspec:sig-method:';
  const RECEIPT_PREFIX = 'urn:formspec:receipt-method:';

  it('emits MAP_3 with alg, kid, and method_uri at label -65540', () => {
    const protectedHeader = detachedSignatureProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x33),
      SIG_METHOD_URI,
    );

    // 0xa3 = MAP_3, then alg(1)=-8 -> 01 27, kid label 04, bstr-16, 16 kid bytes
    expect(protectedHeader[0]).toBe(0xa3);
    expect(Array.from(protectedHeader.slice(1, 3))).toEqual([0x01, 0x27]);
    expect(Array.from(protectedHeader.slice(3, 5))).toEqual([0x04, 0x50]);
    expect(Array.from(protectedHeader.slice(21, 26))).toEqual([0x3a, 0x00, 0x01, 0x00, 0x03]);
    // tstr header for SIG_METHOD_URI (length 44 -> 0x78 0x2c)
    expect(Array.from(protectedHeader.slice(26, 28))).toEqual([0x78, 0x2c]);
    const decoded = new TextDecoder().decode(protectedHeader.slice(28));
    expect(decoded).toBe(SIG_METHOD_URI);
  });

  it('round-trips through decodeCoseSign1, surfacing methodUri', () => {
    const protectedHeader = detachedSignatureProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x44),
      RECEIPT_METHOD_URI,
    );
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64).fill(7));

    const decoded = decodeCoseSign1(encoded);

    expect(decoded.alg).toBe(-8);
    expect(decoded.kid).toEqual(new Uint8Array(16).fill(0x44));
    expect(decoded.methodUri).toBe(RECEIPT_METHOD_URI);
    expect(decoded.artifactType).toBeNull();
    expect(decoded.suiteId).toBeNull();
  });

  it('decodeCoseSign1WithMethodUri accepts an envelope whose URI matches the expected prefix', () => {
    const protectedHeader = detachedSignatureProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x55),
      SIG_METHOD_URI,
    );
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    const { cose, methodUri } = decodeCoseSign1WithMethodUri(encoded, SIG_PREFIX);

    expect(methodUri).toBe(SIG_METHOD_URI);
    expect(cose.methodUri).toBe(SIG_METHOD_URI);
  });

  it('decodeCoseSign1WithMethodUri rejects envelopes missing method_uri', () => {
    // Legacy alg-only header (label 1 only) — no method_uri at -65540.
    const protectedHeader = protectedHeaderBytesForAlg(-8, new Uint8Array([0xAA]));
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    expect(() => decodeCoseSign1WithMethodUri(encoded, SIG_PREFIX)).toThrow(
      new RegExp(`missing method_uri protected header \\(label ${COSE_LABEL_METHOD_URI}\\)`),
    );
  });

  it('decodeCoseSign1WithMethodUri rejects cross-domain prefix swap (sig-method routed as receipt-method)', () => {
    const protectedHeader = detachedSignatureProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x66),
      SIG_METHOD_URI,
    );
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    expect(() => decodeCoseSign1WithMethodUri(encoded, RECEIPT_PREFIX)).toThrow(
      /does not match expected prefix/,
    );
  });

  it('decodeCoseSign1WithMethodUri rejects cross-domain prefix swap (receipt-method routed as sig-method)', () => {
    // Inverse check; both directions of the disjoint subspaces must reject.
    const protectedHeader = detachedSignatureProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x77),
      RECEIPT_METHOD_URI,
    );
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    expect(() => decodeCoseSign1WithMethodUri(encoded, SIG_PREFIX)).toThrow(
      /does not match expected prefix/,
    );
  });

  it('extractMethodUri returns the URI value when prefix matches', () => {
    const protectedHeader = detachedSignatureProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x88),
      SIG_METHOD_URI,
    );
    const encoded = encodeCoseSign1(protectedHeader, new Uint8Array([1]), new Uint8Array(64));

    expect(extractMethodUri(encoded, SIG_PREFIX)).toBe(SIG_METHOD_URI);
  });

  it('decodeCoseSign1 rejects method_uri values over the byte cap', () => {
    const methodUri = 'a'.repeat(MAX_METHOD_URI_LEN + 1);
    const protectedHeader = detachedSignatureProtectedHeader(
      -8,
      new Uint8Array(16).fill(0x99),
      methodUri,
    );
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    expect(() => decodeCoseSign1(encoded)).toThrow(/MethodUriTooLong/);
  });
});
