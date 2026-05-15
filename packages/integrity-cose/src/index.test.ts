/** @filedesc Unit tests for the TypeScript integrity COSE package. */
import { describe, expect, it } from 'vitest';
import {
  COSE_LABEL_PROFILE_ID,
  FORMSPEC_PROFILE_ID,
  WOS_PROFILE_ID,
  decodeCoseSign1,
  decodeFormspecCoseSign1,
  deriveKid,
  encodeCoseSign1,
  protectedHeaderBytesForAlg,
  protectedHeaderBytesForAlgWithProfileId,
  protectedHeaderBytesForFormspec,
  protectedHeaderBytesWithProfileId,
  resolvePayload,
  sigStructureBytes,
} from './index';

describe('COSE_Sign1 helpers', () => {
  it('decodes detached COSE_Sign1 with Formspec profile id', () => {
    const protectedHeader = protectedHeaderBytesForFormspec(-8, new Uint8Array([1, 2, 3]));
    const signature = new Uint8Array(64).fill(7);
    const encoded = encodeCoseSign1(protectedHeader, null, signature);

    const decoded = decodeCoseSign1(encoded);

    expect(decoded.alg).toBe(-8);
    expect(decoded.kid).toEqual(new Uint8Array([1, 2, 3]));
    expect(decoded.profileId).toBe(FORMSPEC_PROFILE_ID);
    expect(decoded.payload).toBeNull();
    expect(decoded.signature).toEqual(signature);
    expect(resolvePayload(decoded, new Uint8Array([9]))).toEqual(new Uint8Array([9]));
  });

  it('rejects missing Formspec profile id', () => {
    const protectedHeader = protectedHeaderBytesForAlg(-8, new Uint8Array([1, 2, 3]));
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    expect(() => decodeFormspecCoseSign1(encoded)).toThrow(
      `missing Formspec profile_id protected header (label ${COSE_LABEL_PROFILE_ID})`,
    );
  });

  it('rejects wrong Formspec profile id', () => {
    const protectedHeader = protectedHeaderBytesForAlgWithProfileId(
      -8,
      new Uint8Array([1, 2, 3]),
      WOS_PROFILE_ID,
    );
    const encoded = encodeCoseSign1(protectedHeader, null, new Uint8Array(64));

    expect(() => decodeFormspecCoseSign1(encoded)).toThrow(
      `wrong Formspec profile_id: expected ${FORMSPEC_PROFILE_ID}, got ${WOS_PROFILE_ID}`,
    );
  });

  it('emits Formspec protected-header bytes with profile id 2', () => {
    const protectedHeader = protectedHeaderBytesForFormspec(-8, new Uint8Array(16).fill(0xaa));

    expect(Array.from(protectedHeader)).toEqual([
      0xa3, 0x01, 0x27, 0x04, 0x50, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x3a, 0x00, 0x01,
      0x00, 0x02, 0x02,
    ]);
  });

  it('emits suite protected-header bytes matching the Rust golden vector', () => {
    const protectedHeader = protectedHeaderBytesWithProfileId(new Uint8Array(16).fill(0x11), 1);

    expect(Array.from(protectedHeader)).toEqual([
      0xa4, 0x01, 0x27, 0x04, 0x50, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x3a, 0x00, 0x01,
      0x00, 0x00, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x01,
    ]);
  });

  it('rejects embedded payload mismatch', () => {
    const protectedHeader = protectedHeaderBytesForFormspec(-8);
    const encoded = encodeCoseSign1(
      protectedHeader,
      new Uint8Array([1]),
      new Uint8Array([2]),
    );
    const decoded = decodeFormspecCoseSign1(encoded);
    expect(() => resolvePayload(decoded, new Uint8Array([3]))).toThrow(
      /embedded COSE payload does not match/,
    );
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
