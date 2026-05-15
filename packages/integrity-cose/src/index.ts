/** @filedesc Shared TypeScript COSE_Sign1 byte helpers. */

export const COSE_LABEL_ALG = 1;
export const COSE_LABEL_KID = 4;
export const COSE_LABEL_SUITE_ID = -65_537;
export const COSE_LABEL_PROFILE_ID = -65_539;
export const COSE_SIGN1_TAG = 18;
export const SUITE_ID_PHASE_1 = 1;
export const WOS_PROFILE_ID = 1;
export const FORMSPEC_PROFILE_ID = 2;

export interface CoseSign1 {
  protectedHeader: Map<number, unknown>;
  protectedHeaderBytes: Uint8Array;
  unprotectedHeader: Map<number, unknown>;
  payload: Uint8Array | null;
  signature: Uint8Array;
  alg: number | null;
  kid: Uint8Array | null;
  suiteId: number | null;
  profileId: number | null;
}

export class CoseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CoseError';
  }
}

type CborValue =
  | number
  | Uint8Array
  | string
  | boolean
  | null
  | CborTag
  | CborValue[]
  | Map<CborValue, CborValue>;

interface CborTag {
  tag: number;
  value: CborValue;
}

export function decodeCoseSign1(bytes: Uint8Array): CoseSign1 {
  const decoder = new CborDecoder(bytes);
  const root = decoder.read();
  decoder.assertDone();

  if (!isTag(root) || root.tag !== COSE_SIGN1_TAG) {
    throw new CoseError('value is not tagged COSE_Sign1');
  }
  if (!Array.isArray(root.value) || root.value.length !== 4) {
    throw new CoseError('COSE_Sign1 body must be a four-field array');
  }

  const [protectedValue, unprotectedValue, payloadValue, signatureValue] = root.value;
  if (!(protectedValue instanceof Uint8Array)) {
    throw new CoseError('protected header is not a byte string');
  }
  const protectedHeaderValue = new CborDecoder(protectedValue).readFully();
  if (!(protectedHeaderValue instanceof Map)) {
    throw new CoseError('protected header does not decode to a map');
  }
  if (!(unprotectedValue instanceof Map)) {
    throw new CoseError('unprotected header is not a map');
  }
  if (unprotectedValue.size !== 0) {
    throw new CoseError('unprotected header map must be empty');
  }
  const payload = payloadValue === null ? null : asBytes(payloadValue, 'payload');
  const signature = asBytes(signatureValue, 'signature');

  return {
    protectedHeader: protectedHeaderValue as Map<number, unknown>,
    protectedHeaderBytes: protectedValue,
    unprotectedHeader: unprotectedValue as Map<number, unknown>,
    payload,
    signature,
    alg: optionalIntegerLabel(protectedHeaderValue, COSE_LABEL_ALG),
    kid: optionalBytesLabel(protectedHeaderValue, COSE_LABEL_KID),
    suiteId: optionalUnsignedIntegerLabel(protectedHeaderValue, COSE_LABEL_SUITE_ID),
    profileId: optionalUnsignedIntegerLabel(protectedHeaderValue, COSE_LABEL_PROFILE_ID),
  };
}

export function decodeCoseSign1WithProfileId(
  bytes: Uint8Array,
  expectedProfileId: number,
  profileName = 'profile',
): CoseSign1 {
  const cose = decodeCoseSign1(bytes);
  if (cose.profileId === null) {
    throw new CoseError(
      `missing ${profileName} profile_id protected header (label ${COSE_LABEL_PROFILE_ID})`,
    );
  }
  if (cose.profileId !== expectedProfileId) {
    throw new CoseError(
      `wrong ${profileName} profile_id: expected ${expectedProfileId}, got ${cose.profileId}`,
    );
  }
  return cose;
}

export function decodeFormspecCoseSign1(bytes: Uint8Array): CoseSign1 {
  return decodeCoseSign1WithProfileId(bytes, FORMSPEC_PROFILE_ID, 'Formspec');
}

export function extractFormspecProfileId(bytes: Uint8Array): number {
  return decodeFormspecCoseSign1(bytes).profileId ?? unreachableProfileId();
}

export function resolvePayload(cose: CoseSign1, detachedPayload?: Uint8Array): Uint8Array {
  if (cose.payload === null) {
    if (!detachedPayload) {
      throw new CoseError('detached COSE payload was not supplied');
    }
    return detachedPayload;
  }
  if (detachedPayload && !bytesEqual(cose.payload, detachedPayload)) {
    throw new CoseError('embedded COSE payload does not match supplied signed bytes');
  }
  return cose.payload;
}

export function sigStructureBytes(protectedHeader: Uint8Array, payload: Uint8Array): Uint8Array {
  return concatBytes(
    new Uint8Array([0x84]),
    encodeText('Signature1'),
    encodeBytes(protectedHeader),
    new Uint8Array([0x40]),
    encodeBytes(payload),
  );
}

export function protectedHeaderBytesForAlg(alg: number, kid?: Uint8Array): Uint8Array {
  const fields = kid !== undefined ? 2 : 1;
  const chunks = [encodeMajorLen(5, fields), encodeInt(COSE_LABEL_ALG), encodeInt(alg)];
  if (kid !== undefined) {
    chunks.push(encodeInt(COSE_LABEL_KID), encodeBytes(kid));
  }
  return concatBytes(...chunks);
}

export function protectedHeaderBytesForAlgWithProfileId(
  alg: number,
  kid: Uint8Array | undefined,
  profileId: number,
): Uint8Array {
  const fields = kid !== undefined ? 3 : 2;
  const chunks = [encodeMajorLen(5, fields), encodeInt(COSE_LABEL_ALG), encodeInt(alg)];
  if (kid !== undefined) {
    chunks.push(encodeInt(COSE_LABEL_KID), encodeBytes(kid));
  }
  chunks.push(encodeInt(COSE_LABEL_PROFILE_ID), encodeInt(profileId));
  return concatBytes(...chunks);
}

export function protectedHeaderBytesForFormspec(alg: number, kid?: Uint8Array): Uint8Array {
  return protectedHeaderBytesForAlgWithProfileId(alg, kid, FORMSPEC_PROFILE_ID);
}

export function protectedHeaderBytesWithSuiteId(
  kid: Uint8Array,
  suiteId = SUITE_ID_PHASE_1,
): Uint8Array {
  if (kid.byteLength !== 16) {
    throw new CoseError('kid must be 16 bytes');
  }
  return concatBytes(
    new Uint8Array([0xa3]),
    encodeInt(COSE_LABEL_ALG),
    encodeInt(-8),
    encodeInt(COSE_LABEL_KID),
    encodeBytes(kid),
    encodeInt(COSE_LABEL_SUITE_ID),
    encodeInt(suiteId),
  );
}

export function protectedHeaderBytesWithProfileId(
  kid: Uint8Array,
  profileId: number,
  suiteId = SUITE_ID_PHASE_1,
): Uint8Array {
  if (kid.byteLength !== 16) {
    throw new CoseError('kid must be 16 bytes');
  }
  return concatBytes(
    new Uint8Array([0xa4]),
    encodeInt(COSE_LABEL_ALG),
    encodeInt(-8),
    encodeInt(COSE_LABEL_KID),
    encodeBytes(kid),
    encodeInt(COSE_LABEL_SUITE_ID),
    encodeInt(suiteId),
    encodeInt(COSE_LABEL_PROFILE_ID),
    encodeInt(profileId),
  );
}

export function encodeCoseSign1(
  protectedHeader: Uint8Array,
  payload: Uint8Array | null,
  signature: Uint8Array,
): Uint8Array {
  return concatBytes(
    new Uint8Array([0xd2, 0x84]),
    encodeBytes(protectedHeader),
    new Uint8Array([0xa0]),
    payload === null ? new Uint8Array([0xf6]) : encodeBytes(payload),
    encodeBytes(signature),
  );
}

export async function deriveKid(suiteId: number, publicKey: Uint8Array): Promise<Uint8Array> {
  if (publicKey.byteLength !== 32) {
    throw new CoseError('Ed25519 public key must be 32 bytes');
  }
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new CoseError('Web Crypto SHA-256 is unavailable');
  }
  const digest = new Uint8Array(
    await subtle.digest('SHA-256', concatBytes(encodeInt(suiteId), publicKey) as BufferSource),
  );
  return digest.slice(0, 16);
}

function optionalIntegerLabel(map: Map<CborValue, CborValue>, label: number): number | null {
  const value = map.get(label);
  if (value === undefined) {
    return null;
  }
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new CoseError(`COSE label ${label} is not an integer`);
  }
  return value;
}

function optionalUnsignedIntegerLabel(map: Map<CborValue, CborValue>, label: number): number | null {
  const value = optionalIntegerLabel(map, label);
  if (value === null) {
    return null;
  }
  if (value < 0) {
    throw new CoseError(`COSE label ${label} is not an unsigned integer`);
  }
  return value;
}

function optionalBytesLabel(map: Map<CborValue, CborValue>, label: number): Uint8Array | null {
  const value = map.get(label);
  if (value === undefined) {
    return null;
  }
  if (!(value instanceof Uint8Array)) {
    throw new CoseError(`COSE label ${label} is not bytes`);
  }
  return value;
}

function unreachableProfileId(): never {
  throw new CoseError('decodeFormspecCoseSign1 did not return profile_id');
}

function asBytes(value: CborValue, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  throw new CoseError(`${field} is not a byte string`);
}

function isTag(value: CborValue): value is CborTag {
  return typeof value === 'object' && value !== null && 'tag' in value && 'value' in value;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return a.every((byte, index) => byte === b[index]);
}

function encodeText(text: string): Uint8Array {
  const textBytes = new TextEncoder().encode(text);
  return concatBytes(encodeMajorLen(3, textBytes.byteLength), textBytes);
}

function encodeBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes(encodeMajorLen(2, bytes.byteLength), bytes);
}

function encodeInt(value: number): Uint8Array {
  if (!Number.isSafeInteger(value)) {
    throw new CoseError('CBOR integer must be a safe integer');
  }
  return value >= 0 ? encodeMajorLen(0, value) : encodeMajorLen(1, -1 - value);
}

function encodeMajorLen(major: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new CoseError('CBOR length must be a non-negative safe integer');
  }
  const header = major << 5;
  if (value <= 23) {
    return new Uint8Array([header | value]);
  }
  if (value <= 0xff) {
    return new Uint8Array([header | 24, value]);
  }
  if (value <= 0xffff) {
    return new Uint8Array([header | 25, value >> 8, value & 0xff]);
  }
  if (value <= 0xffffffff) {
    const out = new Uint8Array(5);
    out[0] = header | 26;
    new DataView(out.buffer).setUint32(1, value);
    return out;
  }
  throw new CoseError('64-bit CBOR lengths are not supported');
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

class CborDecoder {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  readFully(): CborValue {
    const value = this.read();
    this.assertDone();
    return value;
  }

  read(): CborValue {
    const initial = this.nextByte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    switch (major) {
      case 0:
        return this.readLen(additional);
      case 1:
        return -1 - this.readLen(additional);
      case 2:
        return this.readBytes(this.readLen(additional));
      case 3:
        return new TextDecoder('utf-8', { fatal: true }).decode(
          this.readBytes(this.readLen(additional)),
        );
      case 4:
        return this.readArray(this.readLen(additional));
      case 5:
        return this.readMap(this.readLen(additional));
      case 6:
        return { tag: this.readLen(additional), value: this.read() };
      case 7:
        return this.readSimple(additional);
      default:
        throw new CoseError(`unsupported CBOR major type ${major}`);
    }
  }

  assertDone(): void {
    if (this.offset !== this.bytes.byteLength) {
      throw new CoseError('trailing bytes after CBOR value');
    }
  }

  private readLen(additional: number): number {
    if (additional <= 23) {
      return additional;
    }
    if (additional === 24) {
      return this.nextByte();
    }
    if (additional === 25) {
      return (this.nextByte() << 8) | this.nextByte();
    }
    if (additional === 26) {
      if (this.offset + 4 > this.bytes.byteLength) {
        throw new CoseError('truncated CBOR length');
      }
      const view = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4);
      this.offset += 4;
      return view.getUint32(0);
    }
    throw new CoseError('indefinite or 64-bit CBOR lengths are not supported');
  }

  private readBytes(len: number): Uint8Array {
    if (this.offset + len > this.bytes.byteLength) {
      throw new CoseError('truncated CBOR byte string');
    }
    const out = this.bytes.slice(this.offset, this.offset + len);
    this.offset += len;
    return out;
  }

  private readArray(len: number): CborValue[] {
    return Array.from({ length: len }, () => this.read());
  }

  private readMap(len: number): Map<CborValue, CborValue> {
    const map = new Map<CborValue, CborValue>();
    for (let i = 0; i < len; i += 1) {
      const key = this.read();
      const value = this.read();
      if (typeof key === 'number' && map.has(key)) {
        throw new CoseError(`duplicate protected-header label ${key}`);
      }
      map.set(key, value);
    }
    return map;
  }

  private readSimple(additional: number): boolean | null {
    if (additional === 20) {
      return false;
    }
    if (additional === 21) {
      return true;
    }
    if (additional === 22) {
      return null;
    }
    throw new CoseError(`unsupported CBOR simple value ${additional}`);
  }

  private nextByte(): number {
    if (this.offset >= this.bytes.byteLength) {
      throw new CoseError('truncated CBOR value');
    }
    const byte = this.bytes[this.offset];
    this.offset += 1;
    return byte;
  }
}
