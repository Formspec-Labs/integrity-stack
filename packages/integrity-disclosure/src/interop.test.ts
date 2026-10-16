/**
 * Interop oracle: OpenWallet Foundation's sd-jwt-js (`@sd-jwt/core`, pinned exact in package.json)
 * is an independent RFC 9901 implementation. It must accept what we issue and present, and we must
 * accept what it issues.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SDJwtInstance } from '@sd-jwt/core';
import { verify } from './index.js';
import { b64uDecode, b64uEncode, sha256, utf8, type Json } from './wire.js';
import { ISS, KID, PK_1, SEED_1, TYP, fromHex, pin } from './testkit.js';

const vectors = JSON.parse(
  readFileSync(new URL('../../../tests/fixtures/selective-disclosure/vectors.json', import.meta.url), 'utf8'),
);

const PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

/** sd-jwt-js wired to Ed25519 through Web Crypto: it brings no crypto of its own. */
async function oracle(seedHex: string, publicKeyHex: string, salts?: () => string) {
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(fromHex(seedHex), 16);
  const signKey = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']);
  const verifyKey = await crypto.subtle.importKey('raw', fromHex(publicKeyHex), 'Ed25519', false, ['verify']);
  return new SDJwtInstance({
    signAlg: 'EdDSA',
    hashAlg: 'sha-256',
    hasher: async (data, alg) => {
      expect(alg).toBe('sha-256');
      return sha256(typeof data === 'string' ? utf8(data) : new Uint8Array(data));
    },
    signer: async (data) => b64uEncode(new Uint8Array(await crypto.subtle.sign('Ed25519', signKey, utf8(data)))),
    verifier: async (data, sig) => crypto.subtle.verify('Ed25519', verifyKey, b64uDecode(sig), utf8(data)),
    saltGenerator: salts ? () => salts() : undefined,
  });
}

/** The claims sd-jwt-js should resolve for a presentation: public claims, iss, and disclosures. */
function expectedClaims(publicClaims: unknown, iss: string, disclosed: { path: string; value: Json }[]) {
  return { ...(publicClaims as object), iss, ...Object.fromEntries(disclosed.map((c) => [c.path, c.value])) };
}

describe('sd-jwt-js accepts what integrity-disclosure issues and presents', () => {
  it('resolves every Rust-issued presentation to the claims we verify', async () => {
    const instance = await oracle(SEED_1, PK_1);
    // sd-jwt-js refuses a disclosed name that already exists on the payload object, which includes
    // inherited `Object.prototype` names such as `__proto__`. Those presentations are left out of
    // the comparison; this package reads them correctly (see the shared vectors).
    let compared = 0;
    for (const issuance of vectors.issue) {
      for (const presentation of issuance.presentations) {
        if (presentation.paths.some((p: string) => p === '__proto__' || p === 'constructor')) continue;
        const ours = await verify(presentation.compact, [pin(KID, PK_1)], { expectedTyp: TYP, encoding: 'pinned' });
        const theirs = await instance.verify(presentation.compact);
        const { _sd_alg: _ignored, ...resolved } = theirs.payload as Record<string, unknown>;
        expect(resolved).toEqual(expectedClaims(ours.publicClaims, ours.iss, ours.disclosed));
        expect(theirs.header).toMatchObject({ alg: 'EdDSA', kid: KID, typ: TYP });
        compared += 1;
      }
    }
    expect(compared).toBeGreaterThanOrEqual(6);
  });

  it('rejects the same tampering we reject: a forged value, swapped salt or foreign key', async () => {
    const instance = await oracle(SEED_1, PK_1);
    const full = vectors.issue[1].presentations[2].compact as string;
    await expect(instance.verify(full)).resolves.toBeTruthy();
    const [jwt, ...disclosures] = full.split('~');
    const forged = `${jwt}~${b64uEncode(utf8(JSON.stringify([b64uEncode(new Uint8Array(16)), 'flag', true])))}~`;
    await expect(instance.verify(forged)).rejects.toThrow();
    expect(disclosures.length).toBeGreaterThan(1);
    const other = await oracle(SEED_1, 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511b');
    await expect(other.verify(full)).rejects.toThrow();
  });
});

describe('integrity-disclosure accepts what sd-jwt-js issues', () => {
  async function issueWithOracle() {
    let counter = 0;
    const instance = await oracle(SEED_1, PK_1, () => b64uEncode(new Uint8Array(16).fill(++counter)));
    const claims = { iss: ISS, accepted_at: '2026-10-16T12:00:00Z', name: 'Zoë', income: 42000.5, flag: true, nothing: null, list: [1, 'a'] };
    const compact = await instance.issue(claims, { _sd: ['name', 'income', 'flag', 'nothing', 'list'], _sd_decoy: 3 } as never, {
      header: { kid: KID, typ: TYP },
    });
    return { instance, compact, claims };
  }

  it('verifies a sd-jwt-js SD-JWT in RFC 9901 mode and resolves the same claims', async () => {
    const { instance, compact, claims } = await issueWithOracle();
    const presented = await instance.present(compact, { name: true, flag: true } as never);
    const ours = await verify(presented, [pin(KID, PK_1)], { expectedTyp: TYP, encoding: 'rfc9901' });
    expect(ours.iss).toBe(ISS);
    expect(ours.publicClaims).toEqual({ accepted_at: claims.accepted_at });
    expect(ours.disclosed.map((c) => [c.path, c.valueJcs]).sort()).toEqual([['flag', 'true'], ['name', '"Zoë"']]);
    const theirs = await instance.verify(presented);
    expect(theirs.payload).toMatchObject({ iss: ISS, name: 'Zoë', flag: true });
    expect(theirs.payload).not.toHaveProperty('income');
  });

  it('verifies the unfiltered sd-jwt-js SD-JWT, decoys included, and reads every value exactly', async () => {
    const { compact } = await issueWithOracle();
    const ours = await verify(compact, [pin(KID, PK_1)], { expectedTyp: TYP, encoding: 'rfc9901' });
    expect(Object.fromEntries(ours.disclosed.map((c) => [c.path, c.valueJcs]))).toEqual({
      name: '"Zoë"', income: '42000.5', flag: 'true', nothing: 'null', list: '[1,"a"]',
    });
  });

  it('still refuses that SD-JWT in pinned mode, because its header and payload are not JCS', async () => {
    const { compact } = await issueWithOracle();
    await expect(verify(compact, [pin(KID, PK_1)], { expectedTyp: TYP, encoding: 'pinned' })).rejects.toMatchObject({
      code: expect.stringMatching(/^(unsupported_header|malformed_json|non_canonical_disclosure)$/),
    });
  });
});
