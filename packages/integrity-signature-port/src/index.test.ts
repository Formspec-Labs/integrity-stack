import { describe, expect, it } from 'vitest';

import {
  KeyResolverError,
  StaticKeyResolver,
  keyRefKid,
  keyRefRawPublicKey,
  resolveRegistryEntry,
  sanitizeReason,
  uri,
  type SignatureMethodRegistry,
} from './index.js';

describe('signature port helpers', () => {
  it('resolves kid key references through static byte-key lookup', async () => {
    const kid = new Uint8Array([1, 2, 3]);
    const publicKey = new Uint8Array([9, 8, 7]);
    const resolver = new StaticKeyResolver([[kid, publicKey]]);

    await expect(resolver.resolve(keyRefKid(new Uint8Array([1, 2, 3])))).resolves.toEqual(publicKey);
    expect(resolver.resolverId()).toBe(StaticKeyResolver.RESOLVER_ID);
  });

  it('rejects missing and raw public key references from the resolver path', async () => {
    const resolver = new StaticKeyResolver();

    await expect(resolver.resolve(keyRefKid(new Uint8Array([1])))).rejects.toMatchObject({
      code: 'key_not_found',
    } satisfies Partial<KeyResolverError>);
    await expect(
      resolver.resolve(keyRefRawPublicKey(new Uint8Array([1]))),
    ).rejects.toMatchObject({
      code: 'unsupported_key_ref',
    } satisfies Partial<KeyResolverError>);
  });

  it('sanitizes attacker-controlled reason text', () => {
    expect(sanitizeReason(' bad\u0000\n\t reason ')).toBe('bad reason');
  });

  it('resolves registry entries by method URI', () => {
    const method = uri('urn:integrity-stack:signature-method:ed25519@1');
    const registry: SignatureMethodRegistry = {
      version: '1.0.0' as SignatureMethodRegistry['version'],
      entries: [{ id: method, suite: 'Ed25519', wire: 'cose-sign1', alg: -8, status: 'registered' }],
    };

    expect(resolveRegistryEntry(registry, method)?.suite).toBe('Ed25519');
    expect(resolveRegistryEntry(registry, uri('urn:missing'))).toBeUndefined();
  });
});
