/**
 * Interop proof for a presentation a real formspec-server issued.
 *
 * Not part of `npm test`: formspec-server's `sd_jwt_js_verifies_what_the_server_presented_and_rejects_a_tampered_disclosure`
 * writes the presentation and the agency's published `(iss, kid, key)` to the file named by
 * FORMSPEC_SERVER_PRESENTATION, then runs this file with `vitest.server.config.ts`. Without the
 * variable the suite fails; it never skips.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SDJwtInstance } from '@sd-jwt/core';
import { verify } from './index.js';
import { b64uDecode, b64uEncode, sha256, utf8 } from './wire.js';

interface ServerPresentation {
  presentation: string;
  iss: string;
  typ: string;
  kid: string;
  /** Ed25519 public key, base64url, exactly as GET /admin/attestation-issuer publishes it. */
  publicKey: string;
  /** Path to JCS text of every answer the request asked for. */
  disclosed: Record<string, string>;
  /** Values the response holds that the request did not ask for. */
  hidden: string[];
  /** Paths of the answers the request did not ask for. */
  hiddenPaths: string[];
}

const file = process.env.FORMSPEC_SERVER_PRESENTATION;

describe('sd-jwt-js and integrity-disclosure verify what formspec-server presented', () => {
  const served = (): ServerPresentation => {
    if (!file) throw new Error('FORMSPEC_SERVER_PRESENTATION names no server-written fixture');
    return JSON.parse(readFileSync(file, 'utf8'));
  };

  async function oracle(publicKey: string) {
    const key = await crypto.subtle.importKey('raw', b64uDecode(publicKey), 'Ed25519', false, ['verify']);
    return new SDJwtInstance({
      hashAlg: 'sha-256',
      hasher: async (data, alg) => {
        expect(alg).toBe('sha-256');
        return sha256(typeof data === 'string' ? utf8(data) : new Uint8Array(data));
      },
      verifier: async (data, sig) => crypto.subtle.verify('Ed25519', key, b64uDecode(sig), utf8(data)),
    });
  }

  it('shows the disclosed answers to an independent RFC 9901 verifier and hides the rest', async () => {
    const s = served();
    const theirs = await (await oracle(s.publicKey)).verify(s.presentation);
    const resolved = theirs.payload as Record<string, unknown>;
    expect(theirs.header).toMatchObject({ alg: 'EdDSA', kid: s.kid, typ: s.typ });
    expect(resolved.iss).toBe(s.iss);
    for (const [path, jcs] of Object.entries(s.disclosed)) expect(JSON.stringify(resolved[path])).toBe(jcs);
    for (const path of s.hiddenPaths) expect(Object.keys(resolved)).not.toContain(path);
    expect(s.hiddenPaths.length).toBeGreaterThan(0);

    // Neither the compact text nor any decoded disclosure carries a withheld value or path.
    const decoded = s.presentation.split('~').map((part) => {
      try {
        return new TextDecoder().decode(b64uDecode(part));
      } catch {
        return '';
      }
    });
    for (const hidden of s.hidden) {
      expect(s.presentation).not.toContain(hidden);
      for (const text of decoded) expect(text).not.toContain(hidden);
    }
    for (const path of s.hiddenPaths) for (const text of decoded) expect(text).not.toContain(path);

    const ours = await verify(s.presentation, [{ iss: s.iss, kid: s.kid, publicKey: b64uDecode(s.publicKey) }], {
      expectedTyp: s.typ,
      encoding: 'pinned',
    });
    expect(Object.fromEntries(ours.disclosed.map((c) => [c.path, c.valueJcs]))).toEqual(s.disclosed);
  });

  it('refuses the presentation once one disclosure is tampered with', async () => {
    const s = served();
    const [jwt, first, ...rest] = s.presentation.split('~');
    const [salt, path] = JSON.parse(new TextDecoder().decode(b64uDecode(first)));
    const forged = [jwt, b64uEncode(utf8(JSON.stringify([salt, path, 'forged']))), ...rest].join('~');
    await expect((await oracle(s.publicKey)).verify(forged)).rejects.toThrow();
    await expect(
      verify(forged, [{ iss: s.iss, kid: s.kid, publicKey: b64uDecode(s.publicKey) }], { expectedTyp: s.typ, encoding: 'pinned' }),
    ).rejects.toMatchObject({ code: expect.stringMatching(/unknown_digest|non_canonical_disclosure/) });
  });
});
