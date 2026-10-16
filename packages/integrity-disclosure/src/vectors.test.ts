import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { REFUSED_CLAIM_NAMES, disclosureDigest, verify, type Encoding } from './index.js';
import { buildDisclosures, issue, present, type ClaimInput, type IssuanceSalts } from './issue.js';
import { ISS, KID, TYP, fromHex } from './testkit.js';

interface Vectors {
  typ: string;
  refusedClaimNames: string[];
  issuer: { iss: string; kid: string; seedHex: string; publicKeyHex: string };
  publicClaims: Record<string, unknown>;
  issue: {
    name: string;
    claims: { path: string; value: unknown }[];
    salts: IssuanceSalts;
    jwt: string;
    disclosures: { path: string; encoded: string; digest: string }[];
    presentations: { paths: string[]; compact: string }[];
  }[];
  verify: {
    name: string;
    presentation: string;
    typ: string;
    encoding: Encoding;
    pins: { iss: string; kid: string; publicKeyHex: string }[];
    expect: { code: string } | { ok: { iss: string; kid: string; publicClaims: unknown; disclosed: { path: string; valueJcs: string }[] } };
  }[];
}

const vectors: Vectors = JSON.parse(
  readFileSync(new URL('../../../tests/fixtures/selective-disclosure/vectors.json', import.meta.url), 'utf8'),
);

describe('shared Rust / TS selective-disclosure wire vectors', () => {
  for (const vector of vectors.issue) {
    describe(vector.name, () => {
      const params = { iss: ISS, kid: KID, typ: TYP, publicClaims: vectors.publicClaims };
      const claims: ClaimInput[] = vector.claims.map((c) => [c.path, c.value]);
      const seed = fromHex(vectors.issuer.seedHex);

      it('issues a byte-identical issuer JWT and disclosures from the stored salts', async () => {
        const issued = await issue(params, claims, vector.salts, seed);
        expect(issued.jwt).toBe(vector.jwt);
        expect(issued.disclosures).toEqual(vector.disclosures);
      });
      it('rebuilds the committed digests from claims and salts', async () => {
        expect(await buildDisclosures([...claims].reverse(), vector.salts)).toEqual(vector.disclosures);
      });
      it('presents byte-identical allowlisted subsets', async () => {
        for (const presentation of vector.presentations) {
          expect(await present(vector.jwt, vector.disclosures, presentation.paths)).toBe(presentation.compact);
        }
      });
    });
  }

  for (const vector of vectors.verify) {
    it(`verify: ${vector.name} gives the same outcome as Rust`, async () => {
      const pins = vector.pins.map((p) => ({ iss: p.iss, kid: p.kid, publicKey: fromHex(p.publicKeyHex) }));
      const run = verify(vector.presentation, pins, { expectedTyp: vector.typ, encoding: vector.encoding });
      if ('code' in vector.expect) {
        await expect(run).rejects.toMatchObject({ code: vector.expect.code });
      } else {
        const result = await run;
        const want = vector.expect.ok;
        expect({
          iss: result.iss,
          kid: result.kid,
          publicClaims: result.publicClaims,
          disclosed: result.disclosed.map((c) => ({ path: c.path, valueJcs: c.valueJcs })),
        }).toEqual(want);
      }
    });
  }
});

describe('refused claim names', () => {
  it('are the same closed list, in the same order, as Rust', () => {
    expect([...REFUSED_CLAIM_NAMES]).toEqual(vectors.refusedClaimNames);
  });
});

describe('RFC 9901 examples', () => {
  it('hashes the section 4.2 family_name disclosure to the printed digest', async () => {
    const disclosure = 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0';
    expect(await disclosureDigest(disclosure)).toBe('X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0');
  });
  it('hashes the appendix A.1 top-level disclosures to the printed digests', async () => {
    const cases: [string, string][] = [
      ['WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN1YiIsICI2YzVjMGE0OS1iNTg5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiXQ', 'X6ZAYOII2vPN40V7xExZwVwz7yRmLNcVwt5DL8RLv4g'],
      ['WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiXHU1OTJhXHU5MGNlIl0', 'ommFAicVT8LGHCB0uywx7fYuo3MHYKO15cz-RZEYM5Q'],
      ['WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImZhbWlseV9uYW1lIiwgIlx1NWM3MVx1NzUzMCJd', 'C9inp6YoRaEXR427zYJP7Qrk1WH_8bdwOA_YUrUnGQU'],
      ['WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlciIsICIrODEtODAtMTIzNC01Njc4Il0', 's0BKYsLWxQQeU8tVlltM7MKsIRTrEIa1PkJmqxBBf5U'],
      ['WyJ5eXRWYmRBUEdjZ2wyckk0QzlHU29nIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0', 'MMldOFFzB2d0umlmpTIaGerhWdU_PpYfLvKhh_f_9aY'],
    ];
    for (const [disclosure, digest] of cases) expect(await disclosureDigest(disclosure)).toBe(digest);
  });
});
