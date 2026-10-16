/** Properties of issue, present and verify. Test names state the property proved. */
import { describe, expect, it } from 'vitest';
import { MAX_DISCLOSURES, MAX_PRESENTATION_BYTES, REFUSED_CLAIM_NAMES, SALT_BYTES, disclosureDigest, verify, type IssuerPin } from './index.js';
import {
  buildDisclosures, generateSalts, issue, issueWithRandom, osSecureRandom, paddedDigestCount, present, type ClaimInput, type IssueParams,
} from './issue.js';
import { ISS, KID, PK_1, PK_2, SEED_1, SEED_2, TYP, countingRandom, fromHex, headerText, pin, signRaw } from './testkit.js';
import { b64uDecode, b64uEncode, compareUtf8, utf8 } from './wire.js';

const params = (kid = KID): IssueParams => ({
  iss: ISS, kid, typ: TYP, publicClaims: { accepted_at: '2026-10-16T12:00:00Z', definition: { url: 'https://forms.example/intake' } },
});
const claimsA: ClaimInput[] = [
  ['applicant.name', 'Zoë Müller'], ['applicant.ssn_last4', '1234'], ['household[0].income', 100],
  ['household[1].income', 42000.5], ['flag', true], ['nothing', null], ['toJSON', 'p'], ['prototype', 'c'],
];
const pinned = { expectedTyp: TYP, encoding: 'pinned' } as const;
const lenient = { expectedTyp: TYP, encoding: 'rfc9901' } as const;
const pinsNow = (): IssuerPin[] => [pin(KID, PK_1)];

async function issueA(kid = KID, seed = SEED_1, start = 1) {
  return issueWithRandom(params(kid), claimsA, fromHex(seed), countingRandom(start));
}
const disc = (salt: string, path: string, value: unknown) => b64uEncode(utf8(JSON.stringify([salt, path, value])));
const salt = (n: number) => b64uEncode(new Uint8Array(SALT_BYTES).fill(n));
const sdPayload = (digests: string[], extra = '') =>
  `{"_sd":${JSON.stringify([...digests].sort())},"_sd_alg":"sha-256","iss":"${ISS}"${extra}}`;
async function crafted(disclosures: string[], extra = '') {
  return signRaw(SEED_1, headerText(), sdPayload(await Promise.all(disclosures.map(disclosureDigest)), extra));
}
const join = (jwt: string, disclosures: string[]) => `${jwt}~${disclosures.map((d) => `${d}~`).join('')}`;
const rejects = (promise: Promise<unknown>, code: string) => expect(promise).rejects.toMatchObject({ code });

describe('issuing and presenting', () => {
  it('verifies an issued presentation offline against the pinned key', async () => {
    const { issued } = await issueA();
    const verified = await verify(await present(issued.jwt, issued.disclosures, ['applicant.name', 'household[0].income']), pinsNow(), pinned);
    expect(verified.disclosed.map((c) => [c.path, c.valueJcs])).toEqual([['applicant.name', '"Zoë Müller"'], ['household[0].income', '100']]);
    expect(verified.publicClaims).toMatchObject({ accepted_at: '2026-10-16T12:00:00Z' });
  });

  it('puts only allowlisted values in the presentation and no aggregate hash', async () => {
    const { issued } = await issueA();
    const presentation = await present(issued.jwt, issued.disclosures, ['applicant.name']);
    const [jwt, ...disclosures] = presentation.split('~');
    const text = [...jwt.split('.').slice(0, 2), ...disclosures].map((s) => new TextDecoder().decode(b64uDecode(s))).join('\n');
    for (const withheld of ['1234', '42000.5', 'household', 'ssn_last4']) expect(text).not.toContain(withheld);
    expect(text).not.toMatch(/responseHash|response_hash/);
  });

  it('pads the digest list to a power of two with decoys', async () => {
    for (let n = 1; n <= 9; n++) {
      const claims: ClaimInput[] = Array.from({ length: n }, (_, i) => [`f${i}`, i] as const);
      const { issued, salts } = await issueWithRandom(params(), claims, fromHex(SEED_1), countingRandom(0));
      const sd = JSON.parse(new TextDecoder().decode(b64uDecode(issued.jwt.split('.')[1]))) as { _sd: string[] };
      expect(sd._sd.length).toBe(2 ** Math.ceil(Math.log2(n)));
      expect(sd._sd.length).toBe(paddedDigestCount(n));
      expect(salts.decoys.length).toBe(sd._sd.length - n);
      expect([...sd._sd].sort()).toEqual(sd._sd);
      expect(new Set(sd._sd).size).toBe(sd._sd.length);
    }
  });

  it('draws every salt as 128 bits and all salts distinct', () => {
    const salts = generateSalts(Array.from({ length: 64 }, (_, i) => `f${i}`), osSecureRandom);
    const all = [...Object.values(salts.claims), ...salts.decoys];
    expect(all.length).toBe(64);
    for (const s of all) expect(b64uDecode(s).length).toBe(SALT_BYTES);
    expect(new Set(all).size).toBe(all.length);
    expect(SALT_BYTES * 8).toBe(128);
  });

  it('reissues byte-identically from stored salts, whatever the claim input order', async () => {
    const { issued, salts } = await issueA();
    const restored = JSON.parse(JSON.stringify(salts));
    expect(await issue(params(), claimsA, restored, fromHex(SEED_1))).toEqual(issued);
    expect(await issue(params(), [...claimsA].reverse(), restored, fromHex(SEED_1))).toEqual(issued);
    expect(await buildDisclosures(claimsA, restored)).toEqual(issued.disclosures);
  });

  it('orders disclosures by UTF-8 bytes, not UTF-16 units', async () => {
    const claims: ClaimInput[] = [['\u{1F600}', 1], ['￿', 2]];
    expect(compareUtf8('￿', '\u{1F600}')).toBeLessThan(0);
    const { issued } = await issueWithRandom(params(), claims, fromHex(SEED_1), countingRandom(0));
    expect(issued.disclosures.map((d) => d.path)).toEqual(['￿', '\u{1F600}']);
  });

  it('refuses an unknown or repeated allowlist path and foreign disclosures', async () => {
    const { issued } = await issueA();
    await rejects(present(issued.jwt, issued.disclosures, ['nope']), 'unknown_path');
    await rejects(present(issued.jwt, issued.disclosures, ['flag', 'flag']), 'duplicate_path');
    const other = await issueWithRandom(params(), [['flag', false]], fromHex(SEED_1), countingRandom(200));
    await rejects(present(issued.jwt, other.issued.disclosures, ['flag']), 'unknown_digest');
  });

  it('refuses empty, oversized, duplicate, reserved and hostile claim inputs', async () => {
    const attempt = (claims: ClaimInput[], p = params()) => issueWithRandom(p, claims, fromHex(SEED_1), countingRandom(0));
    await rejects(attempt([]), 'invalid_claims');
    await rejects(attempt([['a', 1], ['a', 2]]), 'invalid_claims');
    await rejects(attempt([['', 1]]), 'invalid_claims');
    await rejects(attempt([['_sd', 1]]), 'invalid_claims');
    await rejects(attempt([['p'.repeat(1025), 1]]), 'invalid_claims');
    await rejects(attempt([['a', { _sd: ['x'] }]]), 'invalid_claims');
    await rejects(attempt([['a', [{ '...': 'x' }]]]), 'invalid_claims');
    await rejects(attempt([['a', undefined]]), 'invalid_claims');
    await rejects(attempt([['a', 1n]]), 'invalid_claims');
    await rejects(attempt([['accepted_at', 'x']]), 'reserved_claim_name');
    await rejects(attempt([['a', 1]], { ...params(), publicClaims: { iss: 'x' } }), 'invalid_params');
    await rejects(attempt([['a', 1]], { ...params(), publicClaims: { zz: { _sd: [] } } }), 'invalid_params');
    const deep = Array.from({ length: 40 }).reduce<unknown>((inner) => [inner], 1);
    await rejects(attempt([['a', deep]]), 'invalid_claims');
  });

  it('refuses stored salts that do not match the claims', async () => {
    const claims: ClaimInput[] = [['a', 1], ['b', 2], ['c', 3]];
    const { salts } = await issueWithRandom(params(), claims, fromHex(SEED_1), countingRandom(100));
    expect(salts.decoys.length).toBe(1);
    await rejects(issue(params(), claims, { ...salts, decoys: [] }, fromHex(SEED_1)), 'invalid_salts');
    await rejects(issue(params(), claims, { ...salts, claims: { ...salts.claims, a: salt(1).slice(0, 8) } }, fromHex(SEED_1)), 'invalid_salts');
  });
});

describe('adversarial verification', () => {
  it('rejects a tampered value as an unknown digest', async () => {
    const { issued, salts } = await issueA();
    const forged = disc(salts.claims['applicant.ssn_last4'], 'applicant.ssn_last4', '9999');
    await rejects(verify(join(issued.jwt, [forged]), pinsNow(), pinned), 'unknown_digest');
  });

  it('rejects a swapped salt as an unknown digest', async () => {
    const { issued } = await issueA();
    await rejects(verify(join(issued.jwt, [disc(salt(77), 'flag', true)]), pinsNow(), pinned), 'unknown_digest');
  });

  it('rejects a disclosure from another credential', async () => {
    const { issued } = await issueA();
    const other = await issueWithRandom(params(), [['flag', false]], fromHex(SEED_1), countingRandom(100));
    await rejects(verify(join(issued.jwt, [other.issued.disclosures[0].encoded]), pinsNow(), pinned), 'unknown_digest');
  });

  it('rejects a wrong iss even when kid and key match', async () => {
    const { issued } = await issueA();
    const wrong = [{ ...pin(KID, PK_1), iss: 'https://formspec.example/t/other/w/main/e/prod' }];
    await rejects(verify(await present(issued.jwt, issued.disclosures, []), wrong, pinned), 'wrong_issuer');
  });

  it('keeps the old kid valid under the old pinned key across a rotation', async () => {
    const oldOne = (await issueA('att-2026-10', SEED_1)).issued;
    const newOne = (await issueA('att-2027-01', SEED_2)).issued;
    const pins = [pin('att-2026-10', PK_1), pin('att-2027-01', PK_2)];
    const present1 = (i: typeof oldOne) => present(i.jwt, i.disclosures, ['flag']);
    await expect(verify(await present1(oldOne), pins, pinned)).resolves.toMatchObject({ kid: 'att-2026-10' });
    await expect(verify(await present1(newOne), pins, pinned)).resolves.toMatchObject({ kid: 'att-2027-01' });
    await rejects(verify(await present1(newOne), pins.slice(0, 1), pinned), 'unknown_key');
    const forged = (await issueA('att-2026-10', SEED_2)).issued;
    await rejects(verify(await present1(forged), pins.slice(0, 1), pinned), 'bad_signature');
  });

  it('refuses two pins that share a kid', async () => {
    const { issued } = await issueA();
    await rejects(verify(await present(issued.jwt, issued.disclosures, []), [pin(KID, PK_1), pin(KID, PK_2)], pinned), 'ambiguous_pins');
  });

  it('breaks the signature when the signed payload is edited', async () => {
    const { issued } = await issueA();
    const [h, p, s] = issued.jwt.split('.');
    const edited = new TextDecoder().decode(b64uDecode(p)).replace('2026-10-16', '2026-10-17');
    await rejects(verify(`${h}.${b64uEncode(utf8(edited))}.${s}~`, pinsNow(), pinned), 'bad_signature');
  });

  it('rejects a repeated disclosure, duplicate digests in _sd and a repeated path', async () => {
    const { issued } = await issueA();
    const flag = issued.disclosures.find((d) => d.path === 'flag')!.encoded;
    await rejects(verify(join(issued.jwt, [flag, flag]), pinsNow(), pinned), 'duplicate_disclosure');
    const d = disc(salt(1), 'a', 1);
    const digest = await disclosureDigest(d);
    const dupSd = await signRaw(SEED_1, headerText(), sdPayload([digest, digest]));
    await rejects(verify(join(dupSd, [d]), pinsNow(), lenient), 'duplicate_digest');
    const [d1, d2] = [disc(salt(1), 'a', 1), disc(salt(2), 'a', 2)];
    await rejects(verify(join(await crafted([d1, d2]), [d1, d2]), pinsNow(), lenient), 'duplicate_path');
  });

  it('refuses a path that shadows a payload claim or a reserved name', async () => {
    for (const name of ['iss', 'accepted_at', '_sd', '_sd_alg', '...', 'definition']) {
      const d = disc(salt(1), name, 'x');
      const jwt = await crafted([d], ',"accepted_at":"x","definition":1');
      await rejects(verify(join(jwt, [d]), pinsNow(), lenient), 'reserved_claim_name');
    }
  });

  it('refuses key binding, a missing trailing tilde, cnf, nested structure and array-element disclosures', async () => {
    const { issued } = await issueA();
    await rejects(verify(issued.jwt, pinsNow(), pinned), 'malformed_compact');
    await rejects(verify(`${issued.jwt}~${issued.jwt}`, pinsNow(), pinned), 'malformed_compact');
    const cnf = await signRaw(SEED_1, headerText(), `{"_sd":[],"_sd_alg":"sha-256","cnf":{"kid":"x"},"iss":"${ISS}"}`);
    await rejects(verify(`${cnf}~`, pinsNow(), pinned), 'unsupported_structure');
    const nested = await crafted([], ',"zz":{"_sd":[]}');
    await rejects(verify(`${nested}~`, pinsNow(), pinned), 'unsupported_structure');
    const element = b64uEncode(utf8(JSON.stringify([salt(1), 'x'])));
    await rejects(verify(join(await crafted([element]), [element]), pinsNow(), pinned), 'unsupported_structure');
    const hostile = disc(salt(1), 'a', { _sd: ['x'] });
    await rejects(verify(join(await crafted([hostile]), [hostile]), pinsNow(), pinned), 'unsupported_structure');
  });

  it('refuses header and algorithm substitutions', async () => {
    const headers = [
      '{"alg":"none","kid":"att-2026-10","typ":"formspec-response+sd-jwt"}',
      '{"alg":"ES256","kid":"att-2026-10","typ":"formspec-response+sd-jwt"}',
      '{"alg":"EdDSA","kid":"att-2026-10","typ":"JWT"}',
      '{"alg":"EdDSA","kid":"att-2026-10","typ":"formspec-response+sd-jwt","jwk":{}}',
      '{"alg":"EdDSA","typ":"formspec-response+sd-jwt"}',
    ];
    for (const header of headers) {
      const jwt = await signRaw(SEED_1, header, sdPayload([]));
      await rejects(verify(`${jwt}~`, pinsNow(), lenient), 'unsupported_header');
    }
    const sha512 = await signRaw(SEED_1, headerText(), `{"_sd":[],"_sd_alg":"sha-512","iss":"${ISS}"}`);
    await rejects(verify(`${sha512}~`, pinsNow(), pinned), 'unsupported_sd_alg');
  });

  it('demands JCS and 128-bit salts in pinned mode but not in RFC 9901 mode', async () => {
    const spaced = b64uEncode(utf8(`["${salt(1)}", "a", 1]`));
    let presentation = join(await crafted([spaced]), [spaced]);
    await rejects(verify(presentation, pinsNow(), pinned), 'non_canonical_disclosure');
    await expect(verify(presentation, pinsNow(), lenient)).resolves.toBeTruthy();
    const short = disc(b64uEncode(new Uint8Array(8).fill(9)), 'a', 1);
    presentation = join(await crafted([short]), [short]);
    await rejects(verify(presentation, pinsNow(), pinned), 'weak_salt');
    await expect(verify(presentation, pinsNow(), lenient)).resolves.toBeTruthy();
  });

  it('keeps over-long and over-deep input bounded and refuses it before decoding', async () => {
    await rejects(verify('A'.repeat(MAX_PRESENTATION_BYTES + 1), pinsNow(), pinned), 'input_too_large');
    const { issued } = await issueA();
    await rejects(verify(`${issued.jwt}${'~A'.repeat(MAX_DISCLOSURES + 1)}~`, pinsNow(), pinned), 'input_too_large');
    const digests = await Promise.all(Array.from({ length: 9000 }, (_, i) => disclosureDigest(String(i))));
    await rejects(verify(`${await signRaw(SEED_1, headerText(), sdPayload(digests))}~`, pinsNow(), pinned), 'input_too_large');
    const nested = `${'['.repeat(100_000)}1${']'.repeat(100_000)}`;
    const deep = await signRaw(SEED_1, headerText(), `{"_sd":[],"iss":"${ISS}","zz":${nested}}`);
    await rejects(verify(`${deep}~`, pinsNow(), lenient), 'malformed_json');
  });

  it('fails closed on malformed input of every shape with a DisclosureError only', async () => {
    const { issued } = await issueA();
    const good = await present(issued.jwt, issued.disclosures, ['flag']);
    const inputs = ['', '~', '~~', 'a.b~', 'a.b.c~', 'a.b.c.d~', '..~', 'é~', `${good} `, good.replaceAll('~', '~~')];
    for (let cut = 0; cut < good.length; cut++) inputs.push(good.slice(0, cut));
    for (let i = 0; i < good.length; i += 7) inputs.push(`${good.slice(0, i)}${good[i] === 'A' ? 'B' : 'A'}${good.slice(i + 1)}`);
    for (const input of inputs) {
      try {
        const verified = await verify(input, pinsNow(), pinned);
        expect(verified.disclosed.length).toBeLessThanOrEqual(1);
      } catch (error) {
        expect(error).toMatchObject({ name: 'DisclosureError' });
      }
    }
  });

  it('refuses lone surrogates and out-of-range numbers inside a disclosure', async () => {
    for (const valueText of ['"\\ud800"', '1e999']) {
      const d = b64uEncode(utf8(`["${salt(1)}","a",${valueText}]`));
      await rejects(verify(join(await crafted([d]), [d]), pinsNow(), lenient), 'malformed_json');
    }
  });
});

describe('refused names, derived presentation and signature malleability', () => {
  const GROUP_ORDER_LE = fromHex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');

  it('refuses every refused claim name at issue and at the verifier, in both encodings', async () => {
    expect(REFUSED_CLAIM_NAMES.length).toBeGreaterThan(20);
    for (const required of ['exp', 'nbf', 'sub', 'iat', 'aud', 'jti', 'iss', 'cnf', 'vct', 'status', 'toString', 'valueOf', 'hasOwnProperty', '__proto__', 'constructor', '_sd', '_sd_alg', '...']) {
      expect(REFUSED_CLAIM_NAMES).toContain(required);
    }
    for (const name of REFUSED_CLAIM_NAMES) {
      await rejects(issueWithRandom(params(), [[name, 'x']], fromHex(SEED_1), countingRandom(0)), 'invalid_claims');
      const d = disc(salt(1), name, 'x');
      const jwt = await crafted([d]);
      for (const options of [pinned, lenient]) await rejects(verify(join(jwt, [d]), pinsNow(), options), 'reserved_claim_name');
    }
  });

  it('derives path and digest from the encoded disclosure, so a mismatched struct cannot leak', async () => {
    const { issued } = await issueA();
    const ssn = issued.disclosures.find((d) => d.path === 'applicant.ssn_last4')!;
    const slot = issued.disclosures.findIndex((d) => d.path === 'flag');
    const relabelled = issued.disclosures.map((d, i) => (i === slot ? { ...d, encoded: ssn.encoded } : d));
    await rejects(present(issued.jwt, relabelled, ['flag']), 'malformed_disclosure');
    const forgedDigest = issued.disclosures.map((d, i) => (i === slot ? { ...d, digest: ssn.digest } : d));
    await rejects(present(issued.jwt, forgedDigest, ['flag']), 'malformed_disclosure');
    await rejects(present(issued.jwt, relabelled, ['applicant.name']), 'malformed_disclosure');
  });

  it('rejects a non-canonical signature S plus L, which WebCrypto also refuses', async () => {
    const { issued } = await issueA();
    const [head, signature] = [issued.jwt.slice(0, issued.jwt.lastIndexOf('.')), issued.jwt.slice(issued.jwt.lastIndexOf('.') + 1)];
    const bytes = b64uDecode(signature);
    let carry = 0;
    for (let i = 0; i < 32; i++) {
      const sum = bytes[32 + i] + GROUP_ORDER_LE[i] + carry;
      bytes[32 + i] = sum & 0xff;
      carry = sum >> 8;
    }
    expect(carry).toBe(0);
    await rejects(verify(`${head}.${b64uEncode(bytes)}~`, pinsNow(), pinned), 'bad_signature');
  });

  it('refuses a flood of tilde segments by count', async () => {
    await rejects(verify(`a.b.c${'~'.repeat(MAX_PRESENTATION_BYTES - 10)}`, pinsNow(), pinned), 'input_too_large');
  });
});
