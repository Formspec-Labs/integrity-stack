/** Test helpers: hex, deterministic entropy, and hostile-credential crafting. Not published. */
import { b64uEncode, utf8 } from './wire.js';
import type { SecureRandom } from './issue.js';

export const TYP = 'formspec-response+sd-jwt';
export const ISS = 'https://formspec.example/t/acme/w/main/e/prod';
export const KID = 'att-2026-10';
// RFC 8032 section 7.1 test vectors 1 and 2: the current and the rotated issuer keys.
export const SEED_1 = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
export const PK_1 = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
export const SEED_2 = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
export const PK_2 = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';

export const fromHex = (hex: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));

/** Counter-driven entropy: distinct, reproducible salts. */
export function countingRandom(start: number): SecureRandom {
  let next = start;
  return {
    fillBytes(dest) {
      for (let i = 0; i < dest.length; i++) dest[i] = next++ & 0xff;
    },
  };
}

export async function signRaw(seedHex: string, header: string, payload: string): Promise<string> {
  const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(prefix);
  pkcs8.set(fromHex(seedHex), 16);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']);
  const input = `${b64uEncode(utf8(header))}.${b64uEncode(utf8(payload))}`;
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', key, utf8(input)));
  return `${input}.${b64uEncode(signature)}`;
}

export const headerText = (kid = KID, typ = TYP): string => `{"alg":"EdDSA","kid":"${kid}","typ":"${typ}"}`;
export const pin = (kid: string, keyHex: string, iss = ISS) => ({ iss, kid, publicKey: fromHex(keyHex) });
