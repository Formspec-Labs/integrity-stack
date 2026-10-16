/** Stable failure classes, identical to the Rust `ErrorCode::as_str` names. */
export type ErrorCode =
  | 'input_too_large'
  | 'malformed_compact'
  | 'malformed_base64url'
  | 'malformed_json'
  | 'unsupported_header'
  | 'unknown_key'
  | 'ambiguous_pins'
  | 'bad_signature'
  | 'wrong_issuer'
  | 'unsupported_sd_alg'
  | 'malformed_sd'
  | 'duplicate_digest'
  | 'unsupported_structure'
  | 'malformed_disclosure'
  | 'non_canonical_disclosure'
  | 'weak_salt'
  | 'unknown_digest'
  | 'duplicate_disclosure'
  | 'duplicate_path'
  | 'reserved_claim_name'
  | 'invalid_claims'
  | 'invalid_salts'
  | 'invalid_params'
  | 'unknown_path'
  | 'entropy';

/** A failed disclosure operation. The message names the rule and never echoes a claim value. */
export class DisclosureError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'DisclosureError';
    this.code = code;
  }
}

export function fail(code: ErrorCode, message: string): never {
  throw new DisclosureError(code, message);
}
