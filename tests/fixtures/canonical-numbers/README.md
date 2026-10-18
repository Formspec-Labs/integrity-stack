# Canonical number vectors

`vectors.json` pins how `integrity-canonical-json-v1` writes one JSON number: its exact decimal value in ECMAScript `Number::toString` layout. A nonzero value is refused when binary64 round-to-nearest-even takes it to zero (magnitude ≤ 2^−1075) or to infinity (magnitude ≥ 2^1024 − 2^970). The refusal is decided from the digits, with exponents read up to 10^15. The cases cover zero with any exponent, zero padding, integers above 2^53, decimals beyond a double's precision, both range thresholds to their last digit, and JSON-grammar refusals.

Rust (`crates/integrity-canonical/tests/canonical_number_vectors.rs`) and TypeScript (`packages/integrity-canonical/src/numbers.test.ts`) must match it. `generate.py` derives it with `../exact_jcs.py` and checks that three 1 MB numbers lay out in well under a second. Use `python3 tests/fixtures/canonical-numbers/generate.py` to regenerate, or add `--check` to verify without writing. It needs Python with `rfc8785` 0.1.4.
