"""Shared number vectors for integrity-canonical-json-v1, derived by ../exact_jcs.py.

Writes vectors.json beside this file: edge cases, then 2000 seeded random
numbers ("differential", null where refused) that Rust and TypeScript must match. With --check it writes nothing and fails
unless the committed file matches. Either way it first checks that three 1 MB
numbers lay out in well under a second, so the oracle stays linear.
"""
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import exact_jcs  # noqa: E402

HI, LO = exact_jcs.OVERFLOW_DIGITS, exact_jcs.UNDERFLOW_DIGITS
ZEROS = "0" * (1 << 20)
for big in (f"1.{ZEROS}1", f"1{ZEROS}e-{1 << 20}", f"0.{ZEROS}5e+{1 << 20}"):
    started = time.perf_counter()
    exact_jcs.exact_number(big)
    assert time.perf_counter() - started < 1, "a 1 MB number must lay out in well under a second"

admitted = [
    "0", "-0", "0.0", "-0.000e5", "0e99999999999999999999", "-0e-99999999999999999999",
    "4.50", "123e-2", "2e-3", "0.000001", "1e-7", "1e20", "1E30", "1e21", "1e+21",
    "9007199254740993", "1152921504606846976", "-1.0000000000000000001", "1234567890123456789012",
    "0.0000001234567890123456789", "1234567890.123456789", "333333333.33333329",
    "0.1" + "0" * 1000, "0." + "0" * 1000 + "1e1001", "1" + "0" * 400 + "e-401",
    "1.7976931348623157e308", "1.7976931348623158e308", str(2**1024 - 2**970 - 1),
    "5e-324", "2.4703282292062328e-324", "0." + "0" * 323 + LO + "1", "3e-324",
]
refused = [
    "1e400", "-1e400", "1e-400", "-1e-400", "1e99999999999999999999", "1e-99999999999999999999",
    "2e308", "1.7976931348623159e308", HI, "-" + HI, "1e-324", "2.4703282292062327e-324",
    "0." + "0" * 323 + LO, "01", "1.", ".5", "+1", "NaN", "Infinity", "1e", "1e+", "-", "--1", "0x10",
]
valid = [[text, exact_jcs.exact_number(text)] for text in admitted]
invalid = []
for text in refused:
    try:
        exact_jcs.exact_number(text)
    except ValueError:
        invalid.append(text)
    else:
        raise AssertionError(f"{text} must be refused")
# Differential cases: seeded random numbers, many near the precision and range edges.
rng = random.Random(20261017)


def random_number() -> str:
    sign = rng.choice(["", "-"])
    integer = rng.choice(["0", str(rng.randint(1, 9)) + "".join(rng.choice("0123456789") for _ in range(rng.randint(0, 30)))])
    fraction = "" if rng.random() < 0.3 else "." + "".join(rng.choice("0000123456789") for _ in range(rng.randint(1, 30)))
    exponent = "" if rng.random() < 0.4 else rng.choice("eE") + rng.choice(["", "+", "-"]) + str(rng.choice([rng.randint(0, 25), rng.randint(280, 345)]))
    return sign + integer + fraction + exponent


differential = []
for _ in range(2000):
    text = random_number()
    try:
        differential.append([text, exact_jcs.exact_number(text)])
    except exact_jcs.OutOfRange:
        differential.append([text, None])
fixture = json.dumps({
    "profile": "integrity-canonical-json-v1 numbers",
    "oracle": "tests/fixtures/exact_jcs.py (rfc8785 0.1.4 cross-check)",
    "notes": "Each valid input is one JSON number document and its canonical text. Out of range means a nonzero value that binary64 round-to-nearest-even takes to zero (magnitude <= 2^-1075) or infinity (magnitude >= 2^1024 - 2^970); exponents are read up to 10^15.",
    "valid": valid,
    "invalid": invalid,
    "differential": differential,
}, indent=1) + "\n"
target = Path(__file__).with_name("vectors.json")
if "--check" in sys.argv:
    assert target.read_text() == fixture, "vectors.json differs from the oracle; regenerate it"
else:
    target.write_text(fixture)
