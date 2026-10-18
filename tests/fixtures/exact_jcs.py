"""integrity-canonical-json-v1 oracle: rfc8785 0.1.4 plus exact decimal numbers.

RFC 8785 rounds every number to a double before laying it out. The profile keeps
the exact decimal value instead, laid out by ECMAScript Number::toString
(ECMA-262 6.1.6.1.20). This module reads number text itself, independently of
the Rust and TypeScript code, and lets rfc8785 handle everything else (strings,
escaping, UTF-16 member order). Where a number's text is its double's shortest
round-trip form, it checks the layout against rfc8785's own output.

A nonzero number is refused when binary64 round-to-nearest-even takes it to zero
(magnitude <= 2**-1075) or to infinity (magnitude >= 2**1024 - 2**970). The
decision compares digits with those two bounds; no float parser takes part.
Exponents are read up to 10**15; a larger one is already far outside the range.
"""
import json
import math
import re
from decimal import Decimal, InvalidOperation

import rfc8785

_MARK = "number:"
_NUMBER = re.compile(r"(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?)([0-9]+))?")
MAX_EXPONENT = 10**15
# Both bounds as value = 0.DIGITS x 10**n. 2**-1075 = 5**1075 / 10**1075, and 5**1075 has 752 digits.
OVERFLOW_DIGITS, OVERFLOW_N = str(2**1024 - 2**970), 309
UNDERFLOW_DIGITS, UNDERFLOW_N = str(5**1075), 752 - 1075
assert len(OVERFLOW_DIGITS) == OVERFLOW_N and len(UNDERFLOW_DIGITS) == 752


class OutOfRange(ValueError):
    """The number's magnitude rounds to zero or infinity as a binary64."""


class Number(str):
    """JSON number text kept verbatim by loads()."""


def _compare(digits: str, bound: str) -> int:
    """Compares 0.digits with 0.bound; neither has trailing zeros."""
    for left, right in zip(digits, bound):
        if left != right:
            return -1 if left < right else 1
    return (len(digits) > len(bound)) - (len(digits) < len(bound))


def exact_number(text: str) -> str:
    """Lays out JSON number text like Number::toString lays out a double's digits."""
    match = _NUMBER.fullmatch(text)
    if not match:
        raise ValueError(f"{text!r} is not a JSON number")
    sign, integer, fraction, exponent_sign, exponent_digits = match.groups()
    fraction = fraction or ""
    exponent = 0
    for character in exponent_digits or "":
        if exponent >= MAX_EXPONENT:
            break
        exponent = exponent * 10 + int(character)
    if exponent_sign == "-":
        exponent = -exponent
    stripped_integer = integer.lstrip("0")
    if stripped_integer:
        significant = (stripped_integer + fraction).rstrip("0")
        n = exponent + len(stripped_integer)
    else:
        stripped_fraction = fraction.lstrip("0")
        if not stripped_fraction:
            return "0"
        significant = stripped_fraction.rstrip("0")
        n = exponent - (len(fraction) - len(stripped_fraction))
    if n > OVERFLOW_N or (n == OVERFLOW_N and _compare(significant, OVERFLOW_DIGITS) >= 0):
        raise OutOfRange(f"number {text} rounds to infinity as a binary64")
    if n < UNDERFLOW_N or (n == UNDERFLOW_N and _compare(significant, UNDERFLOW_DIGITS) <= 0):
        raise OutOfRange(f"number {text} rounds to zero as a binary64")
    k = len(significant)
    if k <= n <= 21:
        body = significant + "0" * (n - k)
    elif 0 < n <= 21:
        body = significant[:n] + "." + significant[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + significant
    else:
        body = significant[0] + ("." + significant[1:] if k > 1 else "") + "e" + ("+" if n > 0 else "-") + str(abs(n - 1))
    result = sign + body
    _check_against_rfc8785(text, result)
    return result


def _check_against_rfc8785(text: str, result: str) -> None:
    """Where the text is its double's shortest round-trip form, RFC 8785 applies unchanged."""
    if len(text) > 400:
        return
    try:
        magnitude = float(text)
        exact = Decimal(text)
    except (OverflowError, InvalidOperation):
        return
    if math.isfinite(magnitude) and Decimal(repr(magnitude)) == exact:
        assert result == rfc8785.dumps(magnitude).decode(), (text, result)


def loads(text: str):
    """Parses JSON text, keeping every number's text verbatim."""
    return json.loads(text, parse_float=Number, parse_int=Number)


def dumps(value) -> bytes:
    """Canonical bytes of a value from loads(): rfc8785 with exact numbers spliced in."""
    numbers = []

    def mark(node):
        if isinstance(node, Number):
            numbers.append(exact_number(node))
            return f"{_MARK}{len(numbers) - 1}"
        if isinstance(node, list):
            return [mark(item) for item in node]
        if isinstance(node, dict):
            return {key: mark(item) for key, item in node.items()}
        return node

    canonical = rfc8785.dumps(mark(value)).decode()
    for index, number in enumerate(numbers):
        canonical = canonical.replace(json.dumps(f"{_MARK}{index}", ensure_ascii=False), number, 1)
    return canonical.encode()
