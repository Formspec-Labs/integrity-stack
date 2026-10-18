"""integrity-canonical-json-v1 oracle: rfc8785 0.1.4 plus exact decimal numbers.

RFC 8785 rounds every number to a double before laying it out. The profile keeps
the exact decimal value instead, laid out by ECMAScript Number::toString
(ECMA-262 6.1.6.1.20). This module parses numbers with Python's Decimal, lays
them out independently of the Rust and TypeScript code, and lets rfc8785
handle everything else (strings, escaping, UTF-16 member order). It checks that
the layout equals rfc8785's own output wherever a double holds the number
exactly, so the two oracles cannot drift on ordinary numbers.
"""
import json
import math
from decimal import Decimal

import rfc8785

_MARK = "number:"


def exact_number(value: Decimal) -> str:
    """Lays out a decimal like Number::toString lays out a double's digits."""
    sign, digit_tuple, exponent = value.as_tuple()
    significant = "".join(map(str, digit_tuple)).lstrip("0")
    if not significant:
        return "0"
    magnitude = float(value)
    if not math.isfinite(magnitude) or magnitude == 0:
        raise ValueError(f"number {value} is outside the binary64 range")
    digits = significant.rstrip("0")
    k = len(digits)
    n = exponent + (len(significant) - k) + k
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + digits
    else:
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if n > 0 else "-") + str(abs(n - 1))
    text = ("-" if sign else "") + body
    # repr() is the double's shortest round-trip form: when it equals the value, RFC 8785 applies unchanged.
    if Decimal(repr(magnitude)) == value:
        assert text == rfc8785.dumps(magnitude).decode(), (value, text)
    return text


def loads(text: str):
    """Parses JSON text, keeping every number as an exact Decimal."""
    return json.loads(text, parse_float=Decimal, parse_int=Decimal)


def dumps(value) -> bytes:
    """Canonical bytes of a value from loads(): rfc8785 with exact numbers spliced in."""
    numbers = []

    def mark(node):
        if isinstance(node, Decimal):
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
