"""Reproduce shared handoff vectors with maintained independent Python JCS plus exact decimal numbers."""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import exact_jcs  # noqa: E402

DOMAIN = b"formspec.response.handoff.v1\x00"
response = {
    "$formspecResponse": "1.0", "id": "response-handoff-vector-001",
    "definitionUrl": "urn:form:handoff-vector", "definitionVersion": "1.0.0",
    "status": "completed", "data": {"name": "Alex", "income": "2200"},
    "authored": "2026-10-06T12:00:00Z",
    "authoredSignatures": [{"signatureId": "sig-vector-001", "signatureValue": "AQIDBA==",
        "signedPayload": {"canonicalization": "formspec-response-signing-v1", "digest": "a" * 64},
        "verificationReceipt": {"result": "verified", "receiptBytes": "BQYHCA=="}}],
    "displayedLocale": {"locale": "es-US", "version": "1.0.0"},
    "metadata": {"provenance": {"name": {"class": "user-input", "attestedBy": "applicant"}}},
}
without_signature = {key: value for key, value in response.items() if key != "authoredSignatures"}
inputs = [
    ("key-order", ['{"z":1,"a":{"b":2,"a":3}}', '{ "a": { "a":3, "b":2 }, "z":1 }']),
    ("unicode-and-numbers", ['{"data":{"\\ue000":"private-use","😀":"astral","text":"€\\n\\u000f/é","minusZero":-0,"numbers":[333333333.33333329,1E30,4.50,2e-3,1e-27,1e-7,1e20,1e21]}}']),
    ("full-response-with-signature", [json.dumps(response, ensure_ascii=False),
                                         json.dumps(dict(reversed(list(response.items()))), ensure_ascii=False)]),
    ("same-response-without-signature", [json.dumps(without_signature, ensure_ascii=False)]),
    ("nineteen-digit-decimals", [
        '{"data":{"amount":1234567890.123456789,"count":9007199254740993,"rate":-0.0000001234567890123456789}}',
        '{"data":{"rate":-1.234567890123456789e-7,"count":9.007199254740993E15,"amount":1234567890.1234567890}}',
    ]),
]
cases = []
for name, input_json in inputs:
    canonical = exact_jcs.dumps(exact_jcs.loads(input_json[0]))
    for variant in input_json[1:]:
        assert exact_jcs.dumps(exact_jcs.loads(variant)) == canonical
    framed = DOMAIN + canonical
    cases.append({"name": name, "inputJson": input_json, "canonicalJson": canonical.decode(),
                  "bytesHex": framed.hex(), "sha256": hashlib.sha256(framed).hexdigest()})
fixture = {
    "profile": "formspec.response.handoff.v1",
    "oracle": "rfc8785.py 0.1.4 with exact Decimal numbers (tests/fixtures/exact_jcs.py) + Python hashlib",
    "notes": "Signature fields are synthetic preservation inputs, not cryptographically valid authored-signature evidence.",
    "valid": cases,
    "invalid": [
        {"name": "null-root", "inputJson": "null"},
        {"name": "array-root", "inputJson": "[]"},
        {"name": "scalar-root", "inputJson": '"response"'},
        {"name": "boolean-root", "inputJson": "true"},
        {"name": "invalid-json", "inputJson": '{"data":}'},
        {"name": "lone-high-surrogate", "inputJson": '{"data":"\\ud800"}'},
        {"name": "lone-low-surrogate", "inputJson": '{"data":"\\udfff"}'},
        {"name": "surrogate-object-key", "inputJson": '{"\\ud800":"data"}'},
        {"name": "number-above-binary64-range", "inputJson": '{"data":1e400}'},
        {"name": "number-below-binary64-range", "inputJson": '{"data":-1e-400}'},
    ],
}
Path(__file__).with_name('vectors.json').write_text(json.dumps(fixture, indent=2, ensure_ascii=False)+'\n')
