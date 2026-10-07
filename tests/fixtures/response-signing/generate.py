"""Independent full-Response signing vectors: Python rfc8785 and hashlib only."""
import hashlib
import json
from pathlib import Path
import rfc8785

DOMAIN = b'formspec.response.signed-payload.v1\0'
response = {
    '$formspecResponse': '1.0', 'id': 'resp-001',
    'definitionUrl': 'https://example.org/forms/test', 'definitionVersion': '1.0.0',
    'status': 'completed', 'data': {'z': 1, 'a': 2},
    'authored': '2026-05-08T12:00:00Z',
    'authoredSignatures': [{'signatureId': 'sig-001'}],
}
rich = {**response, 'id': 'signing-vector-002',
        'displayedLocale': {'locale': 'es-US', 'version': '0.1.0'},
        'displayedIssuer': {'url': 'urn:issuer:test', 'version': '1.0.0'},
        'extensions': {'authoredSignatures': ['nested and signed'], '😀': 'astral', '\ue000': 'private'},
        'metadata': {'provenance': {'income': {'class': 'user-input'}}},
        '__proto__': {'retain': True}, 'constructor': 'retain', 'toJSON': 'ordinary JSON'}
variants = [{k: v for k, v in rich.items() if k != 'authoredSignatures'}]
variants += [{**rich, 'authoredSignatures': signatures} for signatures in
             [None, {}, [], [{'signatureId': 'one'}], [{'signatureId': 'one'}, {'signatureId': 'two'}]]]
inputs = [('existing-rust-vector', [json.dumps(response)]),
          ('retained-members-and-cosignature-stability', [json.dumps(v, ensure_ascii=False) for v in variants]),
          ('reordered-rich-response', [json.dumps(dict(reversed(list(rich.items()))), ensure_ascii=False)]),
          ('unicode-and-numbers', ['{"data":{"\\ue000":"private-use","😀":"astral","text":"€\\n\\u000f/é","minusZero":-0,"numbers":[333333333.33333329,1E30,4.50,2e-3,1e-27,1e-7,1e20,1e21]}}'])]
valid = []
for name, raw_inputs in inputs:
    outputs = [rfc8785.dumps({k: v for k, v in json.loads(raw).items() if k != 'authoredSignatures'}) for raw in raw_inputs]
    assert all(output == outputs[0] for output in outputs)
    framed = DOMAIN + outputs[0]
    valid.append({'name': name, 'inputJson': raw_inputs, 'canonicalJson': outputs[0].decode(),
                  'bytesHex': framed.hex(), 'sha256': hashlib.sha256(framed).hexdigest()})
# Reuse only raw invalid input definitions; no oracle output drives expected bytes.
invalid = json.loads(Path(__file__).parent.parent.joinpath('response-handoff/vectors.json').read_text())['invalid']
invalid += [{'name': 'surrogate-in-omitted-signature', 'inputJson': '{"authoredSignatures":[{"value":"\\ud800"}]}'},
            {'name': 'surrogate-key-in-omitted-signature', 'inputJson': '{"authoredSignatures":{"\\udfff":true}}'}]
Path(__file__).with_name('vectors.json').write_text(json.dumps({
    'profile': 'formspec-response-signing-v1', 'domain': DOMAIN[:-1].decode(),
    'oracle': 'rfc8785.py 0.1.4 + Python hashlib',
    'notes': 'Synthetic signature members prove omission only; no signing or verification claim.',
    'valid': valid, 'invalid': invalid}, indent=2, ensure_ascii=False)+'\n')
