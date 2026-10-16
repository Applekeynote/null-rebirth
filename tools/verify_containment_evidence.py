"""Verify downloaded current-state KMS signatures without AWS credentials."""
import sys
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

root = Path(__file__).resolve().parents[1]
report = json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else root / "private-containment-validation.json").read_text())
key = serialization.load_der_public_key(base64.b64decode(report["signing_public_key_der_base64"]))
verified = []
for run in report["runs"]:
    seal = run["attestation"]
    body = seal["body"]
    message = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    key.verify(base64.b64decode(seal["signature"]), message, ec.ECDSA(hashes.SHA256()))
    assert body["checks_passed"] == body["checks_total"] == 25
    assert body["run_id"] == run["result"]["run_id"]
    assert body["environment_digest"] == run["result"]["verification"]["environment_digest"]
    tampered = dict(body, healthy=False)
    try:
        key.verify(base64.b64decode(seal["signature"]), json.dumps(tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), ec.ECDSA(hashes.SHA256()))
        raise AssertionError("Tampered evidence accepted")
    except InvalidSignature:
        pass
    verified.append(dict(scenario=run["scenario"], signature_valid=True, tampering_rejected=True))
out = dict(passed=True, cases=verified, count=len(verified))
(root / "evidence/aws/CONTAINMENT_OFFLINE_VERIFICATION.json").write_text(json.dumps(out, indent=2))
print(json.dumps(dict(passed=True, signatures=len(verified), tampering_rejected=len(verified))))
