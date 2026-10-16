"""Independently verify the exported KMS proof without AWS credentials."""
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from cloud.core import canonical

folder = root / "evidence/aws"
proof = json.loads((folder / "offline-proof.json").read_text())
cert = proof["certificate"]
key = serialization.load_der_public_key(base64.b64decode(proof["public_key_der_base64"]))
assert isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"
signature = base64.b64decode(cert["signature"])
algorithm = ec.ECDSA(utils.Prehashed(hashes.SHA256()))
key.verify(signature, hashlib.sha256(canonical(cert["body"])).digest(), algorithm)
tampered = copy.deepcopy(cert["body"])
tampered["mode"] = "FORGED"
try:
    key.verify(signature, hashlib.sha256(canonical(tampered)).digest(), algorithm)
    raise AssertionError("Tampered proof accepted")
except InvalidSignature:
    pass
report_path = folder / "HEALING_DEPLOYMENT_REPORT.json"
if not report_path.exists():
    report_path = folder / "BRIDGE_DEPLOYMENT_REPORT.json"
if report_path.exists():
    checks = json.loads(report_path.read_text())
    assert checks["passed"] and all(checks["checks"].values())
    packages = checks["lambda_hashes"]
else:
    report_path = folder / "FINAL_DEPLOYMENT_CHECKS.json"
    checks = json.loads(report_path.read_text())
    packages = checks["lambda_code_sha256_base64"]
expected = base64.b64encode(hashlib.sha256((root / "dist/app.zip").read_bytes()).digest()).decode()
assert len(packages) == 7 and all(h == expected for h in packages.values())
template_path = folder / "HEALING_DEPLOYED_TEMPLATE.json"
if not template_path.exists():
    template_path = folder / "BRIDGE_DEPLOYED_TEMPLATE.json"
if not template_path.exists():
    template_path = folder / "DEPLOYED_TEMPLATE.json"
assert json.loads((root / "dist/template.json").read_text()) == json.loads(template_path.read_text())
result = {"offline_signature_valid": True, "tampering_rejected": True,
          "all_seven_lambda_packages_match_local": True, "deployed_template_matches_local": True,
          "historical_proof_only": True, "current_health_asserted": False,
          "package_report": report_path.name, "template_report": template_path.name}
if report_path.name == "HEALING_DEPLOYMENT_REPORT.json":
    signing_key = serialization.load_der_public_key(base64.b64decode(checks["signing_public_key_der_base64"]))
    assert isinstance(signing_key, ec.EllipticCurvePublicKey) and signing_key.curve.name == "secp256r1"
    assert len(checks["runs"]) == 20 and len({r["scenario"] for r in checks["runs"]}) == 20
    for run in checks["runs"]:
        seal, final = run["attestation"], run["result"]
        body = seal["body"]
        signing_key.verify(base64.b64decode(seal["signature"]), hashlib.sha256(canonical(body)).digest(), algorithm)
        assert body["domain"] == "NULL_REBIRTH_HEALING_LAB_ECDSA_V1"
        assert body["run_id"] == final["run_id"] and body["scenario"] == run["scenario"]
        assert body["healthy"] and body["checks_passed"] == body["checks_total"] == 20
        assert body["environment_digest"] == final["verification"]["environment_digest"]
        assert body["runbook"] == final["plan"]["runbook"]
        assert body["issued_at"] <= final["verification"]["verified_at"] < body["expires_at"] - 2
        assert run["passed"] and final["phase"] == "COMPLETE" and run["orders_created"] == 0
        assert 2 <= len(final["ai_usage"]) <= 4 and all(u["model"] == "amazon.nova-micro-v1:0" for u in final["ai_usage"])
        assert len(final["diagnosis_attempts"]) == len(final["ai_usage"]) - 1
        assert final["diagnosis_attempts"][-1]["accepted"] is True
        forged = copy.deepcopy(body)
        forged["environment_digest"] = "0" * 64
        try:
            signing_key.verify(base64.b64decode(seal["signature"]), hashlib.sha256(canonical(forged)).digest(), algorithm)
            raise AssertionError("Tampered healing proof accepted")
        except InvalidSignature:
            pass
    result.update(twenty_healing_signatures_valid=True, twenty_healing_tamper_cases_rejected=True,
                  live_model_calls_recorded=sum(len(r["result"]["ai_usage"]) for r in checks["runs"]), healing_orders_created=0)
(folder / "OFFLINE_VERIFICATION.json").write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
