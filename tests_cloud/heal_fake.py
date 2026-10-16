"""Test-only CAS store and local ECDSA signer. Never included in Lambda package."""
import copy
import hashlib
import json
import re
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cloud.core import canonical, digest, Denied, utc_now


class FakeRuntime:
    TABLE = "unit-lab"
    KEY = "unit-only-signing-key"
    DEADLINE = 1796122800

    def __init__(self):
        self.items, self.events, self.counters = {}, [], {}
        self.signer = ec.generate_private_key(ec.SECP256R1())
        self.signature_valid = True
        self.transactions = 0

    def db(self):
        return self

    def update_item(self, **kwargs):
        key = kwargs["Key"]["PK"]
        current = self.counters.get(key, 0)
        if current >= kwargs["ExpressionAttributeValues"][":max"]:
            raise Denied("QUOTA_EXHAUSTED")
        self.counters[key] = current + 1

    def get(self, run, name):
        if (run, name) not in self.items:
            raise Denied("RECORD_MISSING:" + name)
        return copy.deepcopy(self.items[run, name])

    def payload(self, run, name):
        rec = self.get(run, name)
        body = json.loads(rec["payload"])
        if digest(body) != rec["digest"]:
            raise Denied("RECORD_CORRUPTED")
        return body

    def record(self, run, name, body, expiry, create=True):
        if create and (run, name) in self.items:
            raise Denied("ALREADY_EXISTS")
        item = dict(PK=name + "#" + run, SK="STATE", run_id=run,
                    payload=canonical(body).decode(), digest=digest(body), expires_at=expiry)
        self.items[run, name] = item
        return copy.deepcopy(item)

    def audit(self, run, phase, result):
        self.events.append((run, phase, result))

    def trusted_run(self, event):
        run = event.get("run_id", "")
        if not re.fullmatch(r"run-[a-f0-9]{32}", run):
            raise Denied("INVALID_RUN_ID")
        return run

    def client(self, service):
        if service == "dynamodb":
            return self
        if service == "kms":
            return SimpleNamespace(sign=self.sign, verify=self.verify)
        raise AssertionError(service)

    def sign(self, **kwargs):
        return {"Signature": self.signer.sign(kwargs["Message"], ec.ECDSA(utils.Prehashed(hashes.SHA256())))}

    def verify(self, **kwargs):
        if not self.signature_valid:
            return {"SignatureValid": False}
        try:
            self.signer.public_key().verify(kwargs["Signature"], kwargs["Message"], ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return {"SignatureValid": True}
        except InvalidSignature:
            return {"SignatureValid": False}

    def transact_write_items(self, TransactItems):
        staged = []
        for action in TransactItems:
            op = next(iter(action)); d = action[op]
            name, run = d["Key"]["PK"]["S"].split("#", 1)
            old = self.get(run, name); values = d["ExpressionAttributeValues"]
            expected = values.get(":old", values.get(":p"))["S"]
            expected_digest = values.get(":old_digest", values.get(":d"))["S"]
            if old["payload"] != expected or old["digest"] != expected_digest or old["expires_at"] <= int(values[":now"]["N"]):
                raise Denied("CAS_REJECTED")
            if op == "Update":
                changed = copy.deepcopy(old)
                changed.update(payload=values[":new"]["S"], digest=values[":dig"]["S"])
                staged.append(((run, name), changed))
        for key, value in staged:
            self.items[key] = value
        self.transactions += 1
