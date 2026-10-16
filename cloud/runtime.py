"""Role-separated Lambda sandbox. Only Commit can create the ORDER item.

Faults are deliberate sandbox inputs; this does not monitor real customer work.
All operational facts are read from DynamoDB, never supplied by a web client.
"""
import base64
import hashlib
import json
import os
import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cloud.core import (SCENARIOS, GUARDS, Denied, canonical, digest, utc_now,
                        decision, validate_certificate, build_transaction)
from cloud import review_auth
from rpp_v15.proof_frontier import POLICIES, POLICY_HASH, VerifiedFact, assess
from datetime import datetime, timezone

CFG = Config(connect_timeout=3, read_timeout=15, retries={"max_attempts": 2})
TABLE = os.environ.get("TABLE", "")
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "")
KEY = os.environ.get("SIGNING_KEY", "")
PREFIX = os.environ.get("PREFIX", "null-rebirth")
DEADLINE = 1796122800  # 2026-12-01 20:00 JST (well before Dec 3)
CONTRACT = {"environment": "SANDBOX", "operation": "new_mock_order",
            "allow_degraded_writes": False, "policy_hash": POLICY_HASH, "revision": 1}
CONTRACT_HASH = digest(CONTRACT)


def client(service):
    return boto3.client(service, config=CFG)


def db():
    return boto3.resource("dynamodb", config=CFG).Table(TABLE)


def plain(obj):
    # DynamoDB resource returns Decimal. Sandbox records contain integer numbers.
    return json.loads(json.dumps(obj, default=lambda x: int(x)))


def get(run, name):
    out = db().get_item(Key={"PK": name + "#" + run, "SK": "STATE"}, ConsistentRead=True).get("Item")
    if not out:
        raise Denied("RECORD_MISSING:" + name)
    return plain(out)


def payload(run, name):
    rec = get(run, name)
    body = json.loads(rec["payload"])
    if rec["digest"] != digest(body):
        raise Denied("RECORD_CORRUPTED:" + name)
    return body


def record(run, name, body, expiry, create=True):
    item = {"PK": name + "#" + run, "SK": "STATE", "run_id": run, "payload": canonical(body).decode(),
            "digest": digest(body), "expires_at": expiry}
    args = {"Item": item}
    if create:
        args["ConditionExpression"] = "attribute_not_exists(PK)"
    db().put_item(**args)
    return item


def audit(run, phase, result):
    # Each role can append evidence, but cannot delete or replace previous records.
    body = {"phase": phase, "result": result, "observed_at": utc_now(),
            "source_role": os.environ.get("ROLE", "unknown")}
    boto3.resource("dynamodb", config=CFG).Table(AUDIT_TABLE).put_item(
        Item={"PK": run, "SK": "EVENT#" + phase + "#" + uuid.uuid4().hex,
              "payload": canonical(body).decode(), "digest": digest(body),
              "expires_at": utc_now() + 86400}, ConditionExpression="attribute_not_exists(PK)")


def invoke(role, data):
    out = client("lambda").invoke(FunctionName=PREFIX + "-" + role,
                                   Payload=canonical(data))
    result = json.loads(out["Payload"].read())
    if out.get("FunctionError"):
        raise Denied("WORKER_FAILED:" + role)
    return result


def trusted_run(event):
    run = event.get("run_id", "")
    if not re.fullmatch(r"run-[a-f0-9]{32}", run):
        raise Denied("INVALID_RUN_ID")
    if utc_now() >= DEADLINE:
        raise Denied("DEMO_EXPIRED")
    return run


def bootstrap(event):
    scenario = event.get("scenario")
    if scenario not in SCENARIOS:
        raise Denied("UNKNOWN_SCENARIO")
    now = utc_now()
    if now >= DEADLINE:
        raise Denied("DEMO_EXPIRED")
    # Atomic lifetime limit survives restarts and cannot be reset by API clients.
    db().update_item(Key={"PK": "CONTROL#QUOTA", "SK": "STATE"},
        UpdateExpression="ADD used :one", ConditionExpression="attribute_not_exists(used) OR used < :max",
        ExpressionAttributeValues={":one": 1, ":max": 300})
    run = "run-" + uuid.uuid4().hex
    state = {"run_id": run, "scenario": scenario, "mode": "FULL", "route": "primary",
             "route_revision": 1, "epoch": 1, "challenge": uuid.uuid4().hex,
             "contract_hash": CONTRACT_HASH, "policy_hash": POLICY_HASH,
             "conflict": scenario == "conflicting-evidence", "allow_degraded_writes": False,
             "lease_until": now + 180,
             "fault": "SILENT" if scenario in ("silent-monitor-death", "backup-recovered",
                                                 "untrusted-receipt") else "NONE"}
    expiry = now + 180
    records = {
        "AUTH": {"decision": "ALLOW", "principal": "sandbox-operator", "run_id": run,
                 "operation": "new_mock_order", "contract_hash": CONTRACT_HASH},
        "POLICY": {"active": True, "policy_hash": POLICY_HASH, "revision": 1},
        "CONTRACT": CONTRACT,
        "CONTRACT_ACTIVE": {"contract_hash": CONTRACT_HASH, "revision": 1},
        "TRUST": {"key_id": KEY, "active": True, "usage": "RESUME_SIGNER"},
        "INCIDENT": state, "LEASE": {"epoch": 1, "valid_until": now + 180},
        "MODE": {"mode": "FULL", "allow_degraded_writes": False, "epoch": 1},
        "ROUTE": {"route": "primary", "revision": 1, "epoch": 1},
        "CAPABILITY": {"runbook": "RB-001", "status": "ISSUED", "run_id": run},
    }
    for name, body in records.items():
        record(run, name, body, expiry)
    db().put_item(Item={"PK": "CLAIM#" + run, "SK": "STATE", "run_id": run,
                       "status": "RESERVED", "expires_at": expiry},
                  ConditionExpression="attribute_not_exists(PK)")
    audit(run, "AUTH_CONTRACT_CLAIM", "SANDBOX_INITIALIZED")
    return {"run_id": run}


def witness(event):
    run = trusted_run(event)
    state = payload(run, "INCIDENT")
    # An actual, separately permissioned Lambda invocation observes persisted state.
    # The primary fault switch deliberately models a missing heartbeat.
    status = "NO_HEARTBEAT" if state["route"] == "primary" and state["fault"] == "SILENT" else "PASS"
    now = utc_now()
    canary = {"run_id": run, "status": status, "route_revision": state["route_revision"],
              "epoch": state["epoch"], "challenge": state["challenge"],
              "route": state["route"], "observed_at": now, "expires_at": now + 120}
    record(run, "CANARY", canary, now + 120, create=False)
    audit(run, "INDEPENDENT_CANARY", status)
    return canary


def recovery(event):
    run = trusted_run(event)
    old = get(run, "INCIDENT")
    state = json.loads(old["payload"])
    canary = payload(run, "CANARY")
    cap = get(run, "CAPABILITY")
    capbody = json.loads(cap["payload"])
    if (state["route"] != "primary" or canary["status"] != "NO_HEARTBEAT"
            or canary["expires_at"] <= utc_now() + 2 or capbody["status"] != "ISSUED"):
        raise Denied("RECOVERY_CAPABILITY_OR_FAULT_INVALID")
    now = utc_now()
    state.update(mode="DEGRADED", route="backup", route_revision=2, epoch=2,
                 challenge=uuid.uuid4().hex, lease_until=now + 120)
    values = {
        "INCIDENT": state, "ROUTE": {"route": "backup", "revision": 2, "epoch": 2},
        "MODE": {"mode": "DEGRADED", "allow_degraded_writes": False, "epoch": 2},
        "LEASE": {"epoch": 2, "valid_until": now + 120},
        "CAPABILITY": {**capbody, "status": "CONSUMED"},
    }
    actions = []
    for name, body in values.items():
        before = get(run, name)
        actions.append({"Update": {"TableName": TABLE,
            "Key": {"PK": {"S": name + "#" + run}, "SK": {"S": "STATE"}},
            "UpdateExpression": "SET #p = :new, #d = :dig, expires_at = :exp",
            "ConditionExpression": "#p = :old AND expires_at > :now",
            "ExpressionAttributeNames": {"#p": "payload", "#d": "digest"},
            "ExpressionAttributeValues": {":new": {"S": canonical(body).decode()},
                ":dig": {"S": digest(body)}, ":old": {"S": before["payload"]},
                ":exp": {"N": str(now + 120)}, ":now": {"N": str(now + 2)}}}})
    client("dynamodb").transact_write_items(TransactItems=actions)
    audit(run, "WATCHDOG_RB001_ATOMIC_SWITCH", "CAPABILITY_CONSUMED_ONCE")
    return {"mode": "DEGRADED", "route_revision": 2}


def frontier(state, canary, now):
    atoms = {a for p in POLICIES for g in p.obligations for a in g.one_of}
    states = {a: "PASS" for a in atoms}
    states.update(original_route_failed="FAIL", incident_monitor_failed="FAIL",
                  degraded_writes_contract_allowed="FAIL")
    if state["route"] == "backup":
        states.update(original_route_healthy="FAIL", original_route_failed="PASS",
                      primary_pipeline_fresh="FAIL", incident_monitor_failed="PASS")
    if state["conflict"]:
        states["original_route_failed"] = "PASS"
    if canary["status"] != "PASS":
        states["primary_pipeline_fresh"] = "UNKNOWN"
        states["backup_pipeline_fresh_authorized"] = "UNKNOWN"
    expiry = datetime.fromtimestamp(canary["expires_at"], timezone.utc)
    facts = {a: VerifiedFact(a, s, True, state["run_id"], CONTRACT_HASH, expiry,
                              digest(canary)) for a, s in states.items()}
    gates = assess(facts, as_of=datetime.fromtimestamp(now, timezone.utc),
                   scope=state["run_id"], contract_hash=CONTRACT_HASH,
                   conflict_latched=state["conflict"])
    return {a: {"status": g.status, "eligible": g.eligible,
                "missing": g.missing_proof_frontier, "failed": g.blocking_failed_atoms,
                "digest": g.evidence_digest} for a, g in gates.items()}


def verifier(event):
    run = trusted_run(event)
    state = payload(run, "INCIDENT")
    canary = payload(run, "CANARY")
    now = utc_now()
    gates = frontier(state, canary, now)
    current = decision(state, canary, now)
    if gates["new_mock_order"]["eligible"] != current["allowed"]:
        raise Denied("FRONTIER_POLICY_DISAGREEMENT")
    body = {k: state[k] for k in ("run_id", "scenario", "mode", "route", "route_revision",
                                 "epoch", "challenge", "contract_hash", "policy_hash", "conflict")}
    body.update(domain="NULL_REBIRTH_AWS_SANDBOX_ECDSA_V1", issued_at=now,
                expires_at=now + 60, canary_digest=digest(canary),
                decision=current, frontier=gates, key_id=KEY)
    signed = client("kms").sign(KeyId=KEY, Message=hashlib.sha256(canonical(body)).digest(),
                                MessageType="DIGEST", SigningAlgorithm="ECDSA_SHA_256")
    envelope = {"body": body, "signature": base64.b64encode(signed["Signature"]).decode(),
                "algorithm": "ECDSA_SHA_256", "key_id": KEY}
    record(run, "PROOF", {"certificate_digest": digest(body), "key_id": KEY}, now + 60)
    record(run, "FRONTIER", {"frontier_digest": digest(gates), "policy_hash": POLICY_HASH}, now + 60)
    record(run, "SAFETY", {"body_digest": digest(body), "allowed": current["allowed"]}, now + 60)
    record(run, "CERTIFICATE", envelope, now + 60)
    audit(run, "INDEPENDENT_VERIFIER_KMS", "ALLOW" if current["allowed"] else "BLOCK")
    return envelope


def commit(event):
    run = trusted_run(event)
    envelope = event.get("certificate") or payload(run, "CERTIFICATE")
    try:
        body = envelope["body"]
        if (envelope["key_id"] != KEY or body["key_id"] != KEY
                or envelope["algorithm"] != "ECDSA_SHA_256"
                or body["domain"] != "NULL_REBIRTH_AWS_SANDBOX_ECDSA_V1"):
            raise Denied("SIGNER_IDENTITY_INVALID")
        try:
            verification = client("kms").verify(KeyId=KEY,
                Message=hashlib.sha256(canonical(body)).digest(), MessageType="DIGEST",
                Signature=base64.b64decode(envelope["signature"], validate=True),
                SigningAlgorithm="ECDSA_SHA_256")
        except (ClientError, ValueError):
            raise Denied("SIGNATURE_INVALID")
        if not verification["SignatureValid"]:
            raise Denied("SIGNATURE_INVALID")
        state, canary = payload(run, "INCIDENT"), payload(run, "CANARY")
        now = utc_now()
        validate_certificate(body, state, canary, now)
        records = {name: get(run, name) for name in GUARDS}
        expected = {
            "AUTH": {"decision": "ALLOW", "principal": "sandbox-operator", "run_id": run,
                     "operation": "new_mock_order", "contract_hash": CONTRACT_HASH},
            "POLICY": {"active": True, "policy_hash": POLICY_HASH, "revision": 1},
            "CONTRACT": CONTRACT,
            "CONTRACT_ACTIVE": {"contract_hash": CONTRACT_HASH, "revision": 1},
            "TRUST": {"key_id": KEY, "active": True, "usage": "RESUME_SIGNER"},
            "INCIDENT": state, "CANARY": canary,
            "LEASE": {"epoch": state["epoch"], "valid_until": state["lease_until"]},
            "MODE": {"mode": state["mode"], "allow_degraded_writes": False, "epoch": state["epoch"]},
            "ROUTE": {"route": state["route"], "revision": state["route_revision"], "epoch": state["epoch"]},
            "PROOF": {"certificate_digest": digest(body), "key_id": KEY},
            "FRONTIER": {"frontier_digest": digest(body["frontier"]), "policy_hash": POLICY_HASH},
            "SAFETY": {"body_digest": digest(body), "allowed": True},
        }
        for name, wanted in expected.items():
            if json.loads(records[name]["payload"]) != wanted:
                raise Denied("GUARD_SEMANTICS_INVALID:" + name)
        tx = build_transaction(TABLE, run, records, body, now)
        client("dynamodb").transact_write_items(**tx, ClientRequestToken=uuid.uuid4().hex)
        result = {"committed": True, "actions": 15, "order_kind": "MOCK_NO_PAYMENT"}
    except Denied as exc:
        result = {"committed": False, "reason": str(exc)}
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        result = {"committed": False, "reason": "ATOMIC_CAS_REJECTED"}
    audit(run, "PROOF_CARRYING_ATOMIC_COMMIT", result)
    return result


def api_response(code, data, html=False):
    return {"statusCode": code, "headers": {
        "Content-Type": "text/html; charset=utf-8" if html else "application/json; charset=utf-8",
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; connect-src 'self'",
    }, "body": data if html else json.dumps(data, ensure_ascii=False)}


def api(event):
    path = event.get("rawPath", "/")
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    now = utc_now()
    if now >= DEADLINE:
        return api_response(410, {"error": "DEMO_EXPIRED"})
    key = os.environ.get("OPERATOR_TOKEN", "")
    headers = event.get("headers") or {}
    bearer = review_auth.key_matches(headers.get("authorization", ""), "Bearer " + key) if len(key) >= 32 else False
    session = review_auth.valid(event, key, now, DEADLINE)
    if method == "POST" and path == "/auth/login":
        if not review_auth.same_origin(event):
            return api_response(403, {"error": "ORIGIN_REJECTED"})
        try:
            raw = event.get("body") or "{}"
            if event.get("isBase64Encoded"):
                raw = base64.b64decode(raw, validate=True).decode()
            if len(raw) > 1024:
                raise ValueError()
            data = json.loads(raw)
            if not isinstance(data, dict) or not review_auth.key_matches(data.get("key"), key):
                return api_response(401, {"error": "REVIEW_KEY_REQUIRED"})
        except (ValueError, TypeError, UnicodeError):
            return api_response(400, {"error": "INVALID_INPUT"})
        result = api_response(200, {"authenticated": True})
        result["cookies"] = [review_auth.issue(key, now, DEADLINE)]
        return result
    if method == "POST" and path == "/auth/logout":
        if not review_auth.same_origin(event):
            return api_response(403, {"error": "ORIGIN_REJECTED"})
        result = api_response(200, {"authenticated": False})
        result["cookies"] = [review_auth.clear()]
        return result
    if not (session or bearer):
        if method == "GET" and path == "/":
            return api_response(200, Path(__file__).with_name("login.html").read_text(encoding="utf-8"), True)
        return api_response(401, {"error": "REVIEW_KEY_REQUIRED"})
    if method == "POST" and not bearer and not review_auth.same_origin(event):
        return api_response(403, {"error": "ORIGIN_REJECTED"})
    if method == "GET" and path == "/":
        return api_response(200, Path(__file__).with_name("index.html").read_text(encoding="utf-8"), True)
    if method == "GET" and path in ("/bridge.css", "/bridge.js", "/proof"):
        filename, mime = {"/bridge.css": ("bridge.css", "text/css; charset=utf-8"),
                          "/bridge.js": ("bridge.js", "text/javascript; charset=utf-8"),
                          "/proof": ("proof.html", "text/html; charset=utf-8")}[path]
        result = api_response(200, Path(__file__).with_name(filename).read_text(encoding="utf-8"), True)
        result["headers"]["Content-Type"] = mime
        return result
    if method == "GET" and path == "/api/config":
        from cloud.incidents import public_catalog
        return api_response(200, {"scenarios": SCENARIOS, "deadline": DEADLINE, "target_usd": 5,
            "region": os.environ.get("AWS_REGION"), "mode": "AWS_SANDBOX_REAL_STORAGE_SYNTHETIC_FAULTS",
            "incidents": public_catalog(), "ai_model": "amazon.nova-micro-v1:0"})
    if path in ("/api/heal", "/api/heal/step"):
        return healing_api(event, method, path)
    if method != "POST" or path != "/api/run":
        return api_response(404, {"error": "NOT_FOUND"})
    try:
        raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw).decode()
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("scenario") not in SCENARIOS or set(data) - {"scenario"}:
            return api_response(400, {"error": "INVALID_SCENARIO_INPUT"})
        run = invoke("bootstrap", data)["run_id"]
        first = invoke("witness", {"run_id": run})
        recovery_result = None
        if first["status"] == "NO_HEARTBEAT":
            recovery_result = invoke("recovery", {"run_id": run})
            invoke("witness", {"run_id": run})
        cert = invoke("verifier", {"run_id": run})
        submitted = json.loads(json.dumps(cert))
        if data["scenario"] == "untrusted-receipt":
            submitted["body"]["mode"] = "FULL"
        with ThreadPoolExecutor(max_workers=2) as pool:
            commits = list(pool.map(lambda _: invoke("commit", {"run_id": run, "certificate": submitted}), range(2)))
        order_count = int(bool(db().get_item(Key={"PK": "ORDER#" + run, "SK": "STATE"},
                                             ConsistentRead=True).get("Item")))
        items = plain(boto3.resource("dynamodb", config=CFG).Table(AUDIT_TABLE).query(
            KeyConditionExpression="PK = :r", ExpressionAttributeValues={":r": run},
            ConsistentRead=True)["Items"])
        events = [json.loads(i["payload"]) for i in items if i["SK"].startswith("EVENT#")]
        result = {"run_id": run, "scenario": data["scenario"], "certificate": cert,
            "signature_tampered_for_test": data["scenario"] == "untrusted-receipt",
            "commits": commits, "order_count": order_count, "recovery": recovery_result,
            "events": sorted(events, key=lambda e: e["observed_at"]),
            "actual_aws_storage_and_kms": True, "production_safety_certified": False,
            "current_health": "NOT_MONITORED_AFTER_RUN", "historical_certificate": True}
        return api_response(200, result)
    except (Denied, ClientError) as exc:
        return api_response(409, {"error": str(exc)[:200]})
    except (ValueError, TypeError, UnicodeError):
        return api_response(400, {"error": "INVALID_INPUT"})


def healing_api(event, method, path):
    from cloud import healing
    try:
        if method == "GET" and path == "/api/heal":
            params = event.get("queryStringParameters") or {}
            if set(params) != {"run_id"}:
                raise Denied("INVALID_HEAL_INPUT")
            run = trusted_run(params)
            _, state = healing.load(sys.modules[__name__], run)
            return api_response(200, healing.public(state))
        if method != "POST":
            return api_response(405, {"error": "METHOD_NOT_ALLOWED"})
        raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw, validate=True).decode()
        if len(raw) > 1024:
            raise ValueError()
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError()
        if path == "/api/heal":
            from cloud.incidents import CATALOG
            if set(data) != {"scenario"} or not isinstance(data["scenario"], str) or data["scenario"] not in CATALOG:
                raise ValueError()
            result = invoke("bootstrap", {**data, "task": "heal-start"})
        else:
            if set(data) != {"run_id", "revision"} or type(data["revision"]) is not int:
                raise ValueError()
            trusted_run(data)
            result = invoke("recovery", {**data, "task": "heal-advance"})
        run = result["run_id"]
        if result["phase"] in ("NORMAL", "ANOMALY", "REPAIRING"):
            result["probe"] = invoke("witness", {"run_id": run, "task": "heal-observe"})
        if result["phase"] == "VERIFYING":
            invoke("verifier", {"run_id": run, "task": "heal-attest"})
            result = invoke("commit", {"run_id": run, "task": "heal-normalize"})
        return api_response(200, result)
    except (Denied, ClientError) as exc:
        return api_response(409, {"error": str(exc)[:120]})
    except (ValueError, TypeError, UnicodeError):
        return api_response(400, {"error": "INVALID_HEAL_INPUT"})


def janitor(event):
    # Repeated daily during the shutdown window: disable public work first,
    # stop KMS billing, then ask CloudFormation to remove only this stack.
    if utc_now() < DEADLINE and not event.get("alarmData"):
        raise Denied("EARLY_TEARDOWN_REJECTED")
    client("lambda").put_function_concurrency(FunctionName=PREFIX + "-api", ReservedConcurrentExecutions=0)
    try:
        client("kms").schedule_key_deletion(KeyId=KEY, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "KMSInvalidStateException":
            raise
    out = client("cloudformation").delete_stack(StackName=PREFIX)
    return {"delete_requested": True, "request_id": out["ResponseMetadata"]["RequestId"]}


def handler(event, context):
    role = os.environ["ROLE"]
    if role != "api" and isinstance(event.get("task"), str) and event["task"].startswith("heal-"):
        from cloud import healing
        return healing.dispatch(sys.modules[__name__], event)
    return {"api": api, "bootstrap": bootstrap, "witness": witness,
            "recovery": recovery, "verifier": verifier, "commit": commit,
            "janitor": janitor}[role](event)
