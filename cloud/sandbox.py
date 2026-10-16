"""Bounded service laboratory: execute functional probes over durable configuration.

No shell, user code, arbitrary URL, AWS infrastructure modification, or real
customer data. Faults mutate configurations/data; repairs change their behavior.
All loops and collections are small and fixed. Measurements describe this lab.
"""
import calendar
import copy
from datetime import date
from cloud.core import Denied, digest
from cloud.incidents import INCIDENTS, CATALOG
from cloud import containment

CHECK_TOTAL = len(INCIDENTS)

DATA = {"order-001": "alpha", "order-002": "beta", "order-003": "gamma"}
OBJECTS = {"obj-a": "A", "obj-b": "B", "obj-c": "C"}
TENANT = {"site": "review-lab", "projects": ["aurora", "orbit"], "active": True}


def baseline():
    return dict(waf_rule="linear", export_sites=["east", "west", "central"],
        route_filters=["allow-service", "deny-all"], leaders=["east"], journal=[1, 2, 3],
        replicas={"east": [1, 2, 3], "west": [1, 2, 3]}, database=copy.deepcopy(DATA),
        snapshot=copy.deepcopy(DATA), snapshot_digest=digest(DATA), edge_release="stable",
        backbone=True, dns_advertised=True, dns={"service.lab": "edge.lab"},
        identity_quota=16, backend_wait=1, worker_count=4, queue=list(range(8)),
        subscription_mode="polling", subscriber_count=8,
        zones={"a": "ONLINE", "b": "ONLINE", "c": "ONLINE"},
        objects=copy.deepcopy(OBJECTS), object_index={k: k for k in OBJECTS},
        retry_limit=1, retry_backoff=True, tenant=copy.deepcopy(TENANT),
        tenant_snapshot=copy.deepcopy(TENANT), tenant_digest=digest(TENANT),
        channel_fields=["process", "path", "event"], channel_expected=3,
        site_power={"primary": False, "standby": True}, active_site="standby",
        control_jobs={"east": True, "west": True, "central": True},
        certificate_calendar="clamp", policy={"scopes": ["read", "write"]},
        security_policy=containment.baseline(), security_events=[],
        build_route="production-stable", builds={"production-stable": "production", "staging-next": "staging"})


def inject(env, scenario):
    e = copy.deepcopy(env)
    fault = CATALOG[scenario]["fault"]
    if fault in containment.GATES:
        return containment.inject(e, fault)
    changes = {
        "waf": {"waf_rule": "backtracking"},
        "bgp": {"export_sites": ["east"]},
        "filter": {"route_filters": ["deny-all", "allow-service"]},
        "leaders": {"leaders": ["east", "west"], "replicas": {"east": [1, 2, 3], "west": [1, 2, 9]}},
        "database": {"database": {}}, "release": {"edge_release": "regression"},
        "dns": {"backbone": False, "dns_advertised": False}, "quota": {"identity_quota": 0},
        "workers": {"backend_wait": 30}, "coordination": {"subscription_mode": "streaming"},
        "quorum": {"zones": {"a": "MAINTENANCE", "b": "SLOW_DISK", "c": "ONLINE"}},
        "index": {"object_index": {}}, "retries": {"retry_limit": 8, "retry_backoff": False},
        "tenant": {"tenant": {}}, "schema": {"channel_fields": ["process", "path"]},
        "power": {"active_site": "primary"},
        "maintenance": {"control_jobs": {"east": False, "west": False, "central": False}},
        "calendar": {"certificate_calendar": "naive"}, "policy": {"policy": {"scopes": None}},
        "deployment": {"build_route": "staging-next"},
    }
    e.update(copy.deepcopy(changes[fault]))
    return e


def probe(env, challenge="A"):
    """Run 20 functional checks. Challenge changes the request batch, not criteria."""
    e = env
    checks = []
    def check(name, component, actual, expected, detail):
        checks.append(dict(id=name, component=component, passed=actual == expected,
                           actual=actual, expected=expected, detail=detail))
    # Bounded rule interpreter: no catastrophic regex is executed on the host.
    ops = sum(len(s) if e["waf_rule"] == "linear" else len(s) ** 3
              for s in ("request=alpha", "request=beta", "request=" + challenge * 12))
    check("waf", "EDGE", ops <= 128, True, "Rule interpreter instruction budget <= 128")
    sites = [e["export_sites"][n % len(e["export_sites"])] for n in range(12)] if e["export_sites"] else []
    check("bgp", "NETWORK", max([sites.count(s) for s in set(sites)] or [12]) <= 4, True,
          "Twelve routed requests; no site receives more than four")
    route = next((x for x in e["route_filters"] if x in ("allow-service", "deny-all")), "deny-all")
    check("filter", "NETWORK", route, "allow-service", "First matching route policy must permit service")
    leaders = e["leaders"]
    coherent = len(leaders) == 1 and all(v == e["journal"] for v in e["replicas"].values())
    check("leaders", "DATA", coherent, True, "Single writable leader and journal-consistent replicas")
    check("database", "DATA", [e["database"].get(k) for k in sorted(DATA)],
          [DATA[k] for k in sorted(DATA)], "Read every expected record; check exact values")
    response = "502" if e["edge_release"] == "regression" else "200:valid-config"
    check("release", "EDGE", response, "200:valid-config", "Serve a valid triggering configuration")
    resolved = e["dns"].get("service.lab") if e["backbone"] and e["dns_advertised"] else None
    check("dns", "NETWORK", resolved, "edge.lab", "Resolve the service through an advertised reachable path")
    authenticated = sum(n < e["identity_quota"] for n in range(8))
    check("quota", "IDENTITY", authenticated, 8, "Authenticate eight disposable sandbox principals")
    completed = min(len(e["queue"]), (4 // max(1, e["backend_wait"])) * e["worker_count"])
    check("workers", "COMPUTE", completed, 8, "Drain eight jobs within four bounded scheduler quanta")
    # Shared streaming serialization vs. independent bounded poll scheduling.
    ticks = e["subscriber_count"] ** 2 if e["subscription_mode"] == "streaming" else e["subscriber_count"]
    check("coordination", "COMPUTE", ticks <= 16, True, "Subscription work completes within sixteen scheduler ticks")
    online = [z for z, status in e["zones"].items() if status == "ONLINE"]
    check("quorum", "DATA", len(online) >= 2, True, "Obtain two matching replica responses out of three")
    fetched = {k: e["objects"].get(e["object_index"].get(k)) for k in OBJECTS}
    check("index", "DATA", fetched, OBJECTS, "Fetch all objects through their lookup index")
    calls = 8 * (1 + e["retry_limit"]) if not e["retry_backoff"] else 8 + min(e["retry_limit"], 2)
    check("retries", "NETWORK", calls <= 16, True, "Eight requests generate at most sixteen downstream calls")
    check("tenant", "DATA", e["tenant"], TENANT, "Resolve the site and its complete project manifest")
    try:
        fields = [e["channel_fields"][n] for n in range(e["channel_expected"])]
    except IndexError:
        fields = "FIELD_INDEX_ERROR"
    check("schema", "EDGE", fields, ["process", "path", "event"], "Decode all fields required by the content interpreter")
    served = "200:control" if e["site_power"].get(e["active_site"]) else "SITE_UNAVAILABLE"
    check("power", "COMPUTE", served, "200:control", "Serve control requests from a powered site")
    reachable = sorted(k for k, running in e["control_jobs"].items() if running)
    check("maintenance", "NETWORK", reachable, ["central", "east", "west"], "All unaffected control jobs must respond")
    try:
        start = date(2012, 2, 29)
        day = min(start.day, calendar.monthrange(2013, 2)[1]) if e["certificate_calendar"] == "clamp" else start.day
        anniversary = date(2013, 2, day).isoformat()
    except ValueError:
        anniversary = "INVALID_CALENDAR_DATE"
    check("calendar", "IDENTITY", anniversary, "2013-02-28", "Create a valid one-year leap-day certificate boundary")
    try:
        scopes = e["policy"]["scopes"]
        authorized = len(scopes) > 0 and "read" in scopes and "write" in scopes
    except (TypeError, KeyError):
        authorized = "POLICY_PARSE_ERROR"
    check("policy", "IDENTITY", authorized, True, "Evaluate both required operations using non-null policy fields")
    response = "200:kv-value" if e["builds"].get(e["build_route"]) == "production" else "401:wrong-environment"
    check("deployment", "EDGE", response, "200:kv-value", "Read a value through the production build route")
    for gate, (component, mechanism) in containment.GATES.items():
        measured = containment.challenges(e, gate, challenge)
        check(gate, component, measured, dict(denied=3, attempted=3, legitimate_read=True),
              "Deny three unauthorized requests with zero returned records; retain a legitimate read. Mechanism: " + mechanism)
    failed = [c["id"] for c in checks if not c["passed"]]
    return dict(healthy=not failed, checks=checks, failed=failed, passed_count=CHECK_TOTAL - len(failed),
                total=CHECK_TOTAL, challenge=challenge, environment_digest=digest(env),
                metrics=dict(success_percent=round(100 * (CHECK_TOTAL - len(failed)) / CHECK_TOTAL),
                             failed_checks=len(failed), rule_instructions=ops,
                             downstream_calls=calls, scheduler_ticks=ticks,
                             authenticated=authenticated, queue_completed=completed))


RUNBOOKS = {i["runbook"]: dict(target=i["fault"], description=i["adaptation"]) for i in INCIDENTS}


def repair(env, runbook):
    if runbook not in RUNBOOKS:
        raise Denied("RUNBOOK_NOT_ALLOWLISTED")
    before = probe(env)
    if before["failed"] != [RUNBOOKS[runbook]["target"]]:
        raise Denied("RUNBOOK_PRECONDITION_FAILED")
    e, good = copy.deepcopy(env), baseline()
    targets = {
        "waf": ["waf_rule"], "bgp": ["export_sites"], "filter": ["route_filters"],
        "leaders": ["leaders", "replicas"], "database": ["database"], "release": ["edge_release"],
        "dns": ["backbone", "dns_advertised"], "quota": ["identity_quota"], "workers": ["backend_wait"],
        "coordination": ["subscription_mode"], "quorum": ["zones"], "index": ["object_index"],
        "retries": ["retry_limit", "retry_backoff"], "tenant": ["tenant"], "schema": ["channel_fields"],
        "power": ["active_site"], "maintenance": ["control_jobs"], "calendar": ["certificate_calendar"],
        "policy": ["policy"], "deployment": ["build_route"],
    }
    fault = RUNBOOKS[runbook]["target"]
    fields = ["security_policy"] if fault in containment.GATES else targets[fault]
    if fault in containment.GATES:
        e["security_policy"][fault] = copy.deepcopy(good["security_policy"][fault])
    elif fault == "database":
        if digest(e["snapshot"]) != e["snapshot_digest"] or e["snapshot"] != DATA:
            raise Denied("SNAPSHOT_INTEGRITY_FAILED")
        e["database"] = copy.deepcopy(e["snapshot"])
    elif fault == "tenant":
        if digest(e["tenant_snapshot"]) != e["tenant_digest"] or e["tenant_snapshot"] != TENANT:
            raise Denied("TENANT_SNAPSHOT_INTEGRITY_FAILED")
        e["tenant"] = copy.deepcopy(e["tenant_snapshot"])
    elif fault == "index":
        e["object_index"] = {k: k for k in e["objects"]}
    elif fault == "leaders":
        e["leaders"] = ["east"]
        e["replicas"] = {k: copy.deepcopy(e["journal"]) for k in e["replicas"]}
    else:
        for key in fields:
            e[key] = copy.deepcopy(good[key])
    if not probe(e, "B")["healthy"]:
        raise Denied("REPAIR_DRY_RUN_FAILED")
    delta = [{"field": k, "before": env[k], "after": e[k]} for k in fields if env[k] != e[k]]
    return e, delta


def validate_plan(plan, observed):
    if not isinstance(plan, dict) or set(plan) != {"runbook", "diagnosis", "reason"}:
        raise Denied("AI_PLAN_SCHEMA_INVALID")
    if plan["runbook"] not in RUNBOOKS:
        raise Denied("RUNBOOK_NOT_ALLOWLISTED")
    for key in ("diagnosis", "reason"):
        if not isinstance(plan[key], str) or not 1 <= len(plan[key]) <= 600:
            raise Denied("AI_PLAN_TEXT_INVALID")
    if observed["failed"] != [RUNBOOKS[plan["runbook"]]["target"]]:
        raise Denied("AI_PLAN_EVIDENCE_MISMATCH")
    return plan
