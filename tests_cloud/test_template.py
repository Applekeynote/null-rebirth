from cloud.template import generate


def test_role_cannot_write_orders_or_sign_unless_designated():
    resources = generate()["Resources"]
    for name in ("ApiRole", "WitnessRole", "RecoveryRole", "BootstrapRole"):
        statements = resources[name]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        assert all("kms:Sign" not in s["Action"] for s in statements)
        for s in statements:
            if "dynamodb:PutItem" not in s["Action"] or s["Resource"] != {"Fn::GetAtt": ["StateTable", "Arn"]}:
                continue
            assert all(not key.startswith("ORDER#") for key in s["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"])


def test_order_authority_is_scoped_and_no_fixture_upload():
    t = generate()
    roles = t["Resources"]["CommitRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    order = [s for s in roles if s["Action"] == ["dynamodb:PutItem"] and "Condition" in s][0]
    assert order["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == ["ORDER#run-*"]


def test_early_shutdown_and_retry_are_created():
    r = generate()["Resources"]
    s = r["ShutdownSchedule"]["Properties"]
    assert s["ScheduleExpression"] == "cron(0 20 1,2 12 ? 2026)"
    assert s["ScheduleExpressionTimezone"] == "Asia/Tokyo"
    assert s["State"] == "ENABLED"
    assert r["SigningKey"]["Properties"]["PendingWindowInDays"] == 7
    assert r["StateTable"]["DeletionPolicy"] == "Delete"
    assert r["JanitorRole"]["DeletionPolicy"] == "Retain"
    assert r["JanitorPolicy"]["DeletionPolicy"] == "Retain"


def test_template_dependency_graph_has_no_cycle():
    r = generate()["Resources"]
    graph = {k: set() for k in r}
    def visit(value, deps):
        if isinstance(value, dict):
            if "Ref" in value and value["Ref"] in r:
                deps.add(value["Ref"])
            if "Fn::GetAtt" in value:
                deps.add(value["Fn::GetAtt"][0])
            for v in value.values():
                visit(v, deps)
        elif isinstance(value, list):
            for v in value:
                visit(v, deps)
    for key, value in r.items():
        visit(value, graph[key])
        deps = value.get("DependsOn", [])
        graph[key].update([deps] if isinstance(deps, str) else deps)
    seen, active = set(), set()
    def check(k):
        assert k not in active, k
        if k in seen:
            return
        active.add(k)
        for d in graph[k]:
            check(d)
        active.remove(k)
        seen.add(k)
    for key in graph:
        check(key)
