"""Twenty incident-inspired experiments; adaptations, never full reproductions.

Only original, short factual summaries are shipped. Recovery procedures are
our bounded sandbox adaptations, not claims about the operators' exact fixes.
"""

def incident(slug, title, company, date, category, component, fault, runbook,
             summary, adaptation, source):
    return dict(id=slug, title=title, company=company, date=date, category=category,
                component=component, fault=fault, runbook=runbook, summary=summary,
                adaptation=adaptation, source=source)


INCIDENTS = [
    incident("regex-exhaustion", "The runaway rule", "Cloudflare", "2019-07-02", "COMPUTE", "EDGE",
        "waf", "ROLLBACK_WAF_RULE", "A WAF regular expression exhausted serving CPUs.",
        "Replace the costly sandbox rule and rerun bounded request matching.",
        "https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/"),
    incident("route-leak", "All roads to one router", "Cloudflare", "2020-07-17", "NETWORK", "NETWORK",
        "bgp", "RESTORE_ROUTE_EXPORT", "A router configuration leaked routes and concentrated backbone traffic.",
        "Restore the sandbox export allowlist and distribute requests across sites.",
        "https://blog.cloudflare.com/cloudflare-outage-on-july-17-2020/"),
    incident("route-filter", "The inverted policy", "Cloudflare", "2022-06-21", "NETWORK", "NETWORK",
        "filter", "REORDER_ROUTE_FILTER", "A network policy change disconnected busy data centers.",
        "Correct ordered sandbox route filters and test reachability.",
        "https://blog.cloudflare.com/cloudflare-outage-on-june-21-2022/"),
    incident("split-brain", "Two leaders, one truth", "GitHub", "2018-10-21", "DATA", "DATA",
        "leaders", "FENCE_STALE_LEADER", "A network partition triggered database failover and divergent writes.",
        "Fence the stale sandbox leader and reconcile the known journal before reads.",
        "https://github.blog/news-insights/company-news/oct21-post-incident-analysis/"),
    incident("lost-database", "The missing records", "GitLab", "2017-01-31", "DATA", "DATA",
        "database", "RESTORE_VERIFIED_SNAPSHOT", "Accidental primary database removal caused an outage and data loss.",
        "Restore the complete disposable dataset from its checksum-verified snapshot.",
        "https://about.gitlab.com/blog/postmortem-of-database-outage-of-january-31/"),
    incident("latent-release", "A valid trigger", "Fastly", "2021-06-08", "RELEASE", "EDGE",
        "release", "ROLLBACK_EDGE_RELEASE", "A valid configuration triggered a previously undiscovered software bug.",
        "Route the sandbox request handler back to the tested stable release.",
        "https://www.fastly.com/blog/summary-of-june-8-outage"),
    incident("dns-withdrawal", "The address book vanishes", "Meta", "2021-10-04", "NETWORK", "NETWORK",
        "dns", "RESTORE_BACKBONE_AND_DNS", "Backbone disconnection caused authoritative DNS routes to be withdrawn.",
        "Restore sandbox connectivity, then advertise and resolve the service name.",
        "https://engineering.fb.com/2021/10/05/networking-traffic/outage-details/"),
    incident("identity-quota", "Identity at zero", "Google", "2020-12-14", "IDENTITY", "IDENTITY",
        "quota", "RESTORE_IDENTITY_QUOTA", "Quota automation reduced identity-service capacity and blocked authentication.",
        "Restore the approved sandbox token-processing quota and authenticate a batch.",
        "https://status.cloud.google.com/incident/zall/20013"),
    incident("worker-starvation", "A queue without workers", "Slack", "2021-01-04", "COMPUTE", "COMPUTE",
        "workers", "BOUND_WORKER_WAIT", "Network degradation saturated the web tier and impeded provisioning.",
        "Bound sandbox backend waits and drain the queued workload with the existing pool.",
        "https://slack.engineering/slacks-outage-on-january-4th-2021/"),
    incident("coordination-contention", "The coordination knot", "Roblox", "2021-10-28", "COMPUTE", "COMPUTE",
        "coordination", "DISABLE_CONTENDED_STREAMING", "Consul streaming contention and BoltDB behavior contributed to a prolonged outage.",
        "Replace the contended sandbox subscription scheduler with bounded polling.",
        "https://about.roblox.com/newsroom/2022/01/roblox-return-to-service-10-28-10-31-2021"),
    incident("quorum-loss", "One zone too few", "Discord", "2023-11-06", "DATA", "DATA",
        "quorum", "RESTORE_QUORUM_MEMBER", "An OS upgrade and a degraded disk combined to overload authentication storage.",
        "Reinstate the maintained sandbox replica and obtain a majority read.",
        "https://discord.com/blog/authentication-outage"),
    incident("index-capacity", "Objects without an index", "AWS S3", "2017-02-28", "DATA", "DATA",
        "index", "REBUILD_OBJECT_INDEX", "An incorrect operational input removed excess capacity from S3 subsystems.",
        "Rebuild the disposable object lookup index from intact object records.",
        "https://aws.amazon.com/message/41926/"),
    incident("retry-amplification", "The echo storm", "AWS", "2021-12-07", "NETWORK", "NETWORK",
        "retries", "BOUND_RETRIES_WITH_BACKOFF", "Connection surges and retries sustained congestion between internal networks.",
        "Cap sandbox retries with backoff and measure downstream call amplification.",
        "https://aws.amazon.com/message/12721/"),
    incident("deleted-tenant", "A site disappears", "Atlassian", "2022-04-05", "DATA", "DATA",
        "tenant", "RESTORE_TENANT_MANIFEST", "A maintenance operation unexpectedly deleted customer sites.",
        "Restore the disposable tenant manifest from its protected local snapshot.",
        "https://www.atlassian.com/blog/how-we-build/post-incident-review-april-2022-outage"),
    incident("schema-mismatch", "The unchecked field", "CrowdStrike", "2024-07-19", "RELEASE", "EDGE",
        "schema", "RESTORE_VALIDATED_CHANNEL", "A content configuration update caused Windows sensors to crash.",
        "Replace a mismatched sandbox content schema with the validated channel payload.",
        "https://www.crowdstrike.com/en-us/blog/channel-file-291-rca-available/"),
    incident("site-power-loss", "The dark facility", "Cloudflare", "2023-11-02", "NETWORK", "COMPUTE",
        "power", "FAIL_OVER_CONTROL_SITE", "A data-center power event disrupted control-plane and analytics services.",
        "Move the sandbox control service to its already available standby site.",
        "https://blog.cloudflare.com/post-mortem-on-cloudflare-control-plane-and-analytics-outage/"),
    incident("maintenance-scope", "Maintenance escapes its cell", "Google Cloud", "2019-06-02", "NETWORK", "NETWORK",
        "maintenance", "RESTORE_CONTROL_PLANE_JOBS", "Maintenance behavior and configuration issues reduced network control capacity.",
        "Restore sandbox control-plane jobs outside the intended maintenance scope.",
        "https://status.cloud.google.com/incidents/Nm7HSYZu9RqCY2HXRQQf"),
    incident("leap-day", "A date that cannot exist", "Microsoft Azure", "2012-02-29", "RELEASE", "IDENTITY",
        "calendar", "CLAMP_CERTIFICATE_DATE", "A leap-day calculation produced an invalid certificate validity date.",
        "Clamp the sandbox certificate anniversary to a valid calendar date.",
        "https://azure.microsoft.com/en-us/blog/summary-of-windows-azure-service-disruption-on-feb-29th-2012/"),
    incident("blank-policy", "The empty policy", "Google Cloud", "2025-06-12", "RELEASE", "IDENTITY",
        "policy", "RESTORE_NON_NULL_POLICY", "Unintended blank policy fields triggered a Service Control crash loop.",
        "Restore a schema-valid sandbox policy and re-evaluate authorized requests.",
        "https://status.cloud.google.com/incidents/ow5i3PPK96RduMcb1SsW"),
    incident("wrong-environment", "Production points at staging", "Cloudflare", "2023-10-30", "RELEASE", "EDGE",
        "deployment", "RESTORE_PRODUCTION_ROUTE", "A deployment-tool misconfiguration sent Workers KV traffic to the wrong destination.",
        "Bind the sandbox production route to the last known-good production build.",
        "https://blog.cloudflare.com/cloudflare-incident-on-october-30-2023/"),
]
# Publication dates, not inferred attack dates. Lab mechanisms are adaptations.
BREACHES = [
    ("sourcenext-api", "The abused member API", "Sourcenext", "2026-10-15", "EDGE", "member_api", "ENFORCE_MEMBER_API_SCOPE",
     "22,519,960 potentially affected records; unauthorized use of a member-information API was disclosed.",
     "Preserve synthetic access evidence, require a scoped lab API principal, and re-test unauthorized reads.",
     "https://www.sourcenext.com/support/i/2026/1015_info/", 22519960, "POTENTIALLY AFFECTED RECORDS"),
    ("monogatari-members", "The member access breach", "Yakiniku King", "2026-10-05", "NETWORK", "app_members", "BLOCK_UNTRUSTED_MEMBER_ORIGINS",
     "10,788,963 member records leaked; the operator reported communication blocking and defensive measures.",
     "Preserve synthetic evidence, restrict the lab member route to trusted origins, and verify denial.",
     "https://www.monogatari.co.jp/news/261005_news/", 10788963, "LEAKED MEMBER RECORDS"),
    ("daiichi-vendor", "The compromised vendor device", "Daiichikosho", "2026-10-08", "COMPUTE", "vendor_endpoint", "ISOLATE_VENDOR_DEVICE",
     "About 8,724,000 customer and employee records potentially affected after a vendor PC malware infection; leakage unconfirmed.",
     "Preserve synthetic device evidence, isolate the lab vendor endpoint and revoke its access, then verify blocked egress.",
     "https://www.dkkaraoke.co.jp/news/newsletter/261008_2.html", 8724000, "POTENTIALLY AFFECTED RECORDS"),
    ("times-documents", "The identity document boundary", "Times Car", "2026-09-28", "DATA", "document_gateway", "SEAL_DOCUMENT_ACCESS_PATH",
     "About 6,600,000 accounts affected; member information included identity-document data. Access paths were blocked and tested.",
     "Preserve synthetic retrieval evidence, seal the external lab document path, and test denied retrieval with legitimate-read controls.",
     "https://www.timesmobi.co.jp/news/2026/09/33b24fb783a2d303b7e8664249ab57022cda975d.html", 6600000, "AFFECTED ACCOUNTS"),
    ("bookoff-members", "The outbound member records", "Bookoff", "2026-10-09", "IDENTITY", "member_export", "REVOKE_MEMBER_EXPORT_SESSION",
     "6,427,735 member-number records / 6,383,279 people affected; external transmission was confirmed. Details remain undisclosed.",
     "Preserve synthetic export evidence, revoke the compromised lab export session, and verify denied retransmission.",
     "https://ssl4.eir-parts.net/doc/9278/tdnet/2896130/00.pdf", 6427735, "TRANSMITTED MEMBER RECORDS"),
]
for slug, title, company, date, component, fault, runbook, summary, adaptation, source, count, label in BREACHES:
    item = incident(slug, title, company, date, "SECURITY", component, fault, runbook, summary, adaptation, source)
    item.update(mode="containment", affected_count=count, affected_label=label, source_checked="2026-10-16")
    INCIDENTS.append(item)

CATALOG = {i["id"]: i for i in INCIDENTS}
assert len(CATALOG) == 25


def public_catalog():
    return [{k: v for k, v in i.items() if k not in ("fault", "runbook")} for i in INCIDENTS]
