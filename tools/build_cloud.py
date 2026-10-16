"""Package only reviewed cloud code and the pure reference policy, no fixtures."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cloud.template import generate

dist = ROOT / "dist"
dist.mkdir(exist_ok=True)
(dist / "template.json").write_text(json.dumps(generate(), indent=2), encoding="utf-8")
app_files = [(ROOT / "cloud" / n, "cloud/" + n) for n in ("__init__.py", "core.py", "runtime.py", "review_auth.py", "incidents.py", "containment.py", "sandbox.py", "healing.py", "index.html", "login.html", "proof.html", "bridge.css", "bridge.js")]
app_files += [(ROOT / "source/rpp_v15" / n, "rpp_v15/" + n) for n in ("__init__.py", "proof_frontier.py")]
with zipfile.ZipFile(dist / "app.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for p, name in app_files:
        z.write(p, name)
with zipfile.ZipFile(dist / "null-rebirth-aws.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for name in ("app.zip", "template.json"):
        z.write(dist / name, name)
    for name in ("deploy_cloud.py", "acceptance_cloud.py", "teardown_rehearsal.py", "deadline_cleanup.py", "update_bridge.py", "update_healing.py"):
        z.write(ROOT / "tools" / name, name)
manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in dist.iterdir()
            if p.suffix in (".zip", ".json") and p.name != "SHA256SUMS.json"}
(dist / "SHA256SUMS.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print(json.dumps(manifest, indent=2))
