import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))
from cloud import review_auth as auth
from cloud import runtime

KEY = "review-test-key-" + "a" * 40  # Unit-test credential, never deployed.
DOMAIN = "example.lambda-url.us-east-1.on.aws"


def event(path="/", method="GET", cookie=None, origin=None, body=None, bearer=None):
    headers = {}
    if origin is not None:
        headers["origin"] = origin
    if bearer is not None:
        headers["authorization"] = bearer
    return {"rawPath": path, "requestContext": {"domainName": DOMAIN, "http": {"method": method}},
            "headers": headers, "cookies": [cookie] if cookie else [],
            "body": json.dumps(body) if body is not None else ""}


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv("OPERATOR_TOKEN", KEY)
    monkeypatch.setattr(runtime, "utc_now", lambda: 1000)


def test_anonymous_get_only_returns_gate_and_apis_deny():
    result = runtime.api(event())
    assert result["statusCode"] == 200
    assert "AUTHORIZE ACCESS" in result["body"]
    assert "EXECUTE MISSION" not in result["body"]
    assert KEY not in result["body"]
    for path in ("/api/config", "/index.html", "/login.html", "/cloud/runtime.py", "/api/run", "/bridge.js", "/bridge.css", "/proof", "/api/heal", "/api/heal/step"):
        assert runtime.api(event(path))["statusCode"] == 401
    assert runtime.api(event("/api/run", "POST", body={"scenario": "primary-healthy"}))["statusCode"] == 401


def test_login_and_authenticated_document_and_config():
    result = runtime.api(event("/auth/login", "POST", origin="https://" + DOMAIN, body={"key": KEY}))
    assert result["statusCode"] == 200
    cookie = result["cookies"][0]
    for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=1800"):
        assert flag in cookie
    assert KEY not in cookie
    assert "RUN INCIDENT" in runtime.api(event(cookie=cookie))["body"]
    assert runtime.api(event("/api/config", cookie=cookie))["statusCode"] == 200


@pytest.mark.parametrize("provided", ["", "wrong", None, [], "日本語のキー"])
def test_invalid_passwords_are_rejected(provided):
    result = runtime.api(event("/auth/login", "POST", origin="https://" + DOMAIN, body={"key": provided}))
    assert result["statusCode"] == 401
    assert "cookies" not in result


def test_cross_origin_login_and_cookie_writes_are_rejected():
    cookie = auth.issue(KEY, 1000, runtime.DEADLINE)
    for origin in (None, "https://evil.example", "null", "https://" + DOMAIN + ".evil.example"):
        assert runtime.api(event("/auth/login", "POST", origin=origin, body={"key": KEY}))["statusCode"] == 403
        assert runtime.api(event("/api/run", "POST", cookie=cookie, origin=origin,
                                 body={"scenario": "primary-healthy"}))["statusCode"] == 403


def test_expired_tampered_future_and_rotated_key_sessions_deny():
    cookie = auth.issue(KEY, 1000, 10000)
    assert auth.valid(event(cookie=cookie), KEY, 1000, 10000)
    assert not auth.valid(event(cookie=cookie), KEY, 2800, 10000)
    assert not auth.valid(event(cookie=cookie), KEY, 999, 10000)
    assert not auth.valid(event(cookie=cookie), KEY + "b", 1001, 10000)
    token = cookie.split(";", 1)[0]
    assert not auth.valid(event(cookie=token[:-1] + ("a" if token[-1] != "a" else "b")), KEY, 1001, 10000)
    for raw in (auth.COOKIE + "=broken", auth.COOKIE + "=@@.bad", "x=" + "a" * 5000):
        assert not auth.valid(event(cookie=raw), KEY, 1001, 10000)


def test_logout_clears_cookie_and_deadline_overrides_auth(monkeypatch):
    result = runtime.api(event("/auth/logout", "POST", origin="https://" + DOMAIN))
    assert "Max-Age=0" in result["cookies"][0]
    cookie = auth.issue(KEY, runtime.DEADLINE - 10, runtime.DEADLINE)
    assert "Max-Age=10" in cookie
    monkeypatch.setattr(runtime, "utc_now", lambda: runtime.DEADLINE)
    for path in ("/", "/api/config", "/auth/login"):
        assert runtime.api(event(path, cookie=cookie))["statusCode"] == 410


def test_missing_key_fails_closed_and_bearer_still_requires_exact_key(monkeypatch):
    assert runtime.api(event("/api/config", bearer="Bearer " + KEY))["statusCode"] == 200
    assert runtime.api(event("/api/config", bearer="Bearer wrong"))["statusCode"] == 401
    monkeypatch.delenv("OPERATOR_TOKEN")
    assert runtime.api(event("/api/config", bearer="Bearer "))["statusCode"] == 401


def test_bad_json_returns_400_without_running_workers(monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail("Invalid input reached an AWS worker")
    monkeypatch.setattr(runtime, "invoke", forbidden)
    for data in ([], {"scenario": "unknown"}, {"scenario": "primary-healthy", "extra": True}):
        assert runtime.api(event("/api/run", "POST", bearer="Bearer " + KEY, body=data))["statusCode"] == 400
    request = event("/auth/login", "POST", origin="https://" + DOMAIN)
    request["body"] = "{" 
    assert runtime.api(request)["statusCode"] == 400


def test_heal_endpoints_reject_bad_inputs_and_cross_origin_without_workers(monkeypatch):
    monkeypatch.setattr(runtime, "invoke", lambda *a, **kw: pytest.fail("Invalid input reached a worker"))
    for body in ([], {"scenario": "unknown"}, {"scenario": []}, {"scenario": "regex-exhaustion", "command": "bash"}):
        assert runtime.api(event("/api/heal", "POST", bearer="Bearer " + KEY, body=body))["statusCode"] == 400
    for body in ({"run_id": "invalid", "revision": 0}, {"run_id": "run-" + "a"*32, "revision": "0"}, {"revision": 1}):
        assert runtime.api(event("/api/heal/step", "POST", bearer="Bearer " + KEY, body=body))["statusCode"] in (400, 409)
    cookie = auth.issue(KEY, 1000, runtime.DEADLINE)
    assert runtime.api(event("/api/heal", "POST", cookie=cookie, origin="https://evil.example", body={"scenario": "regex-exhaustion"}))["statusCode"] == 403


def test_private_assets_have_correct_mime_and_same_origin_csp():
    for path, mime in (("/bridge.js", "text/javascript"), ("/bridge.css", "text/css"), ("/proof", "text/html")):
        response = runtime.api(event(path, bearer="Bearer " + KEY))
        assert response["statusCode"] == 200 and response["headers"]["Content-Type"].startswith(mime)
        csp = response["headers"]["Content-Security-Policy"]
        assert "script-src 'self' 'unsafe-inline'" in csp and "style-src 'self' 'unsafe-inline'" in csp
        assert "frame-ancestors 'none'" in csp and "https:" not in csp
