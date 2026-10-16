"""Short-lived review sessions, domain separated from the existing API key.

No additional AWS resources or IAM permissions. The original high-entropy
operator key remains the review credential; it is never embedded in HTML.
"""
import base64
import hashlib
import hmac
import json
import secrets
from http.cookies import SimpleCookie, CookieError

COOKIE = "__Host-nr_review"
LIFETIME = 1800


def key_matches(provided, key):
    return (isinstance(provided, str) and len(key) >= 32
            and hmac.compare_digest(provided.encode(), key.encode()))


def signature(value, key):
    return hmac.new(key.encode(), ("NULL_REBIRTH_REVIEW_V1:" + value).encode(), hashlib.sha256).hexdigest()


def issue(key, now, deadline):
    if len(key) < 32 or now >= deadline:
        raise ValueError("REVIEW_UNAVAILABLE")
    expiry = min(now + LIFETIME, deadline)
    payload = {"v": 1, "iat": now, "exp": expiry, "nonce": secrets.token_hex(16)}
    value = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    token = value + "." + signature(value, key)
    return f"{COOKIE}={token}; Path=/; Max-Age={expiry-now}; Secure; HttpOnly; SameSite=Strict"


def valid(event, key, now, deadline):
    if len(key) < 32 or now >= deadline:
        return False
    raw = "; ".join(event.get("cookies") or [])
    if not raw:
        raw = (event.get("headers") or {}).get("cookie", "")
    if len(raw) > 4096:
        return False
    try:
        jar = SimpleCookie()
        jar.load(raw)
        token = jar[COOKIE].value
        value, mac = token.split(".")
        if not hmac.compare_digest(mac, signature(value, key)):
            return False
        claims = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
        return (claims["v"] == 1 and isinstance(claims["iat"], int)
                and isinstance(claims["exp"], int)
                and claims["iat"] <= now < claims["exp"] <= deadline
                and 0 < claims["exp"] - claims["iat"] <= LIFETIME
                and isinstance(claims["nonce"], str) and len(claims["nonce"]) == 32)
    except (CookieError, KeyError, ValueError, TypeError, UnicodeError):
        return False


def clear():
    return f"{COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"


def same_origin(event):
    headers = event.get("headers") or {}
    domain = event.get("requestContext", {}).get("domainName", "")
    return bool(domain) and headers.get("origin") == "https://" + domain
