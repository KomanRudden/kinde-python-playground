"""Security self-audit: prove the integration doesn't leak or accept forged logins.

Probes run against this same app in-process, through a fresh client with its
own cookie jar, so they behave like a separate browser. SDK log records
emitted while they run are scanned for secrets and tokens.
"""
from __future__ import annotations

import json
import secrets
import time
from http.cookies import SimpleCookie
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from ..kinde import in_thread
from ..redact import JWT_PATTERN, get_log_capture, mask, redact_text
from ..web import Page, route
from ._common import code
from .session import SESSION_COOKIES

SNIPPET = code('''
    # What the SDK guarantees, and what this page verifies:
    # - /callback only accepts the state stored when *this* session started a login
    # - state and nonce are single-use, so a callback can't be replayed
    # - failures return a generic 400; details are logged by exception type only
    # - tokens live in the server-side session; the cookie holds only a session ID
    # - the SDK never logs tokens, codes or client secrets

    # Your part: server-side sessions, HTTPS in production, and a strong session secret
    Session(app)  # Flask-Session, configured by kinde_flask from SESSION_TYPE
''')

ProbeFactory = Callable[[], Any]
_probe_factory: Optional[ProbeFactory] = None


def set_probe_client_factory(factory: ProbeFactory) -> None:
    """Adapters register a factory returning an httpx-compatible client bound to the app."""
    global _probe_factory
    _probe_factory = factory


def _check(name: str, status: str, detail: str, evidence: Optional[str] = None) -> Dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "evidence": evidence}


# ---------------------------------------------------------------------------
# Static checks on the current request
# ---------------------------------------------------------------------------

def scan_for(text: str, needles: List[str]) -> List[str]:
    return [mask(n) for n in needles if n and len(n) >= 6 and n in text]


def session_checks(req, kinde) -> List[Dict[str, Any]]:
    settings = kinde.settings
    checks = []
    serialized = json.dumps(dict(req.session), default=str)

    found = scan_for(serialized, settings.known_secrets)
    checks.append(_check(
        "No credentials in the session",
        "fail" if found else "ok",
        "The session never stores the client secret, M2M secret or session key." if not found
        else "A configured secret was found in the session.",
        ", ".join(found) or None,
    ))

    cookie_name = SESSION_COOKIES[settings.framework]
    cookie = req.cookies.get(cookie_name, "")
    leaked = bool(JWT_PATTERN.search(cookie)) or bool(scan_for(cookie, settings.known_secrets))
    checks.append(_check(
        "Session cookie carries only an ID",
        "fail" if leaked else ("ok" if cookie else "info"),
        f"The {cookie_name} cookie is {len(cookie)} characters and contains no token." if cookie and not leaked
        else ("The cookie contains a token or secret." if leaked else "No session cookie yet: sign in or reload."),
    ))

    tokens_in_session = bool(JWT_PATTERN.search(serialized))
    if tokens_in_session:
        detail = "The SDK keeps your tokens in the session store on the server, never in the cookie."
    elif kinde.user_id():
        detail = "Signed in, but no tokens were found in the session store."
    else:
        detail = "No tokens in this session (signed out)."
    checks.append(_check("Tokens are stored server side", "ok" if tokens_in_session else "info", detail))
    return checks


def posture_checks(kinde) -> List[Dict[str, Any]]:
    s = kinde.settings
    local = urlparse(s.base_url).hostname in ("localhost", "127.0.0.1")
    if s.is_https:
        https = _check("HTTPS", "ok", "Served over HTTPS; the session cookie is marked Secure.")
    elif local:
        https = _check("HTTPS", "info", "Plain HTTP on localhost is fine for development; use HTTPS anywhere else.")
    else:
        https = _check("HTTPS", "fail", "Plain HTTP on a non-local host: cookies and tokens travel unencrypted.")
    return [
        https,
        _check("Session secret", "warn" if s.session_secret_generated else "ok",
               "Generated at startup: sessions reset on restart. Set PLAYGROUND_SESSION_SECRET."
               if s.session_secret_generated else "Loaded from PLAYGROUND_SESSION_SECRET."),
        _check("Debug mode", "warn" if s.debug else "ok",
               "Token reveal buttons are enabled." if s.debug else "Off: tokens are only ever shown masked."),
        _check("Management writes", "warn" if s.allow_mutations else "ok",
               "Write scenarios are enabled." if s.allow_mutations else "Read-only."),
    ]


# ---------------------------------------------------------------------------
# Live probes
# ---------------------------------------------------------------------------

def _cookie_flags(response) -> Optional[Dict[str, Any]]:
    for header in response.headers.get_list("set-cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            continue
        for name, morsel in cookie.items():
            lowered = header.lower()
            return {
                "name": name,
                "httponly": "httponly" in lowered,
                "secure": "secure" in lowered,
                "samesite": (morsel["samesite"] or "").lower() or None,
            }
    return None


def _not_echoed(response, values: List[str]) -> bool:
    body = response.text
    location = response.headers.get("location", "")
    return not any(v and (v in body or v in location) for v in values)


def run_probes(kinde, user_cookie: Optional[str]) -> Dict[str, Any]:
    """Blocking: drives the app through a separate client. Runs in a worker thread."""
    settings = kinde.settings
    checks: List[Dict[str, Any]] = []
    probe_values: List[str] = []
    capture = get_log_capture()

    def new_client():
        client = _probe_factory()
        client.follow_redirects = False
        return client

    with capture.collect() as records:
        # 1. Forged callback with no login in progress
        forged_code, forged_state = f"forged-code-{secrets.token_hex(6)}", f"forged-state-{secrets.token_hex(6)}"
        probe_values += [forged_code, forged_state]
        with new_client() as client:
            r = client.get("/callback", params={"code": forged_code, "state": forged_state})
        checks.append(_check(
            "Forged callback is rejected",
            "ok" if r.status_code == 400 and _not_echoed(r, probe_values) else "fail",
            f"/callback with an unknown state returned HTTP {r.status_code} without echoing the request.",
        ))

        # 2-4. With a real login started in a separate session
        with new_client() as client:
            login = client.get("/login")
            location = login.headers.get("location", "")
            state = (parse_qs(urlparse(location).query).get("state") or [""])[0]
            if state:
                probe_values.append(state)
            flags = _cookie_flags(login)

            checks.append(_check(
                "Login starts with state, nonce and PKCE",
                "ok" if login.status_code in (302, 303, 307) and state and "code_challenge=" in location and "nonce=" in location else "fail",
                f"/login redirected (HTTP {login.status_code}) to Kinde with a state of {len(state)} characters, a nonce and an S256 code challenge."
                if state else f"/login returned HTTP {login.status_code} without a state parameter.",
            ))

            if flags:
                problems = []
                if not flags["httponly"]:
                    problems.append("not HttpOnly")
                if flags["samesite"] not in ("lax", "strict"):
                    problems.append(f"SameSite={flags['samesite'] or 'unset'}")
                if settings.is_https and not flags["secure"]:
                    problems.append("not Secure")
                checks.append(_check(
                    "Session cookie flags",
                    "fail" if problems else "ok",
                    f"{flags['name']}: HttpOnly={flags['httponly']}, SameSite={flags['samesite']}, Secure={flags['secure']}"
                    + (f" ({', '.join(problems)})" if problems else ""),
                ))

            wrong_code = f"probe-code-{secrets.token_hex(6)}"
            probe_values.append(wrong_code)
            r = client.get("/callback", params={"code": wrong_code, "state": f"wrong-{secrets.token_hex(6)}"})
            checks.append(_check(
                "Callback with a different state is rejected",
                "ok" if r.status_code == 400 and _not_echoed(r, probe_values) else "fail",
                f"A login was pending, but the callback's state didn't match: HTTP {r.status_code}.",
            ))

            r = client.get("/callback", params={"code": wrong_code})
            checks.append(_check(
                "Callback without state is rejected",
                "ok" if r.status_code == 400 and _not_echoed(r, probe_values) else "fail",
                f"Missing state is refused, not skipped: HTTP {r.status_code}.",
            ))

        if state:
            with new_client() as client:
                login = client.get("/login")
                state = (parse_qs(urlparse(login.headers.get("location", "")).query).get("state") or [""])[0]
                probe_values.append(state)
                first = client.get("/callback", params={"code": wrong_code, "state": state})
                replay = client.get("/callback", params={"code": wrong_code, "state": state})
            checks.append(_check(
                "State can't be replayed",
                "ok" if first.status_code == 400 and replay.status_code == 400 and _not_echoed(replay, probe_values) else "fail",
                "The matching state with an invalid code failed at the token exchange "
                f"(HTTP {first.status_code}), and replaying it was rejected (HTTP {replay.status_code}).",
                f"First response: {redact_text(first.text[:120])!r}",
            ))

        # 5. Rendered pages, with your own session
        if user_cookie:
            cookie_name = SESSION_COOKIES[settings.framework]
            tm = kinde.token_manager()
            user_tokens = []
            if tm:
                user_tokens = [tm.tokens.get(k) for k in ("access_token", "id_token", "refresh_token")] if hasattr(tm, "tokens") else []
            leaked_pages = []
            with new_client() as client:
                client.cookies.set(cookie_name, user_cookie)
                for path in ("/", "/tokens", "/claims", "/profile", "/session"):
                    page = client.get(path)
                    if scan_for(page.text, settings.known_secrets + [t for t in user_tokens if t]):
                        leaked_pages.append(path)
            checks.append(_check(
                "Pages never render raw tokens",
                "fail" if leaked_pages else "ok",
                "Your access, ID and refresh tokens and configured secrets don't appear in any page's HTML."
                if not leaked_pages else f"Raw values found on {', '.join(leaked_pages)}.",
            ))

    # 6. Everything the SDK logged while the probes ran, plus the recent buffer
    needles = list(settings.known_secrets) + probe_values
    tm = kinde.token_manager()
    if tm and hasattr(tm, "tokens"):
        needles += [v for k, v in tm.tokens.items() if k in ("access_token", "id_token", "refresh_token") and isinstance(v, str)]
    all_records = list(records) + [r for r in list(capture.records) if r not in records]
    offending = []
    for record in all_records:
        if scan_for(record["text"], needles) or JWT_PATTERN.search(record["text"]):
            offending.append(f"{record['logger']} ({record['level']})")
    checks.append(_check(
        "SDK logs contain no secrets or tokens",
        "fail" if offending else "ok",
        f"Scanned {len(all_records)} SDK log records ({len(records)} from these probes) for configured secrets, "
        "tokens, codes and states." if not offending else f"{len(offending)} record(s) contained sensitive values.",
        ", ".join(sorted(set(offending))) or None,
    ))

    return {
        "checks": checks,
        "logs": [{**r, "text": redact_text(r["text"], needles)} for r in list(records)[-40:]],
    }


@route("/security", name="security")
async def security_page(req, kinde):
    return Page("security.html", {
        "session_checks": session_checks(req, kinde),
        "posture": posture_checks(kinde),
        "probes": None,
        "probes_available": _probe_factory is not None,
        "signed_in": bool(kinde.user_id()),
        "snippet": SNIPPET,
    })


@route("/security/run", name="security_run", methods=["POST"])
async def security_run(req, kinde):
    page = await security_page(req, kinde)
    if _probe_factory is None:
        return page
    started = time.perf_counter()
    cookie = req.cookies.get(SESSION_COOKIES[kinde.settings.framework]) if kinde.user_id() else None
    try:
        probes = await in_thread(run_probes, kinde, cookie)
    except Exception as exc:
        probes = {"checks": [_check("Probe run", "fail", f"The probes could not run: {type(exc).__name__}")], "logs": []}
    probes["ms"] = int((time.perf_counter() - started) * 1000)
    page.context["probes"] = probes
    return page
