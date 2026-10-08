"""Live reads against the configured Kinde business.

These sit beside the unit regression. They use the real SDK: the Management
API with the M2M application, and the account API with the signed-in user's
token. A missing scope or a missing plan fails that one check and leaves the
unit count alone.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Callable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from kinde_sdk.auth.api_options import ApiOptions

from .features._common import safe_error, to_plain
from .kinde import in_thread

_SECRET_QUERY = ("secret", "token", "password", "code", "verifier")


def clean_url(url: str) -> str:
    parts = urlsplit(str(url))
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if any(part in key.lower() for part in _SECRET_QUERY):
            value = "REDACTED"
        query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


@contextmanager
def capture_http():
    """Record urllib3 and requests calls made while a check runs."""
    import requests
    import urllib3

    seen: List[dict] = []
    orig_pool = urllib3.PoolManager.request
    orig_requests = requests.Session.request

    def pool(self, method, url, *args, **kwargs):
        response = orig_pool(self, method, url, *args, **kwargs)
        _remember(seen, method, url, getattr(response, "status", None))
        return response

    def session(self, method, url, *args, **kwargs):
        response = orig_requests(self, method, url, *args, **kwargs)
        _remember(seen, method, url, getattr(response, "status_code", None))
        return response

    urllib3.PoolManager.request = pool
    requests.Session.request = session
    try:
        yield seen
    finally:
        urllib3.PoolManager.request = orig_pool
        requests.Session.request = orig_requests


def _remember(seen: List[dict], method: Any, url: Any, status: Any) -> None:
    item = {"method": str(method or "GET").upper(), "url": clean_url(str(url)), "status": status}
    if not seen or seen[-1] != item:
        seen.append(item)


def describe_http(calls: List[dict], empty: str) -> str:
    if not calls:
        return empty
    parts = []
    for call in calls[:3]:
        status = call.get("status")
        came = f" came back {status}" if isinstance(status, int) else " did not complete"
        parts.append(f"{call.get('method') or 'GET'} {call.get('url')}{came}.")
    extra = len(calls) - 3
    if extra > 0:
        parts.append(f"{extra} more call{'s' if extra != 1 else ''}.")
    return " ".join(parts)


def _bad_status(calls: List[dict]) -> Optional[int]:
    bad = [call["status"] for call in calls if isinstance(call.get("status"), int) and call["status"] >= 400]
    return bad[-1] if bad else None


def _refusal(status: int, subject: str = "") -> str:
    text = f"Kinde returned HTTP {status}" + (f" for {subject}" if subject else "") + "."
    if status == 403:
        text += " This application may be missing the scope for this call."
    return text


def _shown(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None or value == "":
        return "empty"
    return str(value)


def _judge(calls: List[dict], error: Optional[BaseException], expects_http: bool, subject: str, success: str):
    status = _bad_status(calls)
    empty = (
        "Nothing is sent to Kinde. The SDK made no request."
        if expects_http else
        "Nothing is sent to Kinde. This reads the token already in the session."
    )
    http = describe_http(calls, empty)
    if error is not None:
        result = _refusal(status, subject) if status else safe_error(error)
        if expects_http and not calls:
            http = "Nothing is sent to Kinde. The call failed before a request was sent."
        return "failed", http, result
    if status:
        return "failed", http, _refusal(status, subject) + " The SDK did not raise."
    if expects_http and not calls:
        return "failed", http, "The SDK made no request, so this did not reach Kinde."
    return "passed", http, success


def _check(group: str, name: str, did: str, outcome: str, http: str, result: str) -> dict:
    return {
        "id": f"{group}:{name}".lower().replace(" ", "-"),
        "group": group,
        "name": name,
        "did": did,
        "outcome": outcome,
        "http": http,
        "result": result,
    }


def _skipped(group: str, name: str, did: str, result: str) -> dict:
    return _check(
        group, name, did, "skipped",
        "Nothing is sent to Kinde.",
        result,
    )


def _items(value: Any) -> List[Any]:
    plain = to_plain(value)
    if isinstance(plain, list):
        return plain
    if isinstance(plain, dict):
        for key in ("users", "organizations", "roles", "permissions", "entitlements"):
            if isinstance(plain.get(key), list):
                return plain[key]
        for item in plain.values():
            if isinstance(item, list):
                return item
    return []


def _label(item: Any) -> str:
    if not isinstance(item, dict):
        return _shown(item)
    for key in ("email", "name", "feature_key", "key", "code", "id"):
        if item.get(key):
            return str(item[key])
    return "one item"


def _count(singular: str, plural: str, value: Any) -> str:
    items = _items(value)
    count = len(items)
    if count == 0:
        return f"No {plural} came back."
    label = _label(items[0])
    if count == 1:
        return f"1 {singular} came back: {label}."
    return f"{count} {plural} came back. The first is {label}."


def _find(value: Any, key: str) -> Optional[str]:
    plain = to_plain(value)
    found = _walk(plain, key)
    return str(found) if found else None


def _walk(value: Any, key: str):
    if isinstance(value, dict):
        if value.get(key):
            return value[key]
        for item in value.values():
            found = _walk(item, key)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _walk(item, key)
            if found:
                return found
    return None


def _call_sync(func: Callable[[], Any]):
    with capture_http() as seen:
        try:
            return func(), None, list(seen)
        except Exception as exc:
            return None, exc, list(seen)


async def _call_async(func: Callable[[], Any]):
    with capture_http() as seen:
        try:
            return await func(), None, list(seen)
        except Exception as exc:
            return None, exc, list(seen)


def _entitlements_client(host: str, token: str):
    from kinde_sdk.auth.entitlements import Entitlements
    return Entitlements(host, token)


async def _management_checks(kinde) -> List[dict]:
    group = "Management"
    if not kinde.settings.management_enabled:
        return [_skipped(
            group, "Management API",
            "Would call the Management API with the M2M application.",
            "Set KINDE_MANAGEMENT_CLIENT_ID and KINDE_MANAGEMENT_CLIENT_SECRET to run these.",
        )]
    client = kinde.management()
    if client is None:
        return [_skipped(group, "Management API", "Would call the Management API.", "The Management client is not available.")]

    catalog = [
        ("Users", "Asks Kinde for users.", "user", "users", lambda: client.users_api.get_users(page_size=1)),
        ("Organizations", "Asks Kinde for organizations.", "organization", "organizations",
         lambda: client.organizations_api.get_organizations(page_size=1)),
        ("Roles", "Asks Kinde for roles.", "role", "roles", lambda: client.roles_api.get_roles(page_size=5)),
        ("Permissions", "Asks Kinde for permissions.", "permission", "permissions",
         lambda: client.permissions_api.get_permissions(page_size=5)),
    ]
    checks = []
    for name, did, singular, plural, func in catalog:
        value, error, calls = await in_thread(_call_sync, func)
        outcome, http, result = _judge(calls, error, True, name.lower(), _count(singular, plural, value))
        checks.append(_check(group, name, did, outcome, http, result))

    value, error, calls = await in_thread(_call_sync, lambda: client.business_api.get_business())
    name = _find(value, "name") if error is None else None
    success = f"The business is {name}." if name else "Kinde returned the business."
    outcome, http, result = _judge(calls, error, True, "the business", success)
    checks.append(_check(group, "Business", "Asks Kinde for this business.", outcome, http, result))
    return checks


def _flag_sentence(flag) -> str:
    if getattr(flag, "is_default", False):
        return f"{flag.code} is not on this token, so the default {_shown(flag.value)} was used."
    return f"{flag.code} came back as a {flag.type} set to {_shown(flag.value)}."


async def _user_checks(kinde) -> List[dict]:
    group = "Signed-in user"
    if not await kinde.is_authenticated():
        return [_skipped(
            group, "Your user",
            "Would read flags, permissions, and entitlements for the signed-in user.",
            "Sign in to run these against your user.",
        )]

    checks = []
    settings = kinde.settings
    api = ApiOptions(force_api=True)

    claims, error, calls = await _call_async(lambda: kinde.claims.get_all_claims(token_type="access_token"))
    identity, id_error, id_calls = await _call_async(lambda: kinde.claims.get_all_claims(token_type="id_token"))
    email = (identity or {}).get("email") if isinstance(identity, dict) else None
    sub = None
    org = None
    if isinstance(identity, dict):
        sub = identity.get("sub")
    if isinstance(claims, dict):
        sub = sub or claims.get("sub")
        org = claims.get("org_code")
    who = email or "this user"
    if sub:
        who = f"{who} ({sub})"
    if org:
        who = f"{who} in {org}"
    claim_error = error or id_error
    outcome, http, result = _judge(
        calls + id_calls, claim_error, False, "the token",
        f"Signed in as {who}." if sub else "The token has no user id.",
    )
    if outcome == "passed" and not sub:
        outcome, result = "failed", "The token has no user id."
    checks.append(_check(group, "Claims", "Reads the claims on the access token and the ID token.", outcome, http, result))

    flag_code = settings.demo_flag
    flag, error, calls = await _call_async(
        lambda: kinde.feature_flags.get_flag(flag_code, default_value=False)
    )
    outcome, http, result = _judge(calls, error, False, flag_code, _flag_sentence(flag) if flag else "No flag came back.")
    checks.append(_check(group, f"Flag {flag_code} from the token", f"Reads the {flag_code} flag from the token.", outcome, http, result))

    flag, error, calls = await _call_async(
        lambda: kinde.feature_flags.get_flag(flag_code, default_value=False, options=api)
    )
    if not flag:
        success = "No flag came back."
    elif getattr(flag, "is_default", False):
        success = f"{flag.code} is not assigned to this user, so the default {_shown(flag.value)} was used."
    else:
        success = f"{flag.code} came back from the account API as a {flag.type} set to {_shown(flag.value)}."
    outcome, http, result = _judge(calls, error, True, flag_code, success)
    checks.append(_check(group, f"Flag {flag_code} from the account API", f"Reads the {flag_code} flag from the account API.", outcome, http, result))

    flags, error, calls = await _call_async(lambda: kinde.feature_flags.get_all_flags(api))
    count = len(flags or {})
    if count == 0:
        success = "No flags came back."
    else:
        first = next(iter(flags.values()))
        noun = "flag" if count == 1 else "flags"
        success = f"{count} {noun} came back. The first is {first.code}, a {first.type} set to {_shown(first.value)}."
    outcome, http, result = _judge(calls, error, True, "flags", success)
    checks.append(_check(group, "All flags from the account API", "Reads every flag from the account API.", outcome, http, result))

    permission = settings.demo_permission
    granted, error, calls = await _call_async(
        lambda: kinde.permissions.get_permission(permission, api)
    )
    is_granted = bool((granted or {}).get("isGranted")) if isinstance(granted, dict) else False
    org_code = (granted or {}).get("orgCode") if isinstance(granted, dict) else None
    where = f" in {org_code}" if org_code else ""
    success = f"{permission} is {'granted' if is_granted else 'not granted'}{where}."
    outcome, http, result = _judge(calls, error, True, permission, success)
    checks.append(_check(group, f"Permission {permission}", f"Checks {permission} on the account API.", outcome, http, result))

    role = settings.demo_role
    role_result, error, calls = await _call_async(lambda: kinde.roles.get_role(role, api))
    is_granted = bool((role_result or {}).get("isGranted")) if isinstance(role_result, dict) else False
    success = f"Role {role} is {'assigned' if is_granted else 'not assigned'}."
    outcome, http, result = _judge(calls, error, True, role, success)
    checks.append(_check(group, f"Role {role}", f"Checks the {role} role on the account API.", outcome, http, result))

    token = await in_thread(kinde.access_token)
    if not token:
        checks.append(_skipped(
            group, "Entitlements",
            "Would load entitlements for this user.",
            "This session has no access token.",
        ))
        return checks

    client = _entitlements_client(settings.kinde_host, token)
    value, error, calls = await in_thread(_call_sync, client.get_all_entitlements)
    outcome, http, result = _judge(calls, error, True, "entitlements", _count("entitlement", "entitlements", value))
    checks.append(_check(group, "All entitlements", "Loads every entitlement for this user.", outcome, http, result))

    key = settings.demo_entitlement
    value, error, calls = await in_thread(_call_sync, lambda: client.get_entitlement(key))
    feature = _find(value, "feature_key") if error is None else None
    success = f"{feature or key} came back." if feature or error is None else f"{key} came back."
    if feature:
        success = f"{feature} came back."
    outcome, http, result = _judge(calls, error, True, key, success)
    checks.append(_check(group, f"Entitlement {key}", f"Loads the {key} entitlement.", outcome, http, result))
    return checks


def _summary(checks: List[dict], started: float) -> dict:
    passed = sum(1 for check in checks if check["outcome"] == "passed")
    failed = sum(1 for check in checks if check["outcome"] == "failed")
    skipped = sum(1 for check in checks if check["outcome"] == "skipped")
    status = "failed" if failed else "passed" if passed else "skipped"
    return {
        "status": status,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "elapsed": int(time.perf_counter() - started),
        "checks": checks,
    }


async def run_live_checks(kinde) -> dict:
    """Run the live reads and return sentences safe to show on the page."""
    started = time.perf_counter()
    checks = await _management_checks(kinde)
    checks.extend(await _user_checks(kinde))
    return _summary(checks, started)
