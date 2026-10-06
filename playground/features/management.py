"""Management API: curated reads, a read-only console and guarded write scenarios.

Every route here requires a signed-in user: the Management API acts with the
app's M2M credentials, which must never be reachable by anonymous visitors.
Write scenarios additionally need PLAYGROUND_ALLOW_MUTATIONS=true and a typed
confirmation, and only touch resources the playground created itself.
"""
from __future__ import annotations

import base64
import datetime as dt
import inspect
import json
import secrets
import threading
import types
import typing
from typing import Any, Dict, List, Optional

from ..config import STATE_DIR
from ..guards import require_auth
from ..kinde import in_thread
from ..redact import mask, redact_data
from ..web import Page, Partial, Redirect, flash, route
from ._common import attempt, code, safe_error, to_plain

PREFIX = "playground-"
CONFIRM_WORD = "playground"
RESULT_KEY = "pg_mgmt_result"
CREATED_FILE = STATE_DIR / "created.json"
READ_PREFIXES = ("get_", "search_")
SIMPLE_TYPES = {str: "str", int: "int", float: "float", bool: "bool"}
_created_lock = threading.Lock()

SNIPPET = code('''
    from kinde_sdk.management import ManagementClient

    # Create once per process and reuse: the M2M token is cached and refreshed for you
    management = ManagementClient(
        domain="your-business.kinde.com",
        client_id=os.environ["KINDE_MANAGEMENT_CLIENT_ID"],
        client_secret=os.environ["KINDE_MANAGEMENT_CLIENT_SECRET"],
    )

    users = management.users_api.get_users(page_size=5)
    org = management.organizations_api.get_organization(code="org_123")

    # Calls are blocking: in async apps run them in a worker thread
    users = await asyncio.to_thread(management.users_api.get_users, page_size=5)
''')

CURATED = {
    "business": ("Business", "business_api", "get_business", {}),
    "users": ("Users", "users_api", "get_users", {"page_size": 5}),
    "organizations": ("Organizations", "organizations_api", "get_organizations", {"page_size": 5}),
    "roles": ("Roles", "roles_api", "get_roles", {"page_size": 10}),
    "permissions": ("Permissions", "permissions_api", "get_permissions", {"page_size": 10}),
    "applications": ("Applications", "applications_api", "get_applications", {"page_size": 5}),
    "flags": ("Environment feature flags", "environments_api", "get_environement_feature_flags", {}),
}


# ---------------------------------------------------------------------------
# Introspection of the generated API classes
# ---------------------------------------------------------------------------

def _unwrap(annotation: Any) -> Any:
    while typing.get_origin(annotation) is typing.Annotated:
        annotation = typing.get_args(annotation)[0]
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return _unwrap(args[0])
    return annotation


def _description(annotation: Any) -> str:
    for meta in typing.get_args(annotation)[1:] if typing.get_origin(annotation) is typing.Annotated else ():
        text = getattr(meta, "description", None)
        if text:
            return text
    inner = typing.get_args(annotation)[0] if typing.get_origin(annotation) is typing.Annotated else None
    return _description(inner) if inner is not None and inner is not annotation else ""


def describe_method(func: Any) -> Optional[Dict[str, Any]]:
    """Parameters of a generated API method, or None if it can't be driven from a form."""
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return None
    params = []
    for p in signature.parameters.values():
        if p.name.startswith("_") or p.name == "self" or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        base = _unwrap(p.annotation)
        required = p.default is inspect.Parameter.empty
        kind = SIMPLE_TYPES.get(base)
        if kind is None:
            if required:
                return None
            continue
        params.append({"name": p.name, "type": kind, "required": required, "description": _description(p.annotation)})
    doc = (inspect.getdoc(func) or "").split("\n", 1)[0]
    return {"params": params, "doc": doc}


def catalog(management: Any) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """{api_name: {method_name: description}} for read-only methods only."""
    result: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for api_name in sorted(n for n in vars(management) if n.endswith("_api")):
        api = getattr(management, api_name)
        methods = {}
        for name in dir(api):
            if not name.startswith(READ_PREFIXES):
                continue
            if name.endswith(("_with_http_info", "_without_preload_content")):
                continue
            func = getattr(api, name, None)
            if not callable(func):
                continue
            described = describe_method(func)
            if described is not None:
                methods[name] = described
        if methods:
            result[api_name] = methods
    return result


_catalog_cache: Optional[Dict[str, Any]] = None


def get_catalog(management: Any) -> Dict[str, Any]:
    global _catalog_cache
    if _catalog_cache is None:
        _catalog_cache = catalog(management)
    return _catalog_cache


def convert(value: str, kind: str) -> Any:
    if kind == "int":
        return int(value)
    if kind == "float":
        return float(value)
    if kind == "bool":
        return value.lower() in ("1", "true", "yes", "on")
    return value


def present(result: Any) -> Any:
    """Generated models -> plain data, with credentials masked."""
    return redact_data(to_plain(result))


# ---------------------------------------------------------------------------
# Resources created by the playground
# ---------------------------------------------------------------------------

def load_created() -> List[Dict[str, Any]]:
    try:
        return json.loads(CREATED_FILE.read_text())
    except (FileNotFoundError, ValueError):
        return []


def _save_created(items: List[Dict[str, Any]]) -> None:
    CREATED_FILE.parent.mkdir(parents=True, exist_ok=True)
    CREATED_FILE.write_text(json.dumps(items, indent=2))


def record_created(kind: str, ident: str, label: str, **extra: Any) -> None:
    with _created_lock:
        items = load_created()
        items.append({"kind": kind, "id": ident, "label": label,
                      "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), **extra})
        _save_created(items)


def _created_orgs() -> List[str]:
    return [item["id"] for item in load_created() if item["kind"] == "organization"]


def _created_users() -> List[str]:
    return [item["id"] for item in load_created() if item["kind"] == "user"]


# ---------------------------------------------------------------------------
# M2M token
# ---------------------------------------------------------------------------

def _jwt_claims(token: str) -> Dict[str, Any]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def _not_configured():
    return Page("management.html", {"enabled": False, "snippet": SNIPPET})


@route("/management", name="management")
@require_auth
async def management_page(req, kinde):
    management = kinde.management()
    if management is None:
        return _not_configured()
    methods = get_catalog(management)
    selected_api = req.arg("api") or "users_api"
    if selected_api not in methods:
        selected_api = next(iter(methods), "")
    selected_method = req.arg("method")
    if selected_method not in methods.get(selected_api, {}):
        selected_method = next(iter(methods.get(selected_api, {})), "")
    return Page("management.html", {
        "enabled": True,
        "curated": [(key, label) for key, (label, *_rest) in CURATED.items()],
        "catalog": methods,
        "selected_api": selected_api,
        "selected_method": selected_method,
        "method_info": methods.get(selected_api, {}).get(selected_method),
        "console_result": None,
        "last_result": req.session.pop(RESULT_KEY, None),
        "created": load_created(),
        "allow_mutations": kinde.settings.allow_mutations,
        "confirm_word": CONFIRM_WORD,
        "prefix": PREFIX,
        "current_user_id": kinde.kinde_user_id(),
        "snippet": SNIPPET,
    })


@route("/management/partials/token", name="management_token")
@require_auth
async def management_token(req, kinde):
    management = kinde.management()
    if management is None:
        return Partial("partials/denied.html", {"reason": "Management API is not configured."})

    async def fetch():
        token = await in_thread(management.token_manager.get_access_token)
        claims = _jwt_claims(token or "")
        return {
            "token": mask(token),
            "expires": claims.get("exp"),
            "audience": claims.get("aud"),
            "scopes": claims.get("scp") or (claims.get("scope") or "").split() or [],
            "application": claims.get("azp"),
        }

    return Partial("partials/mgmt_token.html", {"call": await attempt("Fetch M2M token", fetch)})


@route("/management/partials/read", name="management_read")
@require_auth
async def management_read(req, kinde):
    management = kinde.management()
    key = req.arg("call")
    if management is None or key not in CURATED:
        return Partial("partials/denied.html", {"reason": "Unknown call."}, status=404)
    label, api_name, method_name, kwargs = CURATED[key]
    func = getattr(getattr(management, api_name), method_name)

    async def call():
        return present(await in_thread(func, **kwargs))

    args = ", ".join(f"{k}={v!r}" for k, v in kwargs.items())
    return Partial("partials/mgmt_call.html", {
        "call": await attempt(label, call),
        "expression": f"management.{api_name}.{method_name}({args})",
    })


@route("/management/console", name="management_console", methods=["POST"])
@require_auth
async def management_console(req, kinde):
    management = kinde.management()
    if management is None:
        return _not_configured()
    methods = get_catalog(management)
    api_name, method_name = req.arg("api"), req.arg("method")
    info = methods.get(api_name, {}).get(method_name)
    if info is None:
        # Only introspected read methods are callable; never getattr arbitrary names
        flash(req.session, "That method is not available in the read-only console.", "error")
        return Redirect("/management")

    kwargs: Dict[str, Any] = {}
    problems = []
    for param in info["params"]:
        raw = req.arg(f"p_{param['name']}")
        if raw == "":
            if param["required"]:
                problems.append(f"{param['name']} is required")
            continue
        try:
            kwargs[param["name"]] = convert(raw, param["type"])
        except ValueError:
            problems.append(f"{param['name']} must be {param['type']}")

    func = getattr(getattr(management, api_name), method_name)
    args = ", ".join(f"{k}={v!r}" for k, v in kwargs.items())
    if problems:
        result = {"label": method_name, "ok": False, "error": "; ".join(problems), "ms": 0}
    else:
        async def call():
            return present(await in_thread(func, **kwargs))
        result = await attempt(method_name, call)

    page = await management_page.__wrapped__(req, kinde)
    page.context.update({
        "selected_api": api_name,
        "selected_method": method_name,
        "method_info": info,
        "console_result": result,
        "console_expression": f"management.{api_name}.{method_name}({args})",
        "console_values": {p["name"]: req.arg(f"p_{p['name']}") for p in info["params"]},
    })
    return page


# ---------------------------------------------------------------------------
# Write scenarios
# ---------------------------------------------------------------------------

def _mutation_blocked(req, kinde) -> Optional[str]:
    if not kinde.settings.allow_mutations:
        return "Write scenarios are disabled. Set PLAYGROUND_ALLOW_MUTATIONS=true to enable them."
    if req.arg("confirm") != CONFIRM_WORD:
        return f'Type "{CONFIRM_WORD}" to confirm changes to your Kinde business.'
    return None


def _store_result(req, title: str, call: Dict[str, Any]) -> None:
    req.session[RESULT_KEY] = {"title": title, **{k: v for k, v in call.items() if k != "label"}}


def _scenario(name: str):
    def decorator(func):
        async def handler(req, kinde):
            management = kinde.management()
            if management is None:
                return _not_configured()
            blocked = _mutation_blocked(req, kinde)
            if blocked:
                flash(req.session, blocked, "error")
                return Redirect("/management#scenarios")
            try:
                title, call = await func(req, kinde, management)
            except ValueError as exc:
                flash(req.session, str(exc), "error")
                return Redirect("/management#scenarios")
            _store_result(req, title, call)
            flash(req.session, f"{title}: {'done' if call['ok'] else 'failed'}", "success" if call["ok"] else "error")
            return Redirect("/management#result")
        handler.__name__ = f"scenario_{name}"
        return route(f"/management/scenarios/{name}", name=f"scenario_{name}", methods=["POST"])(require_auth(handler))
    return decorator


@_scenario("create-user")
async def create_user(req, kinde, management):
    from kinde_sdk.management.models import CreateUserRequest

    suffix = secrets.token_hex(3)
    email = req.arg("email") or f"playground+{suffix}@example.com"
    if "@" not in email:
        raise ValueError("Enter a valid email address.")
    body = CreateUserRequest.from_dict({
        "profile": {"given_name": "Playground", "family_name": f"{PREFIX}{suffix}"},
        "identities": [{"type": "email", "is_verified": False, "details": {"email": email}}],
    })

    async def call():
        created = await in_thread(management.users_api.create_user, create_user_request=body)
        if created and getattr(created, "id", None):
            record_created("user", created.id, email)
        return present(created)

    return "Create user", await attempt("create_user", call)


@_scenario("create-org")
async def create_org(req, kinde, management):
    from kinde_sdk.management.models import CreateOrganizationRequest

    name = req.arg("name") or secrets.token_hex(3)
    if not name.startswith(PREFIX):
        name = PREFIX + name
    body = CreateOrganizationRequest(name=name)

    async def call():
        created = await in_thread(management.organizations_api.create_organization, create_organization_request=body)
        org_code = getattr(created, "code", None) or getattr(getattr(created, "organization", None), "code", None)
        if org_code:
            record_created("organization", org_code, name)
        return present(created)

    return "Create organization", await attempt("create_organization", call)


@_scenario("add-user-to-org")
async def add_user_to_org(req, kinde, management):
    from kinde_sdk.management.models import AddOrganizationUsersRequest

    org_code = req.arg("org_code")
    user_id = req.arg("user_id") or kinde.kinde_user_id() or ""
    role = req.arg("role")
    if org_code not in _created_orgs():
        raise ValueError("Pick an organization created by the playground.")
    if user_id not in _created_users() and user_id != kinde.kinde_user_id():
        raise ValueError("Pick a playground user or yourself.")
    entry: Dict[str, Any] = {"id": user_id}
    if role:
        entry["roles"] = [role]
    body = AddOrganizationUsersRequest.from_dict({"users": [entry]})

    async def call():
        return present(await in_thread(management.organizations_api.add_organization_users,
                                       org_code=org_code, add_organization_users_request=body))

    return "Add user to organization", await attempt("add_organization_users", call)


@_scenario("flag-override")
async def flag_override(req, kinde, management):
    org_code, flag_key, value = req.arg("org_code"), req.arg("flag_key"), req.arg("value")
    if org_code not in _created_orgs():
        raise ValueError("Pick an organization created by the playground.")
    if not flag_key or value == "":
        raise ValueError("Enter a flag key and a value.")

    async def call():
        result = await in_thread(management.organizations_api.update_organization_feature_flag_override,
                                 org_code=org_code, feature_flag_key=flag_key, value=value)
        return present(result)

    return "Override feature flag", await attempt("update_organization_feature_flag_override", call)


@_scenario("meter-usage")
async def meter_usage(req, kinde, management):
    from kinde_sdk.management.models import CreateMeterUsageRecordRequest

    agreement, feature, value = req.arg("customer_agreement_id"), req.arg("billing_feature_code"), req.arg("meter_value")
    if not (agreement and feature and value):
        raise ValueError("Agreement ID, feature code and value are all required.")
    try:
        float(value)
    except ValueError:
        raise ValueError("The meter value must be a number.") from None
    body = CreateMeterUsageRecordRequest(customer_agreement_id=agreement, billing_feature_code=feature, meter_value=value)

    async def call():
        return present(await in_thread(management.billing_meter_usage_api.create_meter_usage_record,
                                       create_meter_usage_record_request=body))

    return "Record metered usage", await attempt("create_meter_usage_record", call)


@route("/management/cleanup", name="management_cleanup", methods=["POST"])
@require_auth
async def cleanup(req, kinde):
    management = kinde.management()
    if management is None:
        return _not_configured()
    if not kinde.settings.allow_mutations:
        flash(req.session, "Cleanup needs PLAYGROUND_ALLOW_MUTATIONS=true.", "error")
        return Redirect("/management#created")

    remaining, removed, failed = [], 0, []
    for item in load_created():
        try:
            if item["kind"] == "user":
                await in_thread(management.users_api.delete_user, id=item["id"], is_delete_profile=True)
            elif item["kind"] == "organization":
                await in_thread(management.organizations_api.delete_organization, org_code=item["id"])
            removed += 1
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                removed += 1
                continue
            failed.append(f"{item['label']} ({safe_error(exc)})")
            remaining.append(item)
    with _created_lock:
        _save_created(remaining)
    if failed:
        flash(req.session, f"Removed {removed}; could not remove: {', '.join(failed)}", "error")
    else:
        flash(req.session, f"Removed {removed} playground resource(s).", "success")
    return Redirect("/management#created")
