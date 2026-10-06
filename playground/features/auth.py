"""Sign in lab: every login option the SDK supports, create-org and invitations."""
from __future__ import annotations

from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlparse

from kinde_sdk.auth.enums import IssuerRouteTypes, PromptTypes
from kinde_sdk.auth.login_options import LoginOptions

from ..redact import mask
from ..web import Page, Redirect, flash, route, safe_next
from ._common import code

TEXT_OPTIONS = [
    (LoginOptions.LOGIN_HINT, "Login hint", "jane@example.com", "Pre-fills the email on the Kinde sign-in page."),
    (LoginOptions.CONNECTION_ID, "Connection ID", "conn_0123…", "Skip the chooser and go straight to one connection (e.g. Google)."),
    (LoginOptions.LANG, "Language", "en", "Language of the hosted pages."),
    (LoginOptions.ORG_CODE, "Organization code", "org_0123…", "Sign in to a specific organization."),
    (LoginOptions.PLAN_INTEREST, "Plan interest", "pro", "Billing: preselect a plan during sign-up."),
    (LoginOptions.PRICING_TABLE_KEY, "Pricing table key", "default", "Billing: which pricing table to show."),
    (LoginOptions.WORKFLOW_DEPLOYMENT_ID, "Workflow deployment ID", "", "Run a specific workflow version."),
]
PROMPTS = [p.value for p in PromptTypes]
DEFAULT_SCOPE = "openid profile email offline"
# Parameters the SDK sets itself; overriding them through auth_params would break
# the callback checks or redirect the code elsewhere
RESERVED_AUTH_PARAMS = {
    "state", "nonce", "code_challenge", "code_challenge_method", "redirect_uri",
    "client_id", "response_type", "scope", "audience",
}
SENSITIVE_URL_PARAMS = {"state", "nonce", "code_challenge"}

SNIPPET = code('''
    from kinde_sdk.auth.login_options import LoginOptions

    login_options = {
        LoginOptions.LOGIN_HINT: "jane@example.com",
        LoginOptions.ORG_CODE: "org_123",
        LoginOptions.SCOPE: "openid profile email offline",   # offline -> refresh token
        LoginOptions.AUTH_PARAMS: {"utm_source": "newsletter"},
    }
    url = await oauth.login(login_options)       # or oauth.register(login_options)

    # Create an organization while signing up
    url = await oauth.register({LoginOptions.IS_CREATE_ORG: True, LoginOptions.ORG_NAME: "Acme"})

    # Accept an invitation (the built-in /login route also accepts ?invitation_code=)
    url = await oauth.login({LoginOptions.INVITATION_CODE: invitation_code})

    # Return to a page after the callback (read and cleared by the /callback route)
    session["post_login_redirect_url"] = {"url": "/billing"}
    return redirect(url)
''')


@route("/auth", name="auth")
async def auth_page(req, kinde):
    return Page("auth.html", {
        "text_options": TEXT_OPTIONS,
        "prompts": PROMPTS,
        "default_scope": DEFAULT_SCOPE,
        "snippet": SNIPPET,
        "preview": None,
        "values": {},
    })


@route("/auth/start", name="auth_start", methods=["GET", "POST"])
async def auth_start(req, kinde):
    flow = "register" if req.arg("flow") == "register" else "login"
    options, errors = build_login_options(req)
    if errors:
        for error in errors:
            flash(req.session, error, "error")
        return Redirect("/auth")

    next_path = safe_next(req.arg("next"), default="/")
    req.session["post_login_redirect_url"] = {"url": next_path}

    if req.method == "POST" and req.arg("action") == "preview":
        return Page("auth.html", {
            "text_options": TEXT_OPTIONS,
            "prompts": PROMPTS,
            "default_scope": DEFAULT_SCOPE,
            "snippet": SNIPPET,
            "values": dict(req.form),
            "preview": await preview(kinde, flow, options),
        })

    url = await (kinde.oauth.register(options) if flow == "register" else kinde.oauth.login(options))
    return Redirect(url, status=302)


def build_login_options(req) -> Tuple[Dict, List[str]]:
    options: Dict = {}
    errors: List[str] = []

    for key, *_ in TEXT_OPTIONS:
        value = req.arg(key)
        if value:
            options[key] = value

    prompt = req.arg("prompt")
    if prompt:
        if prompt not in PROMPTS:
            errors.append(f"Unknown prompt {prompt!r}")
        else:
            options[LoginOptions.PROMPT] = prompt

    scope = " ".join(req.arg("scope").split()) or DEFAULT_SCOPE
    if "openid" not in scope.split():
        errors.append("The scope must include openid: the SDK validates the ID token nonce on every callback.")
    options[LoginOptions.SCOPE] = scope

    if req.arg("is_create_org") in ("on", "true", "1"):
        org_name = req.arg("org_name")
        if not org_name:
            errors.append("Enter a name for the organization to create.")
        options[LoginOptions.IS_CREATE_ORG] = True
        options[LoginOptions.ORG_NAME] = org_name

    invitation = req.arg("invitation_code")
    if invitation:
        options[LoginOptions.INVITATION_CODE] = invitation

    auth_params = {}
    for line in req.arg("auth_params").splitlines():
        line = line.strip()
        if not line:
            continue
        if "=" not in line:
            errors.append(f"Extra parameter {line!r} must look like key=value")
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in RESERVED_AUTH_PARAMS:
            errors.append(f"{key} is set by the SDK and can't be overridden")
            continue
        auth_params[key] = value
    if auth_params:
        options[LoginOptions.AUTH_PARAMS] = auth_params

    return options, errors


async def preview(kinde, flow: str, options: Dict) -> Dict:
    """Build the authorization URL without leaving the page, with one-time values masked."""
    preview_options = dict(options)
    preview_options[LoginOptions.SUPPORT_RE_AUTH] = "true"
    route_type = IssuerRouteTypes.REGISTER if flow == "register" else IssuerRouteTypes.LOGIN
    if flow == "register" and not preview_options.get(LoginOptions.PROMPT):
        preview_options[LoginOptions.PROMPT] = PromptTypes.CREATE.value
    data = await kinde.oauth.generate_auth_url(route_type=route_type, login_options=preview_options)
    parsed = urlparse(data["url"])
    params = [
        {"name": k, "value": mask(v) if k in SENSITIVE_URL_PARAMS else v, "masked": k in SENSITIVE_URL_PARAMS}
        for k, v in parse_qsl(parsed.query)
    ]
    return {
        "flow": flow,
        "endpoint": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
        "params": params,
        "options": options,
    }
