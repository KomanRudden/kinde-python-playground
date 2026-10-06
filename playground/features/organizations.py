"""Organizations from the user's point of view: current org, memberships, switching."""
from __future__ import annotations

from ..guards import require_auth
from ..kinde import in_thread
from ..web import Page, route
from ._common import code

SNIPPET = code('''
    from kinde_sdk.auth import claims

    current = (await claims.get_claim("org_code"))["value"]
    member_of = (await claims.get_claim("org_codes", token_type="id_token"))["value"] or []

    # Switch organization: sign in again with the org code
    url = await oauth.login({"org_code": "org_123"})

    # Names come from the Management API (server side only)
    org = management.organizations_api.get_organization(code="org_123")
''')


@route("/organizations", name="organizations")
@require_auth
async def organizations_page(req, kinde):
    current = (await kinde.claims.get_claim("org_code"))["value"]
    current_name = (await kinde.claims.get_claim("org_name"))["value"]
    codes = (await kinde.claims.get_claim("org_codes", token_type="id_token"))["value"] or []
    if not codes:
        codes = (await kinde.claims.get_claim("org_codes"))["value"] or []

    names = {}
    management = kinde.management()
    if management is not None:
        for org_code in codes[:25]:
            try:
                org = await in_thread(management.organizations_api.get_organization, code=org_code)
                names[org_code] = getattr(org, "name", None)
            except Exception:
                names[org_code] = None

    orgs = [{"code": c, "name": names.get(c) or (current_name if c == current else None), "current": c == current}
            for c in codes]
    if current and current not in codes:
        orgs.insert(0, {"code": current, "name": current_name, "current": True})

    return Page("organizations.html", {
        "orgs": orgs,
        "current": current,
        "management_enabled": management is not None,
        "snippet": SNIPPET,
    })
