"""Billing: entitlements of the current organization and plan management links."""
from __future__ import annotations

from kinde_sdk.auth.entitlements import Entitlements

from ..guards import require_auth
from ..kinde import in_thread
from ..web import Page, route
from ._common import attempt, code, to_plain

SNIPPET = code('''
    from kinde_sdk.auth.entitlements import Entitlements

    access_token = tokens.get_token_manager().get_access_token()
    entitlements = Entitlements(base_url=KINDE_HOST, token=access_token)

    for entitlement in entitlements.get_all_entitlements():     # pages through everything
        print(entitlement.feature_key, entitlement.entitlement_limit_max)

    seats = entitlements.get_entitlement("seats").data.entitlement

    # Let the customer pick or change their plan in the hosted portal
    link = await portals.generate_portal_url(KINDE_HOST, return_url, PortalPage.ORGANIZATION_PLAN_SELECTION)
''')


@route("/billing", name="billing")
@require_auth
async def billing_page(req, kinde):
    key = req.arg("key") or kinde.settings.demo_entitlement

    async def client():
        return Entitlements(base_url=kinde.settings.kinde_host, token=await in_thread(kinde.access_token))

    async def all_entitlements():
        entitlements = await client()
        return [to_plain(e) for e in await in_thread(entitlements.get_all_entitlements)]

    async def one_entitlement():
        entitlements = await client()
        return to_plain(await in_thread(entitlements.get_entitlement, key))

    return Page("billing.html", {
        "key": key,
        "all": await attempt("Entitlements.get_all_entitlements()", all_entitlements),
        "one": await attempt(f"Entitlements.get_entitlement({key!r})", one_entitlement),
        "snippet": SNIPPET,
    })
