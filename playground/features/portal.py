"""Self-serve portal links for every PortalPage."""
from __future__ import annotations

from kinde_sdk.auth.portals import PortalPage

from ..guards import require_auth
from ..web import Page, Redirect, flash, route
from ._common import code, safe_error

DESCRIPTIONS = {
    PortalPage.PROFILE: "The user's own profile, sign-in methods and MFA.",
    PortalPage.ORGANIZATION_DETAILS: "Organization name, logo and settings.",
    PortalPage.ORGANIZATION_MEMBERS: "Invite and manage members.",
    PortalPage.ORGANIZATION_PLAN_DETAILS: "The organization's current plan.",
    PortalPage.ORGANIZATION_PAYMENT_DETAILS: "Payment methods and invoices.",
    PortalPage.ORGANIZATION_PLAN_SELECTION: "Choose or change plan.",
}

SNIPPET = code('''
    from kinde_sdk.auth import portals
    from kinde_sdk.auth.portals import PortalPage

    link = await portals.generate_portal_url(
        domain=KINDE_HOST,
        return_url="https://app.example.com/settings",   # must be absolute
        sub_nav=PortalPage.ORGANIZATION_MEMBERS,
    )
    return redirect(link["url"])   # one-time link: generate it on click, don't cache it
''')


@route("/portal", name="portal")
@require_auth
async def portal_page(req, kinde):
    pages = [{"value": p.value, "label": p.name.replace("_", " ").title(), "description": DESCRIPTIONS.get(p, "")}
             for p in PortalPage]
    return Page("portal.html", {"pages": pages, "snippet": SNIPPET})


@route("/portal/open", name="portal_open", methods=["POST"])
@require_auth
async def portal_open(req, kinde):
    try:
        sub_nav = PortalPage(req.arg("sub_nav"))
    except ValueError:
        flash(req.session, "Unknown portal page.", "error")
        return Redirect("/portal")
    try:
        link = await kinde.portals.generate_portal_url(
            domain=kinde.settings.kinde_host,
            return_url=f"{kinde.settings.base_url}/portal",
            sub_nav=sub_nav,
        )
    except Exception as exc:
        # These SDK messages carry only a status code or a usage error
        message = str(exc)
        detail = message if message.startswith(("Failed to fetch portal URL", "generate_portal_url")) else safe_error(exc)
        flash(req.session, f"Could not create a portal link: {detail}. "
                           "Enable the self-serve portal for this application in Kinde.", "error")
        return Redirect("/portal")
    return Redirect(link["url"], status=302)
