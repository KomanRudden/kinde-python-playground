"""Tokens: decoded claims, expiry, refresh and revoke."""
from __future__ import annotations

import time

from ..guards import require_auth
from ..kinde import in_thread
from ..redact import mask
from ..web import Page, Redirect, flash, route
from ._common import code, safe_error

SNIPPET = code('''
    from kinde_sdk.auth import tokens

    info = tokens.get_token_info()   # {"isAuthenticated", "hasAccessToken", "hasRefreshToken", ...}
    tm = tokens.get_token_manager()

    access_token = tm.get_access_token()   # refreshes transparently when expired
    claims = tm.get_claims("access_token") # or "id_token"

    tm.refresh_access_token()   # needs a refresh token: request the "offline" scope
    tm.revoke_token()           # revokes at Kinde and clears the tokens in this process
''')


@route("/tokens", name="tokens")
@require_auth
async def tokens_page(req, kinde):
    tm = kinde.token_manager()
    stored = dict(tm.tokens) if tm else {}
    expires_at = stored.get("expires_at")
    debug = kinde.settings.debug

    def describe(name: str, value):
        if not value:
            return {"name": name, "present": False}
        return {
            "name": name,
            "present": True,
            "masked": mask(value),
            "length": len(value),
            "value": value if debug else None,
        }

    return Page("tokens.html", {
        "info": kinde.tokens.get_token_info(),
        "tokens": [
            describe("Access token", stored.get("access_token")),
            describe("ID token", stored.get("id_token")),
            describe("Refresh token", stored.get("refresh_token")),
        ],
        "expires_at": expires_at,
        "expires_in": int(expires_at - time.time()) if expires_at else None,
        "access_claims": tm.get_claims("access_token") if tm else {},
        "id_claims": tm.get_claims("id_token") if tm else {},
        "has_refresh": bool(stored.get("refresh_token")),
        "snippet": SNIPPET,
    })


@route("/tokens/refresh", name="tokens_refresh", methods=["POST"])
@require_auth
async def refresh(req, kinde):
    tm = kinde.token_manager()
    previous = tm.tokens.get("access_token")
    try:
        await in_thread(tm.refresh_access_token)
        if tm.tokens.get("access_token") == previous:
            flash(req.session, "Refresh succeeded. Kinde returned the same access token because it is still valid; only the expiry was updated.", "success")
        else:
            flash(req.session, "Access token refreshed: Kinde issued a new access token.", "success")
    except ValueError:
        flash(req.session, "No refresh token in this session. Sign in with the offline scope to get one.", "warn")
    except Exception as exc:
        flash(req.session, f"Refresh failed: {safe_error(exc)}", "error")
    return Redirect("/tokens")


@route("/tokens/revoke", name="tokens_revoke", methods=["POST"])
@require_auth
async def revoke(req, kinde):
    tm = kinde.token_manager()
    await in_thread(tm.revoke_token)
    flash(req.session, "Access token revoked at Kinde and cleared from this process. Sign out to end the Kinde session too.", "success")
    return Redirect("/")
