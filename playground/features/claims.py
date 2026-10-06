"""Claims explorer."""
from __future__ import annotations

from ..guards import require_auth
from ..web import Page, route
from ._common import code, token_type

SNIPPET = code('''
    from kinde_sdk.auth import claims

    all_claims = await claims.get_all_claims()                       # access token
    id_claims = await claims.get_all_claims(token_type="id_token")
    aud = await claims.get_claim("aud")                              # {"name": "aud", "value": [...]}
    email = await claims.get_claim("email", token_type="id_token")
''')

COMMON_CLAIMS = ["aud", "iss", "sub", "exp", "scp", "org_code", "org_name", "permissions", "roles",
                 "feature_flags", "email", "given_name", "family_name", "picture", "org_codes"]


@route("/claims", name="claims")
@require_auth
async def claims_page(req, kinde):
    claim_name = req.arg("claim")
    selected_type = token_type(req.arg("token_type"))
    lookup = await kinde.claims.get_claim(claim_name, token_type=selected_type) if claim_name else None
    return Page("claims.html", {
        "access_claims": await kinde.claims.get_all_claims(token_type="access_token"),
        "id_claims": await kinde.claims.get_all_claims(token_type="id_token"),
        "claim_name": claim_name,
        "selected_type": selected_type,
        "lookup": lookup,
        "common_claims": COMMON_CLAIMS,
        "snippet": SNIPPET,
    })
