"""Profile: userinfo, the Account API profile and user properties."""
from __future__ import annotations

from kinde_sdk.frontend.api.o_auth_api import OAuthApi
from kinde_sdk.frontend.api.properties_api import PropertiesApi

from ..guards import require_auth
from ..kinde import in_thread
from ..web import Page, route
from ._common import attempt, code, to_plain

SNIPPET = code('''
    if oauth.is_authenticated():
        user = oauth.get_user_info()                 # OAuth (sync)
        user = await oauth.get_user_info_async()     # AsyncOAuth / SmartOAuth

    # Anything the helpers don't wrap is on the generated Account API client
    from kinde_sdk.frontend.api.o_auth_api import OAuthApi
    from kinde_sdk.frontend.api_client import ApiClient
    from kinde_sdk.frontend.configuration import Configuration

    config = Configuration(host=KINDE_HOST)
    config.access_token = tokens.get_token_manager().get_access_token()
    profile = OAuthApi(ApiClient(config)).get_user_profile_v2()
''')


@route("/profile", name="profile")
@require_auth
async def profile(req, kinde):
    async def account_profile():
        api = await kinde.account_api(OAuthApi)
        return to_plain(await in_thread(api.get_user_profile_v2))

    async def user_properties():
        api = await kinde.account_api(PropertiesApi)
        response = await in_thread(api.get_user_properties)
        return [to_plain(p) for p in (getattr(response.data, "properties", None) or [])]

    calls = [
        await attempt(f"{kinde.client_kind}.get_user_info" + ("_async()" if kinde.client_kind != "OAuth" else "()"),
                      kinde.get_user_info),
        await attempt("OAuthApi.get_user_profile_v2()", account_profile),
        await attempt("PropertiesApi.get_user_properties()", user_properties),
    ]
    return Page("profile.html", {"calls": calls, "snippet": SNIPPET})
