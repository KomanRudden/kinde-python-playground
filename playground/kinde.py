"""One place where the playground talks to the Kinde SDK.

This is how we recommend wiring the SDK into an app:

* exactly one OAuth client per process, created at startup with explicit
  configuration (the framework integration registers /login, /register,
  /callback and /logout for you);
* one ManagementClient per process, created lazily and reused, so its M2M
  token is cached;
* blocking SDK calls (token refresh, userinfo, Management API) run in a worker
  thread so they never stall an async event loop.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import threading
from typing import Any, Dict, Optional

from kinde_sdk.auth import claims, feature_flags, permissions, portals, roles, tokens
from kinde_sdk.auth.smart_oauth import create_oauth_client

from .config import Settings

logger = logging.getLogger("playground.kinde")

CLIENT_KINDS = {"oauth": "OAuth", "async": "AsyncOAuth", "smart": "SmartOAuth"}


async def in_thread(func, *args, **kwargs):
    """Run a blocking SDK call off the event loop, keeping the request context."""
    return await asyncio.to_thread(functools.partial(func, *args, **kwargs))


def create_oauth(settings: Settings, app: Any):
    """Create the app's single OAuth client for the configured client mode."""
    async_mode = {"oauth": False, "async": True, "smart": None}[settings.client_mode]
    return create_oauth_client(
        async_mode,
        client_id=settings.client_id,
        client_secret=settings.client_secret,
        redirect_uri=settings.redirect_uri,
        host=settings.kinde_host,
        audience=settings.audience,
        framework=settings.framework,
        app=app,
        force_api=settings.force_api,
    )


class Kinde:
    def __init__(self, settings: Settings, oauth: Any):
        self.settings = settings
        self.oauth = oauth
        self._management = None
        self._management_lock = threading.Lock()

    # SDK helper singletons, exposed for the feature modules
    claims = claims
    permissions = permissions
    roles = roles
    feature_flags = feature_flags
    portals = portals
    tokens = tokens

    @property
    def client_kind(self) -> str:
        return CLIENT_KINDS[self.settings.client_mode]

    # ------------------------------------------------------------------
    # Authentication state
    # ------------------------------------------------------------------

    async def is_authenticated(self) -> bool:
        # May refresh an expired access token, which is a blocking HTTP call
        return await in_thread(self.oauth.is_authenticated)

    def token_manager(self):
        return tokens.get_token_manager()

    def user_id(self) -> Optional[str]:
        """The SDK's key for this session's tokens: not the Kinde user ID."""
        return tokens.get_user_id()

    def kinde_user_id(self) -> Optional[str]:
        """The signed-in user's Kinde ID (kp_...), as the Management API expects it."""
        tm = self.token_manager()
        if not tm:
            return None
        return tm.get_claims("id_token").get("sub") or tm.get_claims("access_token").get("sub")

    async def get_user_info(self) -> Dict[str, Any]:
        """Userinfo from Kinde: native async where the client offers it."""
        if hasattr(type(self.oauth), "get_user_info_async"):
            return await self.oauth.get_user_info_async()
        return await in_thread(self.oauth.get_user_info)

    async def auth_context(self) -> Dict[str, Any]:
        """What every page header needs, read from the ID token without a network call."""
        try:
            authenticated = await self.is_authenticated()
        except Exception as exc:
            logger.warning("Authentication check failed: %s", type(exc).__name__)
            authenticated = False
        if not authenticated:
            return {"authenticated": False}
        tm = self.token_manager()
        id_claims = tm.get_claims("id_token") if tm else {}
        access_claims = tm.get_claims("access_token") if tm else {}
        name = " ".join(filter(None, [id_claims.get("given_name"), id_claims.get("family_name")]))
        return {
            "authenticated": True,
            "name": name or id_claims.get("email") or "Signed in",
            "email": id_claims.get("email"),
            "picture": id_claims.get("picture"),
            "initials": "".join(p[0] for p in (name or id_claims.get("email") or "?").split()[:2]).upper(),
            "org_code": access_claims.get("org_code"),
            "org_name": access_claims.get("org_name"),
        }

    def access_token(self) -> Optional[str]:
        tm = self.token_manager()
        return tm.get_access_token() if tm else None

    # ------------------------------------------------------------------
    # Account API (frontend) client, for calls the helpers don't wrap
    # ------------------------------------------------------------------

    async def account_api(self, api_class):
        from kinde_sdk.frontend.api_client import ApiClient
        from kinde_sdk.frontend.configuration import Configuration

        token = await in_thread(self.access_token)
        if not token:
            return None
        config = Configuration(host=self.settings.kinde_host)
        config.access_token = token
        return api_class(api_client=ApiClient(configuration=config))

    # ------------------------------------------------------------------
    # Management API (M2M)
    # ------------------------------------------------------------------

    def management(self):
        """The shared ManagementClient, or None when M2M credentials aren't configured."""
        if not self.settings.management_enabled:
            return None
        with self._management_lock:
            if self._management is None:
                from kinde_sdk.management import ManagementClient
                self._management = ManagementClient(
                    domain=self.settings.management_domain,
                    client_id=self.settings.management_client_id,
                    client_secret=self.settings.management_client_secret,
                )
            return self._management
