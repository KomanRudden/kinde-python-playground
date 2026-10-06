"""Session and storage: what the SDK keeps where."""
from __future__ import annotations

import json

from kinde_sdk.core.framework.framework_factory import FrameworkFactory
from kinde_sdk.core.session_management import KindeSessionManagement
from kinde_sdk.core.storage.storage_factory import StorageFactory
from kinde_sdk.core.storage.storage_manager import StorageManager

from ..redact import is_sensitive_key, mask
from ..web import Page, route
from ._common import code

SNIPPET = code('''
    # In a web framework the integration owns the session: you never touch it.
    # Standalone scripts and workers use KindeSessionManagement instead:
    from kinde_sdk import OAuth, KindeSessionManagement

    oauth = OAuth(client_id=..., redirect_uri=..., host=...)   # no framework -> NullFramework
    sessions = KindeSessionManagement()
    sessions.set_user_id("user-123")         # which user the next SDK calls act for
    sessions.get_session_info()

    # Pick a storage backend for standalone use
    oauth = OAuth(..., storage_config={"type": "memory"})       # or "local_storage"
''')

SESSION_COOKIES = {"flask": "session", "fastapi": "pg_session"}


def describe_value(key: str, value) -> str:
    if is_sensitive_key(key):
        return mask(json.dumps(value, default=str))
    try:
        size = len(json.dumps(value, default=str))
    except (TypeError, ValueError):
        size = 0
    if isinstance(value, dict):
        inner = ", ".join(sorted(value.keys())[:8])
        return f"object with keys: {inner} ({size} bytes)"
    return f"{type(value).__name__} ({size} bytes)"


@route("/session", name="session")
async def session_page(req, kinde):
    framework = FrameworkFactory.get_framework_instance()
    storage = StorageManager()
    keys = [{"key": k, "description": describe_value(k, v), "ours": k.startswith("pg_")}
            for k, v in sorted(req.session.items())]

    try:
        KindeSessionManagement()
        standalone_note = "KindeSessionManagement is available: the SDK is running standalone."
    except RuntimeError as exc:
        standalone_note = str(exc)

    scratch = StorageFactory.create_storage({"type": "memory"})
    scratch.set("demo", {"value": 42})
    roundtrip = scratch.get("demo")
    scratch.delete("demo")

    cookie_name = SESSION_COOKIES[kinde.settings.framework]
    cookie_value = req.cookies.get(cookie_name, "")

    return Page("session.html", {
        "framework_name": framework.get_name() if framework else "none",
        "framework_class": type(framework).__name__ if framework else None,
        "storage_type": getattr(storage, "_storage_type", None),
        "storage_class": type(getattr(storage, "_storage", None)).__name__,
        "device_id": getattr(storage, "_device_id", None),
        "keys": keys,
        "cookie_name": cookie_name,
        "cookie_length": len(cookie_value),
        "standalone_note": standalone_note,
        "roundtrip": roundtrip,
        "after_delete": scratch.get("demo"),
        "user_id": kinde.user_id(),
        "snippet": SNIPPET,
    })
