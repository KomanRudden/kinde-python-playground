"""Settings loaded from the environment and validated once at startup."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from .redact import mask

FRAMEWORKS = ("flask", "fastapi")
CLIENT_MODES = ("oauth", "async", "smart")
DEFAULT_BASE_URLS = {"flask": "http://localhost:5050", "fastapi": "http://localhost:8000"}

STATE_DIR = Path(os.getenv("PLAYGROUND_STATE_DIR", Path.cwd() / ".playground"))


class ConfigError(RuntimeError):
    """Raised at startup when required configuration is missing or invalid."""


def _flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _clean(name: str) -> Optional[str]:
    value = os.getenv(name)
    return value.strip() if value and value.strip() else None


def _normalise_host(host: str) -> str:
    host = host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host


@dataclass(frozen=True)
class Settings:
    framework: str
    base_url: str
    kinde_host: str
    client_id: str
    client_secret: Optional[str] = field(repr=False)
    audience: Optional[str]
    management_domain: Optional[str]
    management_client_id: Optional[str]
    management_client_secret: Optional[str] = field(repr=False)
    session_secret: str = field(repr=False)
    session_secret_generated: bool = False
    client_mode: str = "oauth"
    force_api: bool = False
    allow_mutations: bool = False
    debug: bool = False
    log_level: str = "INFO"
    demo_permission: str = "read:reports"
    demo_role: str = "admin"
    demo_flag: str = "beta_dashboard"
    demo_entitlement: str = "pro_reports"
    warnings: List[str] = field(default_factory=list, compare=False)

    @classmethod
    def from_env(cls, framework: str) -> "Settings":
        if framework not in FRAMEWORKS:
            raise ConfigError(f"Unknown framework {framework!r}")

        problems = []
        warnings = []

        host = _clean("KINDE_HOST") or _clean("KINDE_DOMAIN")
        if not host:
            problems.append("KINDE_HOST is required (e.g. https://your-business.kinde.com)")
        client_id = _clean("KINDE_CLIENT_ID")
        if not client_id:
            problems.append("KINDE_CLIENT_ID is required")

        base_url = (_clean(f"PLAYGROUND_{framework.upper()}_BASE_URL") or DEFAULT_BASE_URLS[framework]).rstrip("/")
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            problems.append(f"PLAYGROUND_{framework.upper()}_BASE_URL must be an absolute URL")
        elif parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
            warnings.append("The app is served over plain HTTP on a non-local host; use HTTPS outside development.")

        client_mode = (_clean("PLAYGROUND_CLIENT_MODE") or "oauth").lower()
        if client_mode not in CLIENT_MODES:
            problems.append(f"PLAYGROUND_CLIENT_MODE must be one of {', '.join(CLIENT_MODES)}")

        if problems:
            raise ConfigError("Invalid playground configuration:\n  - " + "\n  - ".join(problems))

        client_secret = _clean("KINDE_CLIENT_SECRET")
        if not client_secret:
            warnings.append("KINDE_CLIENT_SECRET is not set: running as a public client (PKCE only).")

        session_secret = _clean("PLAYGROUND_SESSION_SECRET")
        generated = session_secret is None
        if generated:
            session_secret = secrets.token_urlsafe(48)
            warnings.append(
                "PLAYGROUND_SESSION_SECRET is not set: a random key was generated, so sessions end on restart."
            )

        kinde_host = _normalise_host(host)
        mgmt_id = _clean("KINDE_MANAGEMENT_CLIENT_ID")
        mgmt_secret = _clean("KINDE_MANAGEMENT_CLIENT_SECRET")
        mgmt_domain = _clean("KINDE_MANAGEMENT_DOMAIN") or urlparse(kinde_host).netloc
        if bool(mgmt_id) != bool(mgmt_secret):
            warnings.append("Set both KINDE_MANAGEMENT_CLIENT_ID and KINDE_MANAGEMENT_CLIENT_SECRET to use the Management API.")

        debug = _flag("PLAYGROUND_DEBUG")
        if debug:
            warnings.append("PLAYGROUND_DEBUG is on: token reveal buttons are enabled. Never use this in production.")

        return cls(
            framework=framework,
            base_url=base_url,
            kinde_host=kinde_host,
            client_id=client_id,
            client_secret=client_secret,
            audience=_clean("KINDE_AUDIENCE"),
            management_domain=mgmt_domain.replace("https://", "").replace("http://", "").rstrip("/"),
            management_client_id=mgmt_id,
            management_client_secret=mgmt_secret,
            session_secret=session_secret,
            session_secret_generated=generated,
            client_mode=client_mode,
            force_api=_flag("PLAYGROUND_FORCE_API"),
            allow_mutations=_flag("PLAYGROUND_ALLOW_MUTATIONS"),
            debug=debug,
            log_level=(_clean("PLAYGROUND_LOG_LEVEL") or "INFO").upper(),
            demo_permission=_clean("PLAYGROUND_DEMO_PERMISSION") or "read:reports",
            demo_role=_clean("PLAYGROUND_DEMO_ROLE") or "admin",
            demo_flag=_clean("PLAYGROUND_DEMO_FLAG") or "beta_dashboard",
            demo_entitlement=_clean("PLAYGROUND_DEMO_ENTITLEMENT") or "pro_reports",
            warnings=warnings,
        )

    @property
    def redirect_uri(self) -> str:
        return f"{self.base_url}/callback"

    @property
    def post_logout_redirect_uri(self) -> str:
        return self.base_url

    @property
    def is_https(self) -> bool:
        return self.base_url.startswith("https://")

    @property
    def management_enabled(self) -> bool:
        return bool(self.management_client_id and self.management_client_secret and self.management_domain)

    @property
    def known_secrets(self) -> List[str]:
        """Values that must never appear in logs, pages or the session."""
        return [s for s in (self.client_secret, self.management_client_secret, self.session_secret) if s]

    def export_sdk_env(self) -> None:
        """Expose the values the SDK and its framework integrations read from the environment."""
        os.environ["KINDE_HOST"] = self.kinde_host
        os.environ["KINDE_CLIENT_ID"] = self.client_id
        os.environ["KINDE_REDIRECT_URI"] = self.redirect_uri
        os.environ["KINDE_POST_LOGOUT_REDIRECT_URI"] = self.post_logout_redirect_uri
        if self.client_secret:
            os.environ["KINDE_CLIENT_SECRET"] = self.client_secret
        else:
            os.environ.pop("KINDE_CLIENT_SECRET", None)
        if self.audience:
            os.environ["KINDE_AUDIENCE"] = self.audience
        if self.framework == "flask":
            # Read by kinde_flask when it configures Flask-Session
            sessions_dir = STATE_DIR / "flask-sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(sessions_dir, 0o700)
            os.environ["SECRET_KEY"] = self.session_secret
            os.environ["SESSION_TYPE"] = "filesystem"
            os.environ["SESSION_FILE_DIR"] = str(sessions_dir)

    def summary(self) -> List[dict]:
        """Configuration as shown on the dashboard: secrets are masked, never rendered."""
        def row(name, value, secret=False, required=False):
            if value in (None, ""):
                status = "missing" if required else "unset"
                shown = "not set"
            else:
                status = "ok"
                shown = mask(value) if secret else str(value)
            return {"name": name, "value": shown, "status": status, "secret": secret}

        return [
            row("KINDE_HOST", self.kinde_host, required=True),
            row("KINDE_CLIENT_ID", self.client_id, required=True),
            row("KINDE_CLIENT_SECRET", self.client_secret, secret=True),
            row("KINDE_AUDIENCE", self.audience),
            row("Callback URL", self.redirect_uri, required=True),
            row("Logout redirect URL", self.post_logout_redirect_uri, required=True),
            row("KINDE_MANAGEMENT_DOMAIN", self.management_domain if self.management_enabled else None),
            row("KINDE_MANAGEMENT_CLIENT_ID", self.management_client_id),
            row("KINDE_MANAGEMENT_CLIENT_SECRET", self.management_client_secret, secret=True),
            row("PLAYGROUND_SESSION_SECRET", None if self.session_secret_generated else self.session_secret, secret=True),
            row("PLAYGROUND_CLIENT_MODE", self.client_mode),
            row("PLAYGROUND_FORCE_API", str(self.force_api).lower()),
            row("PLAYGROUND_ALLOW_MUTATIONS", str(self.allow_mutations).lower()),
            row("PLAYGROUND_DEBUG", str(self.debug).lower()),
        ]
