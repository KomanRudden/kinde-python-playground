"""Small helpers shared by the feature modules."""
from __future__ import annotations

import logging
import textwrap
import time
from typing import Any, Awaitable, Callable, Dict, Optional

from ..redact import get_log_capture, redact_text

logger = logging.getLogger("playground.features")


def code(text: str) -> str:
    """A "How this works" snippet, dedented."""
    return textwrap.dedent(text).strip("\n")


def to_plain(value: Any) -> Any:
    """Generated SDK models -> plain data for display."""
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {k: to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    return value


def safe_error(exc: BaseException) -> str:
    """A message that is safe to show: SDK API errors expose only their status."""
    status = getattr(exc, "status", None)
    reason = getattr(exc, "reason", None)
    if status:
        return f"{type(exc).__name__}: HTTP {status}" + (f" {reason}" if reason else "")
    # Errors wrapping a requests/httpx failure (e.g. the M2M token request) carry the response on a cause.
    cause = exc.__cause__ or exc.__context__
    while cause is not None:
        response = getattr(cause, "response", None)
        code = getattr(response, "status_code", None)
        if isinstance(code, int):
            return f"{type(exc).__name__}: HTTP {code} from Kinde"
        cause = cause.__cause__ or cause.__context__
    return type(exc).__name__


async def attempt(label: str, func: Callable[[], Awaitable[Any]]) -> Dict[str, Any]:
    """Run one SDK call and capture its result, timing, a safe error and SDK warnings.

    Some helpers handle API failures themselves (e.g. a permission check falls
    back to "not granted"), so warnings the SDK logs during the call are shown too.
    """
    started = time.perf_counter()
    with get_log_capture().collect() as records:
        try:
            result = await func()
            outcome = {"label": label, "ok": True, "result": result}
        except Exception as exc:
            logger.warning("%s failed: %s", label, type(exc).__name__)
            outcome = {"label": label, "ok": False, "error": safe_error(exc)}
    outcome["ms"] = _elapsed(started)
    outcome["sdk_warnings"] = [redact_text(r["text"]) for r in records if r["level"] in ("WARNING", "ERROR", "CRITICAL")]
    return outcome


def _elapsed(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def token_type(value: Optional[str]) -> str:
    return "id_token" if value == "id_token" else "access_token"
