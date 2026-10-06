"""Keep secrets out of pages and logs.

``mask`` is used whenever a credential has to be acknowledged in the UI.
``RedactingFormatter`` scrubs known secret values, JWTs and OAuth query
parameters from every log line the app writes, as defence in depth on top of
the SDK not logging them in the first place.
``LogCapture`` keeps the raw (unredacted) SDK records in memory so the
security audit can prove the SDK itself does not log secrets.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, List, Optional

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
SENSITIVE_PARAMS = ("code", "state", "nonce", "code_verifier", "client_secret", "refresh_token",
                    "access_token", "id_token", "id_token_hint", "token", "invitation_code")
QUERY_PATTERN = re.compile(r"(?i)\b(" + "|".join(SENSITIVE_PARAMS) + r")=([^&\s\"']+)")
BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")
SENSITIVE_KEY_PARTS = ("secret", "password", "token", "api_key", "private_key", "code_verifier")


def mask(value: Any, keep: int = 4) -> str:
    """``eyJh…x9Qk (812 chars)`` for long values, ``••••`` for short ones."""
    text = "" if value is None else str(value)
    if not text:
        return ""
    if len(text) <= keep * 3:
        return "•" * 8
    return f"{text[:keep]}…{text[-keep:]} ({len(text)} chars)"


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    for secret in secrets:
        if secret and len(secret) >= 6:
            text = text.replace(secret, "[REDACTED]")
    text = JWT_PATTERN.sub("[JWT]", text)
    text = BEARER_PATTERN.sub("Bearer [REDACTED]", text)
    return QUERY_PATTERN.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def redact_data(data: Any) -> Any:
    """Mask values under secret-looking keys in API responses before they are shown.

    Some Management API responses carry credentials, e.g. ``get_application``
    returns the application's ``client_secret``.
    """
    if isinstance(data, dict):
        return {
            k: (mask(v) if is_sensitive_key(str(k)) and isinstance(v, (str, int)) and v != "" else redact_data(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [redact_data(item) for item in data]
    if isinstance(data, str) and JWT_PATTERN.fullmatch(data):
        return mask(data)
    return data


class RedactingFormatter(logging.Formatter):
    def __init__(self, fmt: str, secrets: Iterable[str] = ()):
        super().__init__(fmt)
        self._secrets = [s for s in secrets if s]

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record), self._secrets)


class LogCapture(logging.Handler):
    """Ring buffer of raw log records from the Kinde SDK and its integrations."""

    def __init__(self, maxlen: int = 1000):
        super().__init__(level=logging.DEBUG)
        self.records: deque = deque(maxlen=maxlen)
        self._collectors: List[list] = []
        self._lock_ = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        if not record.name.startswith("kinde"):
            return
        try:
            text = record.getMessage()
            if record.exc_info:
                text += "\n" + logging.Formatter().formatException(record.exc_info)
        except Exception:
            text = str(record.msg)
        entry = {"time": time.time(), "logger": record.name, "level": record.levelname, "text": text}
        with self._lock_:
            self.records.append(entry)
            for collector in self._collectors:
                collector.append(entry)

    @contextmanager
    def collect(self) -> Iterator[list]:
        collected: list = []
        with self._lock_:
            self._collectors.append(collected)
        try:
            yield collected
        finally:
            with self._lock_:
                self._collectors.remove(collected)


_capture: Optional[LogCapture] = None


def install_logging(level: str, secrets: Iterable[str]) -> LogCapture:
    """Configure root logging with redaction and attach the SDK log capture."""
    global _capture
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    console = next((h for h in root.handlers if getattr(h, "_playground", False)), None)
    if console is None:
        console = logging.StreamHandler()
        console._playground = True  # type: ignore[attr-defined]
        root.addHandler(console)
    console.setLevel(getattr(logging, level, logging.INFO))
    console.setFormatter(RedactingFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", secrets))

    if _capture is None:
        _capture = LogCapture()
        root.addHandler(_capture)
    # The SDK's own loggers stay at DEBUG so the audit sees everything they would emit
    logging.getLogger("kinde_sdk").setLevel(logging.DEBUG)
    for noisy in ("urllib3", "httpx", "httpcore", "asyncio", "multipart", "python_multipart"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return _capture


def get_log_capture() -> LogCapture:
    global _capture
    if _capture is None:
        _capture = LogCapture()
        logging.getLogger().addHandler(_capture)
    return _capture
