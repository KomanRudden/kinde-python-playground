"""Pytest plugin that reports each test's calls, HTTP exchange, and result.

Loaded only by the regression runner. Records are one JSON line on the
terminal reporter so pytest's own capture cannot swallow them.
"""
from __future__ import annotations

import inspect
import json
import os
import re
import threading
import warnings

import pytest
from typing import Any, List, Optional
from unittest import mock
from urllib.parse import urlsplit, urlunsplit

try:
    from playground.redact import redact_data, redact_text
except Exception:  # the runner still works if redaction cannot be imported
    def redact_text(text: str, secrets: Any = ()) -> str:
        return text

    def redact_data(data: Any) -> Any:
        return data

_tls = threading.local()
_installed = False
_config = None
_out = None
_items = {}
_HTTP_ATTRS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "urlopen", "open"}
_SDK_CALL = re.compile(
    r"\b(kinde|oauth|token_manager|permissions|roles|feature_flags|entitlements|portals|claims|ManagementClient|create_oauth)\b"
    r"|\.(login|logout|register|handle_redirect|get_claim|get_claims|get_permission|get_flag|refresh)\("
)
_HTTP_CALL = re.compile(r"\b(get|post|put|patch|delete|urlopen|request)\(")
_SECRET_LITERAL = re.compile(
    r"(?i)([\"'][^\"']*(?:secret|token|password|verifier)[^\"']*[\"']\s*:\s*[\"'])([^\"']+)([\"'])"
)
_orig_enter = None
_orig_request = None
_orig_urlopen = None
_orig_flask_open = None
_orig_testclient = None
_orig_httpx_send = None


def pytest_configure(config):
    global _config, _out
    _config = config
    _out = os.dup(1)
    _install()


def pytest_unconfigure(config):
    _restore()


def pytest_runtest_setup(item):
    _tls.calls = []
    _tls.patches = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    _items[item.nodeid] = item
    if report.when == "call" or (report.when == "setup" and not report.passed):
        item._regression_report = report
    if call.excinfo is not None and report.when in ("setup", "call"):
        item._regression_exc = call.excinfo


def pytest_runtest_logreport(report):
    """Emit after the call, once pytest has printed the result line."""
    if report.when != "call" and not (report.when == "setup" and not report.passed):
        return
    item = _items.get(report.nodeid)
    if item is None:
        return
    try:
        _emit_item(item)
    except Exception as exc:
        _emit({"node": report.nodeid, "summary": "", "duration_ms": 0,
               "lines": [], "calls": [], "error": [f"{type(exc).__name__}: {exc}"]})


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_teardown(item):
    yield
    _tls.calls = None
    _tls.patches = None


def _emit_item(item) -> None:
    report = getattr(item, "_regression_report", None)
    if report is None:
        return
    if report.failed:
        outcome = "failed"
    elif report.skipped:
        outcome = "skipped"
    else:
        outcome = "passed"
    error = _error_lines(getattr(item, "_regression_exc", None))
    lines = _source(item, _fail_lines(error))
    blob = "\n".join(error)
    for line in lines:
        stripped = line["text"].strip()
        if stripped.startswith("assert") and stripped and stripped in blob:
            line["fail"] = True
    calls = _live_calls() + _source_calls(lines, have_http=bool(_live_calls()))
    function = getattr(item, "function", None) or getattr(item, "obj", None)
    doc = inspect.getdoc(function) or getattr(function, "__doc__", None) or ""
    doc = doc.strip()
    summary = redact_text(doc.splitlines()[0])[:180] if doc else ""
    _emit({
        "node": item.nodeid,
        "summary": summary,
        "duration_ms": int((getattr(report, "duration", 0) or 0) * 1000),
        "lines": lines,
        "calls": calls[:40],
        "error": error,
        "story": story_for(lines, calls, outcome, error),
    })


def _live_calls() -> List[dict]:
    calls = getattr(_tls, "calls", None) or []
    patches = getattr(_tls, "patches", None) or []
    recorded = list(calls)
    for attr, mocked in patches:
        recorded.extend(_mock_calls(attr, mocked))
    return _dedupe(recorded)[:30]


def _emit(payload: dict) -> None:
    data = ("@@REGRESSION@@" + json.dumps(payload, default=str) + "\n").encode()
    if _out is not None:
        os.write(_out, data)
        return
    os.write(1, data)


def _install() -> None:
    global _installed, _orig_enter, _orig_request, _orig_urlopen
    global _orig_flask_open, _orig_testclient, _orig_httpx_send
    if _installed:
        return
    _installed = True
    _orig_enter = mock._patch.__enter__

    def _enter(self):
        result = _orig_enter(self)
        patches = getattr(_tls, "patches", None)
        attr = str(getattr(self, "attribute", "") or "")
        getter = str(getattr(self, "getter", "") or "")
        if patches is not None and isinstance(result, mock.Mock) and (
            attr.lower() in _HTTP_ATTRS or "requests" in getter or "httpx" in getter or "urlopen" in getter
        ):
            if len(patches) < 20:
                patches.append((attr.lower(), result))
        return result

    mock._patch.__enter__ = _enter

    try:
        import requests
        _orig_request = requests.Session.request

        def _request(self, method, url, *args, **kwargs):
            try:
                response = _orig_request(self, method, url, *args, **kwargs)
            except Exception as exc:
                _note_http(str(method).upper(), url, kwargs, None, type(exc).__name__)
                raise
            _note_http(str(method).upper(), url, kwargs, response, None)
            return response

        requests.Session.request = _request
    except Exception:
        _orig_request = None

    try:
        import urllib.request
        _orig_urlopen = urllib.request.urlopen

        def _urlopen(url, *args, **kwargs):
            target = url.get_full_url() if hasattr(url, "get_full_url") else url
            try:
                response = _orig_urlopen(url, *args, **kwargs)
            except Exception as exc:
                _note_http(getattr(url, "get_method", lambda: "GET")(), target, {}, None, type(exc).__name__)
                raise
            status = getattr(response, "status", None)
            _note_http("GET", target, {}, _Status(status), None)
            return response

        urllib.request.urlopen = _urlopen
    except Exception:
        _orig_urlopen = None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import flask.testing
        _orig_flask_open = flask.testing.FlaskClient.open

        def _open(self, *args, **kwargs):
            response = _orig_flask_open(self, *args, **kwargs)
            method = str(kwargs.get("method") or "GET").upper()
            target = args[0] if args and isinstance(args[0], str) else str(kwargs.get("path") or "")
            _note_http(method, target, kwargs, response, None)
            return response

        flask.testing.FlaskClient.open = _open
    except Exception:
        _orig_flask_open = None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import starlette.testclient
        _orig_testclient = starlette.testclient.TestClient.request

        def _trequest(self, method, url, **kwargs):
            response = _orig_testclient(self, method, url, **kwargs)
            _note_http(str(method).upper(), url, kwargs, response, None)
            return response

        starlette.testclient.TestClient.request = _trequest
    except Exception:
        _orig_testclient = None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import httpx
        _orig_httpx_send = httpx.Client.send

        def _send(self, request, *args, **kwargs):
            response = _orig_httpx_send(self, request, *args, **kwargs)
            _note_http(str(request.method).upper(), str(request.url), {}, response, None)
            return response

        httpx.Client.send = _send
    except Exception:
        _orig_httpx_send = None


def _restore() -> None:
    global _installed
    if not _installed:
        return
    if _orig_enter is not None:
        mock._patch.__enter__ = _orig_enter
    if _orig_request is not None:
        import requests
        requests.Session.request = _orig_request
    if _orig_urlopen is not None:
        import urllib.request
        urllib.request.urlopen = _orig_urlopen
    if _orig_flask_open is not None:
        import flask.testing
        flask.testing.FlaskClient.open = _orig_flask_open
    if _orig_testclient is not None:
        import starlette.testclient
        starlette.testclient.TestClient.request = _orig_testclient
    if _orig_httpx_send is not None:
        import httpx
        httpx.Client.send = _orig_httpx_send
    _installed = False


class _Status:
    def __init__(self, status):
        self.status_code = status


def _note_http(method: str, url: Any, kwargs: dict, response: Any, error: Optional[str]) -> None:
    calls = getattr(_tls, "calls", None)
    if calls is None or len(calls) >= 30 or not str(url or ""):
        return
    status = getattr(response, "status_code", None)
    if not isinstance(status, int):
        status = None
    calls.append({
        "kind": "http",
        "method": method,
        "url": _clean_url(url),
        "status": status,
        "request": _format_request(kwargs),
        "response": "" if error else _format_response(response),
        "error": error or "",
    })


def _mock_calls(attr: str, mocked: Any) -> List[dict]:
    out = []
    history = list(getattr(mocked, "call_args_list", []) or [])
    for call in history[:10]:
        args = list(getattr(call, "args", ()) or ())
        kwargs = dict(getattr(call, "kwargs", {}) or {})
        method, url = _mock_target(attr, args, kwargs)
        if not url:
            continue
        response = getattr(mocked, "return_value", None)
        out.append({
            "kind": "http",
            "method": method,
            "url": _clean_url(url),
            "status": _status_of(response),
            "request": _format_request(kwargs),
            "response": _format_response(response),
            "error": "",
        })
    return out


def _mock_target(attr: str, args: list, kwargs: dict):
    if attr == "request" and args:
        method = str(args[0]).upper()
        url = args[1] if len(args) > 1 else kwargs.get("url", "")
        return method, url
    if attr in _HTTP_ATTRS and attr not in ("request", "send", "open"):
        url = args[0] if args else kwargs.get("url", "")
        return attr.upper(), url
    if args and isinstance(args[0], str) and (args[0].startswith("http") or args[0].startswith("/")):
        return attr.upper() or "GET", args[0]
    return "", ""


def _status_of(response: Any) -> Optional[int]:
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _clean_url(url: Any) -> str:
    text = redact_text(str(url or ""))
    try:
        parts = urlsplit(text)
    except Exception:
        return text[:300]
    if not parts.scheme:
        return text[:300]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))[:300]


def _format_request(kwargs: dict) -> str:
    if not isinstance(kwargs, dict):
        return ""
    body = kwargs.get("json", None)
    if body is None:
        body = kwargs.get("data", None)
    return _format_body(body)


def _format_response(response: Any) -> str:
    if response is None or isinstance(response, mock.Mock) and not isinstance(getattr(response, "status_code", None), int):
        # A bare MagicMock carries no response. A configured one still does.
        if not isinstance(response, mock.Mock):
            return ""
    if isinstance(response, mock.Mock):
        produced = getattr(getattr(response, "json", None), "return_value", None)
        if produced is not None and not isinstance(produced, mock.Mock):
            return _format_body(produced)
        text = getattr(response, "text", None)
        if isinstance(text, str):
            return _format_body(text)
        return ""
    raw = getattr(response, "_content", None)
    if raw is None:
        data = getattr(response, "data", None)
        raw = data if isinstance(data, (bytes, str)) else None
    if isinstance(raw, bytes):
        if not raw or raw[:1] not in (b"{", b"[") and b"{" not in raw[:1]:
            stripped = raw.lstrip()
            if not stripped.startswith((b"{", b"[")):
                return ""
        raw = raw[:2000].decode("utf-8", "replace")
    if isinstance(raw, str):
        return _format_body(raw)
    return ""


def _format_body(body: Any) -> str:
    if body is None or isinstance(body, mock.Mock):
        return ""
    if isinstance(body, str):
        text = body.strip()
        if not text or text.startswith("<"):
            return ""
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            return redact_text(text)[:400]
    if isinstance(body, (bytes, bytearray)):
        return ""
    safe = redact_data(body)
    if isinstance(safe, dict):
        lines = []
        for key, value in list(safe.items())[:16]:
            if isinstance(value, (dict, list)):
                shown = json.dumps(value)[:180]
            else:
                shown = str(value)
            lines.append(f"{key}: {shown}")
        return "\n".join(lines)
    if isinstance(safe, list):
        return redact_text(json.dumps(safe)[:400])
    return redact_text(str(safe))[:400]


def _dedupe(calls: List[dict]) -> List[dict]:
    kept: List[dict] = []
    for call in calls:
        if kept and _same_http(kept[-1], call):
            continue
        kept.append(call)
    return kept


def _same_http(left: dict, right: dict) -> bool:
    if left.get("kind") != "http" or right.get("kind") != "http":
        return False
    if left.get("method") != right.get("method") or left.get("status") != right.get("status"):
        return False
    a, b = str(left.get("url") or ""), str(right.get("url") or "")
    return a == b or a.endswith(b) or b.endswith(a)


def _source(item, fail_at: set) -> List[dict]:
    try:
        raw, start = inspect.getsourcelines(item.obj)
    except (OSError, TypeError):
        return []
    lines = []
    for offset, line in enumerate(raw[:80]):
        number = start + offset
        text = _mask_literals(line.rstrip("\n"))
        if len(text) > 220:
            text = text[:220] + "…"
        lines.append({"n": number, "text": text, "fail": number in fail_at})
    return lines


def _source_calls(lines: List[dict], have_http: bool) -> List[dict]:
    found = []
    for line in lines:
        text = line["text"].strip()
        if not text or text.startswith(("#", "@", "def ", "class ", '"""', "'''")):
            continue
        kind = None
        shown = text
        if text.startswith("assert ") or text.startswith("assert("):
            kind = "result"
            shown = re.sub(r"\s+", " ", text[len("assert"):].strip())
        elif _HTTP_CALL.search(text) and ("requests" in text or "httpx" in text or "urlopen" in text):
            if not have_http:
                kind = "http"
        elif "(" in text and _SDK_CALL.search(text) and not text.startswith("with patch"):
            kind = "sdk"
        if kind and shown:
            found.append({"kind": kind, "text": shown[:220]})
    return found


def story_for(lines, calls, outcome: str = "passed", error=None) -> dict:
    """Three short sentences: what the SDK did, what happened to HTTP, and the result."""
    source = "\n".join(str(line.get("text", "")) for line in lines or [])
    sdk_bits = [str(call.get("text") or "") for call in calls or [] if call.get("kind") == "sdk"]
    http_calls = [call for call in calls or [] if call.get("kind") == "http" and call.get("url")]
    asserts = []
    for line in lines or []:
        text = str(line.get("text") or "").strip()
        if text.startswith("assert ") or text.startswith("assert("):
            asserts.append(re.sub(r"\s+", " ", text[len("assert"):]).strip())
    for call in calls or []:
        if call.get("kind") == "result" and call.get("text"):
            asserts.append(str(call["text"]))
    return {
        "did": _did_sentence(source, sdk_bits),
        "http": _http_sentence(source, http_calls),
        "result": _result_sentence(asserts, outcome, error or []),
    }


def _did_sentence(source: str, sdk_bits: List[str]) -> str:
    text = source + "\n" + "\n".join(sdk_bits)
    flag = re.search(r"""\.get_flag\(\s*["']([^"']+)["']""", text)
    if flag:
        where = "from the account API" if "force_api=True" in text.replace(" ", "") else "from the token"
        return f"Reads the {flag.group(1)} flag {where}."
    if ".get_all_flags(" in text:
        return "Reads every flag."
    if ".get_all_entitlements(" in text:
        host = re.search(r"""Entitlements\(\s*["'](https?://[^"']+)""", text)
        where = f" from {host.group(1).rstrip('/')}" if host else ""
        return f"Loads every entitlement{where}."
    entitlement = re.search(r"""\.get_entitlement\(\s*["']([^"']+)["']""", text)
    if entitlement:
        return f"Loads the {entitlement.group(1)} entitlement."
    if ".get_claims(" in text:
        return "Reads the claims on the token."
    if ".login(" in text:
        return "Starts sign-in."
    if ".logout(" in text:
        return "Signs out."
    if ".handle_redirect(" in text:
        return "Handles the callback."
    posted = re.search(r"""requests\.post\(\s*["'](https?://[^"']+)""", text)
    if posted:
        return f"Posts to {posted.group(1)}."
    for bit in sdk_bits:
        if "patch(" in bit or "patch.object" in bit or bit.strip().startswith("with "):
            continue
        name = re.search(r"\.(\w+)\(", bit)
        if name:
            return f"Calls {name.group(1).replace('_', ' ')}."
    return "Exercises the SDK."


def _http_sentence(source: str, http_calls: List[dict]) -> str:
    if http_calls:
        parts = []
        for call in http_calls[:3]:
            status = call.get("status")
            came = f" came back {status}" if isinstance(status, int) else " did not complete"
            if call.get("error"):
                came = f" failed ({call['error']})"
            parts.append(f"{call.get('method') or 'GET'} {call.get('url')}{came}.")
        extra = _response_hint(http_calls[0].get("response") or "")
        if extra:
            parts.append(extra)
        return " ".join(parts)
    stub = _stub_sentence(source)
    if "_call_account_api" in source:
        lead = "Nothing is sent to Kinde. The account API is stubbed."
    elif "BillingApi" in source or "get_entitlements" in source:
        lead = "Nothing is sent to Kinde. The billing API is stubbed."
    elif "force_api=False" in source.replace(" ", "") or "_session_manager" in source:
        lead = "Nothing is sent to Kinde. This check reads the token already in the session."
    elif "patch(" in source or "patch.object" in source:
        lead = "Nothing is sent to Kinde. The HTTP client is stubbed."
    else:
        lead = "Nothing is sent to Kinde. This check stays inside the process."
    return f"{lead} {stub}".strip() if stub else lead


def _stub_sentence(source: str) -> str:
    code = re.search(r"""["']code["']\s*:\s*["']([^"']+)""", source)
    kind = re.search(r"""["']t["']\s*:\s*["']([bsi])["']""", source)
    value = re.search(r"""["']v["']\s*:\s*([^,}\n]+)""", source)
    types = {"b": "boolean", "s": "string", "i": "integer"}
    if not code:
        return ""
    type_name = types.get(kind.group(1), "value") if kind else "value"
    shown = ""
    if value:
        raw = value.group(1).strip().strip("\"'")
        shown = {"True": "true", "False": "false", "None": "empty"}.get(raw, raw)
    if shown:
        return f"The stub returns a {type_name} flag, {code.group(1)}, set to {shown}."
    return f"The stub returns the {code.group(1)} flag."


def _response_hint(response: str) -> str:
    if not response:
        return ""
    interesting = []
    for line in response.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if any(part in key.lower() for part in ("secret", "token", "password")):
            continue
        interesting.append(f"{key.strip()} {value.strip()}")
        if len(interesting) == 3:
            break
    if not interesting:
        return ""
    return "The response included " + ", ".join(interesting) + "."


def _result_sentence(asserts: List[str], outcome: str, error: List[str]) -> str:
    if outcome == "failed" and error:
        line = next((item for item in error if item.startswith("E ")), error[-1])
        text = line.removeprefix("E ").strip()
        return text[:240] or "The check failed."
    if outcome == "skipped":
        return "Skipped."
    fields = {}
    other = []
    for expr in asserts:
        if expr.startswith("isinstance(") or expr.startswith("isinstance ("):
            continue
        matched = re.match(r"(\w+)(?:\[0\])?\.(\w+)\s*==\s*(.+)", expr)
        if matched:
            fields[matched.group(2)] = _plain_literal(matched.group(3))
            continue
        matched = re.match(r"(\w+)(?:\[0\])?\.(\w+)\s+is\s+(True|False|None)\b", expr)
        if matched:
            fields[matched.group(2)] = {"True": "true", "False": "false", "None": "empty"}[matched.group(3)]
            continue
        counted = re.match(r"len\((\w+)\)\s*==\s*(\d+)", expr)
        if counted:
            fields["__len__"] = counted.group(2)
            continue
        if ".startswith(" in expr:
            prefix = re.search(r"""startswith\(\s*["']([^"']+)""", expr)
            if prefix:
                other.append(f"The value starts with {prefix.group(1)}.")
            continue
        if len(other) < 2 and expr and "patch" not in expr:
            other.append(_plain_literal(expr).rstrip(".") + ".")
    sentences = []
    if "code" in fields and "value" in fields:
        kind = fields.get("type") or "value"
        sentences.append(f"{fields['code']} came back as a {kind} set to {fields['value']}.")
    elif fields.get("id") or fields.get("feature_key"):
        count = fields.get("__len__")
        lead = f"{count} item came back" if count == "1" else (f"{count} items came back" if count else "An item came back")
        bits = []
        if fields.get("id"):
            bits.append(fields["id"])
        if fields.get("feature_key"):
            bits.append(f"feature {fields['feature_key']}")
        sentences.append(lead + (": " + ", ".join(bits) if bits else "") + ".")
    elif fields.get("__len__"):
        n = fields["__len__"]
        sentences.append(f"{n} item came back." if n == "1" else f"{n} items came back.")
    elif fields.get("value"):
        sentences.append(f"The value is {fields['value']}.")
    sentences.extend(other)
    if not sentences:
        return "Passed." if outcome == "passed" else "Finished."
    return " ".join(sentences[:3])


def _plain_literal(text: str) -> str:
    return text.strip().strip("\"'").rstrip(",")


def _mask_literals(text: str) -> str:
    return _SECRET_LITERAL.sub(lambda match: f"{match.group(1)}[REDACTED]{match.group(3)}", redact_text(text))


def _error_lines(excinfo) -> List[str]:
    if excinfo is None:
        return []
    try:
        text = str(excinfo.getrepr(style="short", funcargs=False, abspath=False))
    except Exception:
        return []
    lines = []
    for line in text.splitlines():
        if "site-packages" in line:
            continue
        cleaned = _mask_literals(line.rstrip())
        if cleaned:
            lines.append(cleaned[:240])
        if len(lines) >= 24:
            break
    if excinfo is not None and not any(getattr(excinfo, "typename", "") in line for line in lines):
        lines.insert(0, f"E   {excinfo.typename}")
    return lines


def _fail_lines(error: List[str]) -> set:
    found = set()
    for line in error:
        match = re.search(r":(\d+):", line)
        if match:
            found.add(int(match.group(1)))
    return found
