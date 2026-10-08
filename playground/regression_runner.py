"""Run the SDK and playground suites in a fresh process and report each file as it finishes.

A fresh interpreter matters: this app already imported the SDK, so a test run
inside it would not see edits on disk. pytest in a subprocess uses the
editable install, which is the code you just changed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# filename -> (area, what this file is checking)
EXPLAINS: Dict[str, Tuple[str, str]] = {
    "test_oauth.py": ("Auth", "Building the authorization URL, PKCE, and exchanging the code."),
    "test_oauth_callback_security.py": ("Auth", "Callback state and nonce are required, checked, and single-use."),
    "test_oauth_edge_cases.py": ("Auth", "OAuth edge cases: missing values and rejected callbacks."),
    "test_async_oauth.py": ("Auth", "AsyncOAuth login, callback, and userinfo."),
    "test_smart_oauth.py": ("Auth", "SmartOAuth picks the sync or async client per call."),
    "test_smart_oauth_integration.py": ("Auth", "SmartOAuth wired up the way an app creates it."),
    "test_factory_function.py": ("Auth", "create_oauth_client returns the sync, async, or smart client."),
    "test_invitation_code.py": ("Auth", "An invitation code is forwarded on the login URL."),
    "test_login.py": ("Auth", "The login flow behaves the way callers expect."),
    "test_base_auth.py": ("Auth", "Helpers shared by permissions, roles, and flags."),
    "test_log_redaction.py": ("Auth", "Errors and logs stay free of tokens, codes, and response bodies."),
    "test_logout_url.py": ("Auth", "The logout URL carries the redirect Kinde reads."),
    "test_account_api_host.py": ("Auth", "Account API calls use the host that issued the user's token."),
    "test_permissions.py": ("Access", "Permission checks from the token and from the Account API."),
    "test_roles.py": ("Access", "Role checks from the token and from the Account API."),
    "test_claims.py": ("Access", "Reading one claim and every claim from both tokens."),
    "test_feature_flags.py": ("Flags", "Flag reads from the token and from the Account API, including types."),
    "test_entitlements.py": ("Billing", "The entitlements client pages through a plan and looks up one feature."),
    "test_token_manager.py": ("Tokens", "Access-token expiry and refresh."),
    "test_tokens.py": ("Tokens", "The tokens helper: who is signed in, and the token manager."),
    "test_user_session.py": ("Session", "Sessions store tokens, and a refresh is written back."),
    "test_user_session_edge_cases.py": ("Session", "Missing or unreadable session data fails closed."),
    "test_session_secrets.py": ("Session", "The client secret stays in memory and never enters the session."),
    "test_storage_manager.py": ("Session", "Session keys include the device ID stored in that session."),
    "test_kinde_session_management.py": ("Session", "The standalone session helper stays out of Flask and FastAPI."),
    "test_kinde_session_management_fixed.py": ("Session", "The standalone session helper, including its guard."),
    "test_helpers.py": ("Core", "PKCE, random strings, and user-detail lookups."),
    "test_null_framework.py": ("Core", "The null framework used when there is no web request."),
    "test_version_sync.py": ("Core", "The published version matches across the package."),
    "test_flask_framework.py": ("Framework", "Flask login, callback, and logout routes."),
    "test_fastapi_framework.py": ("Framework", "FastAPI login, callback, and logout routes."),
    "test_management_client.py": ("Management", "ManagementClient construction and its API surface."),
    "test_management_token_manager.py": ("Management", "The M2M client-credentials token, including refresh."),
    "test_feature_flag_value_types.py": ("Management", "Feature-flag values may be bool, int, or str."),
    "test_sdk_tracking.py": ("Management", "Requests send the Kinde-SDK tracking header."),
    "test_deadlock_secnarios.py": ("Management", "Taking the M2M token lock cannot deadlock."),
    "test_pages.py": ("Playground", "Every page renders signed out and signed in, and a refresh survives restart."),
    "test_guards.py": ("Playground", "Protected routes allow the granted cases and deny the rest."),
    "test_management.py": ("Playground", "The management console stays read-only and write scenarios stay guarded."),
    "test_security.py": ("Playground", "CSRF, cookie flags, forged callbacks, and no secrets in pages or logs."),
    "test_units.py": ("Playground", "Settings validation, redaction, and safe error text."),
    "test_regression.py": ("Playground", "This page groups results by file and keeps the failure detail."),
}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
RESULT_RE = re.compile(
    r"^(?P<node>.+?)\s+(?P<outcome>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\b"
)
SUMMARY_FAIL_RE = re.compile(r"^FAILED\s+(?P<node>.+?)\s+-\s+(?P<detail>.+)$")
_PASSED = {"PASSED"}
_FAILED = {"FAILED", "ERROR", "XPASS"}
_SKIPPED = {"SKIPPED", "XFAIL"}


def node_key(node: str) -> str:
    """File name plus the test id, so a long relative path and a short one still match."""
    path, sep, rest = node.partition("::")
    if not sep:
        return node
    filename = Path(path).name
    if not filename.endswith(".py"):
        filename = ""
    return f"{filename}::{rest}"


def same_node(left: str, right: str) -> bool:
    if left == right:
        return True
    lfile, _, lrest = left.partition("::")
    rfile, _, rrest = right.partition("::")
    return bool(lrest) and lrest == rrest and (lfile == rfile or not lfile or not rfile)


def explain(filename: str) -> Tuple[str, str]:
    area, text = EXPLAINS.get(filename, ("Other", f"Tests in {filename}."))
    return area, text


def sdk_root() -> Optional[Path]:
    """The SDK checkout, when this app is using an editable install that still has tests."""
    override = os.environ.get("PLAYGROUND_SDK_ROOT")
    if override:
        root = Path(override)
        return root if (root / "testv2").is_dir() else None
    import kinde_sdk

    root = Path(kinde_sdk.__file__).resolve().parents[1]
    return root if (root / "testv2").is_dir() else None


def playground_root() -> Path:
    return Path(__file__).resolve().parents[1]


@dataclass
class Suite:
    name: str
    cwd: Path
    args: List[str]
    about: str
    python: str = ""

    def interpreter(self) -> str:
        return self.python or sys.executable


def sdk_python(root: Path) -> str:
    """The SDK checkout's virtualenv, which has pytest-asyncio and the other test plugins."""
    candidate = root / ".venv" / "bin" / "python"
    return str(candidate) if candidate.is_file() else sys.executable


def build_plan() -> Tuple[List[Suite], Optional[str]]:
    """Suites to run, and a warning if the SDK tests cannot be found."""
    suites: List[Suite] = []
    warning = None
    root = sdk_root()
    if root is None:
        warning = "SDK tests were not found next to the installed package. Set PLAYGROUND_SDK_ROOT to the SDK checkout."
    else:
        python = sdk_python(root)
        about = "The SDK suite, in the SDK project's virtualenv, against the code on disk."
        if python == sys.executable:
            about = "The SDK suite, in a fresh process, against the code on disk. The SDK checkout has no .venv, so this app's Python is used."
        suites.append(Suite(
            "SDK",
            root,
            ["testv2", "--timeout=30", "--asyncio-mode=auto"],
            about,
            python,
        ))
    suites.append(Suite(
        "Playground",
        playground_root(),
        ["tests"],
        "This app's suite: both frameworks, with Kinde mocked.",
        sys.executable,
    ))
    return suites, warning


@dataclass
class TestProgress:
    node: str
    name: str
    outcome: str  # passed, failed, skipped
    summary: str = ""
    duration_ms: int = 0
    lines: List[dict] = field(default_factory=list)
    calls: List[dict] = field(default_factory=list)
    error: List[str] = field(default_factory=list)
    story: Dict[str, str] = field(default_factory=dict)


@dataclass
class FileProgress:
    suite: str
    filename: str
    area: str
    explanation: str
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    tests: List[TestProgress] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        if self.failed:
            return "fail"
        if self.passed or self.skipped:
            return "ok"
        return "info"


@dataclass
class RunState:
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    status: str = "running"  # running, passed, failed
    phase: str = "Starting"
    about: str = "Starting a fresh Python process so the run sees the SDK on disk."
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    current_suite: str = ""
    current_file: str = ""
    current_test: str = ""
    current_area: str = ""
    current_explanation: str = ""
    files: List[FileProgress] = field(default_factory=list)
    failures: List[Dict[str, str]] = field(default_factory=list)
    message: str = ""
    _open: Optional[FileProgress] = None
    _pending: Dict[str, dict] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def running(self) -> bool:
        return self.status == "running"

    @property
    def done(self) -> int:
        return self.passed + self.failed + self.skipped

    def note(self, phase: str, about: str) -> None:
        with self._lock:
            self.phase = phase
            self.about = about

    def add_collected(self, count: int) -> None:
        with self._lock:
            self.total += count

    def result_line(self, line: str) -> bool:
        """Record one pytest result line. Returns True when the line was a result."""
        stripped = ANSI_RE.sub("", line).strip()
        if "@@REGRESSION@@" in stripped:
            before, _, payload = stripped.partition("@@REGRESSION@@")
            recorded = self.result_line(before) if before.strip() else False
            try:
                self.add_detail(json.loads(payload))
            except json.JSONDecodeError:
                pass
            return recorded
        match = RESULT_RE.match(stripped)
        if not match:
            summary = SUMMARY_FAIL_RE.match(ANSI_RE.sub("", line).strip())
            if summary:
                self._attach_failure(summary.group("node"), summary.group("detail"))
            return False
        node, outcome = match.group("node"), match.group("outcome")
        filename = Path(node.split("::", 1)[0]).name
        test = node.rsplit("::", 1)[-1]
        area, explanation = explain(filename)
        with self._lock:
            if self._open is None or self._open.filename != filename or self._open.suite != self.current_suite:
                if self._open is not None:
                    self.files.append(self._open)
                self._open = FileProgress(self.current_suite, filename, area, explanation)
            row = self._open
            if outcome in _PASSED:
                row.passed += 1
                self.passed += 1
            elif outcome in _FAILED:
                row.failed += 1
                self.failed += 1
                self.failures.append({"node": node, "detail": ""})
            else:
                row.skipped += 1
                self.skipped += 1
            label = "failed" if outcome in _FAILED else "skipped" if outcome in _SKIPPED else "passed"
            record = TestProgress(node, test, label)
            row.tests.append(record)
            pending = self._take_pending(node_key(node))
            if pending:
                self._apply(record, pending)
            self.current_file = filename
            self.current_test = test
            self.current_area = area
            self.current_explanation = explanation
        return True

    def add_detail(self, payload: dict) -> None:
        node = str(payload.get("node") or "")
        if not node:
            return
        with self._lock:
            record = self._find(node)
            if record is None:
                self._pending[node_key(node)] = payload
                return
            self._apply(record, payload)

    def detail(self, node: str) -> Optional[dict]:
        with self._lock:
            record = self._find(node)
            if record is None:
                return None
            return {
                "node": record.node,
                "name": record.name,
                "outcome": record.outcome,
                "summary": record.summary,
                "duration_ms": record.duration_ms,
                "lines": [dict(line) for line in record.lines],
                "calls": [dict(call) for call in record.calls],
                "error": list(record.error),
                "story": dict(record.story),
            }

    def _find(self, node: str) -> Optional[TestProgress]:
        rows = list(self.files)
        if self._open is not None:
            rows.append(self._open)
        wanted = node_key(node)
        for row in rows:
            for record in row.tests:
                if same_node(node_key(record.node), wanted):
                    return record
        return None

    def _take_pending(self, key: str) -> Optional[dict]:
        if key in self._pending:
            return self._pending.pop(key)
        for existing in list(self._pending):
            if same_node(existing, key):
                return self._pending.pop(existing)
        return None

    def _apply(self, record: TestProgress, payload: dict) -> None:
        record.summary = str(payload.get("summary") or "")
        record.duration_ms = int(payload.get("duration_ms") or 0)
        record.lines = list(payload.get("lines") or [])
        record.calls = list(payload.get("calls") or [])
        record.error = [str(line) for line in (payload.get("error") or [])]
        story = payload.get("story")
        if isinstance(story, dict) and story.get("did"):
            record.story = {key: str(story.get(key) or "") for key in ("did", "http", "result")}
        else:
            from .regression_trace import story_for
            record.story = story_for(record.lines, record.calls, record.outcome, record.error)
        if record.outcome == "failed" and record.error:
            detail = next((line for line in record.error if line.startswith("E ")), record.error[-1])
            self._attach_failure_locked(record.node, detail.removeprefix("E ").strip())

    def _attach_failure(self, node: str, detail: str) -> None:
        with self._lock:
            self._attach_failure_locked(node, detail)

    def _attach_failure_locked(self, node: str, detail: str) -> None:
        for failure in self.failures:
            if failure["node"] == node and not failure["detail"]:
                failure["detail"] = detail
                return
        if not any(failure["node"] == node for failure in self.failures):
            self.failures.append({"node": node, "detail": detail})

    def finish(self, ok: bool, message: str = "") -> None:
        with self._lock:
            if self._open is not None:
                self.files.append(self._open)
                self._open = None
            self.status = "passed" if ok and self.failed == 0 else "failed"
            self.finished_at = time.time()
            self.phase = "Finished"
            self.current_file = ""
            self.current_test = ""
            self.current_area = ""
            self.current_explanation = ""
            self.message = message
            if self.status == "passed":
                self.about = "Every test passed."
            elif message:
                self.about = message
            else:
                self.about = f"{self.failed} test{'s' if self.failed != 1 else ''} failed."

    def snapshot(self) -> dict:
        with self._lock:
            finished = list(self.files)
            current = self._open
            elapsed = (self.finished_at or time.time()) - self.started_at
            percent = int(100 * self.done / self.total) if self.total else 0

            def row(item: FileProgress, in_progress: bool = False) -> dict:
                return {
                    "suite": item.suite, "filename": item.filename, "area": item.area,
                    "explanation": item.explanation, "passed": item.passed,
                    "failed": item.failed, "skipped": item.skipped,
                    "outcome": "info" if in_progress and not item.failed else item.outcome,
                    "current": in_progress,
                    "tests": [
                        {"node": test.node, "name": test.name, "outcome": test.outcome,
                         "summary": test.summary, "duration_ms": test.duration_ms}
                        for test in item.tests
                    ],
                }

            return {
                "running": self.status == "running",
                "status": self.status,
                "phase": self.phase,
                "about": self.about,
                "total": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "skipped": self.skipped,
                "done": self.done,
                "percent": min(percent, 100),
                "elapsed": int(elapsed),
                "current_suite": self.current_suite,
                "current_file": self.current_file,
                "current_test": self.current_test,
                "current_area": self.current_area,
                "current_explanation": self.current_explanation,
                "files": ([row(current, True)] if current is not None else []) + [row(item) for item in reversed(finished)],
                "failures": [dict(item) for item in self.failures],
                "message": self.message,
            }


def _pytest_argv(suite: Suite, extra: List[str]) -> List[str]:
    return [
        suite.interpreter(), "-m", "pytest", *suite.args,
        "-p", "no:cacheprovider",
        "-p", "playground.regression_trace",
        "--override-ini", "addopts=",
        "-o", "console_output_style=classic",
        "--tb=line",
        "--no-header",
        "--rootdir", str(suite.cwd),
        *extra,
    ]


def _stream(argv: List[str], cwd: Path, on_line: Callable[[str], None]) -> int:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    root = str(playground_root())
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        on_line(line.rstrip("\n"))
    return proc.wait()


def _collect(suite: Suite, run: RunState) -> int:
    run.note(suite.name, f"Collecting {suite.name} tests. {suite.about}")
    count = 0

    def on_line(line: str) -> None:
        nonlocal count
        if "::" in line and not line.startswith("="):
            count += 1

    code = _stream(_pytest_argv(suite, ["--collect-only", "-q"]), suite.cwd, on_line)
    run.add_collected(count)
    return code


def _run_suite(suite: Suite, run: RunState) -> int:
    run.note(suite.name, suite.about)
    with run._lock:
        run.current_suite = suite.name

    def on_line(line: str) -> None:
        run.result_line(line)

    return _stream(_pytest_argv(suite, ["-v"]), suite.cwd, on_line)


class RegressionService:
    """One regression at a time. A second request joins the run already in progress."""

    def __init__(self):
        self._lock = threading.Lock()
        self._run: Optional[RunState] = None
        self._thread: Optional[threading.Thread] = None
        self._live: Optional[dict] = None
        self.inline = False

    def start(self) -> RunState:
        with self._lock:
            if self._run is not None and self._run.running:
                return self._run
            run = RunState()
            self._run = run
            if self.inline:
                self._execute(run)
                return run
            self._thread = threading.Thread(target=self._execute, args=(run,), name="regression", daemon=True)
            self._thread.start()
            return run

    def join(self, timeout: float = 5) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def reset(self) -> None:
        with self._lock:
            if self._run is not None and self._run.running and not self.inline:
                return
            self._run = None
            self._thread = None
            self.inline = False
            self._live = None

    def clear_live(self) -> None:
        with self._lock:
            self._live = None

    def store_live(self, result: dict) -> None:
        with self._lock:
            self._live = {
                "status": result.get("status") or "skipped",
                "passed": int(result.get("passed") or 0),
                "failed": int(result.get("failed") or 0),
                "skipped": int(result.get("skipped") or 0),
                "elapsed": int(result.get("elapsed") or 0),
                "checks": [dict(check) for check in result.get("checks") or []],
            }

    def live_snapshot(self) -> Optional[dict]:
        with self._lock:
            if self._live is None:
                return None
            return {
                **self._live,
                "checks": [dict(check) for check in self._live["checks"]],
            }

    def snapshot(self) -> Optional[dict]:
        run = self._run
        return None if run is None else run.snapshot()

    def detail(self, node: str) -> Optional[dict]:
        run = self._run
        return None if run is None else run.detail(node)

    def _execute(self, run: RunState) -> None:
        try:
            suites, warning = build_plan()
            if warning:
                run.note("SDK", warning)
            codes = []
            for suite in suites:
                if _collect(suite, run) != 0:
                    codes.append(1)
                    run.finish(False, f"Collecting the {suite.name} tests failed.")
                    return
                codes.append(_run_suite(suite, run))
            run.finish(all(code == 0 for code in codes))
        except Exception as exc:
            run.finish(False, f"The run stopped: {type(exc).__name__}.")
