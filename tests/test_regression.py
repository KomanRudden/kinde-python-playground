"""The regression page runs both suites and explains each file as it finishes."""
from __future__ import annotations

import re

from playground.regression_runner import RunState, Suite, _run_suite


def test_stubbed_flag_read_is_explained_without_the_test_source():
    from playground.regression_trace import story_for

    lines = [
        {"text": '        mock_feature_flags = {"t": "b", "v": False, "code": "is_dark_mode"}'},
        {"text": '        with patch.object(feature_flags, "_call_account_api", return_value=mock_feature_flags):'},
        {"text": "            options = ApiOptions(force_api=True)"},
        {"text": '            result = await feature_flags.get_flag("is_dark_mode", None, options)'},
        {"text": "            assert isinstance(result, FeatureFlag)"},
        {"text": '            assert result.code == "is_dark_mode"'},
        {"text": '            assert result.type == "boolean"'},
        {"text": "            assert result.value is False"},
    ]
    story = story_for(lines, [], "passed")
    assert story["did"] == "Reads the is_dark_mode flag from the account API."
    assert "Nothing is sent to Kinde" in story["http"]
    assert "stubbed" in story["http"]
    assert "false" in story["http"]
    assert story["result"] == "is_dark_mode came back as a boolean set to false."
    assert "isinstance" not in story["result"]
    assert "Line by line" not in str(story)


def test_stubbed_entitlements_read_names_the_host():
    from playground.regression_trace import story_for

    lines = [
        {"text": "        with patch('kinde_sdk.auth.entitlements.BillingApi') as mock_billing_class:"},
        {"text": '            entitlements = Entitlements("https://test.kinde.com", "test_token")'},
        {"text": "            result = entitlements.get_all_entitlements()"},
        {"text": "            assert len(result) == 1"},
        {"text": '            assert result[0].id == "entitlement_123"'},
        {"text": '            assert result[0].feature_key == "pro_feature"'},
    ]
    story = story_for(lines, [], "passed")
    assert story["did"] == "Loads every entitlement from https://test.kinde.com."
    assert "billing API is stubbed" in story["http"]
    assert "Nothing is sent" in story["http"]
    assert "entitlement_123" in story["result"]
    assert "pro_feature" in story["result"]
    assert "patch(" not in story["did"]


def test_result_lines_group_files_and_keep_failure_detail():
    run = RunState()
    with run._lock:
        run.current_suite = "SDK"
    assert run.result_line("testv2/testv2_auth/test_log_redaction.py::test_token_error PASSED [ 1%]")
    assert run.result_line("testv2/testv2_auth/test_log_redaction.py::test_body_hidden PASSED")
    assert run.result_line("testv2/testv2_auth/test_oauth_callback_security.py::test_missing_state FAILED")
    assert run.result_line("testv2/testv2_auth/test_oauth_callback_security.py::test_replay SKIPPED")
    run.result_line(
        "FAILED testv2/testv2_auth/test_oauth_callback_security.py::test_missing_state - AssertionError: expected 400"
    )
    run.finish(False)

    snap = run.snapshot()
    assert snap["passed"] == 2
    assert snap["failed"] == 1
    assert snap["skipped"] == 1
    assert snap["status"] == "failed"
    redaction = next(row for row in snap["files"] if row["filename"] == "test_log_redaction.py")
    assert redaction["passed"] == 2
    assert "tokens" in redaction["explanation"]
    assert snap["failures"] == [{
        "node": "testv2/testv2_auth/test_oauth_callback_security.py::test_missing_state",
        "detail": "AssertionError: expected 400",
    }]
    assert snap["current_test"] == ""


def test_node_ids_with_spaces_are_counted():
    run = RunState()
    with run._lock:
        run.current_suite = "Playground"
    node = "tests/test_units.py::TestLoginOptions::test_rejects_unsafe_or_invalid[form0-redirect_uri is set by the SDK]"
    assert run.result_line(f"{node} PASSED")
    run.result_line(f"FAILED {node} - AssertionError: scope")
    snap = run.snapshot()
    assert snap["passed"] == 1
    assert snap["files"][0]["filename"] == "test_units.py"
    assert snap["failures"][0]["detail"] == "AssertionError: scope"


def test_a_traced_test_records_the_call_the_http_exchange_and_the_result(tmp_path):
    (tmp_path / "test_exchange.py").write_text(
        "from unittest.mock import MagicMock, patch\n"
        "\n"
        "class token_manager:\n"
        "    @staticmethod\n"
        "    def get_claims():\n"
        "        return {'iss': 'https://example.kinde.com'}\n"
        "\n"
        "def test_posts():\n"
        '    """Exchanges the code for tokens."""\n'
        "    claims = token_manager.get_claims()\n"
        "    resp = MagicMock(status_code=200)\n"
        "    resp.json.return_value = {'access_token': 'secret-token-value-xyz', 'expires_in': 60}\n"
        "    with patch('requests.post', return_value=resp):\n"
        "        import requests\n"
        "        requests.post('https://example.kinde.com/oauth2/token',\n"
        "                      json={'grant_type': 'client_credentials', 'client_secret': 'super-secret-value'})\n"
        "    assert claims['iss'].startswith('https://')\n"
        "\n"
        "def test_broken():\n"
        "    assert 1 == 2\n"
    )
    run = RunState()
    code = _run_suite(Suite("Sample", tmp_path, ["."], "A sample file."), run)
    run.finish(code == 0)
    snap = run.snapshot()
    assert code != 0
    passed = next(test for test in snap["files"][0]["tests"] if test["name"] == "test_posts")
    detail = run.detail(passed["node"])
    assert detail["summary"] == "Exchanges the code for tokens."
    assert "claims" in detail["story"]["did"].lower()
    assert "oauth2/token" in detail["story"]["http"]
    assert "200" in detail["story"]["http"]
    assert "super-secret-value" not in str(detail["story"])
    assert "secret-token-value-xyz" not in str(detail["story"])
    assert "https://" in detail["story"]["result"]
    failed = run.detail(next(test["node"] for test in snap["files"][0]["tests"] if test["name"] == "test_broken"))
    assert any("AssertionError" in line for line in failed["error"])
    assert any(line["fail"] for line in failed["lines"])


def test_a_real_pytest_file_is_reported(tmp_path):
    (tmp_path / "test_sample.py").write_text("def test_ok():\n    assert True\n")
    run = RunState()
    code = _run_suite(Suite("Sample", tmp_path, ["."], "A sample file."), run)
    run.finish(code == 0)
    snap = run.snapshot()
    assert code == 0, snap
    assert snap["passed"] == 1
    assert snap["files"][0]["filename"] == "test_sample.py"
    assert snap["files"][0]["explanation"] == "Tests in test_sample.py."


def test_sdk_suite_uses_the_sdk_virtualenv():
    from playground.regression_runner import build_plan

    suites, warning = build_plan()
    assert warning is None
    sdk = next(suite for suite in suites if suite.name == "SDK")
    assert sdk.python.endswith("/kinde-python-sdk/.venv/bin/python")
    assert "--asyncio-mode=auto" in sdk.args


def test_status_partial_keeps_the_form_token(browser):
    page = browser.get("/regression")
    meta = re.search(r'name="csrf-token" content="([^"]+)"', page.text)
    partial = browser.get("/regression/partials/status")
    form = re.search(r'name="csrf_token" value="([^"]+)"', partial.text)
    assert meta and form, partial.text[:400]
    assert form.group(1) == meta.group(1)


def test_regression_page_is_public(browser):
    page = browser.get("/regression")
    assert page.status == 200, page.text[:400]
    assert "Run full regression" in page.text
    assert "new process" in page.text


def test_run_reports_progress_without_launching_the_real_suites(browser, monkeypatch):
    from playground.features import regression

    def execute(run):
        run.note("SDK", "The SDK suite, in a fresh process, against the code on disk.")
        with run._lock:
            run.current_suite = "SDK"
            run.total = 2
        run.result_line("testv2/testv2_auth/test_log_redaction.py::test_token_error PASSED")
        run.add_detail({
            "node": "testv2/testv2_auth/test_log_redaction.py::test_token_error",
            "summary": "Token errors stay out of the log.",
            "duration_ms": 4,
            "calls": [
                {"kind": "sdk", "text": "oauth.handle_redirect(code)"},
                {"kind": "http", "method": "POST", "url": "https://example.kinde.com/oauth2/token",
                 "status": 200, "request": "grant_type: authorization_code", "response": "expires_in: 60"},
                {"kind": "result", "text": "response.status_code == 200"},
            ],
            "lines": [{"n": 12, "text": "    assert response.status_code == 200", "fail": False}],
            "error": [],
        })
        run.result_line("testv2/testv2_auth/test_oauth_callback_security.py::test_missing_state FAILED")
        run.result_line(
            "FAILED testv2/testv2_auth/test_oauth_callback_security.py::test_missing_state - AssertionError: expected 400"
        )
        run.finish(False)

    regression.service.inline = True
    regression.service.reset()
    monkeypatch.setattr(regression.service, "_execute", execute)
    regression.service.inline = True

    page = browser.post("/regression/run")
    if page.status in (302, 303):
        page = browser.get(page.location or "/regression")
    assert page.status == 200, page.text[:500]
    assert "Errors and logs stay free of tokens" in page.text
    assert "Callback state and nonce are required" in page.text
    assert "expected 400" in page.text
    assert "test_token_error" in page.text
    detail = browser.get("/regression/partials/detail", node="testv2/testv2_auth/test_log_redaction.py::test_token_error")
    assert detail.status == 200, detail.text[:400]
    assert "Handles the callback." in detail.text
    assert "oauth2/token" in detail.text
    assert "200" in detail.text
    assert "Line by line" not in detail.text
    regression.service.reset()
