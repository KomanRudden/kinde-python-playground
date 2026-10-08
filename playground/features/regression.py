"""One button that runs the SDK suite and this app's suite, and reports each as it finishes."""
from __future__ import annotations

from ..regression_runner import RegressionService, sdk_root
from ..web import Page, Partial, Redirect, route
from ..guards import require_auth
from ._common import code, safe_error

service = RegressionService()

SNIPPET = code('''
    # What "Run full regression" does. It is the check to run after changing the SDK.
    # A fresh process imports the SDK from disk, so edits apply without restarting
    # this app. Restart afterwards if you want these pages to use the new code too.

    pytest testv2          # the SDK suite
    pytest tests           # this app, on Flask and FastAPI, with Kinde mocked

    # Live checks are the other button on this page. They call your Kinde
    # business: the Management API with the M2M application, then flags,
    # permissions, and entitlements with the signed-in user's token.
    # Sign in first. Security audit still runs the forged-callback probes.
''')


def _view(req, kinde, run) -> dict:
    return {
        "run": run,
        "live": service.live_snapshot(),
        "signed_in": bool(kinde.user_id()),
        "sdk_root": str(sdk_root() or ""),
        "snippet": SNIPPET,
    }


@route("/regression", name="regression")
async def regression_page(req, kinde):
    # Opening the page hides the previous live run. Results come back only
    # after Run live checks, which redirects here with ?live=1.
    if req.arg("live") != "1":
        service.clear_live()
    return Page("regression.html", _view(req, kinde, service.snapshot()))


@route("/regression/partials/status", name="regression_status")
async def regression_status(req, kinde):
    view = _view(req, kinde, service.snapshot())
    return Partial("partials/regression_status.html", {
        "run": view["run"], "live": view["live"], "signed_in": view["signed_in"],
    })


@route("/regression/partials/detail", name="regression_detail")
async def regression_detail(req, kinde):
    return Partial("partials/regression_detail.html", {"test": service.detail(req.arg("node"))})


@route("/regression/run", name="regression_run", methods=["POST"])
async def regression_run(req, kinde):
    service.start()
    return Redirect("/regression")


@route("/regression/live", name="regression_live", methods=["POST"])
@require_auth
async def regression_live(req, kinde):
    from ..live_checks import run_live_checks
    try:
        service.store_live(await run_live_checks(kinde))
    except Exception as exc:
        service.store_live({
            "status": "failed",
            "passed": 0,
            "failed": 1,
            "skipped": 0,
            "elapsed": 0,
            "checks": [{
                "id": "live:run",
                "group": "Live checks",
                "name": "Live checks",
                "did": "Would call your Kinde business.",
                "outcome": "failed",
                "http": "The run stopped before it finished.",
                "result": safe_error(exc),
            }],
        })
    return Redirect("/regression?live=1")
