# Kinde Python SDK Playground

A test app that exercises every part of the [Kinde Python SDK](../kinde-python-sdk) the way a
real application would use it. The same pages run on **Flask** (`kinde_flask`) and **FastAPI**
(`kinde_fastapi`): one framework-neutral feature layer, two thin adapters.

Every page pairs a live result with a "How this works" panel showing the SDK code behind it.

| Page | What it exercises |
| --- | --- |
| Dashboard | Configuration (secrets masked) and live setup checks: OIDC discovery, callback URL, M2M token |
| Sign in lab | `login()` / `register()` with every `LoginOptions` value, create-org, invitations, `auth_params`, URL preview |
| Profile | `get_user_info()` / `get_user_info_async()`, Account API profile and user properties |
| Tokens | `tokens` helper, claims, expiry countdown, refresh and revoke |
| Claims | `claims.get_claim()` / `get_all_claims()` for access and ID tokens |
| Permissions & roles | Token claims and the Account API (`ApiOptions(force_api=True)`) side by side |
| Feature flags | `get_flag()` with typed defaults, `get_all_flags()` |
| Billing & entitlements | `Entitlements`, plan selection portal |
| Self-serve portal | `portals.generate_portal_url()` for every `PortalPage` |
| Organizations | Memberships, switching org, creating an org at sign-up |
| Client modes | `OAuth`, `AsyncOAuth` and `SmartOAuth` (`create_oauth_client`) |
| Session & storage | What the SDK stores where, `KindeSessionManagement`, storage backends |
| Protected routes | Guards for sign-in, permission, role, flag and entitlement; the framework-native equivalent |
| Management API | M2M token, curated reads, a read-only console over every API, guarded write scenarios with cleanup |
| Security audit | Session and cookie checks, forged / mismatched / replayed callbacks, SDK log scan |

## 1. Set up Kinde

1. **Back-end web application.** In Kinde, go to *Settings → Applications → Add application* and
   choose *Back-end web*. Under *Details*:
   - *Allowed callback URLs*: `http://localhost:5050/callback` and `http://localhost:8000/callback`
   - *Allowed logout redirect URLs*: `http://localhost:5050` and `http://localhost:8000`
   - Copy the domain, client ID and client secret.
2. **Refresh tokens.** The Sign in lab requests the `offline` scope by default. Nothing else to do.
3. **Optional, for richer pages:**
   - Create the permission `read:reports`, the role `admin`, the boolean feature flag
     `beta_dashboard` and assign them to your user's organization. The protected-route examples use
     these keys; change them with `PLAYGROUND_DEMO_*`.
   - Enable the *self-serve portal* for the application to use portal links.
   - Set up billing with a plan containing a `pro_reports` feature for the entitlement examples.
   - The "token claims" results read the access token: make sure roles, permissions and feature
     flags are included in it under the application's *Tokens* settings. The Account API results
     don't depend on this.
4. **Optional, Management API.** Add a *Machine to machine* application, authorize it for the
   *Kinde Management API* with the scopes you want to try (`read:users`, `read:organizations`, …;
   add `create:users`, `create:organizations`, `delete:users`, `delete:organizations`,
   `update:organizations` and `create:meter_usage` for the write scenarios). Use a test business or
   environment for writes.

## 2. Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -e "../kinde-python-sdk[flask,fastapi]" -e ".[dev]"
cp .env.example .env    # then fill in your Kinde values
```

```bash
.venv/bin/python -m apps.flask_app      # http://localhost:5050
.venv/bin/python -m apps.fastapi_app    # http://localhost:8000
```

Both can run at the same time. Real environment variables take precedence over `.env`.

### Configuration

All settings live in [`.env.example`](.env.example). The ones you'll change most:

| Variable | Purpose |
| --- | --- |
| `KINDE_HOST`, `KINDE_CLIENT_ID`, `KINDE_CLIENT_SECRET` | Your back-end web application. Leave the secret empty to run as a public (PKCE-only) client. |
| `PLAYGROUND_SESSION_SECRET` | Session signing key. Without it a random key is generated and sessions end on restart. |
| `PLAYGROUND_CLIENT_MODE` | `oauth`, `async` or `smart`: which SDK client the app creates (one per process). |
| `PLAYGROUND_FORCE_API` | Create the client with `force_api=True`, so helpers always call the Account API. |
| `KINDE_MANAGEMENT_CLIENT_ID`, `KINDE_MANAGEMENT_CLIENT_SECRET` | Enable the Management API page. |
| `PLAYGROUND_ALLOW_MUTATIONS` | Enable the Management write scenarios. Off by default. |
| `PLAYGROUND_DEBUG` | Enable token reveal buttons. Never in production. |

## 3. Test it

```bash
.venv/bin/python -m pytest
```

The suite runs every test against both apps with Kinde mocked (no network): every page signed out
and signed in, the guard matrix, CSRF, cookie flags, session ID rotation, the Management console and
scenarios, the security probes, and an end-to-end scan that no secret, code or token reaches any
page or log line.

## How it's built

```
playground/
  config.py          Settings from the environment, validated at startup; secrets masked
  kinde.py           The one place that talks to the SDK: one OAuth client, one ManagementClient
  web.py             Framework-neutral Request / Page / Redirect, routing, CSRF, flash, templates
  guards.py          require_auth / require_permission / require_role / require_flag / require_entitlement
  redact.py          Masking, redacting log formatter, SDK log capture for the audit
  fastapi_session.py Server-side session store for FastAPI
  app_core.py        Startup and request dispatch shared by both adapters
  features/          One module per page
  templates/, static/
apps/
  flask_app.py       Flask adapter (kinde_flask)
  fastapi_app.py     FastAPI adapter (kinde_fastapi)
```

Patterns worth copying into your own app:

- **One OAuth client per process**, created at startup with explicit configuration. The SDK keeps
  process-wide state (framework, storage), so creating a second client would replace the first.
- **Server-side sessions.** The SDK keeps tokens in the session. Flask uses Flask-Session's
  filesystem store (configured by `kinde_flask` from `SESSION_TYPE` / `SESSION_FILE_DIR`); FastAPI
  uses `playground/fastapi_session.py`. Starlette's default `SessionMiddleware` would put the
  tokens in the cookie.
- **Rotate the session ID at sign-in** to prevent session fixation (both adapters do this).
- **Run blocking SDK calls off the event loop** (`asyncio.to_thread`): token refresh, userinfo and
  every Management API call are blocking HTTP requests.
- **Guards fail closed**: authenticate first, then authorize, and deny if the check errors.
- **Never show raw tokens or API errors.** Exceptions are reported by type and HTTP status only;
  Management API responses are passed through `redact_data`, because some (such as
  `get_application`) return client secrets.
- **CSRF-protect state-changing forms**, and only accept same-site paths as post-login redirects.

## Production notes

The playground is a development tool. Before using any of it as a template:

- Serve over HTTPS; cookies are marked `Secure` automatically when the base URL is `https://`.
- Replace the in-memory FastAPI session store with Redis or a database, and the Flask filesystem
  store with a shared backend if you run more than one instance.
- Keep `PLAYGROUND_DEBUG` and `PLAYGROUND_ALLOW_MUTATIONS` off.
- Run Flask under a production WSGI server and FastAPI with multiple workers only once sessions are
  shared.
