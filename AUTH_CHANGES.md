# LogSentinel — Authentication Changes

Drop-in replacements for your existing project. **Copy these files over your
existing ones, keeping the same folder structure.** Nothing else in your
project needs to change.

## What's in this package

```
backend/
  app.py                          -> backend2 index/app.py
  config.py                       -> backend2 index/config.py
  models/models.py                -> backend2 index/models/models.py
  utils/validators.py             -> backend2 index/utils/validators.py
  utils/jwt_utils.py              -> backend2 index/utils/jwt_utils.py
  routes/auth.py                  -> backend2 index/routes/auth.py
  routes/dashboard.py             -> backend2 index/routes/dashboard.py
  routes/reports.py               -> backend2 index/routes/reports.py
  routes/charts.py                -> backend2 index/routes/charts.py
  routes/upload.py                -> backend2 index/routes/upload.py
  routes/analysis.py              -> backend2 index/routes/analysis.py
  routes/ai.py                    -> backend2 index/routes/ai.py
  routes/code_analysis.py         -> backend2 index/routes/code_analysis.py
  threat_intelligence/routes.py   -> backend2 index/threat_intelligence/routes.py
  test_auth.py                    -> OPTIONAL. Test suite. Not imported by app.py.
index11.html                      -> index11/index11.html
```

`requirements.txt` is unchanged — PyJWT and bcrypt were already listed.

## Railway environment variables

| Variable | Required | Notes |
|---|---|---|
| `SECRET_KEY` | **Yes** | Long random string. Without it, every JWT is forgeable. Generate with: `python -c "import secrets;print(secrets.token_urlsafe(48))"` |
| `ADMIN_EMAILS` | Recommended | Comma-separated. Register with one of these emails to receive the admin role. |
| `JWT_EXPIRY_HOURS` | No | Default 24 |
| `AUTH_RATE_LIMIT` | No | Default `10/minute` on /register and /login |
| `PASSWORD_MIN_LENGTH` | No | Default 8 |

Vercel needs no new environment variables.

## JWT compatibility

PyJWT 2.10 and later reject tokens whose `sub` claim is a number. LogSentinel
stores the numeric user id in `sub`, so `decode_token()` disables only that
subject-type check. Signature and expiry checks are unchanged.

## Database

`app.py` calls `ensure_user_schema()` on startup, which adds the `username`
column to an existing `users` table if it is missing. It is idempotent and
safe to run repeatedly, on both SQLite and Postgres. No migration tool needed.

Analyses created before authentication existed have `user_id = NULL` and are
visible to admins only. Set `ADMIN_EMAILS` and register with that address to
keep your existing reports reachable.

## API surface

Public (no token):
- `GET  /api/health`
- `GET  /api`
- `POST /api/register`  { username, email, password, confirm_password }
- `POST /api/login`     { email | username, password }

Requires `Authorization: Bearer <token>`:
- `GET  /api/me`
- `POST /api/logout`
- `GET  /api/dashboard`              (scoped to the caller; admins see all)
- `GET  /api/report/<id>`            (owner or admin, else 403)
- `GET  /api/charts/<id>`            (owner or admin, else 403)
- `GET  /api/code-report/<id>`       (owner or admin, else 403)
- `POST /api/upload`
- `POST /api/analyze`
- `POST /api/ai`
- `POST /api/code-scan`
- `POST /api/threat-intel/report`
- `POST /api/threat-intel/export/<fmt>`

Admin only (403 for normal users):
- `GET  /api/admin/users`

## Running the tests

```bash
cd "backend2 index"
python test_auth.py
```

Uses a throwaway SQLite database at /tmp/ls_test.db and raises the rate limits
so the suite can run. It does not touch logsentinel.db.

## OpenAI assistant

`POST /api/ai` is the only chat endpoint. The browser sends the JWT and an
optional `analysis_id`. The intended provider is local Ollama. The official
OpenAI SDK is not required and is not listed in `requirements.txt`.

The log detection engine is unchanged. Chat uses a local Ollama model
by default. The model explains stored results. It does not decide what was
detected. Log excerpts stay on this machine and are sent only to local
Ollama after the caller owns that analysis (or is an admin).

See `OLLAMA.md` for install, the 8 GB RAM default model, offline use, and
environment variables.

### Local

```bash
cd backend
pip install -r requirements.txt
copy ..\.env.example ..\.env   # Windows. On macOS/Linux: cp ../.env.example ../.env
```

Install Ollama, start it, and download the small model once:

```powershell
ollama pull llama3.2:1b
```

Keep `AI_PROVIDER=ollama` (or `local`). No API key is required. Start the
API from the `backend` folder with `python app.py`.
The page at `forntend/index11.html` calls `http://127.0.0.1:5000/api`.

If Ollama is down or the model is missing, `POST /api/ai` returns HTTP 503
with install/pull instructions. It does not substitute a canned reply and
does not call a cloud provider.

### Hosted / optional OpenAI

Local Ollama is the default. Set `AI_PROVIDER=openai` only if you explicitly
want the paid path, then set `OPENAI_API_KEY` on the Flask host. Never put
keys in Git, HTML, or JavaScript.

### Tests

```bash
cd backend
python test_ai.py
python test_auth.py
```

`test_ai.py` mocks Ollama (and OpenAI when that provider is selected). It
does not download a model or make a paid API call.

## Live alert visibility

`GET /api/alerts`, `GET /api/dashboard` live-alert counts, and
`GET /api/security-incidents` use the same visibility rule:

- **Shared classroom demo.** Rows with `source=demo_login` come from the
  public `/api/demo/login` burst. They have no owner. Every signed-in
  evaluator sees the same Live Alerts after the guided demo. This is
  intentional so the college demonstration stays consistent.
- **Private user events.** Alerts with any other source, including leftover
  `production_login` rows, are visible only to the owning user. Admins see
  all rows. Production `/api/login` does not create live alerts.
- **Uploaded-log analysis** never writes `SecurityAlert` or `SecurityEvent`
  rows. Attack Summary and Incident Investigation stay on the analysis the
  caller owns.

## Frontend note

`getBackendUrl()` near line 2596 of index11.html still returns the hardcoded
value it had before — this was left exactly as-is. The authentication calls use
the same function as the existing /analyze call, so whatever you point it at
for deployment covers both.
