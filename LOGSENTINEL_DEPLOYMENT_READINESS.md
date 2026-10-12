# LogSentinel — Deployment readiness report

**Date:** 12 October 2026  
**Scope:** inspect the existing repository only. Nothing was deployed. No production settings were changed.  
**Audience:** beginner-friendly checklist before putting the classroom app on the public internet.

**Option A prep (same day, after approval):** `backend/Procfile`, `psycopg2-binary`, `postgres://` → `postgresql://` rewrite, and Render treated as production are now in the project. The website has **not** been deployed. Git is still missing on this machine (see remaining blockers).

This report separates **verified in the repo** from **not verified** (cloud accounts, live Render/Vercel projects, git remotes).

---

## 1. Current project status (verified)

LogSentinel is a **single Flask website**, not a separate React/Next.js app.

| Piece | What is actually in the repo |
|-------|------------------------------|
| Frontend | One HTML page: `forntend/index11.html` (CSS and JavaScript inside the file). Extra page: `forntend/demo-login.html`. Folder name is spelled `forntend`. |
| Frontend framework | **None** (no React, Vue, Vite, `package.json`, or `vercel.json`) |
| Backend | Flask in `backend/app.py`. It also **serves** those HTML files at `/` and `/demo-login`. |
| API | Same Flask process under `/api/...` |
| Database today | **SQLite** file `backend/logsentinel.db` unless `DATABASE_URL` is set |
| Local start | `cd backend` then `python app.py` → `127.0.0.1:5000` |
| Dependencies | `backend/requirements.txt` (Flask, SQLAlchemy, pandas, ReportLab, gunicorn, …) |
| Production WSGI | `gunicorn` is listed, but there is **no** `Procfile`, `render.yaml`, `Dockerfile`, or `runtime.txt` |
| Vercel config | **Not present** (no `vercel.json`) |
| Render config | **Not present** (no `render.yaml`) |
| Postgres driver | **Not listed** in `requirements.txt` (no `psycopg2` / `psycopg2-binary`) |

Local classroom use is working. The project is **not ready to click Deploy** on Vercel + Render without extra files and environment variables.

---

## 2. Vercel frontend + Render backend?

**Verified:** the repo is **not** already configured for that split.

| Check | Finding |
|-------|---------|
| Vercel project files | Missing |
| Render project files | Missing |
| How the main page calls the API | `getBackendUrl()` in `forntend/index11.html`: `window.__BACKEND_URL__` → `localStorage.ls_backend_url` → **`location.origin + '/api'`** on http/https → else `http://127.0.0.1:5000/api` |
| Demo-login page | Always `fetch('/api' + path)` — **same website only** |
| CORS | Flask allows **any origin** (`origins="*"`), no cookies |

**What that means in plain language**

- If you put **only** the HTML on Vercel, the browser will call `https://your-vercel-site/api/...`. Vercel has no Flask, so login and analysis will fail unless you add a rewrite/proxy (not in the repo).
- `demo-login.html` will still call `/api` on Vercel and will **not** reach Render.
- `AUTH_CHANGES.md` still says `getBackendUrl()` is hardcoded to localhost. **That document is stale.** The live HTML uses same-origin `/api` when opened over http/https.

**Recommended hosting (reason):** keep the HTML and Flask **together on one Render Web Service**. Users open one URL. No Vercel rewrite is required. This reuses the current `send_from_directory` design.

Split Vercel + Render is possible later, but it **needs code/config changes** (backend URL for both HTML pages). Do not assume any existing Vercel or Render site works — **not verified**.

---

## 3. Database and persistence

**Verified current store:** SQLite via

```text
DATABASE_URL  or  sqlite:///backend/logsentinel.db
```

Tables include users, uploaded files, analyses, threats, reports, demo accounts, security events/alerts, and demo blocks. Passwords are bcrypt hashes. JWT secrets are **not** stored in the database.

**Uploads and PDF/JSON reports** also write to disk:

- `backend/uploads/`
- `backend/reports/` (example: `report_<id>.json`)

`.gitignore` ignores `.db`, `uploads/`, and `reports/` — those local files are not meant to be committed.

**After a typical free cloud deploy (Render/Railway disk):**

| Data | Survives restart / new deploy? |
|------|--------------------------------|
| SQLite file on the app disk | **Usually no** — the disk is often wiped |
| Upload files and report JSON files | **Usually no** |
| Users, analyses, alerts in SQLite | **Lost** with the file |
| In-memory rate limits | **No** |
| In-process code-scan jobs | **No** (already lost on local Flask restart) |

SQLAlchemy can use Postgres if `DATABASE_URL` is a `postgresql://...` URL, but **`psycopg2-binary` is not in `requirements.txt`**, so a Render Postgres add-on would fail to import until that package is added.

**Recommended database:** Render **PostgreSQL** (or another hosted Postgres) for users, analyses, alerts, and report **rows**. File uploads will still vanish on disk-only hosts unless you later add object storage (not in the project today). For a college demo, re-uploading a sample log after a redeploy is acceptable if you say so honestly.

---

## 4. Security settings (no secret values printed)

| Topic | Verified behavior | Cloud risk |
|-------|-------------------|------------|
| JWT | HS256 Bearer token; `owns_or_admin` on reports/incidents | Must set a long random `JWT_SECRET` |
| Placeholder secret | App **refuses** `change-me-in-production` only if `LOGSENTINEL_ENV`, `FLASK_ENV`, or `RAILWAY_ENVIRONMENT` is `production`/`prod` | **Render is not in that list.** If you forget those flags, the app can still start with the known placeholder |
| CORS | All origins allowed | Works for a split host; weaker than locking to your site |
| Rate limits | In-memory Flask-Limiter | Two workers = weaker limits |
| Uploads | `.log`/`.txt`/`.json`; size caps; ZIP guards | Disk is ephemeral |
| PDF | Built in memory / ReportLab; owner **403** for others | OK if the analysis row still exists in the DB |
| Local `python app.py` | Binds **127.0.0.1**, debug off unless `FLASK_DEBUG` | Cloud must use **gunicorn** and `0.0.0.0:$PORT` |
| `RENDER` env | Not treated as production by `runtime_secrets.py` | You must set `LOGSENTINEL_ENV=production` yourself |

Never commit `.env`. Never paste tokens into Git or the HTML.

---

## 5. SentinelAI after cloud deploy

**Verified:** chat (`POST /api/ai`) talks to **local Ollama** at `http://127.0.0.1:11434`, model `llama3.2:1b`. There is **no** automatic cloud fallback on the intended path.

Render/Vercel **cannot run Ollama** on a normal free web dyno. After deploy, `/api/ai` will return a setup / 503-style error unless you point `OLLAMA_BASE_URL` at some other machine that already runs Ollama.

| Feature | Needs Ollama? | After a simple Render deploy |
|---------|---------------|------------------------------|
| Register / login / JWT | No | Works |
| Log upload, detection, Attack Summary | No | Works |
| Incident investigation | No | Works |
| PDF download | No | Works if analysis is in the DB |
| Live Alerts / demo-login | No | Works |
| Code scan + suggested fix | No | Works (in-process; one worker is safer) |
| `analyze_security()` text on `/api/analyze` | **No** — this is a **rule-based** summary of detector output | Works; if it throws, the route already stores “AI analysis unavailable.” |
| SentinelAI chat (“Hey”, “What attacks were detected?”) | **Yes** | **Unavailable** unless you host Ollama elsewhere |

**Practical options (do not enable a paid API unless you explicitly want that):**

1. **College demo (recommended):** deploy without Ollama. Tell visitors chat is laptop-only. All other features stay up.
2. **Optional later:** run Ollama on your PC or a small GPU VPS and set `OLLAMA_BASE_URL` (that URL would be public unless you add extra protection — **not implemented**).
3. **`AI_PROVIDER=openai` exists** as an opt-in paid path. The college project promised local-only AI. Do **not** turn this on unless you accept a cloud API and a key.

---

## 6. Start command, URLs, and missing pieces

**Local (verified):**

```text
cd backend
python app.py
```

Uses `PORT` if set, else 5000.

**Cloud start command (not in the repo yet; this is what you would add):**

```text
gunicorn --bind 0.0.0.0:$PORT --workers 1 --timeout 120 app:app
```

Run it from the `backend` folder (`app:app` is `backend/app.py`). **One worker** matches in-memory limiter and in-process scan jobs.

**Frontend–backend connection**

- Same-host deploy (recommended): browser uses `https://your-app.onrender.com/api`. Matches current `getBackendUrl()`.
- Split deploy: **missing** a production API URL in both HTML files.

**Missing before a safe first deploy**

1. `Procfile` or Render start command (documented above).
2. `psycopg2-binary` if you use Postgres.
3. Host env vars: `JWT_SECRET`, `SECRET_KEY`, `LOGSENTINEL_ENV=production`, `DATABASE_URL`, `AI_PROVIDER=ollama` (chat will still fail until Ollama exists).
4. GitHub (or other git) remote so Render can pull the repo — **git remote was not verified in this audit**.
5. Python version pin (`runtime.txt` or Render setting). Not in the repo.

---

## 7. What is ready vs what needs fixing

### Ready to reuse (do not rebuild)

- Flask + HTML together
- JWT register/login and ownership
- Log analysis, Attack Summary, PDF, incidents, code scan
- Demo-login Live Alerts
- `requirements.txt` already includes gunicorn
- Production placeholder refusal **if** you set a production env flag

### Must fix or add before a public URL (approval required — not done in this audit)

| Item | Suggested file(s) | Why |
|------|-------------------|-----|
| Process start command | new `backend/Procfile` or Render dashboard | gunicorn is unused today |
| Postgres driver | `backend/requirements.txt` | SQLAlchemy cannot talk to Render Postgres without it |
| Treat Render as production | `backend/utils/runtime_secrets.py` | `RENDER` is not checked today |
| Optional CORS lock | `backend/app.py` | `*` is wide open |
| Only if you insist on Vercel | `forntend/index11.html`, `forntend/demo-login.html` | Same-origin `/api` will miss Render |

### Do not “fix” by redesigning

- Detection rules, UI, branding, local Ollama default, classroom demo thresholds.

---

## 8. Recommended setup

1. **One Render Web Service** rooted at `backend` (or start command `cd backend && gunicorn ...`).  
   Reason: Flask already serves the website.
2. **Render PostgreSQL** and paste `DATABASE_URL` into the web service.  
   Reason: SQLite will lose users on every restart.
3. **Leave Vercel unused** for the first go-live.  
   Reason: no Vercel config; split hosting breaks `demo-login.html`.
4. **Leave SentinelAI chat as “local laptop only”** on the public site.  
   Reason: Ollama is not on Render.
5. **One gunicorn worker**, timeout at least 120 seconds.  
   Reason: analysis + code scan can be slow; jobs are in-process.

---

## 9. Numbered checklist (first step → live site)

Do **not** start this list until you approve the small config changes in section 7.

1. Confirm the project is on GitHub (or another git host Render can see). This audit did **not** verify a remote.
2. Approve adding `Procfile` / start command and `psycopg2-binary` (no UI redesign).
3. Create a **Render** account.
4. Create a **PostgreSQL** database on Render. Copy the internal `DATABASE_URL` into the web service (do not paste it into chat or Git).
5. Create a **Web Service** from this repo. Root directory: `backend` (or equivalent). Runtime: Python.
6. Start command: `gunicorn --bind 0.0.0.0:$PORT --workers 1 --timeout 120 app:app`
7. Set environment variables (values stay in Render, not in Git):
   - `LOGSENTINEL_ENV=production`
   - `JWT_SECRET` = long random string (32+ characters)
   - `SECRET_KEY` = another long random string
   - `DATABASE_URL` = the Postgres URL
   - `AI_PROVIDER=ollama` (chat will still be down)
   - Optional: `ADMIN_EMAILS` for your classroom admin email
8. Deploy. Wait until the service is “Live”.
9. Open `https://<your-service>.onrender.com/` (exact hostname comes from Render).
10. Check `https://<your-service>.onrender.com/api/health` → `{"status":"ok",...}`.
11. Register a new user. Do not reuse the local SQLite users (they are not on Postgres).
12. Load the sample log → Run Analysis → confirm Attack Summary → Download PDF.
13. Open `/demo-login` and test five failed passwords if you want Live Alerts.
14. Open SentinelAI and confirm chat explains that Ollama is not on the server (expected).
15. Sign in from a second account and confirm another user’s PDF is **403**.
16. Keep `logsentinel.db` on your laptop. Do not upload it as “the cloud database.”

---

## 10. The exact first action you should perform

**Do not deploy yet.**

Reply and choose:

- **Option A (recommended):** I may add only the small hosting files (`Procfile` / start command, `psycopg2-binary`, and optionally treat Render as production). Then you create the Render + Postgres services.
- **Option B:** You still want Vercel HTML + Render API. That needs extra frontend URL work and is a worse first deploy.

Until you approve, I will not change application code or production settings.

---

## 11. Could not verify

- Whether you already have a Vercel or Render project (none in this repo).
- Whether git `origin` points at GitHub.
- Current Render free-tier sleep / disk rules.
- Whether gunicorn runs on your Windows PC (Render is Linux; that is enough).
- Any secret values in local `.env` files (intentionally not opened for this report).
