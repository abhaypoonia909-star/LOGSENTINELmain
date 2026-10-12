# LogSentinel — College evaluator notes

Classroom prototype: upload logs, run rule-based detection, review Attack Summary, download a PDF, inspect Live Alerts and incidents, scan source code, and ask a **local-only** Ollama assistant. This is not a production SOC product and does not claim comprehensive detection.

## Architecture (what actually runs)

```
Browser (forntend/index11.html)
        │  JWT Bearer token
        ▼
Flask (backend/app.py)  →  SQLite logsentinel.db
        │
        ├─ LogParser → LogAnalyzer → Attack Summary / incidents / PDF
        ├─ SecurityAlertService (isolated demo-login alerts, threshold 5 / 300s)
        ├─ CodeScannerService (pattern SAST, ZIP in memory, suggested-fix preview)
        └─ AIService → local Ollama llama3.2:1b  (no cloud fallback)
```

- Frontend directory is spelled `forntend/`. Branding is **LOGSENTINEL** (LOG + SENTINEL).
- Detection is keyword/regex plus a failed-login counter. Uploaded-log Brute Force (`BRUTE_FORCE_THRESHOLD`, default **2** per IP) is **intentionally different** from Live Alerts (`ALERT_FAILED_LOGIN_THRESHOLD` **5** failures in **300** seconds on `/demo-login` only).
- Evidence stored in findings and PDFs is the **original log line**. URL decode is detection-only.
- Ownership: reports, incidents, analyses, and private alerts are owner-or-admin. Demo-login alerts are shared classroom events by design.
- Production (`LOGSENTINEL_ENV` / `FLASK_ENV` / `RAILWAY_ENVIRONMENT` = `production` or `prod`) **refuses** the known development JWT placeholder. Local demo without those flags still warns and can start.

## Ten-minute demonstration

1. Start Ollama with `llama3.2:1b`. Start Flask from `backend` (`python app.py` binds `127.0.0.1:5000` unless you set `FLASK_RUN_HOST`).
2. Hard-refresh `http://127.0.0.1:5000/`. Sign in (or register). Confirm **Logout** and **Switch to Light Mode**.
3. **Load sample demonstration log** → **Run Analysis**. Expect **7** Attack Summary rows (including Port Scan). Counts and IPs come from the file, not placeholders.
4. **Download PDF Report**. The file should start with `%PDF` and list the same attack types. A second account must get **403** on that analysis.
5. `/demo-login`: five wrong passwords from one **unused** IP create one HIGH alert. Do not wipe `logsentinel.db` to clean old `127.0.0.1` events; the isolated unit test is the reliable 4-vs-5 proof.
6. **Code Scanner**: upload a small `.py` / ZIP. Findings show original code and a Suggested Fix. The preview is a suggestion, not a verified patch.
7. SentinelAI: `Hey` (canned). Then a general question. Then “What attacks were detected?” after an analysis (`used_analysis` should be true). If Ollama is down, the API returns a setup error — there is no paid fallback.

## Honest limits to mention if asked

- Not every injection or evasion is implemented (`${IFS}whoami`, SQL `WAITFOR DELAY`, CRITICAL *level* without a keyword).
- Evaluation F1 = 1.0 is for the **labeled synthetic set** in `backend/evaluation/`, not for the internet.
- Malware names that share a line with an intrusion rule appear as the intrusion title (not double-counted).
- Analyze can wait on local `llama3.2:1b` after detection finishes.
- Embedded-browser 390×844 `innerWidth` was not achieved on this host (414×896 observed). `overflow-x` is left visible.

## Reproducible commands

See `LOGSENTINEL_FULL_AUDIT_REPORT.md` section 14. Run each `unittest` module in its **own** process. Do not combine them.
