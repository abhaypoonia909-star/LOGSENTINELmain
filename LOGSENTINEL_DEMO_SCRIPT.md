# LogSentinel — 10-minute live demonstration script

All log lines and source snippets used here are **synthetic classroom data**. They are not evidence of a real incident on a college network.

**Do not** delete or reset `backend/logsentinel.db` to make alerts look cleaner.

---

## 0. Before the evaluator arrives (2–3 minutes)

### Start Ollama

```powershell
ollama list
```

You should see `llama3.2:1b`. If not:

```powershell
ollama pull llama3.2:1b
```

Ollama should listen on `http://127.0.0.1:11434`.

### Start Flask

```powershell
cd "C:\Users\abhay\OneDrive\Desktop\LOGSENTINEL AUTH\backend"
.\venv\Scripts\activate
python app.py
```

Expected: process serving `http://127.0.0.1:5000` (default host `127.0.0.1`, debug off unless you set `FLASK_DEBUG`).

### Open the app

Hard-refresh `http://127.0.0.1:5000/` (Ctrl+F5). Stale tabs can still hold an old sample that used `port_scan` (underscore) and will **miss** Port Scan.

**If Flask will not start in production mode:** `LOGSENTINEL_ENV=production` refuses a missing or placeholder JWT secret. For a classroom laptop, do not set that flag, or set a long random `JWT_SECRET`.

**If port 5000 is busy:** another Flask is already running. Either use that process (it may be older code) or stop it and start again.

---

## 1. Sign in (about 30 seconds)

1. Register a classroom account **or** sign in with an account you already created.
2. Confirm **Logout** is visible and the title reads LOGSENTINEL.
3. Optional: click **Switch to Light Mode**, then switch back to Dark so the evaluator sees the theme toggle.

**Expected:** `GET /api/me` works with the JWT the page stores. Without a token, APIs return **401**.

**If register fails:** username 3–30 characters; password at least 8 characters with the project’s strength rules; email unique.

---

## 2. Upload / load a safe sample and run analysis (about 2 minutes)

1. Go to **Log Analyzer**.
2. Click **Load sample demonstration log**. Say out loud: “This is a labeled synthetic file, not a capture from our network.”
3. Click **Run Analysis**. The button may show **Analyzing…** for several seconds because the server also asks local Ollama for an AI summary after detection.

**Expected Attack Summary (7 rows):**

| Attack type | What to point at |
|-------------|------------------|
| Brute Force Attack | `192.168.1.100` — several `Failed password` lines (analyzer threshold is **2**) |
| Port Scan Activity | `172.16.0.200` — line says `port scan` |
| Directory Traversal | `10.0.0.99` — `/../../../etc/passwd` |
| SQL Injection | `10.0.0.99` — `OR 1=1` |
| Cross-Site Scripting (XSS) | `10.0.0.99` — `<script>` |
| Web Shell | `10.0.0.99` — `shell.php` |
| Privilege Escalation / Unauthorized Access | privilege-escalation wording |

Counts and IPs come from the file. If an IP is missing on another demo file, the UI should say **Not available**, not invent one.

**If you see 6 rows and no Port Scan:** hard-refresh and load the sample again. The current sample uses `port scan` with a space.

**If analysis errors:** file must be `.log`, `.txt`, or `.json` and not empty. Default log upload cap is 10 MB.

You may instead upload `samples/multi_attack_demo.log` from the repo. It is the same kind of synthetic multi-attack file.

---

## 3. Explain types, counts, and evidence (about 1 minute)

1. Stay on compact **Attack Summary**. One row per type — not one row per raw line.
2. Open a finding / investigation view and show the **original line** (evidence).
3. Say: “URL decode is only for matching. Encoded `%3Cscript` still stores `%3Cscript` as evidence.”
4. Optional overlap sentence: a line like `; cat /etc/passwd` is **two** titles (Command Injection and Directory Traversal), still one summary row each.

Do not call these “confirmed breaches.”

---

## 4. Download and inspect the PDF (about 1 minute)

1. Click **Download PDF Report**. The button should show **Building PDF…**, then return to the download label.
2. Open the file. It should start with `%PDF` and list Attack Summary types.
3. If asked about isolation: another signed-in user requesting that report ID gets **403** “You do not have access to this analysis.”

**If the click is ignored:** scroll so the button is not under the nav (scroll-margin was added for this). Do not claim a problem if a stale tab is covering the control.

Glyph-perfect layout in every PDF viewer was not exhaustively audited; bytes and extractable strings were.

---

## 5. Authorized demo-login alert (about 2 minutes)

1. Open **Demo** / `http://127.0.0.1:5000/demo-login` (isolated page).
2. Say: “This is **not** production `/api/login`. Production wrong passwords do not create Live Alerts.”
3. Classroom defaults from `.env.example` / `Config`: username `demo`, password `Demo1234` (documented demo account, not a personal secret).
4. Submit the **wrong** password five times.

**Expected**

- Each failure: generic “Invalid credentials” (no SQL/XSS execution).
- After the **fifth** failure from one IP inside 300 seconds: one HIGH `demo_login` alert.
- Live Alerts sidebar count increases. Demo alerts are **shared** with every signed-in user.

**Troubleshooting (important)**

| Symptom | Likely cause | What to say |
|---------|--------------|-------------|
| Fifth failure, no new alert | `127.0.0.1` already had demo events in the 300 s window | “The isolated unit test is the reliable 4-vs-5 proof. We do not wipe the classroom database.” |
| Blocked after alerting | Demo mitigation (default 120 s) | Wait or use another network path; do not reset the DB |
| SQLi/XSS in the username field | Inspected and stored as suspicious input; still generic error | “Payloads are not executed.” |

Do not use production register/login for this threshold demo.

---

## 6. Scan a harmless test source file (about 1.5 minutes)

1. Open **Code Scanner**.
2. Upload a tiny synthetic file, for example a `.py` containing `os.system(input())` and a hardcoded `password = "..."` **you created for class** (do not upload real secrets).
3. Click **Run code scan**.

**Expected**

- Pattern findings with severity, CWE/OWASP **mapping strings**, original snippet, explanation, Suggested Fix, Copy Fixed Code.
- Secrets in snippets appear as `***REDACTED***`.
- Classification is `potential` or `suspected`, not “confirmed exploited.”

**If ZIP:** members are scanned in memory. Nested ZIPs, `..` paths, and vendor folders are skipped with warnings. Default code-scan upload budget is larger than the 10 MB log cap (`CODE_SCAN_*`).

**If `.txt`:** the UI asks Source Code vs Security Logs. Pick **Source Code Scan** for this step.

Say: “This suggested fix is a preview. We did not run the fixed program or prove the project is safe.”

---

## 7. SentinelAI (about 1.5 minutes)

1. Open SentinelAI.
2. Type `Hey`. **Expected:** instant canned greeting, not a model wait.
3. Ask a general question, e.g. “What is 2 + 2?” **Expected:** local Ollama reply; `used_analysis` false; no invented sample-log IPs.
4. After the sample analysis, ask “What attacks were detected?” **Expected:** `used_analysis` true and names that exist in **your** Attack Summary.

**If chat errors**

| Message / status | Meaning | Fix |
|------------------|---------|-----|
| 503 / install Ollama / `ollama pull llama3.2:1b` | Server or model missing | Start Ollama; pull the model; no cloud fallback will appear |
| Slow 10–40 s | 1B model generating tokens on CPU | Explain latency; do not claim ChatGPT speed |
| 401 | Not signed in | Sign in again |

Do not present the model’s wording as new forensic evidence.

---

## 8. Optional 30-second security closer

- “Another student account cannot download my PDF or incidents — we tested **403**.”
- “Production placeholder JWT is refused when the environment is marked production.”
- “F1 = 1.0 was measured on a small synthetic JSONL, not on the internet.”

---

## 9. Timing checklist

| Minute | Action |
|--------|--------|
| 0:00 | Hard-refresh, sign in, show branding / theme |
| 0:30 | Load sample, run analysis |
| 2:30 | Attack Summary + one evidence line |
| 3:30 | Download PDF |
| 4:30 | Demo-login five failures + Live Alerts |
| 6:30 | Code scan + suggested fix |
| 8:00 | Hey / general / analysis question |
| 9:30 | Limitations sentence and stop |

If Ollama is down, skip step 7 and say chat is optional; detection still ran.
