# LogSentinel — 10-slide presentation outline

Use these slides for a college evaluation. Speak only claims that the repository and audit reports support. Do **not** show a “100% accurate IDS” chart. Synthetic F1 = 1.0 belongs on slide 9 as a **dataset** result, not as real-world accuracy.

Suggested time: about 8–10 minutes plus questions.

---

## Slide 1 — Title and introduction

**On slide**

- LogSentinel
- Local log intelligence, classroom alerts, and source-code review
- BCA Cyber Security project
- Flask + JWT + SQLite + rule-based detection + local Ollama `llama3.2:1b`
- Classroom prototype — not a production SOC

**Speaker notes**

Introduce the product as a **local web app** a student can run on a laptop. Users sign in, upload logs or source, and review findings. Mention the frontend folder is `forntend/` if an evaluator opens the repo. Say clearly that the system does not monitor the college network and does not block real attackers on production login.

---

## Slide 2 — Problem statement

**On slide**

- Logs and source files are available; a full SIEM / commercial SAST is not
- Need explainable matches (original log line as evidence)
- Need a safe classroom login-alert demo that is not production authentication
- Need local Q&A without sending logs to a cloud model

**Speaker notes**

The problem is **visibility and explanation**, not “stop every hack automatically.” Students need to see *which rule fired* and *which IP and line* were involved. Live Alerts are isolated to `/demo-login` so a failed classroom password is not confused with a real account takeover feed.

---

## Slide 3 — Project objectives

**On slide**

| Implemented | Not claimed |
|-------------|-------------|
| JWT register/login and ownership | Network-wide monitoring |
| Rule-based log detection + Attack Summary + PDF | Automatic prevention (IPS) |
| Demo-login alerts (5 failures / 300 s) | Cloud AI fallback |
| Pattern SAST + suggested-fix preview | Confirmed exploit / CVE lookup |
| Local SentinelAI | Production-ready multi-tenant SaaS |

**Speaker notes**

Walk the table. “Suggested fix” means a **preview**, not a verified patch. “Local AI” means Ollama on `127.0.0.1:11434`. If Ollama is stopped, detection still works; chat returns a setup error.

---

## Slide 4 — Architecture and technology stack

**On slide**

```
Browser (index11.html)
   → Flask /api  + JWT
        → SQLite
        → LogParser → LogAnalyzer
        → SecurityAlertService
        → CodeScannerService
        → AIService → local Ollama
```

- Python, Flask, pandas, ReportLab, bcrypt, PyJWT
- Default bind: `127.0.0.1:5000`

**Speaker notes**

Draw the flow while speaking. Stress **one process, local files**. Production environment variables refuse the known JWT placeholder `change-me-in-production`. Local demo without `LOGSENTINEL_ENV=production` can still start with a warning — that is intentional for classroom use, not a silent production deploy.

---

## Slide 5 — Log analysis and attack detection

**On slide**

- Upload `.log` / `.txt` / `.json` (empty and `.exe` rejected)
- Parser: original line, IPv4, failed-login flag — no timestamp column
- Analyzer brute force: **2** failed logins / IP (`BRUTE_FORCE_THRESHOLD`) — **not** the Live Alert 5/300s detector
- Rules: SQLi, XSS, traversal, command injection, PowerShell, reverse/web shell, privilege, port scan, malware keywords, critical **keywords**
- Encoded payloads: detection-only URL decode; evidence stays encoded

**Speaker notes**

Say “rule-based IDS-style **detection**, not prevention.” Give one example: `; whoami` and `| whoami` match Command Injection; `${IFS}whoami` does not. CRITICAL as a syslog level without `kernel panic` / `segfault` / etc. does **not** create a Critical System Event. Overlap is honest: `; cat /etc/passwd` is both Command Injection and Directory Traversal.

---

## Slide 6 — Attack Summary and PDF reporting

**On slide**

- One row per attack type
- Real attempt counts and source IPs — or “Not available”
- Sample demonstration log → **7** types (synthetic file)
- PDF: same summary; owner 200 `%PDF-1.4`; other user **403**

**Speaker notes**

Load the sample in the demo, not a secret production log. The seven types are Brute Force, Port Scan, Traversal, SQLi, XSS, Web Shell, Privilege Escalation. If Port Scan is missing, the page may be stale — hard-refresh so `port scan` (space, not `port_scan`) is in the sample. PDF does not invent missing IPs.

---

## Slide 7 — Live Alerts and incident investigation

**On slide**

- Demo page only: 5 failures in 300 seconds → one HIGH alert
- Production `/api/login` failures are **not** alerts
- Demo alerts are shared classroom events; private alerts are owner-only
- Incidents: hypotheses, same IP inside 900 s — not proven compromise
- Other user requesting another analysis → **403**

**Speaker notes**

Do not wipe `logsentinel.db`. If `127.0.0.1` already has demo events, four-then-five on that IP is inconclusive; the isolated unit test is the reliable threshold proof. Incident Investigation groups detections that already exist.

---

## Slide 8 — Source-code scanning and SentinelAI

**On slide**

- Pattern SAST: Python, JS/TS, PHP, HTML/CSS, Java, C#, SQL, `.txt`, ZIP
- Limits separate from 10 MB log cap; ZIP scanned in memory
- Finding cards: original snippet, explanation, Suggested Fix (preview)
- SentinelAI: local `llama3.2:1b`; greetings canned; analysis attached only when authorized

**Speaker notes**

Upload a tiny `bad.py` (`os.system(input())` style). Say “potential / suspected pattern match,” not “we exploited this.” Suggested Fix is an example. For AI: “Hey” is instant; “What is 2+2?” hits Ollama; “What attacks were detected?” should set `used_analysis` after a run. Measured general-question times in the audit were roughly 0.7–9 seconds, not a SLA.

---

## Slide 9 — Testing, limitations, and security

**On slide**

- Suites run **separately** (JWT_SECRET isolation)
- Auth custom runner: 71 PASS, exit 0 after integrity fix
- Synthetic evaluation: TP 20, FP 0, TN 5, FN 0, F1 1.0 **on that JSONL only**
- Unsupported: `${IFS}whoami`, WAITFOR DELAY, CRITICAL level-word
- JWT ownership, upload/ZIP guards, production placeholder refusal
- Not production-ready; rate limits not soak-tested

**Speaker notes**

This is the honesty slide. If asked “is F1 100%?”, answer: “On a small labeled synthetic set the evaluator wrote, yes. That does not mean the engine catches real attackers.” Mention the custom runner used to exit 0 after a FAIL; that was a test-integrity bug and was fixed without changing the model.

---

## Slide 10 — Conclusion and future scope

**On slide**

- Working local pipeline: parse → detect → summarize → PDF → alerts → SAST → local AI
- Strength: explainable evidence and ownership checks
- Limit: regex prototype, small local model, in-process scan jobs
- Future (not built): richer parsers, one threshold config, more tested rules, job queue

**Speaker notes**

Close by offering a live click-through. Invite questions on IDS vs IPS, precision/recall, and JWT. Do not promise a cloud version or “next we will detect everything.”
