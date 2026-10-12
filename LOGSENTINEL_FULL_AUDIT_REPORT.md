# LogSentinel Full Audit Report

**Date:** 12 October 2026 (security and reliability sprint)  
**App under test:** `http://127.0.0.1:5000/` (frontend directory is `forntend/`)  
**Local model:** Ollama `llama3.2:1b` at `http://127.0.0.1:11434` (`GET /api/ai/status` → `ready=true`, provider `ollama`)  
**This pass:** production JWT-placeholder refusal, safer Flask bind defaults, tested command-injection variants, offline detection evaluation metrics. Earlier follow-up (11 Oct) is unchanged in [section 15](#15-follow-up-three-verified-issues). Sprint results are in [section 16](#16-security-and-reliability-sprint-12-october-2026).  
**College demo notes:** `COLLEGE_EVALUATOR_NOTES.md`

This report separates **automated unit/integration tests**, **real parser/analyzer/scanner output**, **live authenticated API calls**, **live local-model inference**, and **browser checks**. A category is marked PASS only when actual detector or API output supported it. Detector rules were expanded only for the verified missing `; whoami` signature and detection-only URL decode. Independent overlapping intrusion titles are now kept; malware aliases that share evidence are still collapsed.

---

## 1. Modules and features reviewed

| Area | Location | Status |
|------|----------|--------|
| Flask app + API index | `backend/app.py` | Working (`GET /api/health` → `ok`) |
| JWT auth / register / login | `backend/routes/auth.py` | Working |
| Isolated demo login | `backend/routes/demo_auth.py`, `/demo-login` | Working |
| Log parser | `backend/services/log_parser.py` | Working (no `timestamp` column) |
| Detection engine | `backend/services/log_analyzer.py` | Working within documented rule limits |
| Attack Summary | `backend/services/attack_wise.py` | Working |
| Dashboard metrics | `backend/routes/dashboard.py` | Working (latest-log `summarize_attacks()`, skips code scans) |
| PDF / JSON reports | `backend/routes/reports.py`, `services/report_service.py` | Working |
| Live Alerts | `backend/routes/alerts.py`, `services/security_alerts.py` | Working |
| Incident correlation | `backend/services/incident_correlation.py` | Working |
| Code scanner | `backend/services/*_scanner.py`, `POST /api/code-scan` | Working |
| SentinelAI | `backend/services/ai_service.py`, `ollama_client.py` | Working locally |
| Frontend | `forntend/index11.html`, `forntend/demo-login.html` | Usable after sample refresh + scroll-margin fix |
| Threat-intel export | `backend/threat_intelligence/` | Present; not the college demo path |

**Implemented log detectors (from code, then exercised):**

- Brute Force (parser `failed password` / `failed login`, analyzer threshold **2** per IP)
- Port Scan (`port scan`, `portscan`, `nmap`, `masscan`, …)
- Intrusion (independent rules can all match one line): SQL Injection, XSS, Directory Traversal, Command Injection (includes `;\s*(whoami|id|uname)`), Suspicious PowerShell, Reverse Shell, Web Shell, Privilege Escalation / Unauthorized Access
- Detection-only URL decode (`unquote_plus`, max 2 passes, 8000-char cap) on the match haystack. Evidence / PDF still store the original raw line.
- Critical System Event (keyword list only: `kernel panic`, `segfault`, `out of memory`, … — **not** the word CRITICAL alone)
- Malware Indicator: Trojan, Virus, Worm, Rootkit, Backdoor, CoinHive Miner, XMRig Miner, Reverse Shell Payload, Base64 Payload, PowerShell Malware, Web Shell Malware, Ransomware

**Still not an independent detector:** CRITICAL *level* without a keyword.

---

## 2. Detector coverage matrix

Evidence: this session’s `LogParser` + `LogAnalyzer.analyze()` via `backend/_audit_runner.py` → `backend/_audit_results.json`. Live `POST /api/analyze` noted where used.

| Attack category | Test input (summary) | Expected | Actual | Count / IP | Result | Notes |
|-----------------|----------------------|----------|--------|------------|--------|-------|
| Brute Force Attack | 2× `Failed password attempt` from `198.51.100.25` | Brute Force | Brute Force | 2 / `198.51.100.25` | **PASS** | Analyzer threshold is 2 (Live Alerts use 5) |
| Port Scan Activity | `Port scan detected` `203.0.113.44` | Port Scan | Port Scan | 1 / `203.0.113.44` | **PASS** | |
| Port Scan (nmap) | `nmap SYN probe` `203.0.113.45` | Port Scan | Port Scan | 1 / `203.0.113.45` | **PASS** | Same detector, extra keyword |
| SQL Injection | `OR 1=1` `203.0.113.60` | SQLi | SQLi | 1 / `203.0.113.60` | **PASS** | |
| Cross-Site Scripting (XSS) | `<script>alert(1)</script>` `203.0.113.61` | XSS | XSS | 1 / `203.0.113.61` | **PASS** | Encoded `%3Cscript` now also matches (detection-only decode) |
| Directory Traversal | `/../../../etc/passwd` `203.0.113.62` | Traversal | Traversal | 1 / `203.0.113.62` | **PASS** | Encoded `..%2F` now also matches |
| Command Injection | `shell_exec(user_input)` `203.0.113.64` | Command Injection | Command Injection | 1 / IP | **PASS** | Also confirmed by live `/api/analyze` |
| Command Injection (overlap) | `; cat /etc/passwd` | Command Injection **and** Traversal | Command Injection + Directory Traversal | 1 each / same evidence | **PASS** | Independent intrusion rules; summary stays one row per name |
| Command Injection (whoami) | `; whoami` only | Command Injection | Command Injection | 1 | **PASS** | Evidence is the original raw line |
| Suspicious PowerShell | line contains `PowerShell` | PowerShell | PowerShell | 1 / `192.0.2.80` | **PASS** | |
| Reverse Shell | `Reverse shell indicator` `192.0.2.81` | Reverse Shell | Reverse Shell | 1 / `192.0.2.81` | **PASS** | |
| Web Shell | `GET /uploads/shell.php` | Web Shell | Web Shell | 1 / `203.0.113.70` | **PASS** | |
| Privilege Escalation | `Privilege escalation detected` | Privilege | Privilege | 1 / `192.0.2.90` | **PASS** | |
| Trojan / Virus / Worm / Rootkit / Backdoor | word-boundary indicators | named malware | named malware | 1 each / `192.0.2.91` | **PASS** | Keyword detectors |
| Ransomware | `Ransomware behavior indicator` | Ransomware | Ransomware | 1 / `192.0.2.91` | **PASS** | |
| XMRig Miner | `XMRig miner` | XMRig | XMRig | 1 / `192.0.2.92` | **PASS** | |
| CoinHive Miner | `CoinHive cryptomining` | CoinHive | CoinHive | 1 / `192.0.2.92` | **PASS** | |
| Base64 Payload | `base64 payload` | Base64 Payload | Base64 Payload | 1 / `192.0.2.94` | **PASS** | Extra implemented rule |
| Critical System Event | `kernel panic` | Critical System Event | Critical System Event | 1 / `192.0.2.93` | **PASS** | |
| Critical System Event (level word) | `CRITICAL` / “Critical system error” only | Critical System Event | *none* | 0 | **UNSUPPORTED** | By design: level word is not a detector |
| Encoded XSS / traversal / SQLi | `%3Cscript`, `..%2F`, `%27%20OR%201%3D1` | matching named types | XSS + Traversal + SQLi | 1 each | **PASS** | `_audit_runner` special + unit tests; evidence still contains `%3Cscript` / `..%2F` |
| PowerShell Malware | `PowerShell -enc payload` | PowerShell Malware | **Suspicious PowerShell** | 1 / `192.0.2.95` | **PARTIAL** | Malware alias dropped as same evidence (not first-match among intrusion rules) |
| Web Shell Malware | `c99.php` | Web Shell Malware | **Web Shell** | 1 / `203.0.113.71` | **PARTIAL** | Same malware-alias collapse |
| Reverse Shell Payload | `/dev/tcp/` | Reverse Shell Payload | **Reverse Shell** | 1 / `192.0.2.96` | **PARTIAL** | Same malware-alias collapse |

**Multi-category file (`samples/multi_attack_demo.log`):** seven named types — Brute Force, Port Scan, Traversal, SQLi, XSS, Web Shell, Privilege Escalation. Live `/api/analyze` returned the same seven.  
**All-types file:** 17 named Attack Summary rows (Critical-from-level-word still absent, as designed).

---

## 3. False positives and duplicate counting

| Case | Actual engine result |
|------|----------------------|
| Benign INFO health/cron/“the word attack” | **No findings** |
| Empty content | 0 threats, empty summary |
| Single failed login (below threshold 2) | Counted in `total_failed_logins=1`, **no** Brute Force finding |
| Duplicate failed-password lines (3) | One Brute Force row, **attempts = 3**, one IP — not three summary rows |
| Two IPs × 2 failures | One Brute Force row: `198.51.100.25 (2); 203.0.113.10 (2)` |
| Privilege + segfault | Two summary rows (Privilege + Critical). Different evidence is not merged away |
| Encoded `%3Cscript` and `..%2F` | **Findings** (XSS / Traversal); original encoded text kept as evidence |
| Encoded benign `health%20check` / `the%20word%20attack` | **No findings** |
| Duplicate `; cat /etc/passwd` lines (2) | One Command Injection row and one Directory Traversal row (`attempts=1` each) |
| Intrusion vs malware same evidence | `_flatten_threats` keeps the intrusion name; malware alias is not double-counted |
| UI sample `port_scan` (underscore) | Did not match Port Scan keywords. **Already fixed** in `SAMPLE_LOG` to `port scan` |

---

## 4. Attack Summary verification

| Scenario | Result |
|----------|--------|
| Single category (`shell_exec` / live cmd log) | One row: Command Injection |
| Multi-category sample / API | One row per named type |
| Multiple IPs same type | Per-IP counts in `source_ip_display` |
| Repeated attempts | Attempt count = failed-login aggregation or 1 per event |
| Missing IP | Display **Not available** (SQLi line without IPv4; privilege line in UI sample has no IPv4) |
| Benign / empty | Empty table |
| Dashboard consistency | `distinct_attack_types` = `summarize_attacks()` row count on the **latest log** analysis. After live `cmd_inject.log`, dashboard showed **1** (not the earlier 7-type file) |
| Browser after hard reload + Load Sample + Run Analysis | `#wsTypes` = **7**, `#awDistinctTypes` = **7**, seven table rows including **Port Scan Activity / 172.16.0.200** |

Stale-tab note: a previously open browser tab still had the old in-memory `port_scan` token and produced 6 rows (no Port Scan). After `?audit=reload`, the current `SAMPLE_LOG` produced 7 rows. Refresh the page before a demo.

---

## 5. Live Alerts

**Automated (`test_security_alerts`, 24 OK, follow-up pass):** 4 failures do not alert; 5th creates HIGH brute-force; different IPs independent; window excludes old failures; production login failure is not a live alert; uploaded analysis does not create alerts; polling does not duplicate; private owned alerts hidden from the other user; `demo_login` alerts are shared.

**Isolated 4-then-5 (`test_isolated_demo_login_four_then_five_threshold`, OK):** uses a temp SQLite file (`%TEMP%/logsentinel_security_alerts_test.db`), not `logsentinel.db`. Clean IP `203.0.113.201`. Four wrong demo passwords → 4 `failed_login` events and **0** brute-force alerts. Fifth → one HIGH `demo_login` alert with `event_count=5`, `owner_user_id=None`. Threshold 5 / window 300s. Production classroom DB was not cleared or written.

**Live HTTP (shared 127.0.0.1 classroom DB, throwaway users `audita739064` / `auditb739064`):**

- Demo success → `200` generic success, not labelled an attack.
- Four + fifth wrong passwords → `401` generic “Invalid credentials.” (API does **not** return an `alert` object; persistence is server-side.)
- SQLi/XSS payloads → `401` generic fail; not executed.
- Production `/api/login` wrong password → `401`; not a demo source.
- Alert totals: **6 before** the live burst, **9 after** for both new users (shared demo visibility). Repeat `GET /api/alerts` → same total **9 / 9**.
- Sidebar **Live Alerts 9** matched that shared total after sign-in.

**Limitation:** the live 4-then-5 check on `127.0.0.1` is **inconclusive** because that address already had demo events in the 300s window (`alerts_before=6`). The isolated suite above is the reliable threshold proof. Do not wipe the classroom database to make a live demo look cleaner.

---

## 6. Incident investigation

`samples/multi_attack_demo.log` / live analysis **19**:

- `confirmed_findings`: 7  
- `possible_correlations`: 1 (same IP `10.0.0.99` within 900s: traversal + SQLi + XSS + webshell)  
- `total_incidents`: 4  
- Disclaimer present: groupings are hypotheses; a rule match is not proven compromise.

Browser Incident Investigation on the earlier sample run showed the same 10.0.0.99 correlation reasons and “No sufficiently strong relationship” singletons. Filters (severity / category / IP / time) rendered. Cross-user `GET /api/analysis/19/incidents` → **403**.

Unrelated same-timestamp events are not correlated on time alone (unit tests, 12 OK).

---

## 7. PDF reports

| Check | Result |
|-------|--------|
| Engine `build_pdf_bytes` on multi-attack result | `%PDF-1.4`, 21,257 bytes, contains Attack Summary / Brute Force / Not available |
| Live `GET /api/report/19/pdf` as owner | `200`, `application/pdf`, `%PDF-1.4`, 21,257 bytes, Attack Summary present |
| Same PDF as other user | **403** “You do not have access to this analysis.” |
| Browser **Download PDF Report** | Click succeeded; button entered **Building PDF…**, then returned to **Download PDF Report** |
| Empty / invented IPs | Missing IPs render **Not available** |

Clipped-glyph layout was not exhaustively measured page-by-page in an external PDF viewer; bytes and extractable strings were validated.

---

## 8. Source-code scanner

Real `CodeScannerService` output this session (code is **not** executed):

| Input | Findings |
|-------|----------|
| `bad.py` (password, api_key, eval, os.system, concatenated SQL, md5) | 6: Hardcoded Credentials (L1, High, CWE-798), Hardcoded API Key (L2, Critical), Code Injection (L3), Command Injection (L4), SQL Injection (L5), Weak Cryptography (L6, Medium) |
| `clean.py` `def add` | **0** |
| `bad.js` innerHTML + eval | XSS + Code Injection |
| `bad.php` echo $_GET + mysql_query | XSS + SQL Injection |
| `bad.html` http form + javascript: | Insecure Form + XSS |
| ZIP of bad.py + clean.py + bad.js | 8 findings |
| Live `POST /api/code-scan` bad.py | 200, 2 findings (password + eval), `scan_type=code`, `analysis_id` stored |
| Live ZIP | 200, 2 findings, `scanned_files: [bad.py, clean.py]` |

HTML `<script>` tags are flagged by design (any inline script). TypeScript is not in `SCANNABLE_EXTENSIONS`.

---

## 9. SentinelAI (live local Ollama)

`GET /api/ai/status` (original audit): `ready=true`, provider `ollama`, model `llama3.2:1b`, base `http://127.0.0.1:11434`. No cloud fallback on the intended path. Defaults remain local Ollama / `llama3.2:1b`.

**Where the time went (measured, not guessed):** greetings are canned (~0 s). Cold-load is avoided with `keep_alive=60m` plus a one-token warmup after ready status. Remaining delay is **CPU token generation** on `llama3.2:1b`. Raising `num_predict` from 80 to 128 made “What is a Python list?” *slower* (24–33 s) than the 14.8 s audit baseline because the 1B model filled the extra tokens. Compact analysis context (cap 1200, 8 summary rows, 2 incidents with `incident_id`, 3 excerpts with `ts=`) plus `num_predict` 80 general / 120 analysis / `num_ctx` 768–1024 is the setting that improved analysis and typical general questions.

| Prompt | Path | Before (audit live `/api/ai`) | After (AIService, new options) | used_analysis | Notes |
|--------|------|-------------------------------|--------------------------------|---------------|-------|
| `Hey` | greeting short-circuit | **0.024 s** | **0.000 s** (`test_ai` this pass) | false | Not a model call |
| `What is a Python list?` | general, `num_predict=80`, `num_ctx=768` | **14.800 s** / 200 | **6.416 s** (prior after-fix) and **9.189 s** (this pass, 353 chars) | false | Same local model; variance is real |
| `What is 2 + 2?` | general (`test_ai` live) | — | **6.400 s** / 21 chars | false | `test_real_ollama_latency_when_available` |
| Follow-up `Give one example` | history 4 turns | **4.854 s** / 200 | **2.164 s** (prior after-fix) and **5.170 s** (this pass, 267 chars) | false | Follow-up is **not** always faster; do not claim a guaranteed win |
| `What attacks were detected?` | analysis attached | **38.624 s** / analysis 19 | **23.613 s** (prior after-fix) and **19.195 s** (this pass, multi-attack demo, 499 chars) | **true** | Listed real detections (this pass started with Brute Force from `samples/multi_attack_demo.log`) |

Greetings do not attach analysis. General questions did not invent sample-log IPs. Analysis answers used authorized findings (`used_analysis=true`).

**Flask on `:5000`:** the process that served the original 14.8 / 38.6 s live-API numbers was **not restarted** in this follow-up. Do not treat the website chat as faster until that process is recycled so it loads the new `ai_service.py` / `ollama_client.py`. The after numbers above are from `AIService` / `test_ai` against local Ollama, not from the still-running Flask worker.

Streaming UI (Stop / SSE) was not re-timed in the browser this pass; unit tests cover SSE tokens, 503/504 mapping, auth, compact limits, and evidence (`test_ai` **53 OK**). `local_ai.py` is unused by the live chat path.

The live-API helper previously crashed printing the greeting emoji on Windows `cp1252`. That is an audit-script issue, not an app defect. Prints are now ASCII-safe.

---

## 10. Authentication and authorization

| Check | Result |
|-------|--------|
| Register two users | `201` + JWT |
| `GET /api/me` no token | `401` Authorization token required |
| Invalid token | `401` Invalid token |
| Valid token | `200` |
| User B dashboard | `analysis_count=0`, `distinct_attack_types=0` (no leak of A’s files) |
| User B PDF / incidents for A’s analysis | **403** |
| Empty upload | `400` Uploaded file is empty |
| `.exe` upload | `400` Only .log, .txt, .json |
| Rate limits | Configured (`AUTH_RATE_LIMIT` 10/min, `RATE_LIMIT` 60/min, demo 30/min); not soak-tested here |

Live JWT bodies were redacted and the audit JSON that briefly contained tokens was deleted. Do not commit `_audit_live_api.json`.

---

## 11. Desktop / mobile browser

Performed on `http://127.0.0.1:5000/` while signed in (Logout visible).

**Desktop**

- First click on **Load sample demonstration log** was intercepted by the fixed `nav` / `.nav-links` until the button was scrolled into view. **Fixed** with `html { scroll-padding-top }` and `scroll-margin-top` on `#analyzer`, `#sampleBtn`, `#analyzeBtn`, `#downloadPdfBtn`.
- After a hard reload (so the current `SAMPLE_LOG` with `port scan` was used): Load Sample → Run Analysis (button showed **Analyzing…**) → Attack Summary **7 rows** = `#wsTypes` **7**.
- **Download PDF Report** entered **Building PDF…** (not intercepted by FAB/toasts) and returned to the download label.
- Live Alerts sidebar **9** matched the shared demo total.
- System font stack (`Segoe UI` / `ui-monospace`); no Google Fonts.

**Mobile (CDP `Emulation.setDeviceMetricsOverride` requested `390×844`, `deviceScaleFactor=3`, `mobile=true`)**

- Host tab stayed **`innerWidth` 414 × `innerHeight` 896**. Exact 390 CSS viewport was **not** achieved in this embedded browser.
- `document.documentElement.clientWidth` **390**, `scrollWidth` **414**, `body.scrollWidth` **414**. The 24 px extra width is the host 414 vs requested 390, not an app overflow hide.
- `matchMedia('(max-width: 390px)')` **false**; `max-width: 600px` **true**.
- `overflow-x` remained `visible` / `visible` on `html`/`body`. **No `overflow-x: hidden` workaround** was added.
- Logout visible, mobile menu `display:flex`.
- Limitation: this Cursor browser host does not apply a true 390×844 `innerWidth`. Record that as an environment limit, not a CSS pass.

---

## 12. Files changed and root causes fixed

| File | Change |
|------|--------|
| `backend/services/log_analyzer.py` | `normalize_for_detection()` (bounded `unquote_plus`, 2 passes); Command Injection includes `; whoami` / `id` / `uname`; haystack uses decode-for-match; `_intrusion` keeps every matching rule per line; evidence stays `_row_evidence` original text. |
| `backend/services/ai_service.py` | Compact Ollama options (`num_ctx` 768/1024, `num_predict` 80/120/512, `keep_alive` 60m); analysis context cap 1200 with attack summary + 2 incidents (`incident_id`) + 3 excerpts (`ts=`); background warmup. |
| `backend/services/ollama_client.py` | Matching default options and `warmup()` one-token `/api/chat`. |
| `backend/test_attack_wise.py` | whoami, overlap, encoded-positive, encoded-benign/duplicate tests; evidence assertions; scroll-padding CSS still asserted. |
| `backend/test_security_alerts.py` | Isolated 4-then-5 on clean temp DB IP `203.0.113.201`. |
| `backend/test_ai.py` | Compact generation/context tests; live Ollama latency when available. |
| `backend/_audit_runner.py` | whoami / overlap / encoded (including `%27%20OR%201%3D1`) coverage. |
| `forntend/index11.html` | Prior polish: `scroll-padding-top` / `scroll-margin-top`; `SAMPLE_LOG` uses `port scan`. |
| `backend/_audit_live_api.py` | Reads `alerts` (not `items`); strips tokens/`raw`; ASCII-safe prints. |
| `LOGSENTINEL_FULL_AUDIT_REPORT.md` | This follow-up: before/after latency, detector matrix, isolated threshold, mobile limit. |

**Deleted:** `backend/_audit_live_api.json` (contained JWTs in raw HTTP dumps).

**Not changed:** JWT / `require_jwt` / `owns_or_admin`, Live Alerts ownership, Attack Summary one-row-per-name, PDF ownership, incident correlation, code scanners, brute-force analyzer threshold (2) and alert threshold (5/300s), Ollama provider / model (no cloud, no extra `ollama pull`).

**Earlier polish still in the tree:** dashboard latest-log Attack Summary metric; PDF stacking/pointer-events; system fonts; mobile nav/banner wrap; parser print-noise removal.

---

## 13. Remaining defects, limitations, priorities

1. **Malware aliases that share evidence with an intrusion rule** still surface as the intrusion name (PARTIAL). Counts are not inflated. This is intentional alias collapse, not first-match among intrusion titles.
2. **CRITICAL level ≠ Critical System Event (by design).** Need `segfault` / `kernel panic` / `out of memory` / etc.
3. **Parser has no `timestamp` column.** ISO prefixes can be recovered later by Attack Summary; Threat rows often have empty timestamps.
4. **Live demo threshold on 127.0.0.1** is polluted by prior classroom events. Use the isolated suite (or a clean unused IP) to demonstrate 4 vs 5. Do not wipe `logsentinel.db`.
5. **Analyze latency.** `POST /api/analyze` also runs `AIService.analyze_security`; UI “Analyzing…” can last tens of seconds even after detection finishes.
6. **SentinelAI still waits on CPU `llama3.2:1b` token generation.** General questions are typically 6–9 s; analysis questions 19–24 s in this follow-up. Follow-up latency varies (2–5 s) and is not always below the 4.854 s audit baseline. No cloud model was added.
7. **Flask `:5000` must be restarted** before the website serves the new analyzer / AI options. After-fix inference numbers are from `AIService` / `test_ai`, not from the still-running worker.
8. **Pandas warnings** on grouped regexes in `_INTRUSION_COMBINED_RE` / `_MALWARE_COMBINED_RE` (noise, not a miss).
9. **390×844 `innerWidth` was not applied** in the embedded browser host (414×896 observed after the CDP request). `overflow-x` left `visible`.
10. **Do not run the four unittest modules in one process** (`JWT_SECRET` isolation).

**College-eval ready if you:** restart Flask so it loads this code, hard-refresh, load the sample (now with `port scan`), run analysis (expect **7** Attack Summary rows), download the PDF, use isolated demo-login for 5 failures, and keep Ollama running.

---

## 14. How to reproduce and rerun

### Engine coverage (no Flask required)

```bat
cd backend
python _audit_runner.py
```

Writes `backend/_audit_results.json`.

### Live API (Flask must already be on port 5000)

```bat
cd backend
python _audit_live_api.py
```

Uses new throwaway users. Do not commit any JSON that contains JWTs.

### Unit / integration suites (separate processes only)

```bat
cd backend
python -m unittest test_runtime_secrets -v
python -m unittest test_detection_eval -v
python evaluation\evaluate_detection.py
python -m unittest test_attack_wise -v
python -m unittest test_security_alerts -v
python -m unittest test_incident_correlation -v
python -m unittest test_ai -v
python -m unittest test_code_scan -v
python -m unittest test_large_codebase_scan -v
python -m unittest test_check_runner -v
python -m unittest test_config_consistency -v
python test_auth.py
python _sprint_live_api.py
```

**Suite results (separate processes only, 12 Oct 2026)**

| Suite | This sprint | Exit | Notes |
|-------|-------------|------|-------|
| `test_runtime_secrets` | **5 OK** (0.002 s) | 0 | Production placeholder refusal |
| `test_detection_eval` | **7 OK** (0.594 s) | 0 | Metrics from `LogAnalyzer` vs labeled JSONL |
| `test_attack_wise` | **23 OK** (1.760 s) | 0 | + pipe/subshell/backtick/encoded whoami |
| `test_security_alerts` | **24 OK** (12.244 s) | 0 | Isolated 4-then-5 still OK |
| `test_incident_correlation` | **12 OK** (0.822 s) | 0 | Cross-user 403 |
| `test_ai` | **53 OK** (11.213 s) this integrity pass | 0 | Live Ollama `2+2` in **0.682 s**; missing-model **503** is mocked |
| `test_code_scan` | **31 OK** (1.159 s) | 0 | ZIP / `.txt` / ownership |
| `test_large_codebase_scan` | **13 OK** (0.955 s) | 0 | Jobs / ZIP bomb skip |
| `test_check_runner` | **8 OK** (0.419 s) | 0 | Failing fixture process exit **1**; passing fixture exit **0** |
| `test_auth.py` (custom runner) | **71 PASS / 0 FAIL / 0 ERROR / 0 SKIP** | 0 | Semantic brute-force check; nonzero exit only when FAIL or ERROR |

Engine `_audit_runner.py` this pass: whoami **PASS**, overlap **PASS** (Command Injection + Directory Traversal), encoded XSS/Traversal/SQLi present, CRITICAL-level-word **UNSUPPORTED**, malware aliases **PARTIAL**. Do not combine the four modules in one `unittest` process.

### Browser

1. Hard-refresh `http://127.0.0.1:5000/` (required after `SAMPLE_LOG` edits).
2. Sign in → Analyzer → **Load sample demonstration log** → **Run Analysis**.
3. Confirm Attack Summary rows = **7** and equal `#wsTypes`.
4. Click **Download PDF Report** (should show Building PDF…).
5. `/demo-login` → five failed passwords from one IP → Live Alerts (use a clean IP/window, or trust the isolated suite).
6. SentinelAI: `Hey`, then a general question, then “What attacks were detected?” after an analysis.

### Overlapping Command Injection + Traversal (now both kept)

```
2026-10-11T09:05:00Z WARNING app 203.0.113.63 Command injection: ; cat /etc/passwd
```

Actual findings this pass: **Command Injection** and **Directory Traversal**, same original evidence, one summary row each. Working single-rule Command Injection lines: `shell_exec(user_input)` and `; whoami`.

---

## 15. Follow-up: three verified issues

### 15.1 Local SentinelAI response time

| Claim | Evidence |
|-------|----------|
| Default still local Ollama `llama3.2:1b` | `_ollama_settings()` / `test_ai` live `provider=ollama` |
| Delay is generation, not greeting or (after warmup) model load | Greeting 0 s; raising `num_predict` to 128 made the list question slower than the 14.8 s baseline |
| After-fix measurements | List 6.416–9.189 s; follow-up 2.164–5.170 s; analysis 19.195–23.613 s `used_analysis=true` |
| Not claimed | Website `/api/ai` is faster (Flask worker not recycled); follow-up is always faster than 4.854 s |

### 15.2 Command injection and encoded input

| Case | Result |
|------|--------|
| `; whoami` | Command Injection; evidence is the raw line |
| `; cat /etc/passwd` | Command Injection **and** Directory Traversal |
| `%3Cscript`, `..%2F`, `%27%20OR%201%3D1` | XSS, Traversal, SQLi; evidence still encoded |
| Encoded benign health / “the word attack” | No findings |
| Duplicate overlap lines | Summary attempts stay 1 + 1 |
| Payloads executed? | No. Decode is match-only |

### 15.3 Reproducible tests and mobile

| Case | Result |
|------|--------|
| Isolated 4 vs 5 | **PASS** on temp DB, IP `203.0.113.201` |
| Production `logsentinel.db` | Not cleared or written by that test |
| 390×844 | Requested via CDP; host stayed 414×896; overflow left visible |

---

## Verdict

LogSentinel’s pipeline still works end-to-end for college evaluation: parse → detect → Attack Summary → incidents → PDF → JWT isolation → shared demo alerts → local Ollama chat → code scan.

This follow-up **verified** `; whoami`, detection-only encoded matching, independent overlapping intrusion titles, the isolated 4-vs-5 threshold, and measured local-inference changes on `llama3.2:1b`. It does **not** claim the still-running Flask worker is faster, does **not** claim a true 390 CSS viewport, and does **not** treat malware-alias PARTIAL rows as new intrusion misses. Restart Flask before a demo so the website loads these analyzer and AI changes.

---

## 16. Security and reliability sprint (12 October 2026)

### 16.1 Inspection: confirmed vs limitation vs unverified

| Item | Class | Evidence |
|------|-------|----------|
| Production boot with `JWT_SECRET` / `SECRET_KEY` missing or `change-me-in-production` | **Confirmed defect — fixed** | `Config` still falls back for local demo; `assert_secure_secrets()` now raises when `LOGSENTINEL_ENV` / `FLASK_ENV` / `RAILWAY_ENVIRONMENT` is `production`/`prod`. `test_runtime_secrets` 5 OK |
| `app.run(host="0.0.0.0", debug=True)` | **Confirmed defect — fixed** | Default is now `127.0.0.1` with `debug=False` unless `FLASK_DEBUG` / `FLASK_RUN_HOST` are set |
| Cross-user PDF / incidents / dashboard / code report | **Already working — re-verified** | Live `_sprint_live_api.py`: other user PDF **403**, incidents **403**, `analysis_count=0`. Suites also 403 |
| JWT required / invalid token | **Already working — re-verified** | Live `GET /api/me` no token **401**, bad token **401**, owner **200** |
| Command Injection `; whoami` | **Already working** | Prior engine tests |
| Command Injection `\| whoami`, `$(whoami)`, `` `whoami` ``, `%3B%20whoami`, `%7C%20whoami` | **Confirmed FN — fixed and tested** | Engine + eval TP; live `/api/analyze` of `\| whoami` + `%3B%20whoami` → **Command Injection** |
| `filesystem(check)` matching `system(` | **Confirmed FP risk — fixed** | Rule is now `\bsystem\s*\(`; benign filesystem line is TN |
| `${IFS}whoami`, CRITICAL level-word, `WAITFOR DELAY` SQLi | **Known unsupported** | Eval `unsupported_miss`; **not** counted as successful detection |
| Malware alias collapse on shared evidence | **Known limitation** | Intrusion title kept; not double-counted |
| Combined unittest process overwrites `JWT_SECRET` | **Known test-environment issue** | Suites must stay separate |
| Live demo 4-vs-5 on `127.0.0.1` | **Known limitation** | Classroom DB already has demo events; isolated suite is the proof. DB was not wiped |
| 390×844 `innerWidth` | **Environment limit** | CDP requested 390; host stayed **414×896**; `overflow-x` left `visible` |
| Rate-limit soak / exhaustive PDF glyph layout | **Not re-verified this pass** | Limits remain configured; PDF bytes/`%PDF-1.4` re-verified live |
| Production readiness / comprehensive detection | **Not claimed** | Keyword/regex prototype with documented gaps |

`logsentinel.db` was not deleted or reset.

### 16.2 Detection evaluation (offline module, production rules unchanged)

Source of truth: `LogParser` + `LogAnalyzer.analyze()` against `backend/evaluation/synthetic_dataset.jsonl`.

**Overlap rule:** each `(original evidence line, attack title)` pair is scored once. A line such as `; cat /etc/passwd` can contribute two TPs (Command Injection and Directory Traversal). Brute Force is one group finding per source IP (analyzer stores evidence from the first failed-login row). Unsupported labels are excluded from TP/FP/TN/FN.

**Actual metrics this run** (`backend/_eval_results.json`):

| Metric | Value |
|--------|-------|
| True Positives | 20 |
| False Positives | 0 |
| True Negatives | 5 |
| False Negatives | 0 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1-score | 1.0000 |
| False Positive Rate | 0.0000 |
| Supported cases | 24 |
| Unsupported cases | 3 (`unsup-ifs-whoami`, `unsup-critical-level`, `unsup-sql-sleep`) all `unsupported_miss` |

These percentages are **not hardcoded**. They are computed from detector output vs labels on this synthetic set only. They do **not** mean the engine detects all real-world attacks.

True positives by attack (this dataset): Command Injection 7; XSS 2; Directory Traversal 2; plus one each of SQL Injection, Reverse Shell, Suspicious PowerShell, Web Shell, Privilege Escalation, Port Scan, Trojan, Critical System Event, Brute Force Attack.

### 16.3 Live API (running Flask, throwaway users, tokens not saved)

| Check | Result |
|-------|--------|
| `GET /api/health` | **200** `ok` |
| Register A/B | **201** + JWT |
| `GET /api/me` | 401 / 401 / 200 |
| Upload + analyze `\| whoami` and `%3B%20whoami` | **200**, Attack Summary **Command Injection** |
| Owner PDF | **200** `application/pdf` `%PDF-1.4` |
| Other user PDF / incidents | **403** “You do not have access to this analysis.” |
| Other user dashboard | **200**, `analysis_count=0`, `distinct_attack_types=0` |
| `GET /api/ai/status` (authenticated) | `ready=true`, `provider=ollama`, `model=llama3.2:1b` |
| POST `/api/ai` with a fake `model` field | **200** — the API **ignores** client model override and uses local `llama3.2:1b`. Unavailable-model **503** is covered by mocked `test_ai`, not by this live payload |

### 16.4 Browser (existing signed-in tab)

- Branding **LOG SENTINEL**, dark theme, **Switch to Light Mode**, Logout, Live Alerts **9**, compact Attack Summary / Analyzer / Code Scanner remain.
- Code Scanner still shows Vulnerable code + Suggested Fix + Copy Fixed Code (existing `app.py` findings).
- Mobile CDP: same host limit as section 11 (`innerWidth` 414 vs requested 390). `overflow-x` still `visible`.
- Full click-through of Load Sample → Analyze → Download PDF was **not** repeated this pass; live PDF bytes above are the download proof.

### 16.5 Files changed this sprint

| File | Change |
|------|--------|
| `backend/utils/runtime_secrets.py` | New. Refuses missing / placeholder / short signing secrets in production |
| `backend/app.py` | `assert_secure_secrets()` at `create_app()`; localhost / debug-off defaults |
| `backend/services/log_analyzer.py` | Command Injection: `[;&|]` whoami/id/uname, backticks, `$(…)`, `\bsystem(` |
| `backend/test_runtime_secrets.py` | New regression tests |
| `backend/test_attack_wise.py` | Pipe / subshell / backtick / encoded / filesystem TN / `system(` TP |
| `backend/evaluation/*` | Separate evaluation module + labeled JSONL |
| `backend/test_detection_eval.py` | Metrics and unsupported-exclusion tests |
| `backend/_sprint_live_api.py` | Status-code-only live helper (no token files) |
| `LOGSENTINEL_FULL_AUDIT_REPORT.md` | This section |
| `COLLEGE_EVALUATOR_NOTES.md` | Architecture and demo path |

**Not changed:** frontend design / LOGSENTINEL branding, Attack Summary layout, Live Alerts thresholds (5/300s), analyzer brute-force threshold (2), PDF/incident ownership, code-scan engines, local-only Ollama, classroom `logsentinel.db`.

### 16.6 Possible false positives still in the rules

- Word-boundary malware keywords (`trojan`, `virus`, …) can match documentation.
- Privilege rule includes `unauthorized` / `access denied` (noisy on some auth logs).
- `powershell` as a substring matches admin troubleshooting lines.
- HTML `<script>` in the code scanner flags any inline script (by design).

Do not treat this sprint as production hardening of a deployed multi-tenant SaaS. It is a stronger classroom prototype with refused production placeholders, tested ownership, and measured detector metrics on a labeled synthetic set.

---

## 17. Test-integrity pass (12 October 2026)

No detection, auth, ownership, alert, PDF, scanner, Ollama, or UI behavior was changed for a green bar.

### 17.1 Brittle AI assertion

The custom runner required the literal substring `brute-force`. Live `llama3.2:1b` answered with “brute force” (space, no hyphen) and was counted as a FAIL even though the reply described password-guessing attacks.

`check_runner.refers_to_brute_force_activity()` now normalizes case, hyphens, underscores, and extra whitespace, requires a `bruteforce` token after that normalize, and also requires an attack/credential clue (`attack`, `password`, `guess`, …). A greeting or “the brute force of the river” still fails. The model was **not** prompted to emit one exact phrase.

### 17.2 Runner exit code

`test_auth.py` printed `FAILED: 1` and then fell off the end of the script, so the process exit code was **0**. That hid the failure from any command that trusts `%ERRORLEVEL%`.

`CheckRunner.summarize()` now returns `1` when there is any FAIL or ERROR, and `test_auth.py` ends with `raise SystemExit(runner.summarize())`. PASS / FAIL / ERROR / SKIP are printed separately. SKIP alone does not fail the process.

### 17.3 Actual outcomes this pass

| Command | Result | Exit |
|---------|--------|------|
| `python -m unittest test_check_runner -v` | **8 OK** (0.419 s). Safe failing fixture printed `FAILED: 1` and exited **1**. Passing fixture exited **0**. | 0 |
| `python test_auth.py` | **71 PASS / 0 FAIL / 0 ERROR / 0 SKIP**. AI answer accepted as brute-force activity. | 0 |
| `python -m unittest test_ai -v` | **53 OK** (11.213 s). Live general question **0.682 s**. | 0 |

Suites were not combined. JWT_SECRET isolation is unchanged.

### 17.4 Files changed this pass

| File | Change |
|------|--------|
| `backend/check_runner.py` | New. Semantic brute-force matcher + PASS/FAIL/ERROR/SKIP runner with exit codes |
| `backend/test_auth.py` | Uses `CheckRunner`; semantic AI check; `SystemExit` from summarize |
| `backend/test_check_runner.py` | Matcher tests and subprocess fixture for exit 0 / 1 |
| `LOGSENTINEL_FULL_AUDIT_REPORT.md` | This section |

**Remaining failures this pass:** none of the three commands above. Unhandled exceptions in `test_auth.py` before `summarize()` still abort with Python’s own nonzero exit (not converted to PASS). Combined-unittest JWT isolation remains a known limitation. This does not make the product production-ready.

---

## 18. Configuration-consistency pass (12 October 2026)

No Attack Summary, PDF, ownership, scanner, or cloud-AI behavior was added.

### 18.1 Two brute-force detectors (intentional)

| Detector | Config | Default | Behavior kept |
|----------|--------|---------|---------------|
| Uploaded logs | `BRUTE_FORCE_THRESHOLD` via `log_brute_force_threshold()` | **2** per IP | Same as the previous hardcoded analyzer |
| Live Alerts | `ALERT_FAILED_LOGIN_THRESHOLD` + window | **5** / **300** s | Unchanged |

`Config.BRUTE_FORCE_THRESHOLD` previously defaulted to **5** and was **unused**. It now defaults to **2** and the analyzer reads the env var at call time. Raising it does not change Live Alerts. Tests: `test_log_brute_force_default_threshold_is_two_not_live_alert_five`, `test_log_brute_force_reads_env_without_changing_alert_threshold`.

### 18.2 Ollama defaults (when env is unset)

Source of truth: `backend/utils/ollama_settings.py` → `AIService._ollama_settings()`.

| Name | Previous doc / Config drift | Actual unset default now documented |
|------|-----------------------------|-------------------------------------|
| `OLLAMA_TIMEOUT_SECONDS` | Config 90 vs AIService 60 | **60** |
| `OLLAMA_NUM_CTX` | `.env.example` 2048 | **1024** (then capped 768/1024) |
| `OLLAMA_NUM_PREDICT` | `.env.example` 256 | **80** |
| `OLLAMA_KEEP_ALIVE` | `.env.example` 30m | **60m** |

A machine-local `backend/.env` may still override timeout to 90. That is an override, not the code default. No cloud fallback and no auto `ollama pull`.

### 18.3 `.env` load order (unchanged code)

`config.py` still: project-root `.env`, then `backend/.env` with `override=True`, then pop empty selected keys. `.env.example` and `OLLAMA.md` were wrong (“backend first, no override”). Docs now match the code. Precedence was **not** changed.

### 18.4 Historical vs current

- Large-codebase audit `test_attack_wise` **22 OK** is historical (before the extra command-injection test).
- Security sprint: `test_attack_wise` **23 OK**.
- This pass: `test_attack_wise` **25 OK**; `test_config_consistency` **5 OK**; `test_security_alerts` **24 OK**; `test_detection_eval` **7 OK**; `test_ai` **53 OK**.
- Synthetic F1 = 1.0 remains a JSONL result only.
- Browser 390 viewport and rate-limit soak stay **unverified**.
- A local `backend/.env` may still set `OLLAMA_TIMEOUT_SECONDS=90`; that overrides the code default of 60 and is not a remaining doc contradiction.
