# LogSentinel — Viva questions and answers

Answers match the **current repository** and the 12 October 2026 audit reports. If a teacher asks for a number that was never measured, say so.

Classroom demo credentials (`demo` / `Demo1234`) are documented defaults, not personal passwords. Do not recite JWT secrets.

---

## A. Project fundamentals

**1. What is LogSentinel?**  
A local Flask web app that analyzes uploaded logs with rule-based detectors, shows a compact Attack Summary, builds a PDF, demonstrates threshold login alerts, scans source/ZIP files for insecure patterns, and chats with a local Ollama model. It is a college prototype, not a production SOC.

**2. What problem does it solve?**  
It gives a student an explainable pipeline: original log evidence, counts and IPs, ownership of reports, and offline assistance — without buying a SIEM or sending logs to a cloud AI.

**3. Is this an IDS, an IPS, or a SIEM?**  
Closest to a **small IDS-style detector plus reporting**. It does **not** prevent attacks on a live network (not IPS). It is not a full SIEM (no enterprise log shipping, correlation across an organization, or 24×7 monitoring).

**4. What data does it actually see?**  
Files the user uploads, plus events from the isolated `/demo-login` page. It does not sniff campus traffic.

**5. Which folder is the frontend?**  
`forntend/` — that spelling is the real directory name. The main page is `index11.html`.

**6. What is synthetic demonstration data?**  
The Load Sample log and `samples/multi_attack_demo.log` are labeled classroom text. They are not proof that those IPs attacked the college.

---

## B. Python and Flask architecture

**7. How is a request handled?**  
The browser sends JSON or multipart data to `/api/...`. Flask blueprints (`auth`, `analysis`, `alerts`, `reports`, `code_analysis`, `ai`, `demo_auth`, …) run the service, then SQLAlchemy reads or writes SQLite.

**8. Why SQLite?**  
Default `DATABASE_URL` is `sqlite:///.../logsentinel.db` so a laptop demo needs no separate database server. `DATABASE_URL` can be changed; `ensure_user_schema()` is written to be safe on SQLite and Postgres.

**9. What happens in `create_app()`?**  
It refuses an insecure production signing secret, loads `Config`, enables CORS and Flask-Limiter, creates tables, seeds the demo account, and registers blueprints.

**10. Why must unittest modules run in separate processes?**  
`JWT_SECRET` is read when `Config` is imported. Combining suites in one process overwrites that value and produces false auth failures. That isolation issue is **known and not silently fixed**.

**11. Where does Flask listen by default?**  
`python app.py` uses host `127.0.0.1` and `debug=False` unless `FLASK_RUN_HOST` / `FLASK_DEBUG` are set. An older `0.0.0.0` + `debug=True` default was removed because it exposed the debugger.

**12. Teacher: Why is in-memory Flask-Limiter a limitation?**  
Counts live in one process. Two gunicorn workers would not share the counter, so rate limits would be weaker. The project documents this; it was not soak-tested.

---

## C. Log parsing and detection rules

**13. What does `LogParser` extract?**  
Each line: original `message`, a coarse level (CRITICAL/ERROR/WARNING/INFO from words in the line), first IPv4, and `is_failed_login` if the text contains `failed password` or `failed login`. **There is no timestamp column.**

**14. How is brute force detected in logs?**  
The analyzer groups failed-login rows by IP and flags the IP when the count is at least **2**. Evidence is the **first** failed-login line for that IP.

**15. Why are there two different brute-force numbers (2 and 5)?**  
They are different detectors. Uploaded-log Brute Force uses `BRUTE_FORCE_THRESHOLD` (default **2** failed logins per IP). Live Alerts use `ALERT_FAILED_LOGIN_THRESHOLD` **5** inside **300** seconds on `/demo-login` only. Changing one does not change the other.

**16. How can one line produce two Attack Summary rows?**  
Intrusion rules are independent. `; cat /etc/passwd` matches Command Injection and Directory Traversal. Summary still has one row per **name**, not two copies of the same name.

**17. How are URL-encoded attacks handled?**  
`normalize_for_detection()` runs bounded `unquote_plus` (max two passes, 8000-character cap) on the match haystack. Evidence and PDF keep the raw encoded line.

**18. Give a command-injection case that works and one that does not.**  
Works (tested): `; whoami`, `| whoami`, `$(whoami)`, backticks, `%3B%20whoami`. Unsupported: `;${IFS}whoami`. The word `whoami` in documentation without a shell metacharacter should not match.

**19. Does the word CRITICAL always create a Critical System Event?**  
No. Only keyword phrases such as `kernel panic`, `segfault`, `out of memory`. A line that is only “CRITICAL system error” is a documented miss.

**20. Teacher: Why can `powershell` be a false positive?**  
The PowerShell rule is a keyword/regex match. An admin troubleshooting line that merely mentions PowerShell can fire. That is a known noisy rule, not a confirmed malware infection.

---

## D. IDS versus IPS

**21. What is an IDS?**  
An Intrusion Detection System **observes** and **alerts**. It does not by itself block the packet or disable the account.

**22. What is an IPS?**  
An Intrusion Prevention System sits in line and can **drop or block** traffic automatically.

**23. Is LogSentinel IDS or IPS?**  
Detection of uploaded logs is IDS-style. Demo-login can apply a **short local mitigation block** on the demo endpoint only (default 120 seconds). That is not campus-wide IPS and does **not** lock production `/api/login`.

**24. Teacher: Why would turning this into an IPS be dangerous?**  
A regex false positive could block a legitimate user. The project keeps prevention off the production login path for that reason.

---

## E. False positives, false negatives, precision, recall, F1

**25. Define false positive and false negative in this project.**  
FP: the engine names an attack on a line that the label says is benign (or names the wrong attack). FN: a labeled supported attack is missing from the output.

**26. Precision, recall, F1, FPR.**  
Precision = TP / (TP+FP). Recall = TP / (TP+FN). F1 is the harmonic mean of precision and recall. FPR = FP / (FP+TN).

**27. What scores did you measure?**  
On `backend/evaluation/synthetic_dataset.jsonl`: TP 20, FP 0, TN 5, FN 0, precision/recall/F1 = 1.0, FPR = 0. **Synthetic set only.**

**28. How are overlapping findings scored?**  
Each `(original evidence line, attack title)` pair is one score. Brute force is one group finding per IP. Unsupported labels are **excluded** and never counted as successful detections.

**29. Teacher: Why is F1 = 1.0 not “100% real-world accuracy”?**  
The dataset is small, labeled, and written to match implemented rules plus a few known gaps. Real logs have novel encodings, different languages, and benign admin text. An F1 on that JSONL does not transfer to the internet.

**30. Give documented false-positive risks.**  
Malware word-boundary keywords (`trojan`, `virus`); privilege phrases like `access denied`; `powershell` in admin logs; HTML `<script>` in the code scanner (any inline script).

---

## F. JWT authentication and authorization

**31. How is a password stored?**  
bcrypt hash. Responses never include `password_hash`.

**32. What is in the JWT?**  
`sub` (numeric user id), `email`, `role`, `exp`. Signed with `JWT_SECRET` (or `SECRET_KEY`) using HS256. PyJWT’s `verify_sub` is disabled because `sub` is a number; signature and expiry are still checked.

**33. What does `owns_or_admin` do?**  
The caller must be the record owner or have role `admin`. `user_id` NULL (pre-auth rows) is admin-only.

**34. What happens if another user opens your PDF or incidents?**  
**403** “You do not have access to this analysis.” Dashboard for a new user shows zero analyses. Live-verified in `_sprint_live_api.py`.

**35. Can a client register as admin by sending `role: admin`?**  
No. The server ignores that field. Admin is granted only if the email is in `ADMIN_EMAILS`.

**36. Teacher: Why refuse `change-me-in-production` only in production?**  
Local classroom laptops may start without a secret and print a warning. If `LOGSENTINEL_ENV` / `FLASK_ENV` / `RAILWAY_ENVIRONMENT` is `production`/`prod`, a missing, placeholder, or shorter-than-16-character secret **aborts startup**, so JWTs cannot be forged with a public default.

**37. Are demo-login alerts private?**  
No. They have no owner and are shared classroom events. Owned (private) alerts stay hidden from other users.

---

## G. File uploads, ZIP safety, and source-code scanning

**38. Which extensions can the log analyzer accept?**  
`.log`, `.txt`, `.json`. Empty files and `.exe` are rejected.

**39. Why is the code-scan size limit different from 10 MB?**  
Logs use `MAX_CONTENT_LENGTH` (default 10 MB). Code-scan routes use `CODE_SCAN_MAX_UPLOAD_BYTES` (default 50 MB) and per-member limits so a ZIP project can be larger than a single log.

**40. How does ZIP scanning stay safer?**  
Members are read in memory. Nested ZIPs, `..` paths, absolute paths, Unix symlinks, and high compression ratios are skipped with a warning. Vendor directories such as `node_modules` are excluded.

**41. Does a clean scan mean the program is secure?**  
No. The scanner is regex/pattern SAST, not compiler-grade taint analysis, and has no CVE feed. Suggested Fix is a preview. Compare-to-zero matches on a snippet does not prove the whole app is safe.

**42. What do `potential` and `suspected` mean?**  
`potential`: rule hit without a nearby untrusted source. `suspected`: untrusted source nearby or a hardcoded-secret rule. Nothing is labelled a confirmed exploit.

**43. Teacher: Why redact `***REDACTED***` in findings?**  
So a hardcoded password in a student upload is not stored or shown in full on screen or in a PDF.

---

## H. PDF reporting and incident correlation

**44. What must a PDF contain?**  
The same Attack Summary types as the analysis, original evidence, and “Not available” for missing IPs. Owner download is `application/pdf` starting `%PDF-1.4`.

**45. What is an incident in LogSentinel?**  
A grouping of **already detected** findings, usually same source IP inside 900 seconds. The UI/API treat this as a hypothesis, not proven compromise.

**46. Will two unrelated events at the same timestamp merge?**  
Unit tests say no — time alone is not enough.

**47. Teacher: Why might Threat rows have empty timestamps?**  
The parser never created a `timestamp` column. Some later grouping recovers ISO prefixes; many stored Threat rows stay empty. That is a documented parser limit, not hidden data.

---

## I. Local LLMs, Ollama, and offline inference

**48. What model does SentinelAI use by default?**  
Local Ollama `llama3.2:1b` at `http://127.0.0.1:11434`. After `ollama pull`, chat can work offline. No Ollama API key is required.

**49. What happens if Ollama is stopped?**  
Chat returns a configuration / 503-style setup error telling you to start Ollama and `ollama pull llama3.2:1b`. Detection, PDF, alerts, and code scan still work. There is **no** cloud fallback on the intended path.

**50. Why is “Hey” instant?**  
Greetings are canned and do not call the model.

**51. When does the model see your analysis?**  
Only when you are asking an analysis-related question and the `analysis_id` is **yours** (or you are admin). Another user cannot inject your findings into their prompt.

**52. Teacher: Why not a 7B model?**  
`OLLAMA.md` warns that 7B/8B models swap or fail on an 8 GB Windows laptop. The 1B model is a quality/RAM trade-off. Measured general answers were often under 10 seconds and still varied; analysis prompts were slower (about 19–24 s in one audit follow-up).

**53. Can the client pick a different model in the JSON body?**  
A live POST with a fake `model` field still used the server’s configured `llama3.2:1b` (200). Missing-model 503 behaviour is covered by **mocked** `test_ai`, not by that live override.

**54. Do the AI tests call a real model?**  
Most `test_ai` cases mock the client. `test_real_ollama_latency_when_available` calls local Ollama when it is up. An older sentence in `OLLAMA.md` said tests never call a model; that sentence has been corrected.

---

## J. Limitations, security risks, and future scope

**55. List three unsupported detector cases.**  
`${IFS}whoami`; SQL `WAITFOR DELAY`; CRITICAL level without a keyword.

**56. What is the malware PARTIAL result?**  
If a line already matched an intrusion title (for example Reverse Shell), the malware alias (Reverse Shell Payload) is not also counted. That avoids duplicate summary rows; it is not a missed intrusion.

**57. Name two security risks that remain in a classroom deploy.**  
(1) Local demo without production flags can still boot on a placeholder JWT — anyone who can reach that instance can forge tokens. (2) In-memory rate limits and a bound-on-localhost assumption fail if the process is exposed on a LAN with debug or a leaked secret.

**58. Why not wipe the database before a viva?**  
The classroom DB holds other students’ analyses and shared demo alerts. Isolated tests use a temp SQLite file. Wiping would destroy evidence and is forbidden by the project rules.

**59. What would you improve next (not already built)?**  
Timestamp-aware parsing; one config-driven brute-force threshold; more tested evasion rules; a durable scan-job queue if more than one worker is needed. Do not promise a cloud IDS.

**60. Teacher: Are you ready for production?**  
No. The audits explicitly refuse production-readiness, comprehensive detection, and “successful remediation” claims. The honest sentence is: “It is a stronger, tested classroom prototype with ownership checks and documented gaps.”
