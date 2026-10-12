# LogSentinel large-codebase scanner audit

Date: 2026-10-12  
Scope: extend the existing local code scanner for ZIP projects, extra languages, progress/jobs, and a results dashboard. The application was not rewritten.

This scanner is pattern-based SAST. It does **not** detect every vulnerability, does **not** prove an application is secure, and does **not** look up CVEs.

## Supported languages and tested categories

| Language / file | Engine | Categories actually tested |
| --- | --- | --- |
| Python `.py` | Existing `PythonScanner` plus added rules | Command injection, eval/exec, hardcoded secrets, SQL concat, pickle, YAML load, debug/CORS, JWT `verify=False`, path/SSRF/randomness patterns |
| JavaScript `.js` | Existing `JavaScriptScanner` plus added rules | eval, innerHTML, `new Function`, child_process, path, Math.random near tokens, MD5 |
| TypeScript `.ts` / `.tsx` / `.jsx` | Same JS scanner (reuse) | XSS `innerHTML` on `.ts` and `.tsx` |
| PHP `.php` | Existing `PHPScanner` plus added rules | mysql_query, echo `$_GET`, include/fopen from superglobals, `move_uploaded_file` |
| HTML / CSS | Existing `HTMLScanner` | Inline script / HTTP script (existing tests) |
| `.txt` as source | Original four language scanners only | `os.system` line preserved |
| Java `.java` | New `JavaScanner` | `Runtime.exec`, SQL concat |
| C# `.cs` | New `CSharpScanner` | `Process.Start` concat |
| SQL `.sql` | New `SQLScanner` | `EXEC(@var)` |
| Config `.json` / `.yml` / `.env` / `.ini` | New `ConfigScanner` | `debug: true`, embedded password |
| `requirements.txt` / `package.json` | Local version hints only | `flask==0.12.0` → Dependency Hint |

Not claimed as supported (no tested engine): Go, Rust, Kotlin, Ruby, Swift, Docker/K8s hardening, full data-flow / taint, or any CVE feed.

CWE/OWASP strings on findings come from the rule definitions. They are mappings for the pattern, not independently re-verified exploits.

## Configured limits

Log uploads still use `MAX_CONTENT_LENGTH` / `MAX_UPLOAD_MB` (default **10 MB**). Code-scan routes set `request.max_content_length` to `CODE_SCAN_MAX_UPLOAD_BYTES` only.

| Setting | Default | Purpose |
| --- | --- | --- |
| `CODE_SCAN_MAX_UPLOAD_BYTES` | 50 MB | Compressed upload for `/api/code-scan*` |
| `CODE_SCAN_MAX_FILE_BYTES` | 1 MB | Per source member |
| `CODE_SCAN_MAX_ZIP_FILES` | 1500 | Members actually scanned |
| `CODE_SCAN_MAX_ZIP_EXTRACT_BYTES` | 80 MB | Sum of expanded member bytes |
| `CODE_SCAN_MAX_DURATION_SECONDS` | 90 | Stops the walk; remaining files listed |
| `CODE_SCAN_MAX_CONCURRENT` | 1 | In-process scans on ~8 GB RAM |
| `CODE_SCAN_MAX_COMPRESSION_RATIO` | 100 | ZIP-bomb guard (claimed/compressed, size > 64 KB) |
| `CODE_SCAN_JOB_TTL_SECONDS` | 1800 | Job record retention |

Adjust via environment variables. `GET /api/code-scan/limits` returns the live values. Split large trees, exclude `node_modules`/`venv`, or raise a specific `CODE_SCAN_MAX_*` if a limit is hit.

Archive members are opened in memory. Nested ZIPs, `..` paths, absolute paths, and Unix symlinks are skipped with a reason. Vendor/build directories are excluded and counted.

## What was tested

Synthetic project built in `backend/test_large_codebase_scan.py` (`sample_project()`): **15 archive members**, **2039** compressed bytes.

| Metric | Value |
| --- | --- |
| Eligible (scannable, not excluded) | 13 |
| Scanned | 13 |
| Lines scanned | 21 |
| Excluded | 1 (`node_modules/leftpad/index.js`) |
| Unsupported | 1 (`readme.md`) |
| Findings | 15 |
| Elapsed | 51 ms (this machine, in-process) |
| `scan_complete` | true |

Finding types on that ZIP: Command Injection 5, XSS 3, SQL Injection 2, plus one each of Code Injection, Hardcoded Credentials, Insecure Deserialization, Dependency Hint, Security Misconfiguration.

Expected planted issues that were found: Python `os.system(input())` and password (redacted), JS/TS `eval`/`innerHTML`, PHP echo/SQL, Java `Runtime.exec` + SQL concat, C# `Process.Start` concat, SQL `EXEC(@dynsql)`, JSON debug + password, `flask==0.12.0` hint, nested `pickle.loads`, `.txt` `os.system`. Clean `src/clean.py` and `web/ok.js` produced no findings.

80-file ZIP (unique `print(n)` plus two distinct command-injection files): **80 scanned**, **2** command-injection findings, **0** duplicates. Duplicate-content ZIP (`a.py` + `copy/a.py` identical): **1** scanned, **1** duplicate skip, **1** finding.

Other checks that passed: ZIP-bomb ratio skip, symlink skip, path-traversal skip (existing), file-count / extract-size / per-file limits (existing), duration limit → `scan_complete=false` + `duration_limit`, job cancel, job owner 403, compare snippet (innerHTML → textContent: 1 → 0 matches), auth on compare.

## Findings vs “confirmed”

Every match is still a **pattern match**. Classification:

- `potential` — rule hit, no nearby untrusted source detected
- `suspected` — untrusted source nearby, or a hardcoded-secret rule

Nothing is labelled a confirmed exploit. Existing rules still flag constant `os.system("ls")` / `eval("1")`; that is unchanged and is a known over-match.

Hardcoded secret values are replaced with `***REDACTED***` in snippets and context.

## False positives, unsupported, skipped

- `node_modules` / `venv` / `.git` / `dist` / `build` / `vendor` are excluded on purpose.
- `.md` and other unknown types are counted as unsupported (first 15 listed).
- Nested ZIPs are not scanned.
- `os.system("ls")` and similar constants still match the original command-injection rule.
- HTML `<script src="http://...">` can still also match the inline-script rule (pre-existing).
- Dependency hints are a two-package local list (`flask`/`django` old pins, `jquery` 1.x/2.x). **Not a CVE database.** Freshness: static, as of this change.
- No memory profiler was attached. ZIP members are decoded one at a time and discarded. Peak RSS was not measured. The 13-file sample took 51 ms; the large-scan unittest module (13 tests) finished in 2.4 s.

## Changed files

- `backend/config.py` — separate `CODE_SCAN_*` limits
- `backend/app.py` — per-route upload budget for `/api/code-scan*`
- `backend/services/security_models.py` — classification, confidence, impact, redacted
- `backend/services/sast_engine.py` — classify, redact, skip paths, ZIP symlink check
- `backend/services/code_scanner.py` — incremental ZIP walk, stats, timeout, grouping
- `backend/services/code_scan_jobs.py` — in-process jobs
- `backend/services/code_fix_advisor.py` — Java/C#/SQL fixes; finalize/redact
- `backend/services/python_scanner.py`, `js_scanner.py`, `php_scanner.py` — added rules
- `backend/services/java_scanner.py`, `csharp_scanner.py`, `sql_scanner.py`, `config_scanner.py` — new
- `backend/routes/code_analysis.py` — jobs, limits, compare, persist cap
- `forntend/index11.html` — progress, dashboard, filters, group-by-file, re-scan
- `backend/test_code_scan.py`, `backend/test_large_codebase_scan.py`

## Regression-test results

Run as **separate processes** (combined modules overwrite `JWT_SECRET`).

| Suite | Result |
| --- | --- |
| `python -m unittest test_code_scan -v` | **31 tests, OK** (3.7 s) |
| `python -m unittest test_large_codebase_scan -v` | **13 tests, OK** (2.4 s) |
| `python -m unittest test_attack_wise -v` | **22 tests, OK** (5.0 s) — historical this audit day; later suites added more analyzer tests |

Suggested-fix checks: JavaScript `innerHTML` → `textContent` compare endpoint returned 1 then 0 snippet matches. That does **not** prove the surrounding program is safe. Python `password = os.environ['PASSWORD']` still parses; `os.system(input())` fix remains a labelled minimal example and was not executed.

## Remaining limitations

- Regex / local AST-less matching, not compiler-grade taint analysis.
- No inter-file data flow, no framework-aware sanitizer recognition.
- Background jobs live in one Flask process (lost on restart; not multi-worker safe).
- Threat rows persisted from a scan are capped at 400; full findings stay in `result_json`.
- Thousands of files will work up to the configured limits; this audit did not scan a real multi-thousand-file product tree.
- No paid/cloud API was added. Ordinary scans stay local.

Do not treat a clean scan, or a suggested fix that “clears” a snippet, as evidence that the project is secure.
