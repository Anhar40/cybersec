# AGENTS.md

`PRD.md` is the authoritative spec — read it fully before writing any code. Phases 1–10 are implemented (chat loop with **streaming** responses via `OpenRouterClient.chat_stream` — SSE deltas rendered live through `AssistantDelta` events + rich `Live`, non-streamed replies still fall back to `AssistantText`; environment tools `environment`/`check_tool`/`path_info`/`package_managers`/`permissions`; TerminalTool with argv-only execution, risk tiers, confirmation, rate limit, JSONL logging; tool-calling policy polish: live TOOL EXECUTION panel, per-action retry cap, session command budget; error recovery: failure classification + structured `recovery` hints on failed tool results, DIAGNOSIS UI panel, per-turn recovery stats, malformed-JSON API retries; Tool Manager: `tool_inventory`, `install_tool`, `fix_path`; Web Security Tools: `http_request`, `port_scan`, `http_probe`, `web_tech`, `nikto_scan`, `vuln_scan`, `dir_fuzz`, `dns_lookup`, `tls_info`; Web Reconnaissance: `subdomain_enum`, `header_audit`; Vulnerability Assessment: structured `vuln_scan` findings, `sqli_probe`; Evidence & Reporting: session evidence ledger, auto-capture, Markdown report generation, `/findings`, `/report`). The PRD §40 phase plan is complete — do not start any work beyond it until the user explicitly says so.

## Hard constraints

- Never give the LLM raw shell access: no `os.system`, no `subprocess.run(..., shell=True)`. The model emits structured tool-call JSON; a safety gate validates it; execution goes through curated runners (argv arrays with `shell=False`) in `tools/terminal.py` and websec/recon/assess toolboxes.
- Config comes from env only: `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `OPENROUTER_BASE_URL`. Never hardcode keys or models.
- Follow the phase plan (PRD §4). Unless the user says otherwise, implement ONLY the current phase and stop at its definition of done. Do not start later phases early.
- Enforce authorized target scope and risk-tier confirmation (PRD §2.3–2.5); destructive or off-scope actions must be blocked or confirmed, never silently allowed.
- Agent-loop guards: never repeat an identical failing action after a failure (`MAX_RETRIES_PER_ACTION = 3` per action key per turn); session command budget 100 via `TerminalTool(max_commands=100)`; outputs capped at 20k chars; commands rate-limited.
- Error recovery in `recovery.py`: every failed tool result gets structured `recovery` hints (original keys preserved), surfaced in the DIAGNOSIS panel and summarized via `recovery_summary()` at turn end.
- Tool Manager lives in `tools/toolmgr.py`: `tool_inventory`, `install_tool`, `fix_path`. `fix_path(apply=true)` persists PATH cross-platform (HIGH risk, always confirmed): Windows user registry PATH + `WM_SETTINGCHANGE` broadcast; POSIX writes a marker-guarded, idempotent block (`# >>> cyberaent path >>>`) into the shell profile (zsh→`~/.zshrc`, bash→`~/.bashrc`, fallback `~/.profile`) with a one-time `.cyberaent.bak` backup. Both platforms also refresh the running session's `PATH`. PATH comparisons fold case on Windows only.
- Filesystem deletion lives in `tools/fsops.py`: one HIGH-risk `file_delete` spec taking structured `paths` (1..20) + `recursive`; executed in pure Python (pathlib/shutil, no shell). Guards refuse protected roots (`/`, `/etc`, `/usr`, `%SystemRoot%`, drive roots, home & cwd roots); deleting a symlink unlinks only the link; per-path statuses (`deleted`/`missing`/`refused_protected`/`directory_needs_recursive`/`os_error`) and every call is JSONL-logged.
- Web Security Tools live in `tools/websec.py`: nine curated MEDIUM-risk specs (curl, nmap, httpx, whatweb, nikto, nuclei, ffuf, dig, openssl s_client) with ArgPlan builders, validators, gate checks, and `postprocess` hooks for output normalization (e.g. nuclei JSONL → normalized findings).
- Web Reconnaissance lives in `tools/recon.py`: `subdomain_enum` (subfinder) and `header_audit` (curl -i plus pure-Python security-header analysis: HSTS/CSP/nosniff/clickjacking/Referrer-/Permissions-Policy/cookie flags/version disclosure).
- Vulnerability Assessment in `tools/assess.py`: `sqli_probe` (sqlmap controlled profile: --batch, --risk 1, --level ≤ 2, --threads ≤ 3, query string required, bounded POST data). Blocked-by-gate calls emit a ToolDiagnosis event so the UI shows the real risk tier instead of UNKNOWN.
- Evidence & Reporting lives in `tools/evidence.py`: session-scoped `EvidenceStore` (deduped, capped ledger); auto-capture through `recording_spec` wrappers (vuln_scan findings, failing/warning header_audit checks); LOW-risk tools `record_finding`, `list_findings`, `generate_report` writing deterministic Markdown reports under `reports/`; slash commands `/findings` and `/report`.

## Commands

PowerShell:

```powershell
# Setup
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"

# Verify
.venv\Scripts\python.exe -m pytest tests -q
.venv\Scripts\python.exe -m ruff check cyberaent tests
.venv\Scripts\python.exe -m mypy cyberaent tests
```

Run:

```powershell
$env:OPENROUTER_API_KEY="sk-or-..."; $env:OPENROUTER_MODEL="..."
.venv\Scripts\cyberaent.exe
```

## Conventions

- Keep code comments minimal and only where they explain non-obvious decisions; docstrings only for public APIs that need them.
- Prefer small pure functions over classes unless state genuinely warrants it.
- Type hints everywhere; strict mypy must stay green; keep ruff clean (line length 100).
- Tests use pytest with tmp_path and fake runners; no network access in unit tests. Smoke/E2E scripts live outside the repo (Temp dir) and run against local fixtures only.
- Every new tool: spec entry with explicit risk tier, ArgPlan builder, validator, gate check, runner seam injectable for tests, and unit tests covering happy path + validation failures + gate blocks.
