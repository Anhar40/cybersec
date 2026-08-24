"""Web Reconnaissance tools (PRD Phase 8).

Two curated additions on top of the Phase 7 web-security wrappers:

- ``subdomain_enum``  — passive subdomain discovery via subfinder.
- ``header_audit``    — fetch response headers with curl and analyse the
  security-header posture locally (pure Python, deterministic checks).

Execution reuses :class:`~cyberaent.tools.websec.WebToolRunner` so missing
binaries, shim launchers, timeouts, output capping and JSONL logging behave
exactly like every other web tool. The model passes plain parameters only;
argv is assembled here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .base import RiskLevel, ToolSpec
from .terminal import CommandHistory
from .websec import (
    ArgPlan,
    WebToolRunner,
    WebToolSpec,
    gate_check_for,
    validate_domain,
    validate_url,
)

MAX_SUBDOMAINS = 200

_STATUS_LINE_RE = re.compile(r"^HTTP/\S*\s+\d{3}", re.IGNORECASE)


# ------------------------------------------------------------- header parsing
def parse_http_headers(raw: str) -> dict[str, Any] | None:
    """Parse the LAST HTTP response out of a curl ``-i``/``-L`` transcript.

    Returns ``{"status": <status line>, "headers": {...}}`` where each value is
    a string or a list of strings (for repeatable headers like set-cookie).
    Returns None when no status line can be found.
    """
    if not raw:
        return None
    lines = raw.replace("\r\n", "\n").split("\n")
    starts = [i for i, line in enumerate(lines) if _STATUS_LINE_RE.match(line.strip())]
    if not starts:
        return None
    start = starts[-1]
    block: list[str] = []
    for line in lines[start:]:
        if not line.strip() and block:
            break
        if line.strip():
            block.append(line)

    status = block[0].strip()
    headers: dict[str, Any] = {}
    for line in block[1:]:
        folded = line[:1] in (" ", "\t")
        if folded and headers:
            last_key = next(reversed(headers))
            current = headers[last_key]
            extra = " " + line.strip()
            if isinstance(current, list):
                current[-1] += extra
            else:
                headers[last_key] = current + extra
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        existing = headers.get(key)
        if existing is None:
            headers[key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            headers[key] = [existing, value]
    return {"status": status, "headers": headers}


def get_all(headers: Mapping[str, Any], key: str) -> list[str]:
    """Return every value for a (lowercase) header key as a flat string list."""
    value = headers.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def has_header(headers: Mapping[str, Any], key: str) -> bool:
    return bool(get_all(headers, key))


# ------------------------------------------------------------ header analysis
def analyze_headers(headers: Mapping[str, Any], *, is_https: bool) -> list[dict[str, str]]:
    """Deterministic security-header audit. Each finding explains itself."""
    findings: list[dict[str, str]] = []

    def add(check: str, status: str, detail: str) -> None:
        findings.append({"check": check, "status": status, "detail": detail})

    hsts = get_all(headers, "strict-transport-security")
    if hsts:
        add(
            "strict-transport-security",
            "pass",
            f"HSTS present ({hsts[0][:80]}).",
        )
    else:
        add(
            "strict-transport-security",
            "fail" if is_https else "warn",
            "HSTS missing; browsers can be downgraded to plain HTTP."
            if is_https
            else "HSTS missing (expected on plain HTTP, enable once HTTPS exists).",
        )

    csp = get_all(headers, "content-security-policy")
    if csp:
        add("content-security-policy", "pass", "CSP present.")
    else:
        add(
            "content-security-policy",
            "fail",
            "Content-Security-Policy missing; strong mitigation against XSS.",
        )

    xcto = get_all(headers, "x-content-type-options")
    if any(v.strip().lower() == "nosniff" for v in xcto):
        add("x-content-type-options", "pass", "nosniff set.")
    else:
        add(
            "x-content-type-options",
            "warn",
            "X-Content-Type-Options is absent or not 'nosniff'; browsers may "
            "MIME-sniff responses.",
        )

    frame_ancestors = any("frame-ancestors" in v.lower() for v in csp)
    xfo = get_all(headers, "x-frame-options")
    if xfo or frame_ancestors:
        add("clickjacking", "pass", "Framing policy declared via X-Frame-Options/CSP.")
    else:
        add(
            "clickjacking",
            "warn",
            "Neither X-Frame-Options nor CSP frame-ancestors; page is framable "
            "(clickjacking exposure).",
        )

    referrer = get_all(headers, "referrer-policy")
    if referrer:
        add("referrer-policy", "pass", f"Referrer-Policy present ({referrer[0][:60]}).")
    else:
        add(
            "referrer-policy",
            "warn",
            "Referrer-Policy missing; full URLs may leak to third parties.",
        )

    permissions = get_all(headers, "permissions-policy")
    if permissions:
        add("permissions-policy", "pass", "Permissions-Policy present.")
    else:
        add(
            "permissions-policy",
            "info",
            "Permissions-Policy absent; consider restricting powerful browser APIs.",
        )

    cookies = get_all(headers, "set-cookie")
    cookie_problems: list[str] = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()[:40] or "<cookie>"
        lower = cookie.lower()
        missing = [
            flag
            for flag, token in (
                ("HttpOnly", "httponly"),
                ("Secure", "secure"),
                ("SameSite", "samesite"),
            )
            if token not in lower
        ]
        if missing:
            cookie_problems.append(f"{name} lacks {', '.join(missing)}")
    if cookie_problems:
        add(
            "cookie-flags",
            "warn" if is_https else "info",
            "; ".join(cookie_problems[:5]) + ("…" if len(cookie_problems) > 5 else ""),
        )
    elif cookies:
        add("cookie-flags", "pass", "All cookies carry HttpOnly/Secure/SameSite.")

    server = get_all(headers, "server")
    if any(re.search(r"\d+\.\d+", v) for v in server):
        add(
            "server-disclosure",
            "info",
            f"Server header discloses a version ({server[0][:60]}).",
        )
    powered = get_all(headers, "x-powered-by")
    if powered:
        add(
            "server-disclosure",
            "info",
            f"X-Powered-By discloses stack details ({powered[0][:60]}).",
        )
    return findings


def score_findings(findings: list[dict[str, str]]) -> str:
    fails = sum(1 for f in findings if f["status"] == "fail")
    warns = sum(1 for f in findings if f["status"] == "warn")
    passes = sum(1 for f in findings if f["status"] == "pass")
    total = len(findings)
    return f"{fails} fail · {warns} warn · {passes}/{total} checks passed"


# ------------------------------------------------------------------- builders
def _build_subdomain_enum(args: Mapping[str, Any]) -> ArgPlan:
    domain = validate_domain(args.get("domain"))
    return ArgPlan(argv=["subfinder", "-d", domain, "-silent"])


def _build_header_audit(args: Mapping[str, Any]) -> ArgPlan:
    url = validate_url(args.get("url"))
    argv = ["curl", "-sS", "-i", "-A", "cyberaent-recon/1.0"]
    timeout_sec = args.get("timeout_sec")
    if timeout_sec is not None:
        try:
            limit = max(1, min(120, int(timeout_sec)))
        except (TypeError, ValueError):
            limit = 30
        argv += ["--max-time", str(limit)]
    if bool(args.get("follow_redirects", True)):
        argv.append("-L")
    argv.append(url)
    return ArgPlan(argv=argv)


RECON_TOOLS: tuple[WebToolSpec, ...] = (
    WebToolSpec(
        tool_name="subdomain_enum",
        binary="subfinder",
        description=(
            "Passive subdomain enumeration for one domain using subfinder "
            "(certificate-transparency and passive-DNS sources; no active "
            "brute forcing). Returns up to 200 unique subdomains."
        ),
        schema={
            "type": "object",
            "required": ["domain"],
            "properties": {"domain": {"type": "string"}, "timeout_sec": {"type": "integer"}},
        },
        builder=_build_subdomain_enum,
        default_timeout_s=300,
    ),
    WebToolSpec(
        tool_name="header_audit",
        binary="curl",
        description=(
            "Fetch a URL's response headers with curl and run a local security-"
            "header analysis: HSTS, CSP, nosniff, clickjacking, Referrer-Policy, "
            "Permissions-Policy, cookie flags and version disclosure. Each check "
            "returns pass/warn/fail with a concrete explanation."
        ),
        schema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string"},
                "follow_redirects": {"type": "boolean"},
                "timeout_sec": {"type": "integer"},
            },
        },
        builder=_build_header_audit,
        default_timeout_s=45,
    ),
)


def parse_subdomains(stdout: str | None) -> dict[str, Any]:
    lines = (stdout or "").splitlines()
    seen: set[str] = set()
    ordered: list[str] = []
    for line in lines:
        host = line.strip().lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            ordered.append(host)
    truncated = len(ordered) > MAX_SUBDOMAINS
    kept = sorted(ordered)[:MAX_SUBDOMAINS]
    return {
        "found_count": len(ordered),
        "subdomains": kept,
        "truncated": truncated,
        "summary": (
            f"{len(ordered)} unique subdomains"
            + (" (showing first 200)" if truncated else "")
        ),
    }


class ReconToolbox:
    """Runs recon specs through the shared WebToolRunner and post-processes."""

    def __init__(
        self,
        *,
        history: CommandHistory | None = None,
        log_path: Path | None = None,
        runner: Callable[..., Any] | None = None,
    ):
        self._inner = WebToolRunner(history=history, log_path=log_path, runner=runner)

    def execute(self, spec: WebToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
        result = self._inner.execute(spec, arguments)
        if result.get("error") is not None or "stdout" not in result:
            return result
        if spec.tool_name == "subdomain_enum":
            result.update(parse_subdomains(result.get("stdout")))
        elif spec.tool_name == "header_audit":
            parsed = parse_http_headers(str(result.get("stdout") or ""))
            if parsed is None:
                result["error"] = "no_http_response"
                result["reason"] = (
                    "No HTTP response could be parsed from the curl output; the "
                    "host may be unreachable or speaking a non-HTTP protocol."
                )
                return result
            headers = parsed["headers"]
            is_https = str(arguments.get("url", "")).lower().startswith("https://")
            findings = analyze_headers(headers, is_https=is_https)
            result["http_status"] = parsed["status"]
            result["headers"] = {
                k: (v if isinstance(v, str) else list(v))
                for k, v in headers.items()
            }
            result["checks"] = findings
            result["summary"] = f"{parsed['status']} · {score_findings(findings)}"
        return result


def build_web_recon_tools(
    *,
    history: CommandHistory | None = None,
    log_path: Path | None = None,
) -> list[ToolSpec]:
    toolbox = ReconToolbox(history=history, log_path=log_path)

    def make_handler(spec: WebToolSpec) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        def handler(arguments: Mapping[str, Any]) -> dict[str, Any]:
            return toolbox.execute(spec, arguments)

        return handler

    specs: list[ToolSpec] = []
    for recon_spec in RECON_TOOLS:
        specs.append(
            ToolSpec(
                name=recon_spec.tool_name,
                description=recon_spec.description,
                parameters=recon_spec.schema,
                risk=RiskLevel.MEDIUM,
                handler=make_handler(recon_spec),
                check_args=gate_check_for(recon_spec),
            )
        )
    return specs
