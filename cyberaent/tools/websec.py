"""Web Security Tools (PRD Phase 7): curated wrappers around known scanners.

The model never supplies raw CLI flags here — every tool exposes a small JSON
schema and this module assembles the argument vector itself. That keeps
execution argv-only with ``shell=False`` while preventing flag injection.
All nine tools are MEDIUM risk: active network interaction requires explicit
user confirmation through the safety gate.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import probes
from .base import RiskLevel, ToolSpec
from .terminal import (
    OUTPUT_CAP_CHARS,
    CommandHistory,
    append_log_line,
)

MAX_URL_LENGTH = 2000
MAX_HOST_LENGTH = 255
MAX_PORTS_LENGTH = 100
MAX_WORDLIST_PATH = 500
MAX_DISPLAY_CHARS = 200
MAX_URLS_PER_PROBE = 50
MAX_TIMEOUT_S = 900

_PORTS_RE = re.compile(r"^\d{1,5}([-,]\d{1,5})*$")
_MATCH_CODES_RE = re.compile(r"^\d{3}(,\d{3})*$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]+$")
_DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")
HTTP_METHODS = ("GET", "HEAD", "OPTIONS")
SEVERITIES = ("info", "low", "medium", "high", "critical")

DEFAULT_MATCH_CODES = "200,204,301,302,307,401,403"


def _cap(text: str | None) -> str:
    value = text or ""
    if len(value) <= OUTPUT_CAP_CHARS:
        return value
    dropped = len(value) - OUTPUT_CAP_CHARS
    return value[:OUTPUT_CAP_CHARS] + f"\n...[truncated {dropped} characters]"


def _clamp_timeout(value: Any, default: int, lo: int, hi: int = MAX_TIMEOUT_S) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, parsed))


def validate_url(value: Any, field: str = "url") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{field}' must be a non-empty string.")
    raw = value.strip()
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError(f"'{field}' exceeds {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        raise ValueError(f"'{field}' must not contain whitespace or control characters.")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"'{field}' must use http:// or https:// (got '{parsed.scheme}').")
    if not parsed.hostname:
        raise ValueError(f"'{field}' needs a host name, e.g. https://example.com")
    if parsed.username or parsed.password:
        raise ValueError(
            f"'{field}' must not embed credentials (user:pass@host); pass them via "
            "the terminal tool only if the user explicitly provides them."
        )
    return raw


def validate_host(value: Any, field: str = "target") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{field}' must be a non-empty host name or IP address.")
    host = value.strip()
    if len(host) > MAX_HOST_LENGTH:
        raise ValueError(f"'{field}' exceeds {MAX_HOST_LENGTH} characters.")
    if any(ch.isspace() for ch in host) or "/" in host or "@" in host or "?" in host:
        raise ValueError(f"'{field}' looks invalid: no spaces, '/', '@' or '?' allowed.")
    if not _HOST_RE.match(host):
        raise ValueError(f"'{field}' contains unsupported characters for a host/IP.")
    return host


def validate_domain(value: Any) -> str:
    domain = validate_host(value, "domain").rstrip(".")
    if not _DOMAIN_RE.match(domain):
        raise ValueError("'domain' must be a valid DNS name like example.com.")
    return domain


def validate_ports(value: Any) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        raise ValueError("'ports' must be a string like '80' or '1-1024,8080'.")
    ports = value.strip()
    if len(ports) > MAX_PORTS_LENGTH or not _PORTS_RE.match(ports):
        raise ValueError("'ports' must look like '80', '80,443' or '1-1024'.")
    for token in re.split(r"[,-]", ports):
        if not 1 <= int(token) <= 65535:
            raise ValueError(f"port numbers must be within 1..65535 (got {token}).")
    return ports


@dataclass(frozen=True)
class ArgPlan:
    """Fully assembled execution plan produced by a builder."""

    argv: list[str]
    stdin_data: str | None = None


Builder = Callable[[Mapping[str, Any]], ArgPlan]


# ------------------------------------------------------------------ builders
def _build_http_request(args: Mapping[str, Any]) -> ArgPlan:
    url = validate_url(args.get("url"))
    method = str(args.get("method") or "GET").upper()
    if method not in HTTP_METHODS:
        raise ValueError(f"'method' must be one of {list(HTTP_METHODS)} (read-only verbs).")
    max_time = _clamp_timeout(args.get("timeout_sec"), default=30, lo=1, hi=120)
    include_headers = args.get("include_headers", True)
    argv = ["curl", "-sS", "--max-time", str(max_time)]
    if method == "HEAD":
        argv.append("-I")
    else:
        if method == "OPTIONS":
            argv += ["-X", "OPTIONS"]
        if include_headers:
            argv.append("-i")
    argv.append(url)
    return ArgPlan(argv=argv)


def _build_port_scan(args: Mapping[str, Any]) -> ArgPlan:
    target = validate_host(args.get("target"))
    ports = validate_ports(args.get("ports"))
    argv = ["nmap"]
    if bool(args.get("service_detection")):
        argv.append("-sV")
    if bool(args.get("skip_ping")):
        argv.append("-Pn")
    if ports:
        argv += ["-p", ports]
    else:
        argv += ["--top-ports", "100"]
    argv.append(target)
    return ArgPlan(argv=argv)


def _build_http_probe(args: Mapping[str, Any]) -> ArgPlan:
    urls_raw = args.get("urls")
    if not isinstance(urls_raw, list) or not urls_raw:
        raise ValueError("'urls' must be a non-empty array of http(s) URLs.")
    if len(urls_raw) > MAX_URLS_PER_PROBE:
        raise ValueError(f"'urls' accepts at most {MAX_URLS_PER_PROBE} entries.")
    urls = [validate_url(u, f"urls[{i}]") for i, u in enumerate(urls_raw)]
    argv = ["httpx", "-silent", "-status-code", "-title"]
    if bool(args.get("tech_detect", True)):
        argv.append("-tech-detect")
    if bool(args.get("follow_redirects")):
        argv.append("-follow-redirects")
    return ArgPlan(argv=argv, stdin_data="\n".join(urls))


def _build_web_tech(args: Mapping[str, Any]) -> ArgPlan:
    url = validate_url(args.get("url"))
    return ArgPlan(argv=["whatweb", "--color=never", "--no-errors", url])


def _build_nikto_scan(args: Mapping[str, Any]) -> ArgPlan:
    target = validate_host(args.get("target"))
    argv = ["nikto", "-h", target]
    port = args.get("port")
    if port is not None:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("'port' must be an integer within 1..65535.")
        argv += ["-p", str(port)]
    if bool(args.get("ssl")):
        argv.append("-ssl")
    return ArgPlan(argv=argv)


def _build_vuln_scan(args: Mapping[str, Any]) -> ArgPlan:
    target = validate_url(args.get("target"))
    severity = args.get("severity")
    if severity:
        chosen = [s.strip().lower() for s in str(severity).split(",") if s.strip()]
        bad = [s for s in chosen if s not in SEVERITIES]
        if bad or not chosen:
            raise ValueError(f"'severity' accepts only {list(SEVERITIES)} (got {bad}).")
        severity_value = ",".join(chosen)
    else:
        severity_value = ""
    rate_limit = args.get("rate_limit")
    if rate_limit is not None:
        if not isinstance(rate_limit, int) or isinstance(rate_limit, bool):
            raise ValueError("'rate_limit' must be an integer requests-per-second cap.")
        if not 1 <= rate_limit <= 500:
            raise ValueError("'rate_limit' must be within 1..500.")
    argv = ["nuclei", "-silent", "-j", "-u", target]
    if severity_value:
        argv += ["-severity", severity_value]
    if rate_limit is not None:
        argv += ["-rl", str(rate_limit)]
    return ArgPlan(argv=argv)


def _build_dir_fuzz(args: Mapping[str, Any]) -> ArgPlan:
    url = validate_url(args.get("url"))
    if "FUZZ" not in url:
        raise ValueError("'url' must contain the FUZZ keyword, e.g. https://host/FUZZ")
    wordlist_raw = args.get("wordlist")
    if not isinstance(wordlist_raw, str) or not wordlist_raw.strip():
        raise ValueError("'wordlist' must be a path to a wordlist file.")
    wordlist = wordlist_raw.strip()
    if len(wordlist) > MAX_WORDLIST_PATH:
        raise ValueError(f"'wordlist' path exceeds {MAX_WORDLIST_PATH} characters.")
    if not Path(wordlist).is_file():
        raise ValueError(f"wordlist file not found: {wordlist}")
    match_codes = str(args.get("match_codes") or DEFAULT_MATCH_CODES).strip()
    if not _MATCH_CODES_RE.match(match_codes):
        raise ValueError("'match_codes' must look like '200,301,403'.")
    return ArgPlan(argv=["ffuf", "-u", url, "-w", wordlist, "-mc", match_codes])


def _build_dns_lookup(args: Mapping[str, Any]) -> ArgPlan:
    domain = validate_domain(args.get("domain"))
    record_type = str(args.get("record_type") or "A").upper()
    if record_type not in DNS_RECORD_TYPES:
        raise ValueError(f"'record_type' must be one of {list(DNS_RECORD_TYPES)}.")
    return ArgPlan(argv=["dig", domain, record_type, "+noall", "+answer"])


def _build_tls_info(args: Mapping[str, Any]) -> ArgPlan:
    host = validate_host(args.get("host"))
    port = args.get("port", 443)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("'port' must be an integer within 1..65535.")
    argv = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-brief",
    ]
    return ArgPlan(argv=argv, stdin_data="")


# --------------------------------------------------------------------- specs
@dataclass(frozen=True)
class WebToolSpec:
    tool_name: str
    binary: str
    description: str
    schema: dict[str, Any]
    builder: Builder
    default_timeout_s: int
    postprocess: Callable[[dict[str, Any]], dict[str, Any]] | None = None


# ------------------------------------------------------- nuclei JSONL parsing
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_FINDINGS = 300


def parse_nuclei_lines(stdout: str | None) -> dict[str, Any]:
    """Normalize ``nuclei -j`` (JSON lines) output into structured findings.

    Tolerant by design: unparseable lines are skipped so a noisy run still
    yields whatever findings were emitted cleanly.
    """
    import json as _json

    raw_findings: list[dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = _json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        info = record.get("info") or {}
        severity = str(info.get("severity") or "unknown").strip().lower()
        raw_findings.append(
            {
                "template_id": str(
                    record.get("template-id")
                    or record.get("templateID")
                    or record.get("id")
                    or ""
                ),
                "name": str(info.get("name") or ""),
                "severity": severity,
                "tags": [str(t) for t in (info.get("tags") or [])][:10],
                "host": str(record.get("host") or ""),
                "matched_at": str(record.get("matched-at") or record.get("matched") or ""),
                "extracted": [
                    str(e)
                    for e in (
                        record.get("extracted-results") or record.get("extracted") or []
                    )
                ][:5],
            }
        )
    raw_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))
    truncated = len(raw_findings) > _MAX_FINDINGS
    findings = raw_findings[:_MAX_FINDINGS]
    counts: dict[str, int] = {}
    for finding in raw_findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    parts = [f"{counts[s]} {s}" for s in order if counts.get(s)]
    other = sum(n for s, n in counts.items() if s not in order)
    if other:
        parts.append(f"{other} unknown")
    summary = " · ".join(parts) + f" ({len(raw_findings)} findings)" if parts else (
        "no findings detected"
    )
    return {
        "findings": findings,
        "severity_counts": counts,
        "truncated": truncated,
        "summary": summary,
    }


def _enrich_vuln_scan(result: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_nuclei_lines(result.get("stdout"))
    exec_summary = result.get("summary", "")
    result.update(parsed)
    result["findings_summary"] = parsed["summary"]
    result["summary"] = f"{parsed['summary']} · {exec_summary}"
    return result


WEB_TOOLS: tuple[WebToolSpec, ...] = (
    WebToolSpec(
        tool_name="http_request",
        binary="curl",
        description=(
            "Fetch a URL with curl (read-only verbs GET/HEAD/OPTIONS only). Returns "
            "status line, response headers (default) and body, capped at 20k chars. "
            "Use it to inspect headers, redirects, robots.txt or API responses."
        ),
        schema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": list(HTTP_METHODS)},
                "include_headers": {"type": "boolean"},
                "timeout_sec": {"type": "integer"},
            },
        },
        builder=_build_http_request,
        default_timeout_s=45,
    ),
    WebToolSpec(
        tool_name="port_scan",
        binary="nmap",
        description=(
            "TCP port scan with nmap against ONE authorized host. Defaults to the "
            "top 100 ports; pass `ports` ('80', '80,443', '1-1024') to override, "
            "`service_detection` for -sV banners, `skip_ping` for -Pn. Raw nmap "
            "flags are not accepted; use the terminal tool only if the user asks "
            "for something these options cannot express."
        ),
        schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string"},
                "service_detection": {"type": "boolean"},
                "skip_ping": {"type": "boolean"},
                "timeout_sec": {"type": "integer"},
            },
        },
        builder=_build_port_scan,
        default_timeout_s=600,
    ),
    WebToolSpec(
        tool_name="http_probe",
        binary="httpx",
        description=(
            "Probe up to 50 http(s) URLs with projectdiscovery httpx and report "
            "status code, title, and detected technologies for each live host. "
            "Great first step to map which hosts actually serve web content."
        ),
        schema={
            "type": "object",
            "required": ["urls"],
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "tech_detect": {"type": "boolean"},
                "follow_redirects": {"type": "boolean"},
            },
        },
        builder=_build_http_probe,
        default_timeout_s=120,
    ),
    WebToolSpec(
        tool_name="web_tech",
        binary="whatweb",
        description=(
            "Identify web technologies (server, CMS, frameworks, JS libraries) for "
            "one URL using whatweb. Use after confirming the host serves HTTP."
        ),
        schema={
            "type": "object",
            "required": ["url"],
            "properties": {"url": {"type": "string"}},
        },
        builder=_build_web_tech,
        default_timeout_s=90,
    ),
    WebToolSpec(
        tool_name="nikto_scan",
        binary="nikto",
        description=(
            "Run a nikto web-server vulnerability scan against ONE authorized "
            "host (optionally `port`, `ssl`). Slow by design — expect minutes. "
            "Only run it when the user asked for deep scanning of that host."
        ),
        schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "port": {"type": "integer"},
                "ssl": {"type": "boolean"},
                "timeout_sec": {"type": "integer"},
            },
        },
        builder=_build_nikto_scan,
        default_timeout_s=900,
    ),
    WebToolSpec(
        tool_name="vuln_scan",
        binary="nuclei",
        description=(
            "Template-based vulnerability scan with nuclei against ONE authorized "
            "URL. Optionally filter `severity` (comma list of "
            "info/low/medium/high/critical) and cap `rate_limit` (req/s, 1..500). "
            "Results come back as structured findings sorted by severity with a "
            "count summary."
        ),
        schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "severity": {"type": "string"},
                "rate_limit": {"type": "integer"},
                "timeout_sec": {"type": "integer"},
            },
        },
        builder=_build_vuln_scan,
        default_timeout_s=900,
        postprocess=_enrich_vuln_scan,
    ),
    WebToolSpec(
        tool_name="dir_fuzz",
        binary="ffuf",
        description=(
            "Directory/file brute force with ffuf. The `url` MUST contain the FUZZ "
            "keyword (e.g. https://host/FUZZ) and `wordlist` must be an existing "
            "local file. Filter hits with `match_codes` ('200,301,403')."
        ),
        schema={
            "type": "object",
            "required": ["url", "wordlist"],
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "string"},
                "match_codes": {"type": "string"},
                "timeout_sec": {"type": "integer"},
            },
        },
        builder=_build_dir_fuzz,
        default_timeout_s=600,
    ),
    WebToolSpec(
        tool_name="dns_lookup",
        binary="dig",
        description=(
            "DNS lookup for one domain via dig. Supports record types "
            "A, AAAA, CNAME, MX, TXT, NS, SOA (default A). Returns the answer "
            "records only."
        ),
        schema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string"},
                "record_type": {"type": "string", "enum": list(DNS_RECORD_TYPES)},
            },
        },
        builder=_build_dns_lookup,
        default_timeout_s=30,
    ),
    WebToolSpec(
        tool_name="tls_info",
        binary="openssl",
        description=(
            "Inspect the TLS certificate/key exchange of host:port with openssl "
            "s_client -brief: protocol version, cipher, certificate subject, "
            "issuer and expiry. Use for HTTPS hardening reviews."
        ),
        schema={
            "type": "object",
            "required": ["host"],
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
            },
        },
        builder=_build_tls_info,
        default_timeout_s=30,
    ),
)


class WebToolRunner:
    """Executes one curated web-security tool with capped, logged output."""

    def __init__(
        self,
        *,
        history: CommandHistory | None = None,
        log_path: Path | None = None,
        runner: Callable[..., Any] | None = None,
    ):
        self.history = history if history is not None else CommandHistory()
        self.log_path = log_path
        self._runner = runner

    # ----------------------------------------------------------------- public
    def execute(self, spec: WebToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
        resolved = probes.resolve_executable(spec.binary)
        if resolved is None:
            return {
                "error": "not_installed",
                "reason": (
                    f"The '{spec.binary}' binary is not available on PATH. Run "
                    f"tool_inventory to confirm, then install_tool {{\"name\": "
                    f"\"{spec.binary}\"}} before retrying."
                ),
                "summary": f"not installed · {spec.tool_name}",
            }
        if Path(resolved).suffix.lower() in probes.SCRIPT_SHIMS:
            return {
                "error": "shim_blocked",
                "reason": (
                    f"'{spec.binary}' resolves to a {Path(resolved).suffix} launcher "
                    "script; this agent only executes real binaries directly."
                ),
                "summary": "shim blocked",
            }

        timeout = _clamp_timeout(
            arguments.get("timeout_sec"), spec.default_timeout_s, lo=1
        )
        try:
            plan = spec.builder(arguments)
        except ValueError as exc:
            return {
                "error": "invalid_arguments",
                "reason": str(exc),
                "summary": f"bad arguments · {spec.tool_name}",
            }

        display_command = " ".join(plan.argv)[:MAX_DISPLAY_CHARS]
        started = time.perf_counter()
        runner = self._runner if self._runner is not None else subprocess.run
        try:
            proc = runner(
                plan.argv,
                shell=False,
                capture_output=True,
                text=True,
                errors="replace",
                input=plan.stdin_data,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - started
            self._record(display_command, duration, status="timeout", exit_code=None)
            return {
                "error": "timeout",
                "reason": (
                    f"{spec.binary} exceeded its {timeout}s time limit and was "
                    "terminated; narrow the scope (fewer URLs/ports, higher "
                    "rate_limit floor) and retry once."
                ),
                "command": display_command,
                "stdout": _cap(getattr(exc, "stdout", None)),
                "stderr": _cap(getattr(exc, "stderr", None)),
                "duration": round(duration, 3),
                "summary": f"timeout · {display_command}",
            }
        except OSError as exc:
            duration = time.perf_counter() - started
            self._record(display_command, duration, status="os_error", exit_code=None)
            return {
                "error": "execution_failed",
                "detail": str(exc)[:300],
                "command": display_command,
                "summary": f"os error · {spec.tool_name}",
            }

        duration = time.perf_counter() - started
        exit_code = int(proc.returncode)
        ok = exit_code == 0
        self._record(
            display_command,
            duration,
            status="ok" if ok else "nonzero_exit",
            exit_code=exit_code,
        )
        payload: dict[str, Any] = {
            "tool": spec.tool_name,
            "command": display_command,
            "exit_code": exit_code,
            "stdout": _cap(proc.stdout),
            "stderr": _cap(proc.stderr),
            "duration": round(duration, 3),
            "summary": f"exit={exit_code} · {display_command}",
        }
        if not ok and not proc.stdout and proc.stderr:
            payload["reason"] = "Non-zero exit with output only on stderr; inspect stderr."
        if ok and spec.postprocess is not None:
            payload = spec.postprocess(payload)
        return payload

    # --------------------------------------------------------------- logging
    def _record(
        self,
        command: str,
        duration: float,
        *,
        status: str,
        exit_code: int | None,
    ) -> None:
        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "command": f"[websec] {command}",
            "status": status,
            "exit_code": exit_code,
            "duration_s": round(duration, 3),
            "timed_out": status == "timeout",
        }
        self.history.add(entry)
        append_log_line(self.log_path, entry)


def gate_check_for(spec: WebToolSpec) -> Callable[[Mapping[str, Any]], str | None]:
    """Build a safety-gate ``check_args`` validator from a tool's builder."""
    def check(arguments: Mapping[str, Any]) -> str | None:
        try:
            spec.builder(arguments)
        except ValueError as exc:
            return str(exc)
        except Exception:
            return "Arguments do not match the expected schema."
        return None

    return check


def _handler_for(
    spec: WebToolSpec, runner: WebToolRunner
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    def handler(arguments: Mapping[str, Any]) -> dict[str, Any]:
        return runner.execute(spec, arguments)

    return handler


def build_web_security_tools(
    *,
    history: CommandHistory | None = None,
    log_path: Path | None = None,
) -> list[ToolSpec]:
    runner = WebToolRunner(history=history, log_path=log_path)
    specs: list[ToolSpec] = []
    for web_spec in WEB_TOOLS:
        specs.append(
            ToolSpec(
                name=web_spec.tool_name,
                description=web_spec.description,
                parameters=web_spec.schema,
                risk=RiskLevel.MEDIUM,
                handler=_handler_for(web_spec, runner),
                check_args=gate_check_for(web_spec),
            )
        )
    return specs
