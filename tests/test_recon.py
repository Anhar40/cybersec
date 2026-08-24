from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cyberaent.safety import SafetyGate
from cyberaent.tools import probes
from cyberaent.tools.base import RiskLevel, ToolRegistry
from cyberaent.tools.recon import (
    RECON_TOOLS,
    ReconToolbox,
    analyze_headers,
    build_web_recon_tools,
    get_all,
    parse_http_headers,
    parse_subdomains,
    score_findings,
)
from cyberaent.tools.terminal import CommandHistory


def register_all(tmp_path: Path) -> tuple[ToolRegistry, SafetyGate]:
    registry = ToolRegistry()
    for spec in build_web_recon_tools(log_path=tmp_path / "log.jsonl"):
        registry.register(spec)
    return registry, SafetyGate(registry)


def spec_by_name(name: str) -> Any:
    return next(s for s in RECON_TOOLS if s.tool_name == name)


SAMPLE_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.18.0\r\n"
    "Content-Type: text/html\r\n"
    "Set-Cookie: sid=abc; Path=/\r\n"
    "X-Frame-Options: DENY\r\n"
    "\r\n"
    "<html>body</html>"
)


def test_parse_http_headers_single_response() -> None:
    parsed = parse_http_headers(SAMPLE_RESPONSE)
    assert parsed is not None
    assert parsed["status"] == "HTTP/1.1 200 OK"
    headers = parsed["headers"]
    assert headers["server"] == "nginx/1.18.0"
    assert isinstance(headers["set-cookie"], str)
    cookies = get_all(headers, "set-cookie")
    assert len(cookies) == 1 and cookies[0].startswith("sid=abc")


def test_parse_http_headers_redirect_chain_takes_last() -> None:
    raw = (
        "HTTP/1.1 301 Moved\r\nLocation: https://a.com/final\r\n\r\n"
        "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\n\r\nbody"
    )
    parsed = parse_http_headers(raw)
    assert parsed is not None
    assert parsed["status"].startswith("HTTP/1.1 200")
    assert "strict-transport-security" in parsed["headers"]


def test_parse_http_headers_handles_garbage() -> None:
    assert parse_http_headers("") is None
    assert parse_http_headers("curl: (6) could not resolve host") is None


def test_analyze_headers_reports_expected_findings() -> None:
    parsed = parse_http_headers(SAMPLE_RESPONSE)
    assert parsed is not None
    findings = analyze_headers(parsed["headers"], is_https=True)
    by_check = {f["check"]: f for f in findings}
    assert by_check["strict-transport-security"]["status"] == "fail"
    assert by_check["content-security-policy"]["status"] == "fail"
    assert by_check["x-content-type-options"]["status"] == "warn"
    assert by_check["clickjacking"]["status"] == "pass"
    assert by_check["server-disclosure"]["status"] == "info"
    assert "sid" in by_check["cookie-flags"]["detail"]
    summary = score_findings(findings)
    assert summary.endswith("checks passed") and "2 fail" in summary


def test_analyze_headers_secure_site_passes_core_checks() -> None:
    headers = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
        "set-cookie": ["sid=1; HttpOnly; Secure; SameSite=Lax"],
    }
    findings = analyze_headers(headers, is_https=True)
    statuses = {f["check"]: f["status"] for f in findings}
    assert statuses["strict-transport-security"] == "pass"
    assert statuses["content-security-policy"] == "pass"
    assert statuses["cookie-flags"] == "pass"
    assert not any(s == "fail" for s in statuses.values())


def test_parse_subdomains_dedupes_and_truncates() -> None:
    result = parse_subdomains("\n".join(["a.example.com", "A.EXAMPLE.COM.", "", "b.example.com"]))
    assert result["found_count"] == 2
    assert result["subdomains"] == ["a.example.com", "b.example.com"]
    many = "\n".join(f"h{i}.example.com" for i in range(205))
    result_many = parse_subdomains(many)
    assert result_many["found_count"] == 205
    assert len(result_many["subdomains"]) == 200
    assert result_many["truncated"] is True


def test_recon_tools_registered_medium_and_gated(tmp_path: Path) -> None:
    registry, gate = register_all(tmp_path)
    names = {s.tool_name for s in RECON_TOOLS}
    assert names == {"subdomain_enum", "header_audit"}
    for web_spec in RECON_TOOLS:
        registered = registry.get(web_spec.tool_name)
        assert registered is not None
        assert registered.risk == RiskLevel.MEDIUM
    blocked = gate.evaluate("header_audit", {"url": "ftp://a.com"})
    assert not blocked.allowed
    ok = gate.evaluate("header_audit", {"url": "https://example.com"})
    assert ok.allowed and ok.requires_confirmation
    bad_domain = gate.evaluate("subdomain_enum", {"domain": "not a domain"})
    assert not bad_domain.allowed


def test_header_audit_end_to_end_with_fake_curl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: r"C:\x\curl.exe")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append(argv)
        assert kwargs.get("shell") is False
        return SimpleNamespace(returncode=0, stdout=SAMPLE_RESPONSE, stderr="")

    toolbox = ReconToolbox(runner=fake_run, log_path=tmp_path / "log.jsonl")
    result = toolbox.execute(
        spec_by_name("header_audit"), {"url": "https://example.com/"}
    )
    assert result["exit_code"] == 0
    assert result["http_status"] == "HTTP/1.1 200 OK"
    assert any(c["check"] == "content-security-policy" for c in result["checks"])
    assert "checks passed" in result["summary"]
    assert "-L" in calls[0]


def test_subdomain_enum_enrichment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "subfinder.exe")

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=0,
            stdout="one.example.com\ntwo.example.com\n",
            stderr="",
        )

    toolbox = ReconToolbox(runner=fake_run, log_path=tmp_path / "log.jsonl")
    result = toolbox.execute(spec_by_name("subdomain_enum"), {"domain": "example.com"})
    assert result["command"].startswith("subfinder -d example.com -silent")
    assert result["found_count"] == 2
    assert result["truncated"] is False
    assert "unique subdomains" in result["summary"]


def test_header_audit_unparseable_output_becomes_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: r"C:\x\curl.exe")

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=6, stdout="", stderr="curl: (6) DNS fail")

    toolbox = ReconToolbox(runner=fake_run, log_path=tmp_path / "log.jsonl")
    result = toolbox.execute(spec_by_name("header_audit"), {"url": "https://x.local"})
    assert result["error"] == "no_http_response"


def test_history_logging_via_runner(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    history = CommandHistory()
    toolbox = ReconToolbox(history=history, log_path=log_path)
    spec = spec_by_name("subdomain_enum")

    # missing binary short-circuits before execution: no run, nothing logged
    result = toolbox.execute(spec, {"domain": "example.com"})
    assert result["error"] == "not_installed"
    assert history.recent(10) == []
