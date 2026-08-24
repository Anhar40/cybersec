from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cyberaent.safety import SafetyGate
from cyberaent.tools import probes
from cyberaent.tools.base import RiskLevel, ToolRegistry
from cyberaent.tools.terminal import CommandHistory
from cyberaent.tools.websec import (
    WEB_TOOLS,
    WebToolRunner,
    WebToolSpec,
    build_web_security_tools,
    parse_nuclei_lines,
)


def register_all(tmp_path: Path) -> tuple[ToolRegistry, SafetyGate, CommandHistory]:
    history = CommandHistory()
    registry = ToolRegistry()
    for spec in build_web_security_tools(history=history, log_path=tmp_path / "log.jsonl"):
        registry.register(spec)
    return registry, SafetyGate(registry), history


def fake_run(exit_code: int = 0, stdout: str = "out", stderr: str = "") -> Any:
    calls: list[dict[str, Any]] = []

    def _run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append({"argv": argv, "kwargs": kwargs})
        assert kwargs.get("shell") is False
        return SimpleNamespace(returncode=exit_code, stdout=stdout, stderr=stderr)

    _run.calls = calls  # type: ignore[attr-defined]
    return _run


def spec_by_name(name: str) -> WebToolSpec:
    return next(s for s in WEB_TOOLS if s.tool_name == name)


EXPECTED_NAMES = {
    "http_request",
    "port_scan",
    "http_probe",
    "web_tech",
    "nikto_scan",
    "vuln_scan",
    "dir_fuzz",
    "dns_lookup",
    "tls_info",
}


def test_nine_web_tools_registered_all_medium(tmp_path: Path) -> None:
    registry, gate, _ = register_all(tmp_path)
    assert {s.tool_name for s in WEB_TOOLS} == EXPECTED_NAMES
    for web_spec in WEB_TOOLS:
        registered = registry.get(web_spec.tool_name)
        assert registered is not None
        assert registered.risk == RiskLevel.MEDIUM, web_spec.tool_name


def test_missing_binary_returns_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: None)
    runner = WebToolRunner(log_path=tmp_path / "log.jsonl")
    result = runner.execute(spec_by_name("dns_lookup"), {"domain": "example.com"})
    assert result["error"] == "not_installed"
    assert "install_tool" in result["reason"]
    assert result["summary"].startswith("not installed")


def test_shim_binary_is_blocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: r"C:\x\nmap.bat")
    runner = WebToolRunner(log_path=tmp_path / "log.jsonl")
    result = runner.execute(spec_by_name("port_scan"), {"target": "10.0.0.1"})
    assert result["error"] == "shim_blocked"


def test_http_request_builds_expected_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: r"C:\x\curl.exe")
    run = fake_run()
    runner = WebToolRunner(runner=run, log_path=tmp_path / "log.jsonl")
    result = runner.execute(
        spec_by_name("http_request"),
        {"url": "https://example.com", "method": "HEAD", "timeout_sec": 999},
    )
    argv = run.calls[0]["argv"]
    assert argv[0] == "curl"
    assert argv[-1] == "https://example.com"
    assert "-I" in argv and "-i" not in argv
    assert argv[argv.index("--max-time") + 1] == "120"
    assert result["exit_code"] == 0
    assert result["summary"].startswith("exit=0")

def test_gate_blocks_invalid_inputs_before_confirmation(tmp_path: Path) -> None:
    _, gate, _ = register_all(tmp_path)
    cases = [
        ("http_request", {"url": "file:///etc/passwd"}),
        ("http_request", {"url": "https://user:pw@example.com"}),
        ("http_request", {"url": "https://a.com", "method": "POST"}),
        ("port_scan", {"target": "host with spaces"}),
        ("port_scan", {"target": "h", "ports": "80;rm -rf /"}),
        ("port_scan", {"target": "h", "ports": "70000"}),
        ("vuln_scan", {"target": "https://a.com", "severity": "apocalyptic"}),
        ("dir_fuzz", {"url": "https://a.com/x", "wordlist": "w.txt"}),
        ("dir_fuzz", {"url": "https://a.com/FUZZ", "wordlist": "missing.txt"}),
        ("dns_lookup", {"domain": "example.com", "record_type": "HACKER"}),
        ("tls_info", {"host": "a.com", "port": 99999}),
        ("nikto_scan", {"target": "t", "port": "80"}),
    ]
    for name, args in cases:
        decision = gate.evaluate(name, args)
        assert not decision.allowed, f"{name} {args} should be blocked"


def test_gate_accepts_valid_inputs_and_requires_confirmation(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nbackup\n", encoding="utf-8")
    _, gate, _ = register_all(tmp_path)
    cases = [
        ("http_request", {"url": "https://example.com/robots.txt"}),
        ("port_scan", {"target": "192.168.1.10", "ports": "22,80,443"}),
        ("http_probe", {"urls": ["https://a.com", "http://b.com"]}),
        ("vuln_scan", {"target": "https://example.com", "severity": "high,critical"}),
        ("dir_fuzz", {"url": "https://example.com/FUZZ", "wordlist": str(wordlist)}),
        ("dns_lookup", {"domain": "example.com", "record_type": "mx"}),
        ("tls_info", {"host": "example.com"}),
        ("web_tech", {"url": "https://example.com"}),
        ("nikto_scan", {"target": "10.0.0.5", "port": 8443, "ssl": True}),
    ]
    for name, args in cases:
        decision = gate.evaluate(name, args)
        assert decision.allowed is True, f"{name} {args} should be allowed"
        assert decision.requires_confirmation is True, name


def test_http_probe_feeds_urls_via_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "httpx.exe")
    run = fake_run(stdout="[200] a.com")
    runner = WebToolRunner(runner=run, log_path=tmp_path / "log.jsonl")
    result = runner.execute(spec_by_name("http_probe"), {"urls": ["https://a.com"]})
    kwargs = run.calls[0]["kwargs"]
    assert kwargs.get("input") == "https://a.com"
    assert "-tech-detect" in run.calls[0]["argv"]
    assert result["exit_code"] == 0


def test_dir_fuzz_passes_wordlist_and_match_codes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "ffuf.exe")
    run = fake_run(stdout="matches")
    runner = WebToolRunner(runner=run, log_path=tmp_path / "log.jsonl")
    wordlist = tmp_path / "list.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    result = runner.execute(
        spec_by_name("dir_fuzz"),
        {
            "url": "https://a.com/FUZZ",
            "wordlist": str(wordlist),
            "match_codes": "200,403",
        },
    )
    argv = run.calls[0]["argv"]
    assert argv[0] == "ffuf" and "-w" in argv
    assert argv[argv.index("-mc") + 1] == "200,403"
    assert result["exit_code"] == 0


def test_timeout_payload(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "dig.exe")

    def slow_run(argv: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=argv, timeout=5)

    runner = WebToolRunner(runner=slow_run, log_path=tmp_path / "log.jsonl")
    result = runner.execute(spec_by_name("dns_lookup"), {"domain": "example.com"})
    assert result["error"] == "timeout"
    assert "narrow the scope" in result["reason"]


def test_os_error_maps_to_execution_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "curl.exe")

    def broken_run(argv: list[str], **kwargs: Any) -> Any:
        raise OSError("spawn failed")

    runner = WebToolRunner(runner=broken_run, log_path=tmp_path / "log.jsonl")
    result = runner.execute(spec_by_name("http_request"), {"url": "https://a.com"})
    assert result["error"] == "execution_failed"


def test_nonzero_exit_keeps_outputs_without_error_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "nmap.exe")
    run = fake_run(exit_code=1, stdout="partial scan")
    runner = WebToolRunner(runner=run, log_path=tmp_path / "log.jsonl")
    result = runner.execute(spec_by_name("port_scan"), {"target": "10.0.0.1"})
    assert "error" not in result
    assert result["exit_code"] == 1
    assert result["stdout"] == "partial scan"


def test_successful_run_logs_to_history_and_jsonl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "dig.exe")
    log_path = tmp_path / "log.jsonl"
    history = CommandHistory()
    run = fake_run(stdout="93.184.216.34")
    runner = WebToolRunner(history=history, log_path=log_path, runner=run)
    runner.execute(spec_by_name("dns_lookup"), {"domain": "example.com"})
    entry = history.recent(1)[0]
    assert entry["command"].startswith("[websec] dig ")
    assert entry["status"] == "ok"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and "[websec]" in lines[0]


NUCLEI_JSONL = (
    '{"template-id":"cves/2021/44228","info":{"name":"Spring4Shell RCE",'
    '"severity":"critical","tags":["rce","cve"]},"host":"https://t.local",'
    '"matched-at":"https://t.local/login","extracted-results":["poc"]}\n'
    "not-json-noise\n"
    '{"templateID":"tech-detect","info":{"name":"nginx","severity":"info"},'
    '"host":"https://t.local"}\n'
    "{broken json\n"
)


def test_parse_nuclei_lines_normalizes_and_sorts() -> None:
    result = parse_nuclei_lines(NUCLEI_JSONL)
    findings = result["findings"]
    assert [f["severity"] for f in findings] == ["critical", "info"]
    assert findings[0]["template_id"] == "cves/2021/44228"
    assert findings[0]["tags"] == ["rce", "cve"]
    assert findings[0]["extracted"] == ["poc"]
    assert findings[1]["name"] == "nginx"
    assert result["severity_counts"] == {"critical": 1, "info": 1}
    assert result["summary"].startswith("1 critical")
    assert "(2 findings)" in result["summary"]


def test_parse_nuclei_lines_empty_and_garbage() -> None:
    assert parse_nuclei_lines(None)["findings"] == []
    assert parse_nuclei_lines("")[  "summary"] == "no findings detected"
    assert parse_nuclei_lines("garbage lines only")["findings"] == []


def test_vuln_scan_enriches_findings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: r"C:\x\nuclei.exe")
    run = fake_run(stdout=NUCLEI_JSONL)
    runner = WebToolRunner(runner=run, log_path=tmp_path / "log.jsonl")
    spec = next(s for s in WEB_TOOLS if s.tool_name == "vuln_scan")
    result = runner.execute(spec, {"target": "https://t.local"})
    argv = run.calls[0]["argv"]
    assert "-j" in argv and "-silent" in argv
    assert len(result["findings"]) == 2
    assert result["findings"][0]["severity"] == "critical"
    assert "findings_summary" in result
    assert result["summary"].startswith("1 critical")


def test_vuln_scan_failure_keeps_generic_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: r"C:\x\nuclei.exe")
    run = fake_run(exit_code=2, stdout="", stderr="boom")
    runner = WebToolRunner(runner=run, log_path=tmp_path / "log.jsonl")
    spec = next(s for s in WEB_TOOLS if s.tool_name == "vuln_scan")
    result = runner.execute(spec, {"target": "https://t.local"})
    assert "findings" not in result
    assert result["exit_code"] == 2
