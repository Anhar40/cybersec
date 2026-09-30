from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from cyberaent.safety import SafetyGate
from cyberaent.tools.base import RiskLevel, ToolRegistry, ToolSpec
from cyberaent.tools.evidence import (
    MAX_TEXT_LENGTH,
    MAX_TITLE_LENGTH,
    SEVERITIES,
    STATUSES,
    EvidenceStore,
    build_evidence_tools,
    recording_spec,
    render_markdown_report,
)

FIXED_NOW = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)


def make_store(**kwargs: Any) -> EvidenceStore:
    return EvidenceStore(clock=lambda: FIXED_NOW, **kwargs)


def vuln_scan_payload() -> dict[str, Any]:
    return {
        "exit_code": 0,
        "findings": [
            {
                "template_id": "missing-hsts",
                "name": "Missing HSTS",
                "severity": "high",
                "tags": ["hsts"],
                "host": "https://example.com",
                "matched_at": "https://example.com",
                "extracted": [],
            },
            {
                "template_id": "tech-detect",
                "name": "Tech detection",
                "severity": "unknown",
                "tags": [],
                "host": "https://example.com",
                "matched_at": "",
                "extracted": ["nginx"],
            },
        ],
        "summary": "2 findings",
    }


def header_audit_payload() -> dict[str, Any]:
    return {
        "http_status": "HTTP/1.1 200 OK",
        "checks": [
            {"check": "strict-transport-security", "status": "pass", "detail": "HSTS present."},
            {"check": "content-security-policy", "status": "fail", "detail": "CSP missing."},
            {"check": "clickjacking", "status": "warn", "detail": "Page is framable."},
            {"check": "server-disclosure", "status": "info", "detail": "Server version shown."},
        ],
        "summary": "200 · 1 fail · 1 warn",
    }


# ------------------------------------------------------------------- the store
def test_add_finding_happy_path() -> None:
    store = make_store()
    result = store.add(
        source_tool="manual",
        title="SQL injection in /item",
        severity="HIGH",
        target="https://example.com/item?id=1",
        evidence="sqlmap confirmed boolean-based blind",
        remediation="Use parameterized queries.",
    )
    assert result.created is True
    assert result.record["id"] == "F-001"
    assert result.record["recorded_at"] == "2026-08-23T12:00:00+00:00"
    assert result.record["severity"] == "high"
    assert [f["id"] for f in store.findings()] == ["F-001"]
    assert store.counts() == {"high": 1}


def test_add_rejects_invalid_input() -> None:
    store = make_store()
    with pytest.raises(ValueError, match="severity"):
        store.add(source_tool="manual", title="x", severity="catastrophic")
    with pytest.raises(ValueError, match="title"):
        store.add(source_tool="manual", title="   ", severity="low")
    with pytest.raises(ValueError, match="exceeds"):
        store.add(source_tool="manual", title="t" * (MAX_TITLE_LENGTH + 1), severity="low")
    with pytest.raises(ValueError, match="must be a string"):
        store.add(source_tool="manual", title=123, severity="low")
    long_evidence = "e" * (MAX_TEXT_LENGTH + 1)
    with pytest.raises(ValueError, match="evidence"):
        store.add(source_tool="manual", title="x", severity="low", evidence=long_evidence)


def test_duplicate_findings_are_not_stored_twice() -> None:
    store = make_store()
    first = store.add(source_tool="vuln_scan", title="Same issue", severity="high")
    second = store.add(source_tool="VULN_SCAN", title="same ISSUE", severity="high")
    assert first.created is True
    assert second.created is False
    assert second.record["id"] == first.record["id"]
    assert len(store.findings()) == 1


def test_store_capacity_is_enforced() -> None:
    store = make_store(max_findings=2)
    store.add(source_tool="manual", title="one", severity="low")
    store.add(source_tool="manual", title="two", severity="low")
    with pytest.raises(ValueError, match="full"):
        store.add(source_tool="manual", title="three", severity="low")


def test_clear_returns_removed_count() -> None:
    store = make_store()
    store.add(source_tool="manual", title="one", severity="low")
    assert store.clear() == 1
    assert store.findings() == []


# ------------------------------------------------------- auto-capture (observe)
def test_observe_captures_vuln_scan_findings() -> None:
    store = make_store()
    created = store.observe("vuln_scan", vuln_scan_payload())
    assert len(created) == 2
    assert created[0]["title"] == "Missing HSTS"
    assert created[0]["severity"] == "high"
    assert created[0]["target"] == "https://example.com"
    assert created[1]["severity"] == "info"

    again = store.observe("vuln_scan", vuln_scan_payload())
    assert again == []
    assert len(store.findings()) == 2


def test_observe_captures_header_audit_checks() -> None:
    store = make_store()
    created = store.observe("header_audit", header_audit_payload())
    titles = [record["title"] for record in created]
    severities = [record["severity"] for record in created]
    assert titles == [
        "Security header audit: content-security-policy",
        "Security header audit: clickjacking",
        "Security header audit: server-disclosure",
    ]
    assert severities == ["medium", "low", "info"]


def test_observe_ignores_error_payloads_and_noise() -> None:
    store = make_store()
    assert store.observe("vuln_scan", {"error": "timeout"}) == []
    assert store.observe("subdomain_enum", {"subdomains": ["a.example.com"]}) == []
    broken = vuln_scan_payload()
    broken["findings"] = [{"name": "", "severity": "high"}, "not-a-mapping"]
    assert store.observe("vuln_scan", broken) == []


# ------------------------------------------------------------- report renderer
def test_render_report_orders_by_severity() -> None:
    store = make_store()
    store.add(source_tool="manual", title="Low thing", severity="low")
    store.add(source_tool="manual", title="Critical thing", severity="critical")
    report = render_markdown_report(
        title="Pentest Report",
        findings=store.findings(),
        generated_at="2026-08-23T12:00:00+00:00",
    )
    assert report.index("# Pentest Report") < report.index("| Severity |")
    assert report.index("Critical thing") < report.index("Low thing")
    assert "| critical | 1 |" in report
    assert "explicitly authorized" in report


def test_render_report_includes_evidence_and_remediation() -> None:
    store = make_store()
    store.add(
        source_tool="sqli_probe",
        title="SQLi",
        severity="critical",
        target="https://h/x?id=1",
        evidence="parameter 'id' is vulnerable",
        remediation="Parameterize queries.",
    )
    report = render_markdown_report(title="R", findings=store.findings(), generated_at="now")
    assert "- Target: `https://h/x?id=1`" in report
    assert "**Evidence**" in report
    assert "parameter 'id' is vulnerable" in report
    assert "**Remediation:** Parameterize queries." in report
    assert "````text" in report


def test_render_report_empty_state_is_honest() -> None:
    report = render_markdown_report(title="Empty", findings=[], generated_at="now")
    assert "No verified findings were recorded" in report
    assert "not proof of security" in report


# --------------------------------------------------------------- tool handlers
@pytest.fixture()
def built(tmp_path: Path) -> tuple[list[Any], EvidenceStore, Path]:
    store = make_store()
    reports_dir = tmp_path / "reports"
    return build_evidence_tools(store=store, reports_dir=reports_dir), store, reports_dir


def spec_by_name(specs: list[Any], name: str) -> Any:
    return next(spec for spec in specs if spec.name == name)


def test_tool_names_and_risk_tiers(built: tuple[list[Any], EvidenceStore, Path]) -> None:
    specs = built[0]
    assert [spec.name for spec in specs] == [
        "record_finding",
        "verify_finding",
        "list_findings",
        "generate_report",
    ]
    assert all(spec.risk is RiskLevel.LOW for spec in specs)


def test_record_finding_handler(built: tuple[list[Any], EvidenceStore, Path]) -> None:
    specs, store, _ = built
    record = spec_by_name(specs, "record_finding")
    payload = record.handler(
        {"title": "Open dir listing", "severity": "medium", "target": "https://h/backup/"}
    )
    assert payload["duplicate"] is False
    assert payload["finding"]["id"] == "F-001"
    assert "stored" in str(payload["summary"])

    duplicate = record.handler(
        {"title": "Open dir listing", "severity": "low", "target": "https://h/backup/"}
    )
    assert duplicate["duplicate"] is True

    with pytest.raises(ValueError, match="severity"):
        record.handler({"title": "Bad", "severity": "extreme"})
    assert len(store.findings()) == 1


def test_list_findings_handler(built: tuple[list[Any], EvidenceStore, Path]) -> None:
    specs, store, _ = built
    listing = spec_by_name(specs, "list_findings")
    empty = listing.handler({})
    assert empty["count"] == 0
    assert empty["findings"] == []

    store.add(source_tool="manual", title="one", severity="high")
    store.add(source_tool="manual", title="two", severity="low")
    payload = listing.handler({})
    assert payload["count"] == 2
    assert payload["severity_counts"] == {"high": 1, "low": 1}
    assert "2 total" in str(payload["summary"])


def test_generate_report_handler_writes_file(
    built: tuple[list[Any], EvidenceStore, Path],
) -> None:
    specs, store, reports_dir = built
    store.add(source_tool="manual", title="Found it", severity="high")
    generator = spec_by_name(specs, "generate_report")
    payload = generator.handler({"title": "Acme Assessment"})
    path = Path(str(payload["path"]))
    assert path.parent == reports_dir
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "# Acme Assessment" in content
    assert "Found it" in content
    assert payload["finding_count"] == 1
    assert payload["severity_counts"] == {"high": 1}


def test_generate_report_handler_write_failure(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    store = make_store()
    specs = build_evidence_tools(store=store, reports_dir=blocker / "reports")
    generator = spec_by_name(specs, "generate_report")
    payload = generator.handler({})
    assert payload["error"] == "report_write_failed"
    assert "detail" in payload


# ------------------------------------------------------------- gate + registry
def test_gate_treats_evidence_tools_as_low_risk(
    built: tuple[list[Any], EvidenceStore, Path],
) -> None:
    registry = ToolRegistry()
    for spec in built[0]:
        registry.register(spec)
    gate = SafetyGate(registry)

    ok = gate.evaluate("record_finding", {"title": "XSS in search", "severity": "high"})
    assert ok.allowed is True and ok.requires_confirmation is False and ok.risk is RiskLevel.LOW

    bad_severity = gate.evaluate("record_finding", {"title": "XSS", "severity": "apocalyptic"})
    assert bad_severity.allowed is False

    missing = gate.evaluate("record_finding", {"title": "XSS"})
    assert missing.allowed is False

    long_title = gate.evaluate("record_finding", {"title": "x" * 500, "severity": "low"})
    assert long_title.allowed is False

    report_ok = gate.evaluate("generate_report", {})
    assert report_ok.allowed is True

    report_bad = gate.evaluate("generate_report", {"title": ""})
    assert report_bad.allowed is False

    list_ok = gate.evaluate("list_findings", {})
    assert list_ok.allowed is True


# ------------------------------------------------------------ auto-capture wire
def test_recording_spec_captures_without_mutating_payload() -> None:
    store = make_store()

    def inner(_arguments: Any) -> dict[str, Any]:
        return vuln_scan_payload()

    spec = ToolSpec(
        name="vuln_scan",
        description="d",
        parameters={"type": "object", "properties": {}},
        risk=RiskLevel.MEDIUM,
        handler=inner,
    )
    wrapped = recording_spec(spec, store)
    result = wrapped.handler({})
    assert set(result) == set(vuln_scan_payload())
    assert len(store.findings()) == 2

    failed = recording_spec(
        ToolSpec(
            name="vuln_scan",
            description="d",
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.MEDIUM,
            handler=lambda _a: {"error": "timeout"},
        ),
        store,
    )
    failed.handler({})
    assert len(store.findings()) == 2


def test_severities_constant_ordering() -> None:
    assert SEVERITIES == ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------- status taxonomy
def test_statuses_constant_ordering() -> None:
    assert STATUSES == ("verified", "observed", "suspected", "refuted")


def test_manual_finding_defaults_to_suspected() -> None:
    store = make_store()
    result = store.add(source_tool="manual", title="Maybe SQLi", severity="high")
    assert result.record["status"] == "suspected"
    assert result.record["verification"] == ""
    assert result.record["verified_at"] == ""


def test_manual_finding_with_verification_is_verified() -> None:
    store = make_store()
    result = store.add(
        source_tool="manual",
        title="SQLi",
        severity="critical",
        verification="reproduced with sqlmap --level 3",
    )
    assert result.record["status"] == "verified"
    assert result.record["verified_at"] == "2026-08-23T12:00:00+00:00"


def test_explicit_status_is_validated() -> None:
    store = make_store()
    observed = store.add(
        source_tool="manual", title="Odd header", severity="info", status="OBSERVED"
    )
    assert observed.record["status"] == "observed"
    with pytest.raises(ValueError, match="status"):
        store.add(source_tool="manual", title="Bad", severity="info", status="probably-fine")

def test_duplicate_add_promotes_but_never_downgrades() -> None:
    store = make_store()
    store.add(source_tool="vuln_scan", title="Missing HSTS", severity="high", status="observed")
    store.add(
        source_tool="vuln_scan",
        title="Missing HSTS",
        severity="high",
        status="verified",
        verification="curl -I confirms no Strict-Transport-Security",
    )
    record = store.findings()[0]
    assert record["status"] == "verified"
    assert record["verified_at"]

    store.add(source_tool="vuln_scan", title="Missing HSTS", severity="high", status="observed")
    assert store.findings()[0]["status"] == "verified"
    assert len(store.findings()) == 1


def test_verify_marks_verified_with_method() -> None:
    store = make_store()
    added = store.add(source_tool="manual", title="IDOR", severity="high")
    result = store.verify(
        added.record["id"],
        method="GET /api/orders/1002 as user bob returned alice's order",
        evidence="200 with foreign user_id",
    )
    record = result.record
    assert record["status"] == "verified"
    assert record["verified_at"] == "2026-08-23T12:00:00+00:00"
    assert record["evidence"] == "200 with foreign user_id"
    assert "alice" in record["verification"]
    assert store.findings(status="verified")[0]["id"] == added.record["id"]


def test_verify_can_refute() -> None:
    store = make_store()
    added = store.add(source_tool="vuln_scan", title="Possible open redirect", severity="low")
    record = store.verify(
        added.record["id"], method="retested, server normalizes input", confirmed=False
    ).record
    assert record["status"] == "refuted"
    assert store.findings(status="refuted") == [record]
    assert store.findings(status="verified") == []


def test_verify_rejects_bad_input() -> None:
    store = make_store()
    with pytest.raises(ValueError, match="No finding"):
        store.verify("F-999", method="curl")
    added = store.add(source_tool="manual", title="X", severity="low")
    with pytest.raises(ValueError, match="method"):
        store.verify(added.record["id"], method="   ")


def test_observe_captures_as_observed_not_verified() -> None:
    store = make_store()
    created = store.observe("vuln_scan", vuln_scan_payload())
    assert [record["status"] for record in created] == ["observed", "observed"]
    assert store.status_counts() == {"observed": 2}
    assert store.findings(status="verified") == []


def test_status_counts_and_filters(built: tuple[list[Any], EvidenceStore, Path]) -> None:
    _specs, store, _ = built
    store.add(source_tool="manual", title="a", severity="high", verification="proved")
    store.add(source_tool="manual", title="b", severity="low")
    store.add(source_tool="manual", title="c", severity="info", status="observed")
    assert store.status_counts() == {"verified": 1, "suspected": 1, "observed": 1}
    assert [f["title"] for f in store.findings(status="observed")] == ["c"]
    with pytest.raises(ValueError, match="status"):
        store.findings(status="maybe")


# ----------------------------------------------------------------- report layout
def test_report_separates_confirmed_unconfirmed_and_refuted() -> None:
    store = make_store()
    store.add(
        source_tool="manual", title="Confirmed RCE", severity="critical", verification="proof"
    )
    store.add(source_tool="manual", title="Hypothesis only", severity="medium")
    refuted = store.add(source_tool="manual", title="False positive", severity="low")
    store.verify(refuted.record["id"], method="not reproducible", confirmed=False)

    report = render_markdown_report(title="R", findings=store.findings(), generated_at="now")

    assert "## Confirmed findings" in report
    assert "## Unconfirmed observations" in report
    assert "## Refuted" in report
    assert report.index("## Confirmed findings") < report.index("## Unconfirmed observations")
    assert report.index("## Unconfirmed observations") < report.index("## Refuted")
    assert "Status breakdown: 1 verified · 1 suspected · 1 refuted" in report
    assert "**Verification:** proof" in report
    assert "not confirmed vulnerabilities" in report


def test_report_shows_status_line_per_finding() -> None:
    store = make_store()
    store.add(source_tool="manual", title="Hypothesis", severity="medium")
    report = render_markdown_report(title="R", findings=store.findings(), generated_at="now")
    assert "- Status: suspected" in report
    assert "## Findings" not in report


# ------------------------------------------------------------ verify tool wiring
def test_verify_finding_handler(built: tuple[list[Any], EvidenceStore, Path]) -> None:
    specs, store, _ = built
    store.add(source_tool="manual", title="XSS in search", severity="high")
    verifier = spec_by_name(specs, "verify_finding")
    payload = verifier.handler(
        {"finding_id": "F-001", "method": "confirmed reflected payload", "evidence": "alert(1)"}
    )
    assert payload["status"] == "verified"
    assert payload["finding"]["verification"] == "confirmed reflected payload"
    assert "marked verified" in str(payload["summary"])


def test_verify_finding_handler_reports_unknown_id(
    built: tuple[list[Any], EvidenceStore, Path],
) -> None:
    specs, _store, _ = built
    verifier = spec_by_name(specs, "verify_finding")
    payload = verifier.handler({"finding_id": "F-404", "method": "curl"})
    assert payload["error"] == "verification_failed"
    assert "F-404" in payload["detail"]


def test_list_findings_handler_filters_by_status(
    built: tuple[list[Any], EvidenceStore, Path],
) -> None:
    specs, store, _ = built
    store.add(source_tool="manual", title="a", severity="high", verification="proved")
    store.add(source_tool="manual", title="b", severity="low")
    listing = spec_by_name(specs, "list_findings")

    payload = listing.handler({"status": "verified"})

    assert payload["filter_status"] == "verified"
    assert payload["count"] == 1
    assert payload["status_counts"] == {"verified": 1, "suspected": 1}

    with pytest.raises(ValueError, match="status"):
        listing.handler({"status": "maybe"})


def test_record_finding_handler_defaults_and_hint(
    built: tuple[list[Any], EvidenceStore, Path],
) -> None:
    specs, _store, _ = built
    recorder = spec_by_name(specs, "record_finding")
    payload = recorder.handler({"title": "Guess", "severity": "low"})
    assert payload["finding"]["status"] == "suspected"
    assert "verify_finding" in payload["hint"]

    confirmed = recorder.handler(
        {"title": "Proven", "severity": "high", "verification": "curl reproduced"}
    )
    assert confirmed["finding"]["status"] == "verified"
    assert confirmed["hint"] == ""


def test_gate_validates_verify_and_list_arguments(
    built: tuple[list[Any], EvidenceStore, Path],
) -> None:
    registry = ToolRegistry()
    for spec in built[0]:
        registry.register(spec)
    gate = SafetyGate(registry)

    ok = gate.evaluate("verify_finding", {"finding_id": "F-001", "method": "replayed request"})
    assert ok.allowed is True

    missing_method = gate.evaluate("verify_finding", {"finding_id": "F-001"})
    assert missing_method.allowed is False

    empty_id = gate.evaluate("verify_finding", {"finding_id": "  ", "method": "curl"})
    assert empty_id.allowed is False

    bad_status = gate.evaluate("list_findings", {"status": "nope"})
    assert bad_status.allowed is False

    explicit_status = gate.evaluate(
        "record_finding", {"title": "t", "severity": "low", "status": "refuted"}
    )
    assert explicit_status.allowed is True


def test_generate_report_handler_reports_status_counts(
    built: tuple[list[Any], EvidenceStore, Path],
) -> None:
    specs, store, _reports = built
    store.add(source_tool="manual", title="Confirmed", severity="high", verification="proof")
    generator = spec_by_name(specs, "generate_report")
    payload = generator.handler({})
    assert payload["status_counts"] == {"verified": 1}
    assert payload["verified_count"] == 1
    content = Path(str(payload["path"])).read_text(encoding="utf-8")
    assert "## Confirmed findings" in content
    assert "## Unconfirmed observations" not in content
