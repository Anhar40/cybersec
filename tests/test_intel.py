from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cyberaent.intel import PLAN_STATUSES, IntelHub
from cyberaent.strategy import (
    PRIORITY_HEADERS,
    PRIORITY_HYPOTHESIS,
    PRIORITY_INJECTION,
    PRIORITY_SCAN,
    PRIORITY_SCOPE,
    PRIORITY_TECH,
    PRIORITY_VERIFY,
    StrategyEngine,
)


def make_hub(tmp_path: Path, scope: str = "") -> IntelHub:
    return IntelHub(memory_path=tmp_path / "knowledge.json", scope=scope)


def maybe_tool_of(actions: list[dict[str, Any]], tool: str) -> dict[str, Any] | None:
    return next((action for action in actions if action.get("tool") == tool), None)


def tool_of(actions: list[dict[str, Any]], tool: str) -> dict[str, Any]:
    found = maybe_tool_of(actions, tool)
    assert found is not None, f"{tool} missing from {[a.get('tool') for a in actions]}"
    return found


# ------------------------------------------------------------------ auto-capture
def test_observe_captures_endpoints_technologies_and_tests(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    result = hub.observe_tool_result(
        "http_probe",
        {
            "summary": "2 live hosts",
            "results": [
                {"url": "https://x.test/app?id=1", "status_code": 200, "webserver": "nginx"},
            ],
            "headers": {"server": "nginx/1.18", "x-powered-by": "PHP/8.2"},
            "ports": [80, 443],
        },
        {"urls": ["https://x.test"]},
    )

    assert result["error"] is False
    assert result["captured"]["endpoints"] >= 1
    assert result["captured"]["technologies"] >= 3
    assert result["captured"]["observations"] >= 2
    assert hub.memory.endpoints()
    techs = {tech["name"] for tech in hub.memory.technologies()}
    assert "nginx" in techs
    assert hub.memory.tests(tool="http_probe")[0]["outcome"] == "ok"
    assert hub.memory.test_done("http_probe", "https://x.test")


def test_observe_records_errors_without_facts(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    result = hub.observe_tool_result(
        "vuln_scan", {"error": "timeout", "reason": "nuclei exceeded 300s"}, {"target": "x.test"}
    )
    assert result["error"] is True
    assert result["target"] == "x.test"
    assert hub.memory.tests(tool="vuln_scan")[0]["outcome"] == "error"
    assert hub.memory.endpoints() == []
    assert hub.memory.observations(kind="tool_summary") == []


def test_observe_ignores_non_url_strings(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.observe_tool_result("terminal", {"stdout": "ok", "command": "whoami"}, {})
    assert [row["url"] for row in hub.memory.endpoints()] == []


def test_observe_captures_header_check_gaps(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.observe_tool_result(
        "header_audit",
        {
            "http_status": "HTTP/1.1 200 OK",
            "checks": [
                {"check": "csp", "status": "fail", "detail": "missing"},
                {"check": "hsts", "status": "pass", "detail": "ok"},
            ],
            "summary": "200 · 1 fail",
        },
        {"url": "https://x.test"},
    )
    notes = hub.memory.observations(kind="headers")
    assert notes and "csp" in notes[0]["text"]
    assert hub.surface.hosts() == ["x.test"]


# -------------------------------------------------------------------- strategy
def test_no_knowledge_yields_scope_action(tmp_path: Path) -> None:
    hub = make_hub(tmp_path, scope="https://x.test")
    actions = hub.next_actions()
    probe = tool_of(actions, "http_probe")
    assert probe is not None
    assert probe["priority"] == PRIORITY_SCOPE
    assert probe["arguments"]["urls"] == ["https://x.test"]
    assert "No endpoint has been observed" in probe["reason"]


def test_coverage_actions_appear_and_disappear_with_tests(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.observe_tool_result(
        "http_probe",
        {"summary": "1 live", "results": [{"url": "https://x.test/app?id=1", "status_code": 200}]},
        {"urls": ["https://x.test/app?id=1"]},
    )
    actions = hub.next_actions(limit=10)
    assert tool_of(actions, "header_audit")["priority"] == PRIORITY_HEADERS
    assert tool_of(actions, "web_tech")["priority"] == PRIORITY_TECH
    injection = tool_of(actions, "sqli_probe")
    assert injection["priority"] == PRIORITY_INJECTION
    assert injection["arguments"]["url"] == "https://x.test/app?id=1"
    scan = tool_of(actions, "vuln_scan")
    assert scan["priority"] == PRIORITY_SCAN
    assert scan["arguments"]["target"] == "x.test"

    for tool, args in (
        ("header_audit", {"url": "https://x.test/app?id=1"}),
        ("web_tech", {"url": "https://x.test/app?id=1"}),
        ("sqli_probe", {"url": "https://x.test/app?id=1"}),
        ("vuln_scan", {"target": "x.test"}),
    ):
        hub.observe_tool_result(tool, {"summary": "done"}, args)

    assert hub.next_actions(limit=10) == []


def test_hypotheses_outrank_coverage(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.observe_tool_result(
        "http_probe", {"results": [{"url": "https://x.test/a"}]}, {"urls": ["https://x.test/a"]}
    )
    hub.propose_hypothesis(
        statement="Admin panel exists",
        rationale="found in robots.txt",
        test_plan="GET /admin and compare response with /",
    )
    actions = hub.next_actions(limit=10)
    first = actions[0]
    assert first["priority"] == PRIORITY_HYPOTHESIS
    assert first["hypothesis_id"] == "H-001"
    assert first["instruction"] == "GET /admin and compare response with /"
    assert "tool" not in first


def test_unverified_high_finding_asks_for_verification(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.record_finding(title="Possible IDOR", severity="high", evidence="200 on foreign id")
    actions = hub.next_actions(limit=10)
    verify = tool_of(actions, "verify_finding")
    assert verify["priority"] == PRIORITY_VERIFY
    assert verify["arguments"]["finding_id"] == "F-001"
    assert "200 on foreign id" in verify["basis"]


def test_verified_findings_stop_asking_for_verification(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.record_finding(title="Possible IDOR", severity="high", verification="replayed")
    assert maybe_tool_of(hub.next_actions(limit=10), "verify_finding") is None


def test_next_actions_are_deduplicated_and_capped(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    for index in range(4):
        hub.remember_endpoint(url=f"https://x.test/p{index}")
    actions = hub.next_actions(limit=3)
    assert len(actions) == 3
    keys = [
        (action.get("tool"), str(action.get("arguments"))) for action in actions
    ]
    assert len(keys) == len(set(keys))


def test_coverage_gaps_report_shape(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.remember_endpoint(url="https://x.test/a")
    gaps = hub.strategy.coverage_gaps()
    assert gaps["endpoints"] == 1
    assert gaps["gaps"]["headers"]["tool"] == "header_audit"
    assert gaps["gaps"]["headers"]["missing"] == ["https://x.test/a"]
    assert gaps["findings"] == {}


def test_strategy_markdown_and_empty_state(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    empty = StrategyEngine(
        memory=hub.memory,
        surface=hub.surface,
        evidence=hub.evidence,
        hypotheses=hub.hypotheses,
    ).markdown()
    assert "Ask the user for the exact target URL" in empty
    hub.remember_endpoint(url="https://x.test/a")
    text = hub.strategy.markdown()
    assert "# Next actions" in text
    assert "`header_audit`" in text
    assert "- because:" in text


# ------------------------------------------------------------------- evidence
def test_record_and_verify_close_hypotheses(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    record = hub.record_finding(title="SQLi in search", severity="critical", evidence="' OR 1=1")
    hyp = hub.propose_hypothesis(
        statement="Search parameter is injectable",
        rationale="error-based responses differ",
        test_plan="send a quote and compare errors",
        evidence=[record["id"]],
    )
    assert hub.finding_exists("F-001") is True

    verified = hub.verify_finding("F-001", method="sqlmap confirmed", confirmed=True)

    assert verified["status"] == "verified"
    assert verified["closed_hypotheses"] == [hyp["id"]]
    assert hub.hypotheses.get(hyp["id"])["status"] == "supported"
    assert hub.hypotheses.open() == []


def test_refuting_a_finding_refutes_hypotheses(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    record = hub.record_finding(title="Guess", severity="low")
    hyp = hub.propose_hypothesis(
        statement="Guess is real",
        rationale="looks odd",
        test_plan="retest carefully",
        evidence=[record["id"]],
    )
    hub.verify_finding("F-001", method="not reproducible", confirmed=False)
    assert hub.hypotheses.get(hyp["id"])["status"] == "refuted"
    assert hub.evidence.status_counts() == {"refuted": 1}


def test_verified_record_closes_hypotheses_on_record(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    first = hub.record_finding(title="Confirmed", severity="high", verification="proved")
    hub.propose_hypothesis(
        statement="Confirmed is real",
        rationale="already known",
        test_plan="none",
        evidence=[first["id"]],
    )
    # a second, different finding carrying verification closes its own citations
    second = hub.record_finding(title="Other", severity="high", verification="proved")
    assert "closed_hypotheses" not in second
    assert hub.hypotheses.stats()["open"] == 1


# ---------------------------------------------------------------------- plans
def test_set_plan_validates_steps(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    with pytest.raises(ValueError, match="steps"):
        hub.set_plan("assess x.test", [])
    with pytest.raises(ValueError, match="at most"):
        hub.set_plan("big", [f"step {i}" for i in range(26)])
    with pytest.raises(ValueError, match="status"):
        hub.set_plan("assess", ["a", {"title": "b", "status": "wat"}])
    with pytest.raises(ValueError, match="title"):
        hub.set_plan("assess", ["ok", "   "])


def test_plan_roundtrip(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    plan = hub.set_plan("assess x.test", ["recon", {"title": "headers", "status": "done"}])
    assert [step["index"] for step in plan["steps"]] == [1, 2]
    assert plan["steps"][1]["status"] == "done"

    step = hub.update_step(1, "in_progress")
    assert step["status"] == "in_progress"
    assert hub.plan()["steps"][0]["status"] == "in_progress"

    note = hub.update_step(1, "blocked", note="target unreachable")
    assert note["note"] == "target unreachable"
    assert "target unreachable" in hub.brief()


def test_update_step_validation(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    with pytest.raises(ValueError, match="no plan"):
        hub.update_step(1, "done")
    hub.set_plan("g", ["a", "b"])
    with pytest.raises(ValueError, match="between"):
        hub.update_step(3, "done")
    with pytest.raises(ValueError, match="integer"):
        hub.update_step("1", "done")
    with pytest.raises(ValueError, match="Step status"):
        hub.update_step(1, "wat")


def test_plan_statuses_constant() -> None:
    assert PLAN_STATUSES == ("pending", "in_progress", "done", "blocked", "skipped")


# --------------------------------------------------------------- notes + brief
def test_note_and_prefer(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    record = hub.note("banner", "server is nginx", "x.test")
    assert record["kind"] == "banner"
    assert hub.prefer("always start with recon")["text"] == "always start with recon"
    with pytest.raises(ValueError, match="empty"):
        hub.note("banner", "  ")
    with pytest.raises(ValueError, match="empty"):
        hub.prefer("")


def test_brief_combines_memory_and_coverage(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    assert hub.brief() == ""
    hub.remember_endpoint(url="https://x.test/a?id=1", tech="nginx")
    hub.set_plan("assess x.test", ["recon", "headers"])
    hub.propose_hypothesis(statement="admin exists", rationale="robots", test_plan="probe /admin")
    hub.record_finding(title="Missing HSTS", severity="medium", evidence="no header")

    brief = hub.brief()

    assert "Known endpoints" in brief
    assert "assess x.test" in brief
    assert "Open hypotheses (1)" in brief
    assert "1 graph nodes" not in brief
    assert "graph nodes" in brief
    assert "findings 1 suspected" in brief
    assert "Coverage gaps" in brief
    assert len(brief) <= 2000


def test_markdown_includes_all_three_reports(tmp_path: Path) -> None:
    hub = make_hub(tmp_path)
    hub.remember_endpoint(url="https://x.test/a", tech="nginx")
    hub.propose_hypothesis(statement="A", rationale="r", test_plan="t")
    text = hub.markdown()
    assert "# Attack surface" in text
    assert "# Hypotheses" in text
    assert "# Next actions" in text


def test_intel_state_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.json"
    hub = IntelHub(memory_path=path, scope="https://x.test")
    hub.observe_tool_result(
        "http_probe", {"results": [{"url": "https://x.test/a"}]}, {"urls": ["https://x.test/a"]}
    )
    hub.set_plan("assess", ["recon"])

    reloaded = IntelHub(memory_path=path, scope="https://x.test")

    assert reloaded.memory.endpoints()[0]["url"] == "https://x.test/a"
    assert reloaded.plan()["steps"][0]["title"] == "recon"
    assert reloaded.surface.hosts() == ["x.test"]
    assert reloaded.brief() != ""
