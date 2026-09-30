from __future__ import annotations

from pathlib import Path

import pytest

from cyberaent.intel import IntelHub
from cyberaent.safety import SafetyGate
from cyberaent.tools.base import RiskLevel, ToolRegistry, ToolSpec
from cyberaent.tools.evidence import build_evidence_tools
from cyberaent.tools.intel import INTEL_TOOL_NAMES, build_intel_tools

TOOL_NAMES = (
    "set_plan",
    "update_plan_step",
    "remember_endpoint",
    "note_observation",
    "remember_preference",
    "propose_hypothesis",
    "update_hypothesis",
    "recall_memory",
    "next_actions",
)


@pytest.fixture()
def hub(tmp_path: Path) -> IntelHub:
    return IntelHub(memory_path=tmp_path / "knowledge.json")


@pytest.fixture()
def specs(hub: IntelHub) -> dict[str, ToolSpec]:
    return {spec.name: spec for spec in build_intel_tools(hub)}


# --------------------------------------------------------------------- registry
def test_tool_set_is_exactly_intel_tools(specs: dict[str, ToolSpec]) -> None:
    assert set(specs) == set(TOOL_NAMES)
    assert set(INTEL_TOOL_NAMES) == set(TOOL_NAMES)


def test_all_intel_tools_are_low_risk(specs: dict[str, ToolSpec]) -> None:
    assert all(spec.risk is RiskLevel.LOW for spec in specs.values())


def test_gate_accepts_valid_intel_calls(specs: dict[str, ToolSpec], hub: IntelHub) -> None:
    registry = ToolRegistry()
    for spec in specs.values():
        registry.register(spec)

    gate = SafetyGate(registry)

    assert gate.evaluate("set_plan", {"steps": ["recon"]}).allowed is True
    assert gate.evaluate("note_observation", {"text": "nginx banner"}).allowed is True
    assert gate.evaluate("next_actions", {}).allowed is True
    assert gate.evaluate("recall_memory", {"query": "nginx"}).allowed is True
    assert (
        gate.evaluate(
            "propose_hypothesis",
            {"statement": "s", "rationale": "r", "test_plan": "t"},
        ).allowed
        is True
    )


def test_gate_rejects_malformed_intel_calls(specs: dict[str, ToolSpec]) -> None:
    registry = ToolRegistry()
    for spec in specs.values():
        registry.register(spec)

    gate = SafetyGate(registry)

    assert gate.evaluate("set_plan", {}).allowed is False
    assert gate.evaluate("note_observation", {}).allowed is False
    assert gate.evaluate("remember_endpoint", {}).allowed is False
    assert gate.evaluate("update_plan_step", {"index": 1, "status": "wat"}).allowed is False
    assert (
        gate.evaluate("propose_hypothesis", {"statement": "s", "rationale": "r"}).allowed is False
    )
    assert gate.evaluate("update_hypothesis", {"hypothesis_id": "H-1"}).allowed is False


# ------------------------------------------------------------------ plan tools
def test_set_plan_tool_roundtrip(specs: dict[str, ToolSpec], hub: IntelHub) -> None:
    payload = specs["set_plan"].handler(
        {"goal": "assess x.test", "steps": ["recon", {"title": "headers", "status": "done"}]}
    )
    assert payload["plan"]["steps"][1]["status"] == "done"
    assert "2 step" in payload["summary"]

    update = specs["update_plan_step"].handler({"index": 1, "status": "in_progress"})
    assert update["step"]["status"] == "in_progress"
    assert hub.plan()["steps"][0]["status"] == "in_progress"


def test_plan_tools_return_recoverable_errors(specs: dict[str, ToolSpec]) -> None:
    bad_plan = specs["set_plan"].handler({"goal": "g", "steps": []})
    assert bad_plan["error"] == "invalid_arguments"
    assert bad_plan["reason"]

    no_plan = specs["update_plan_step"].handler({"index": 1, "status": "done"})
    assert no_plan["error"] == "invalid_arguments"
    assert "no plan" in no_plan["detail"]

    specs["set_plan"].handler({"steps": ["only step"]})
    out_of_range = specs["update_plan_step"].handler({"index": 9, "status": "done"})
    assert out_of_range["error"] == "invalid_arguments"


# -------------------------------------------------------------- memory tools
def test_remember_endpoint_tool(specs: dict[str, ToolSpec], hub: IntelHub) -> None:
    payload = specs["remember_endpoint"].handler(
        {
            "url": "https://x.test/api?id=1",
            "method": "post",
            "params": "id, page",
            "tech": "nginx",
            "auth": "bearer",
            "role": "admin",
            "status": 200,
        }
    )
    assert payload["node"] == "endpoint:post https://x.test/api"
    assert hub.memory.endpoints()[0]["params"] == ["id", "page"]
    assert hub.surface.technologies() == ["nginx"]

    bad = specs["remember_endpoint"].handler({"url": "   "})
    assert bad["error"] == "invalid_arguments"


def test_note_and_preference_tools(specs: dict[str, ToolSpec], hub: IntelHub) -> None:
    assert specs["note_observation"].handler({"kind": "banner", "text": "nginx"})["observation"]
    assert specs["remember_preference"].handler({"text": "quiet first"})["preference"]
    assert specs["remember_preference"].handler({"text": "  "})["error"] == "invalid_arguments"
    assert hub.memory.preferences()[0]["text"] == "quiet first"


def test_recall_memory_tool(specs: dict[str, ToolSpec], hub: IntelHub) -> None:
    hub.remember_endpoint(url="https://x.test/api", tech="nginx")
    payload = specs["recall_memory"].handler({"query": "nginx", "limit": 5})
    assert payload["count"] >= 1
    assert any(row["memory_kind"] == "technology" for row in payload["memories"])

    filtered = specs["recall_memory"].handler({"kinds": ["endpoint"], "limit": 3})
    assert all(row["memory_kind"] == "endpoint" for row in filtered["memories"])

    assert specs["recall_memory"].handler({"limit": 999})["count"] >= 1
    assert specs["recall_memory"].handler({"limit": "many"})["error"] == "invalid_arguments"


# ----------------------------------------------------------- hypothesis tools
def test_propose_hypothesis_tool(specs: dict[str, ToolSpec]) -> None:
    payload = specs["propose_hypothesis"].handler(
        {
            "statement": "Admin panel is exposed",
            "rationale": "listed in robots.txt",
            "test_plan": "GET /admin",
        }
    )
    assert payload["hypothesis"]["id"] == "H-001"
    assert "H-001 recorded" in payload["summary"]

    incomplete = specs["propose_hypothesis"].handler({"statement": "s", "rationale": "r"})
    assert incomplete["error"] == "invalid_arguments"
    assert "test plan" in incomplete["reason"]


def test_update_hypothesis_tool_requires_evidence(specs: dict[str, ToolSpec]) -> None:
    specs["propose_hypothesis"].handler(
        {"statement": "s", "rationale": "r", "test_plan": "t"}
    )
    testing = specs["update_hypothesis"].handler({"hypothesis_id": "H-001", "status": "testing"})
    assert testing["hypothesis"]["status"] == "testing"

    verdict = specs["update_hypothesis"].handler({"hypothesis_id": "H-001", "status": "supported"})
    assert verdict["error"] == "invalid_arguments"
    assert "evidence" in verdict["detail"]

    bad_ref = specs["update_hypothesis"].handler(
        {"hypothesis_id": "H-001", "status": "supported", "evidence": ["F-404"]}
    )
    assert "F-404" in bad_ref["detail"]


def test_update_hypothesis_tool_with_evidence(specs: dict[str, ToolSpec], hub: IntelHub) -> None:
    finding = hub.record_finding(title="Missing HSTS", severity="medium", evidence="no header")
    specs["propose_hypothesis"].handler(
        {
            "statement": "HSTS is missing",
            "rationale": "no header on probe",
            "test_plan": "curl -I and read headers",
            "evidence": [finding["id"]],
        }
    )
    payload = specs["update_hypothesis"].handler(
        {"hypothesis_id": "H-001", "status": "supported"}
    )
    assert payload["hypothesis"]["status"] == "supported"
    assert payload["summary"] == "H-001 is now supported"


# ------------------------------------------------------------- next actions
def test_next_actions_tool(specs: dict[str, ToolSpec], hub: IntelHub) -> None:
    empty = specs["next_actions"].handler({})
    assert empty["count"] == 1
    assert empty["actions"][0]["instruction"]
    assert "tool" not in empty["actions"][0]

    hub.remember_endpoint(url="https://x.test/a")
    payload = specs["next_actions"].handler({"limit": 3})
    assert payload["count"] == 3
    assert all("reason" in action and "basis" in action for action in payload["actions"])


# ------------------------------------------------------- evidence <-> intel
def test_evidence_tools_use_intel_bridge(hub: IntelHub, tmp_path: Path) -> None:
    evidence_specs = {
        spec.name: spec
        for spec in build_evidence_tools(
            store=hub.evidence, reports_dir=tmp_path / "reports", intel=hub
        )
    }
    record = evidence_specs["record_finding"].handler(
        {"title": "IDOR", "severity": "high", "evidence": "foreign order returned"}
    )
    assert record["finding"]["status"] == "suspected"
    duplicate = evidence_specs["record_finding"].handler({"title": "IDOR", "severity": "high"})
    assert duplicate["duplicate"] is True

    specs = {spec.name: spec for spec in build_intel_tools(hub)}
    specs["propose_hypothesis"].handler(
        {
            "statement": "Order ids are guessable",
            "rationale": "sequential ids in API",
            "test_plan": "request a neighbouring id",
            "evidence": ["F-001"],
        }
    )
    verified = evidence_specs["verify_finding"].handler(
        {"finding_id": "F-001", "method": "neighbouring id returned another user's order"}
    )
    assert verified["status"] == "verified"
    assert verified["closed_hypotheses"] == ["H-001"]
    assert hub.hypotheses.get("H-001")["status"] == "supported"


def test_evidence_tools_work_without_bridge(tmp_path: Path) -> None:
    from cyberaent.tools.evidence import EvidenceStore

    store = EvidenceStore()
    specs = {
        spec.name: spec
        for spec in build_evidence_tools(store=store, reports_dir=tmp_path / "reports")
    }
    payload = specs["record_finding"].handler({"title": "X", "severity": "low"})
    assert payload["duplicate"] is False
    assert store.findings()[0]["status"] == "suspected"
