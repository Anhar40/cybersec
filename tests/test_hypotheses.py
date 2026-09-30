from __future__ import annotations

from pathlib import Path

import pytest

from cyberaent.hypotheses import (
    HYPOTHESIS_STATUSES,
    HypothesisStore,
)
from cyberaent.memory import SessionMemory
from cyberaent.tools.evidence import EvidenceStore


def make_store(
    tmp_path: Path, *, finding_exists: bool = False
) -> tuple[HypothesisStore, EvidenceStore]:
    memory = SessionMemory(tmp_path / "knowledge.json")
    evidence = EvidenceStore()
    if finding_exists:
        evidence.add(source_tool="manual", title="IDOR in orders", severity="high")
    return HypothesisStore(memory, finding_exists=lambda ref: any(
        f["id"].lower() == ref.lower() for f in evidence.findings()
    )), evidence


# ------------------------------------------------------------------- constants
def test_status_ordering() -> None:
    assert HYPOTHESIS_STATUSES == ("proposed", "testing", "supported", "refuted")


# ----------------------------------------------------------------------- write
def test_propose_requires_rationale_and_plan(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    with pytest.raises(ValueError, match="statement"):
        store.propose(statement="  ", rationale="because", test_plan="curl")
    with pytest.raises(ValueError, match="rationale"):
        store.propose(statement="IDOR in /api/orders", rationale="", test_plan="curl")
    with pytest.raises(ValueError, match="test_plan"):
        store.propose(statement="IDOR in /api/orders", rationale="ids are sequential", test_plan="")


def test_propose_creates_pending_hypothesis(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    record = store.propose(
        statement="/api/orders/{id} has no ownership check",
        rationale="ids look sequential and unauthenticated 200s were returned",
        test_plan="request /api/orders/1002 as user bob and compare order owner",
    )
    assert record["id"] == "H-001"
    assert record["status"] == "proposed"
    assert record["evidence"] == []
    assert record["decided_at"] == ""
    assert store.counts()["proposed"] == 1


def test_propose_dedupes_identical_statements(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    first = store.propose(
        statement="Admin panel is reachable",
        rationale="found in sitemap",
        test_plan="GET /admin and check response",
    )
    second = store.propose(
        statement="admin panel is reachable",
        rationale="found in sitemap",
        test_plan="GET /admin and check response",
    )
    assert second["id"] == first["id"]
    assert len(store.all()) == 1


def test_propose_rejects_unknown_evidence_ref(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path, finding_exists=True)
    with pytest.raises(ValueError, match="F-404"):
        store.propose(
            statement="Bad input",
            rationale="guess",
            test_plan="curl",
            evidence=["F-404"],
        )
    ok = store.propose(
        statement="Good input",
        rationale="guess",
        test_plan="curl",
        evidence="F-001",
    )
    assert ok["evidence"] == ["F-001"]


def test_attach_evidence(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path, finding_exists=True)
    record = store.propose(statement="X", rationale="r", test_plan="t")
    with pytest.raises(ValueError, match="at least one"):
        store.attach_evidence(record["id"], [])
    with pytest.raises(ValueError, match="F-404"):
        store.attach_evidence(record["id"], ["F-404"])
    updated = store.attach_evidence(record["id"], ["F-001", "F-001"])
    assert updated["evidence"] == ["F-001"]


def test_set_status_requires_evidence_for_decisions(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    record = store.propose(statement="X", rationale="r", test_plan="t")
    assert store.set_status(record["id"], status="testing")["status"] == "testing"
    with pytest.raises(ValueError, match="without evidence"):
        store.set_status(record["id"], status="supported")
    with pytest.raises(ValueError, match="status"):
        store.set_status(record["id"], status="probably")


def test_set_status_supports_and_refutes(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path, finding_exists=True)
    record = store.propose(statement="X", rationale="r", test_plan="t", evidence=["F-001"])
    supported = store.set_status(record["id"], status="supported")
    assert supported["status"] == "supported"
    assert supported["decided_at"]

    other = store.propose(statement="Y", rationale="r", test_plan="t", evidence=["F-001"])
    refuted = store.set_status(other["id"], status="refuted", note="input is normalized")
    assert refuted["status"] == "refuted"
    assert refuted["rationale"] == "input is normalized"


def test_resolve_by_finding_closes_open_hypotheses(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path, finding_exists=True)
    first = store.propose(statement="X", rationale="r", test_plan="t", evidence=["F-001"])
    second = store.propose(statement="Y", rationale="r", test_plan="t", evidence=["F-001"])
    store.testing(first["id"])
    closed = store.resolve_by_finding("F-001", supported=True)
    assert {row["id"] for row in closed} == {first["id"], second["id"]}
    assert store.open() == []


def test_hypothesis_capacity(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    for i in range(200):
        store.propose(statement=f"claim {i}", rationale="r", test_plan="t")
    with pytest.raises(ValueError, match="full"):
        store.propose(statement="one too many", rationale="r", test_plan="t")


# ------------------------------------------------------------------------ read
def test_next_tests_prioritizes_testing(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    a = store.propose(statement="A", rationale="r", test_plan="probe A")
    store.propose(statement="B", rationale="r", test_plan="probe B")
    store.testing(a["id"])
    plans = store.next_tests()
    assert plans[0]["hypothesis_id"] == a["id"]
    assert plans[0]["test_plan"] == "probe A"
    assert len(plans) == 2


def test_stats_reports_precision(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path, finding_exists=True)
    good = store.propose(statement="A", rationale="r", test_plan="t", evidence=["F-001"])
    store.propose(statement="B", rationale="r", test_plan="t", evidence=["F-001"])
    store.set_status(good["id"], status="supported")
    stats = store.stats()
    assert stats["total"] == 2
    assert stats["open"] == 1
    assert stats["decided"] == 1
    assert stats["precision"] == 1.0


def test_markdown_reports_pending_tests(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    assert "No hypotheses recorded yet" in store.markdown()
    store.propose(statement="A", rationale="r", test_plan="probe A")
    text = store.markdown()
    assert "# Hypotheses" in text
    assert "| H-001 | proposed | A | - |" in text
    assert "- **H-001** — probe A" in text


def test_unknown_hypothesis_raises(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    with pytest.raises(ValueError, match="No hypothesis"):
        store.get("H-999")
    with pytest.raises(ValueError, match="hypothesis_id"):
        store.get("   ")


def test_hypotheses_persist_with_memory(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.json"
    memory = SessionMemory(path)
    store = HypothesisStore(memory)
    record = store.propose(statement="X", rationale="r", test_plan="t")
    memory.save()

    reloaded = HypothesisStore(SessionMemory(path))
    assert reloaded.get(record["id"])["statement"] == "X"
    assert "Open hypotheses (1)" in reloaded._memory.brief()
