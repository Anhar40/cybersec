from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberaent.memory import (
    MAX_ENDPOINTS,
    SessionMemory,
    canonical_url,
)
from cyberaent.surface import AttackSurface


def make_memory(tmp_path: Path) -> SessionMemory:
    return SessionMemory(tmp_path / "knowledge.json")


# ------------------------------------------------------------------ canonical
def test_canonical_url_extracts_params() -> None:
    canonical, params = canonical_url("HTTPS://Example.COM:443/api/v1/?b=2&a=1#frag")
    assert canonical == "https://example.com:443/api/v1"
    assert params == ["a", "b"]


def test_canonical_url_accepts_bare_host() -> None:
    canonical, params = canonical_url("target.co.id")
    assert canonical == "https://target.co.id/"
    assert params == []


# --------------------------------------------------------------------- memory
def test_remember_endpoint_dedupes_and_enriches(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    first = memory.remember_endpoint(
        url="https://x.test/api?id=1", method="get", tech="nginx"
    )
    assert first is not None
    second = memory.remember_endpoint(
        url="https://x.test/api?id=1", method="GET", tech="php", status=200
    )
    assert second is first
    entries = memory.endpoints()
    assert len(entries) == 1
    assert entries[0]["technologies"] == ["nginx", "php"]
    assert entries[0]["status"] == 200


def test_remember_endpoint_separates_methods_and_params(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    memory.remember_endpoint(url="https://x.test/api", method="GET", params=["q"])
    memory.remember_endpoint(url="https://x.test/api", method="POST")
    assert len(memory.endpoints()) == 2


def test_remember_endpoint_returns_none_for_empty(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    assert memory.remember_endpoint(url="") is None


def test_endpoints_cap_is_enforced(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    for i in range(MAX_ENDPOINTS + 25):
        memory.remember_endpoint(url=f"https://x.test/p{i}")
    assert len(memory.endpoints()) == MAX_ENDPOINTS


def test_technology_and_test_dedup(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    memory.remember_technology(name="Nginx", version="1.18", evidence="server header")
    memory.remember_technology(name="nginx", evidence="x-powered-by")
    techs = memory.technologies()
    assert len(techs) == 1
    assert techs[0]["version"] == "1.18"

    memory.remember_test(tool="header_audit", target="https://x.test")
    memory.remember_test(tool="header_audit", target="https://x.test", outcome="warn")
    tests = memory.tests(tool="header_audit")
    assert len(tests) == 1
    assert tests[0]["runs"] == 2
    assert tests[0]["outcome"] == "warn"


def test_test_done_matches_substring_target(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    assert memory.test_done("vuln_scan", "https://x.test") is False
    memory.remember_test(tool="vuln_scan", target="https://x.test/api")
    assert memory.test_done("vuln_scan", "https://x.test") is True
    assert memory.tools_already_run() == {"vuln_scan"}


def test_observations_preferences_and_recall(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    memory.remember_observation(kind="banner", text="server nginx", target="x.test")
    memory.remember_preference("selalu mulai dengan header_audit")
    memory.remember_preference("selalu mulai dengan header_audit")

    assert len(memory.preferences()) == 1
    rows = memory.recall(query="nginx")
    assert any(row["memory_kind"] == "observation" for row in rows)
    assert memory.recall(kinds=["endpoint"]) == []
    assert memory.observations(kind="banner")


def test_memory_persists_and_reloads(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.json"
    memory = SessionMemory(path)
    memory.remember_endpoint(url="https://x.test/a", tech="nginx")
    memory.remember_preference("quiet first")
    memory.save()
    assert json.loads(path.read_text(encoding="utf-8"))["endpoints"]

    reloaded = SessionMemory(path)
    assert reloaded.endpoints()[0]["url"] == "https://x.test/a"
    assert reloaded.preferences()[0]["text"] == "quiet first"
    assert reloaded.stats()["endpoints"] == 1


def test_memory_survives_corrupt_file(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.json"
    path.write_text("{not json", encoding="utf-8")
    memory = SessionMemory(path)
    assert memory.stats()["endpoints"] == 0


def test_brief_is_empty_when_no_knowledge(tmp_path: Path) -> None:
    assert make_memory(tmp_path).brief() == ""


def test_brief_summarizes_facts(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    memory.remember_endpoint(url="https://x.test/api?id=1", tech="nginx")
    memory.remember_technology(name="nginx", version="1.18")
    memory.remember_test(tool="header_audit", target="https://x.test/api")
    memory.remember_preference("avoid noisy scans")

    brief = memory.brief()

    assert "Known endpoints" in brief
    assert "https://x.test/api" in brief
    assert "id" in brief
    assert "nginx 1.18" in brief
    assert "header_audit" in brief
    assert "avoid noisy scans" in brief


def test_brief_shows_open_plan_steps(tmp_path: Path) -> None:
    memory = make_memory(tmp_path)
    memory.state["plan"] = {
        "goal": "assess x.test",
        "steps": [
            {"index": 1, "title": "recon", "status": "done"},
            {"index": 2, "title": "header audit", "status": "in_progress"},
            {"index": 3, "title": "fuzz", "status": "pending"},
        ],
        "updated_at": "",
    }
    memory.remember_endpoint(url="https://x.test")

    brief = memory.brief()

    assert "assess x.test" in brief
    assert "2. header audit" in brief
    assert "3. fuzz" in brief
    assert "1. recon" not in brief


# -------------------------------------------------------------------- surface
def test_surface_builds_nodes_and_edges(tmp_path: Path) -> None:
    surface = AttackSurface(make_memory(tmp_path))
    endpoint = surface.remember_endpoint(
        url="https://x.test/api/user?id=1",
        method="GET",
        params=["role"],
        tech="php",
        auth="bearer",
        role="admin",
        status=200,
    )

    assert endpoint == "endpoint:get https://x.test/api/user"
    assert surface.parameters() == ["id", "role"]
    assert surface.technologies() == ["php"]
    assert surface.hosts() == ["x.test"]

    tech_node = "technology:php"
    param_node = "parameter:id"
    assert surface.link(tech_node, "uses", endpoint) is not None
    assert any(edge["from"] == param_node for edge in surface.edges(relation="parameter_of"))
    assert any(edge["rel"] == "authenticates" for edge in surface.edges())
    assert any(edge["rel"] == "authorized_by" for edge in surface.edges())


def test_surface_neighbors_respects_kind(tmp_path: Path) -> None:
    surface = AttackSurface(make_memory(tmp_path))
    endpoint = surface.remember_endpoint(url="https://x.test/a", tech="nginx")
    assert endpoint is not None

    inbound = surface.neighbors(endpoint)
    assert any(node["kind"] == "technology" and node["direction"] == "in" for node in inbound)

    tech_only = surface.neighbors(endpoint, kind="technology")
    assert [node["label"] for node in tech_only] == ["nginx"]


def test_surface_ignores_unknown_kinds_and_edges(tmp_path: Path) -> None:
    surface = AttackSurface(make_memory(tmp_path))
    assert surface.upsert("bogus", "x") is None
    assert surface.upsert("role", "  ") is None
    endpoint = surface.remember_endpoint(url="https://x.test")
    assert endpoint is not None
    assert surface.link(endpoint, "eats", endpoint) is None
    assert surface.link("role:ghost", "uses", endpoint) is None


def test_surface_markdown_reports_sections(tmp_path: Path) -> None:
    surface = AttackSurface(make_memory(tmp_path))
    surface.remember_endpoint(
        url="https://x.test/api?q=1", tech="nginx", auth="cookie", role="user", status=200
    )

    text = surface.markdown()

    assert "# Attack surface" in text
    assert "## Endpoints" in text
    assert "## Parameters" in text
    assert "## Technologies" in text
    assert "## Roles" in text
    assert "## Auth schemes" in text


def test_surface_markdown_handles_empty(tmp_path: Path) -> None:
    assert "No surface data captured yet" in AttackSurface(make_memory(tmp_path)).markdown()


def test_surface_persists_with_memory(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.json"
    surface = AttackSurface(SessionMemory(path))
    surface.remember_endpoint(url="https://x.test/api?q=1", tech="nginx")
    surface.save()

    reloaded = AttackSurface(SessionMemory(path))

    assert reloaded.technologies() == ["nginx"]
    assert reloaded.parameters() == ["q"]
    assert reloaded.stats()["nodes"] >= 3


def test_surface_clear_empties_graph(tmp_path: Path) -> None:
    surface = AttackSurface(make_memory(tmp_path))
    surface.remember_endpoint(url="https://x.test")
    surface.clear()
    assert surface.stats()["nodes"] == 0


def test_surface_stats_counts_by_kind(tmp_path: Path) -> None:
    surface = AttackSurface(make_memory(tmp_path))
    surface.remember_endpoint(
        url="https://x.test/a?id=1", tech="nginx", auth="bearer", role="admin"
    )
    stats: dict[str, Any] = surface.stats()
    assert stats["endpoint"] == 1
    assert stats["parameter"] == 1
    assert stats["edges"] >= 3
