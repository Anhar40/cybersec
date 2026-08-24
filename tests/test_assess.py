from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cyberaent.safety import SafetyGate
from cyberaent.tools import probes
from cyberaent.tools.assess import build_vulnerability_tools
from cyberaent.tools.base import RiskLevel, ToolRegistry


def register_all(tmp_path: Path) -> tuple[ToolRegistry, SafetyGate]:
    registry = ToolRegistry()
    for spec in build_vulnerability_tools(log_path=tmp_path / "log.jsonl"):
        registry.register(spec)
    return registry, SafetyGate(registry)


def test_sqli_probe_registered_medium(tmp_path: Path) -> None:
    registry, _ = register_all(tmp_path)
    spec = registry.get("sqli_probe")
    assert spec is not None
    assert spec.risk == RiskLevel.MEDIUM


def test_gate_blocks_uncontrolled_or_pointless_calls(tmp_path: Path) -> None:
    _, gate = register_all(tmp_path)
    cases = [
        {"url": "https://host/item"},  # no query string
        {"url": "https://host/item?id=1", "level": 3},
        {"url": "https://host/item?id=1", "threads": 8},
        {"url": "https://user:pw@host/item?id=1"},
        {"url": "ftp://host/item?id=1"},
        {"url": "https://host/item?id=1", "data": "a=1\nb=rm -rf /"},
    ]
    for args in cases:
        decision = gate.evaluate("sqli_probe", args)
        assert not decision.allowed, f"{args} should be blocked"


def test_gate_accepts_controlled_call(tmp_path: Path) -> None:
    _, gate = register_all(tmp_path)
    args = {
        "url": "https://host/item?id=1",
        "level": 2,
        "data": "username=admin",
        "forms": True,
    }
    decision = gate.evaluate("sqli_probe", args)
    assert decision.allowed is True
    assert decision.requires_confirmation is True


def test_sqli_probe_builds_expected_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(probes, "resolve_executable", lambda name: "sqlmap.exe")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append(argv)
        assert kwargs.get("shell") is False
        return SimpleNamespace(returncode=0, stdout="no injection found", stderr="")

    registry_specs = build_vulnerability_tools(
        log_path=tmp_path / "log.jsonl", runner=fake_run
    )
    spec = registry_specs[0]
    result = spec.handler({"url": "http://127.0.0.1/item.php?id=1", "level": 2})
    argv = calls[0]
    assert argv[0] == "sqlmap" and "--batch" in argv
    assert "--risk" in argv and argv[argv.index("--risk") + 1] == "1"
    assert "--level" in argv and argv[argv.index("--level") + 1] == "2"
    assert "--threads" in argv and argv[argv.index("--threads") + 1] == "2"
    assert "-u" in argv and argv[-1] == "http://127.0.0.1/item.php?id=1"
    assert result["exit_code"] == 0
