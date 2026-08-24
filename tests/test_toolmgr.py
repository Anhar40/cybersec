from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cyberaent.safety import SafetyGate
from cyberaent.tools import probes, toolmgr
from cyberaent.tools.base import RiskLevel, ToolRegistry
from cyberaent.tools.probes import ToolProbe
from cyberaent.tools.toolmgr import (
    CommandHistory,
    ToolManager,
    build_tool_manager_tools,
    compute_missing_dirs,
)


def make_manager(**kwargs: Any) -> ToolManager:
    return ToolManager(**kwargs)


def register_all(monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> tuple[ToolRegistry, SafetyGate]:
    monkeypatch.setattr(toolmgr, "probes", probes)
    registry = ToolRegistry()
    for spec in build_tool_manager_tools(**kwargs):
        registry.register(spec)
    return registry, SafetyGate(registry)


def test_inventory_reports_known_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = {
        "nuclei": ToolProbe(name="nuclei", installed=True, path="C:/x/nuclei.exe", version="v2"),
        "ffuf": ToolProbe(name="ffuf", installed=False),
    }

    def fake_probe_tool(name: str) -> ToolProbe:
        return fake.get(name, ToolProbe(name=name, installed=False))

    monkeypatch.setattr(
        probes,
        "probe_tools",
        lambda names, time_budget_s=40.0: [fake_probe_tool(n) for n in names],
    )
    result = make_manager().inventory({})

    assert result["total_count"] >= len(toolmgr.INSTALL_PLANS)
    by_name = {t["name"]: t for t in result["tools"]}
    assert by_name["nuclei"]["installed"] is True
    assert by_name["ffuf"]["installed"] is False
    assert result["summary"].startswith("1/")


def test_inventory_respects_requested_names(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_probe_tools(names: list[str], time_budget_s: float = 40.0) -> list[ToolProbe]:
        seen.append(list(names))
        return [ToolProbe(name=n, installed=False) for n in names]

    monkeypatch.setattr(probes, "probe_tools", fake_probe_tools)
    result = make_manager().inventory({"names": ["go", "openssl"]})
    assert seen == [["go", "openssl"]]
    assert [t["name"] for t in result["tools"]] == ["go", "openssl"]


def test_install_gate_blocks_unknown_and_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    registry, gate = register_all(monkeypatch)
    monkeypatch.setattr(probes, "probe_tool", lambda name: ToolProbe(name=name, installed=True))

    unknown = gate.evaluate("install_tool", {"name": "definitely-not-managed"})
    assert not unknown.allowed and "no managed install plan" in unknown.reason

    installed = gate.evaluate("install_tool", {"name": "Nuclei"})
    assert not installed.allowed and "already installed" in installed.reason


def test_install_gate_blocks_when_no_installer(monkeypatch: pytest.MonkeyPatch) -> None:
    registry, gate = register_all(monkeypatch)
    monkeypatch.setattr(probes, "probe_tool", lambda name: ToolProbe(name=name, installed=False))
    monkeypatch.setattr(toolmgr, "available_installers", lambda: [])

    decision = gate.evaluate("install_tool", {"name": "nuclei"})
    assert not decision.allowed and "package manager" in decision.reason


def test_install_gate_high_risk_when_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    registry, gate = register_all(monkeypatch)
    monkeypatch.setattr(probes, "probe_tool", lambda name: ToolProbe(name=name, installed=False))
    monkeypatch.setattr(toolmgr, "available_installers", lambda: ["scoop"])

    decision = gate.evaluate("install_tool", {"name": "nuclei"})
    assert decision.allowed and decision.requires_confirmation
    assert decision.risk is RiskLevel.HIGH


def test_install_runs_plan_and_verifies(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    log_path = tmp_path / "logs" / "commands.jsonl"
    history = CommandHistory()
    mgr = make_manager(history=history, log_path=log_path)

    probe_calls = {"n": 0}

    def fake_probe(name: str) -> ToolProbe:
        probe_calls["n"] += 1
        if probe_calls["n"] == 1:
            return ToolProbe(name=name, installed=False)
        return ToolProbe(
            name=name, installed=True, path="C:/go/bin/nuclei.exe", version="v3"
        )

    monkeypatch.setattr(probes, "probe_tool", fake_probe)
    monkeypatch.setattr(
        toolmgr, "pick_plan", lambda name: ("scoop", ["scoop", "install", "nuclei"])
    )
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        calls.append(list(argv))
        assert kwargs.get("shell") is False
        return SimpleNamespace(returncode=0, stdout="installed!", stderr="")

    monkeypatch.setattr(toolmgr.subprocess, "run", fake_run)
    payload = mgr.install({"name": "nuclei"})

    assert calls == [["scoop", "install", "nuclei"]]
    assert payload["exit_code"] == 0
    assert payload["verification"]["installed"] is True
    assert "verified" in payload["summary"]
    assert "error" not in payload
    assert history.entries[0]["status"] == "verified"
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert json.loads(lines[0])["command"] == "[toolmgr] install nuclei via scoop"


def test_install_verification_failure_reports_error(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = make_manager()
    monkeypatch.setattr(probes, "probe_tool", lambda name: ToolProbe(name=name, installed=False))
    monkeypatch.setattr(toolmgr, "pick_plan", lambda name: ("go", ["go", "install", "x@latest"]))
    monkeypatch.setattr(
        toolmgr.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=0, stdout="ok", stderr=""),
    )
    payload = mgr.install({"name": "httpx"})

    assert payload["exit_code"] == 0
    assert payload["error"] == "verification_failed"
    assert "fix_path" in payload["reason"]
    assert payload["summary"].endswith("NOT verified · go install x@latest")


def test_install_timeout_and_oserror_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = make_manager()
    monkeypatch.setattr(probes, "probe_tool", lambda name: ToolProbe(name=name, installed=False))
    monkeypatch.setattr(toolmgr, "pick_plan", lambda name: ("go", ["go", "install", "x"]))

    def slow(argv: list[str], **kw: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="go", timeout=1200)

    monkeypatch.setattr(toolmgr.subprocess, "run", slow)
    timed_out = mgr.install({"name": "httpx"})
    assert timed_out["error"] == "timeout"

    def boom(argv: list[str], **kw: Any) -> Any:
        raise OSError("spawn failed")

    monkeypatch.setattr(toolmgr.subprocess, "run", boom)
    failed = mgr.install({"name": "httpx"})
    assert failed["error"] == "execution_failed"


def test_compute_missing_dirs_folds_case_on_windows(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    go_bin = tmp_path / "go" / "bin"
    go_bin.mkdir(parents=True)
    cargo_bin = tmp_path / ".cargo" / "bin"
    cargo_bin.mkdir(parents=True)
    ghost = tmp_path / "ghost"

    candidates = [str(go_bin), str(cargo_bin), str(ghost)]
    monkeypatch.setattr(toolmgr.os, "name", "nt")
    missing = compute_missing_dirs(candidates, [str(go_bin).upper() + "\\", "other"])
    assert missing == [str(cargo_bin)]


def test_compute_missing_dirs_is_case_sensitive_on_posix(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    go_bin = tmp_path / "go" / "bin"
    go_bin.mkdir(parents=True)
    other_bin = tmp_path / "other"
    other_bin.mkdir(parents=True)

    candidates = [str(go_bin), str(other_bin)]
    monkeypatch.setattr(toolmgr.os, "name", "posix")
    exact = compute_missing_dirs(candidates, [str(go_bin)])
    assert exact == [str(other_bin)]

    folded = compute_missing_dirs(candidates, [str(go_bin).upper()])
    assert folded == [str(go_bin), str(other_bin)]


def test_fix_path_dry_run_low_risk_apply_high_risk(monkeypatch: pytest.MonkeyPatch) -> None:
    registry, gate = register_all(monkeypatch)

    dry = gate.evaluate("fix_path", {})
    assert dry.allowed and not dry.requires_confirmation and dry.risk is RiskLevel.LOW

    monkeypatch.setattr(toolmgr.os, "name", "nt")
    apply_decision = gate.evaluate("fix_path", {"apply": True})
    assert apply_decision.requires_confirmation and apply_decision.risk is RiskLevel.HIGH


def test_fix_path_apply_allowed_on_posix_blocked_elsewhere(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, gate = register_all(monkeypatch)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(toolmgr.os, "name", "posix")

    decision = gate.evaluate("fix_path", {"apply": True})
    assert decision.allowed and decision.requires_confirmation
    assert decision.risk is RiskLevel.HIGH

    monkeypatch.setattr(toolmgr.os, "name", "java")
    exotic = gate.evaluate("fix_path", {"apply": True})
    assert not exotic.allowed and "POSIX" in exotic.reason


def test_fix_path_apply_persists_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = make_manager()
    go_bin = r"C:\Users\demo\go\bin"
    cargo_bin = r"C:\Users\demo\.cargo\bin"
    missing_dir = r"C:\nope\missing"

    real_is_dir = Path.is_dir

    def fake_is_dir(self: Path) -> bool:
        if str(self).lower() in {go_bin.lower(), cargo_bin.lower()}:
            return True
        return real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", fake_is_dir)
    monkeypatch.setattr(
        toolmgr, "candidate_tool_dirs", lambda: [go_bin, cargo_bin, missing_dir]
    )
    monkeypatch.setenv("PATH", r"C:\Windows\system32;C:\Other\Tool")
    persisted: list[list[str]] = []

    def fake_persist(additions: list[str]) -> dict[str, int]:
        persisted.append(list(additions))
        return {"previous_chars": 25, "new_chars": 80}

    monkeypatch.setattr(toolmgr, "_persist_user_path", fake_persist)
    monkeypatch.setattr(toolmgr.os, "name", "nt")

    payload = mgr.fix_path({"apply": True})

    assert payload["applied"] is True
    assert persisted == [[go_bin, cargo_bin]]
    assert "user PATH" in payload["summary"]

    dry = mgr.fix_path({})
    assert dry["applied"] is False
    assert dry["dirs_to_add"] == []
    assert "covers all known tool dirs" in dry["summary"]


def test_fix_path_apply_persists_on_posix(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = make_manager()
    go_bin = tmp_path / "go" / "bin"
    go_bin.mkdir(parents=True)
    profile = tmp_path / ".bashrc"
    original = "export EDITOR=vim\n"
    profile.write_text(original, encoding="utf-8")

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(toolmgr, "candidate_tool_dirs", lambda: [str(go_bin)])
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(toolmgr.os, "name", "posix")

    payload = mgr.fix_path({"apply": True})

    assert payload["applied"] is True
    assert payload["persistence"]["profile"] == str(profile)
    assert payload["persistence"]["backup"] == str(tmp_path / ".bashrc.cyberaent.bak")
    text = profile.read_text(encoding="utf-8")
    assert "export EDITOR=vim" in text
    assert f'export PATH="$PATH:{go_bin}"' in text
    assert text.count(toolmgr.PATH_BLOCK_BEGIN) == 1
    backup = tmp_path / ".bashrc.cyberaent.bak"
    assert backup.read_text(encoding="utf-8") == original
    first_entry = toolmgr.os.environ["PATH"].split(toolmgr.os.pathsep)[0]
    assert first_entry == str(go_bin)

    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    again = mgr.fix_path({"apply": True})
    assert again["applied"] is True
    rewritten = profile.read_text(encoding="utf-8")
    assert rewritten.count(toolmgr.PATH_BLOCK_BEGIN) == 1
    assert backup.read_text(encoding="utf-8") == original

    dry = mgr.fix_path({})
    assert dry["applied"] is False
    assert dry["dirs_to_add"] == []


def test_fix_path_posix_profile_selection(tmp_path: Any) -> None:
    assert toolmgr._select_posix_profile(tmp_path, {"SHELL": "/usr/bin/zsh"}) == (
        tmp_path / ".zshrc"
    )
    assert toolmgr._select_posix_profile(tmp_path, {"SHELL": "/bin/bash"}) == (
        tmp_path / ".bashrc"
    )
    plain = tmp_path / "no-rc"
    plain.mkdir()
    assert toolmgr._select_posix_profile(plain, {}) == plain / ".profile"
    (plain / ".bashrc").write_text("", encoding="utf-8")
    assert toolmgr._select_posix_profile(plain, {}) == plain / ".bashrc"


def test_fix_path_rejects_oversized_result(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = make_manager()
    filler = "C:\\" + "x" * (toolmgr.MAX_USER_PATH_CHARS - 10)
    monkeypatch.setattr(toolmgr, "candidate_tool_dirs", lambda: [filler])
    monkeypatch.setattr(Path, "is_dir", lambda self: True)
    monkeypatch.setenv("PATH", r"C:\Windows")
    monkeypatch.setattr(toolmgr.os, "name", "nt")

    result = mgr.fix_path({"apply": True})

    assert result["applied"] is False
    assert result["error"] == "path_too_long"


def test_registry_exposes_three_specs(monkeypatch: pytest.MonkeyPatch) -> None:
    specs = build_tool_manager_tools()
    names = [s.name for s in specs]
    assert names == ["tool_inventory", "install_tool", "fix_path"]
