from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from cyberaent.safety import SafetyGate
from cyberaent.tools import terminal
from cyberaent.tools.base import RiskLevel, ToolRegistry
from cyberaent.tools.terminal import (
    CommandHistory,
    RateLimiter,
    TerminalTool,
    build_terminal_tool,
    classify_risk,
    find_hard_block,
)

PY = sys.executable


def make_tool(**kwargs: Any) -> TerminalTool:
    return TerminalTool(**kwargs)


def run_py(tool: TerminalTool, code: str, **extra: Any) -> dict[str, Any]:
    argv = [PY, "-c", code]
    payload: dict[str, Any] = {**extra}
    return tool.execute({"argv": argv, **payload})


def test_hard_blocks() -> None:
    cases = [
        (["bash", "-c", "rm -rf /"], "shell"),
        (["powershell.exe", "-Command", "x"], "shell"),
        (["wsl", "nmap"], "shell"),
        (["cmd", "/c", "dir"], "shell"),
        (["rm", "-rf", "/"], None),
        (["rm", "-fr", "~"], None),
        (["rm", "-r", "/"], None),
        (["del", "/s", "/q", "C:\\"], None),
        (["dd", "if=x", "of=/dev/sda"], None),
        (["format", "D:"], None),
        (["shutdown", "/s"], None),
        (["reg", "delete", "HKLM\\X"], None),
    ]
    for argv, _marker in cases:
        reason = find_hard_block(argv)
        assert reason is not None, f"expected block for {argv}"


def test_benign_commands_not_blocked(monkeypatch: Any) -> None:
    fake_which = lambda name, **kw: r"C:\Windows\System32\where.exe"  # noqa: E731
    monkeypatch.setattr(terminal.shutil, "which", fake_which)
    tool = make_tool()
    assert tool.block_reason({"argv": ["where", "nmap"]}) is None
    assert find_hard_block(["git", "status"]) is None
    assert find_hard_block(["nmap", "-sV", "example.com"]) is None


def test_unresolvable_executable_blocked() -> None:
    tool = make_tool()
    reason = tool.block_reason({"argv": ["definitely-not-a-real-tool-xyz"]})
    assert reason is not None and "not found" in reason


def test_script_shim_blocked(monkeypatch: Any) -> None:
    monkeypatch.setattr(terminal.shutil, "which", lambda name, **kw: r"C:\npm\npm.cmd")
    tool = make_tool()
    reason = tool.block_reason({"argv": ["npm", "install"]})
    assert reason is not None and "shim" in reason


def test_argv_shape_problems() -> None:
    tool = make_tool()
    assert tool.block_reason({"argv": []}) is not None
    assert tool.block_reason({"argv": ["x", ""]}) is not None
    assert tool.block_reason({"argv": [["nested"]]}) is not None
    long_argv: list[str] = [f"a{i}" for i in range(65)]
    assert tool.block_reason({"argv": long_argv}) is not None


def test_classify_version_flags_low() -> None:
    assert classify_risk([PY, "--version"]) is RiskLevel.LOW
    assert classify_risk(["nuclei", "-version"]) is RiskLevel.LOW
    assert classify_risk(["go", "version"]) is RiskLevel.LOW


def test_classify_readonly_and_tiers() -> None:
    assert classify_risk(["whoami"]) is RiskLevel.LOW
    assert classify_risk(["uname", "-a"]) is RiskLevel.LOW
    assert classify_risk(["where", "nmap"]) is RiskLevel.LOW

    assert classify_risk(["nmap", "-sV", "example.com"]) is RiskLevel.MEDIUM
    assert classify_risk(["totally-unknown-binary", "x"]) is RiskLevel.MEDIUM
    assert classify_risk(["pip", "list"]) is RiskLevel.MEDIUM

    assert classify_risk(["winget", "install", "wireshark"]) is RiskLevel.HIGH
    assert classify_risk(["apt-get", "install", "nmap"]) is RiskLevel.HIGH
    assert classify_risk(["pip", "install", "requests"]) is RiskLevel.HIGH
    assert classify_risk(["winget"]) is RiskLevel.HIGH


def test_execution_success_stdout_exit_duration() -> None:
    result = run_py(make_tool(), "print('hello-term')")
    assert result["exit_code"] == 0
    assert "hello-term" in result["stdout"]
    assert result["timed_out"] is False
    assert result["duration"] >= 0
    assert result["summary"].startswith("exit=0")


def test_execution_captures_stderr_and_nonzero_exit() -> None:
    code = "import sys; print('out-line'); sys.stderr.write('err-line'); sys.exit(3)"
    result = run_py(make_tool(), code)
    assert result["exit_code"] == 3
    assert "out-line" in result["stdout"]
    assert "err-line" in result["stderr"]


def test_timeout_terminates_command() -> None:
    result = run_py(make_tool(), "import time; time.sleep(5); print('late')", timeout_sec=1)
    assert result["timed_out"] is True
    assert result["exit_code"] is None
    assert result["error"] == "timeout"
    assert "late" not in result.get("stdout", "")


def test_large_output_truncated() -> None:
    result = run_py(make_tool(), "print('x' * 60000)")
    assert len(result["stdout"]) < 61000
    assert "[truncated" in result["stdout"]


def test_history_and_jsonl_logging(tmp_path: Any) -> None:
    log_path = tmp_path / "logs" / "commands.jsonl"
    history = CommandHistory()
    tool = make_tool(history=history, log_path=log_path)

    run_py(tool, "print('logged')")

    assert len(history.entries) == 1
    entry = history.entries[0]
    assert entry["status"] == "executed"
    assert entry["exit_code"] == 0
    assert str(PY) in entry["command"]

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["status"] == "executed"

    recent = history.recent(10)
    assert recent == history.entries


def test_blocked_attempt_is_logged(tmp_path: Any) -> None:
    history = CommandHistory()
    tool = make_tool(history=history)

    result = tool.execute({"argv": ["format", "D:"]})

    assert result["error"] == "blocked_by_safety_gate"
    assert history.entries[0]["status"] == "blocked"


def test_rate_limiter_blocks_burst() -> None:
    tool = make_tool(limiter=RateLimiter(max_per_minute=2))

    first = run_py(tool, "pass")
    second = run_py(tool, "pass")
    third = run_py(tool, "pass")

    assert first.get("error") is None
    assert second.get("error") is None
    assert third["error"] == "rate_limited"


def test_resolved_executable_is_used(monkeypatch: Any) -> None:
    captured: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        captured.append(list(argv))
        assert kwargs.get("shell") is False
        from types import SimpleNamespace

        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(terminal.shutil, "which", lambda name, **kw: r"C:\fake\tool.exe")
    monkeypatch.setattr(terminal.subprocess, "run", fake_run)

    result = make_tool().execute({"argv": ["tool", "--flag"]})

    assert result["exit_code"] == 0
    assert captured[0][0] == r"C:\fake\tool.exe"
    assert captured[0][1:] == ["--flag"]


def test_gate_integrates_terminal_policy(monkeypatch: Any) -> None:
    monkeypatch.setattr(terminal.shutil, "which", lambda name, **kw: r"C:\bin\prog.exe")
    registry = ToolRegistry()
    registry.register(build_terminal_tool())
    gate = SafetyGate(registry)

    low = gate.evaluate("terminal", {"argv": ["where", "nmap"]})
    assert low.allowed and not low.requires_confirmation

    medium = gate.evaluate("terminal", {"argv": ["nmap", "-sV", "example.com"]})
    assert medium.allowed and medium.requires_confirmation
    assert "medium" in medium.reason

    high = gate.evaluate("terminal", {"argv": ["winget", "install", "x"]})
    assert high.allowed and high.requires_confirmation
    assert "high" in high.reason

    blocked = gate.evaluate("terminal", {"argv": ["bash", "-c", "x"]})
    assert not blocked.allowed and "shell" in blocked.reason

    missing = gate.evaluate("terminal", {"timeout_sec": 30})
    assert not missing.allowed and "argv" in missing.reason


def test_gate_rejects_out_of_bounds_timeout() -> None:
    registry = ToolRegistry()
    spec = build_terminal_tool()
    registry.register(spec)

    too_big = SafetyGate(registry).evaluate("terminal", {"argv": ["x"], "timeout_sec": 999})
    assert not too_big.allowed
    zero = SafetyGate(registry).evaluate("terminal", {"argv": ["x"], "timeout_sec": 0})
    assert not zero.allowed


@pytest.mark.parametrize("command", ["/history"])
def test_slash_commands(command: str) -> None:
    from cyberaent.app import SLASH_COMMANDS, handle_command

    assert handle_command(command) == command
    assert command in SLASH_COMMANDS


def test_clamp_timeout_defaults_and_bounds() -> None:
    assert TerminalTool._clamp_timeout(None) == 30
    assert TerminalTool._clamp_timeout("abc") == 30
    assert TerminalTool._clamp_timeout(True) == 30
    assert TerminalTool._clamp_timeout(500) == 300
    assert TerminalTool._clamp_timeout(0) == 1
    assert TerminalTool._clamp_timeout(42) == 42


def test_command_budget_exhausts_session() -> None:
    history = CommandHistory()
    tool = make_tool(history=history, max_commands=2)

    first = run_py(tool, "pass")
    second = run_py(tool, "pass")
    third = run_py(tool, "pass")

    assert first.get("error") is None and second.get("error") is None
    assert third["error"] == "command_budget_exhausted"
    assert "100" not in third["reason"]
    assert history.entries[-1]["status"] == "budget_exhausted"

    before = len(history.entries)
    blocked = tool.execute({"argv": ["format", "D:"]})
    assert blocked["error"] == "blocked_by_safety_gate"
    assert tool._attempts == 2
    assert len(history.entries) == before + 1


def test_gate_decision_exposes_dynamic_risk(monkeypatch: Any) -> None:
    monkeypatch.setattr(terminal.shutil, "which", lambda name, **kw: r"C:\bin\prog.exe")
    registry = ToolRegistry()
    registry.register(build_terminal_tool())
    gate = SafetyGate(registry)

    scan = gate.evaluate("terminal", {"argv": ["nmap", "-sV", "example.com"]})
    assert scan.risk is RiskLevel.MEDIUM

    readonly = gate.evaluate("terminal", {"argv": ["where", "nmap"]})
    assert readonly.risk is RiskLevel.LOW

    install = gate.evaluate("terminal", {"argv": ["winget", "install", "x"]})
    assert install.risk is RiskLevel.HIGH
