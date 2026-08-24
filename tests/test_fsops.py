from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberaent.safety import SafetyGate
from cyberaent.tools import fsops
from cyberaent.tools.base import RiskLevel, ToolRegistry
from cyberaent.tools.fsops import (
    MAX_PATHS_PER_CALL,
    FileDeletionTool,
    build_fsops_tools,
    classify_deletions,
)
from cyberaent.tools.terminal import CommandHistory


def make_tool(tmp_path: Path, log_name: str = "commands.jsonl") -> tuple[FileDeletionTool, Path]:
    history = CommandHistory()
    log_path = tmp_path / log_name
    return FileDeletionTool(history=history, log_path=log_path), log_path


def register(monkeypatch: pytest.MonkeyPatch) -> SafetyGate:
    registry = ToolRegistry()
    for spec in build_fsops_tools():
        registry.register(spec)
    return SafetyGate(registry)


def test_classify_deletions_blocks_protected_roots() -> None:
    verdicts = classify_deletions(
        ["/etc/nginx/nginx.conf", "/etc", "/", "/home/demo/x"],
        protected=["/", "/etc", "/home/demo"],
    )
    assert verdicts == {
        "/etc/nginx/nginx.conf": "ok",
        "/etc": "protected",
        "/": "protected",
        "/home/demo/x": "ok",
    }


def test_protected_roots_cover_home_cwd_and_platform(tmp_path: Path) -> None:
    roots = fsops.protected_roots({}, home=tmp_path, cwd=tmp_path / "work")
    assert str(tmp_path.resolve()) in roots
    assert str((tmp_path / "work").resolve()) in roots
    if fsops.os.name == "nt":
        drive = str(Path(str(tmp_path)).anchor)
        assert drive in roots
    else:
        assert "/" in roots and "/usr" in roots and "/etc" in roots


def test_delete_single_file_updates_log(tmp_path: Path) -> None:
    tool, log_path = make_tool(tmp_path)
    target = tmp_path / "artifact.txt"
    target.write_text("data", encoding="utf-8")

    payload = tool.delete({"paths": [str(target)]})

    assert payload["deleted_count"] == 1
    assert payload["results"][0]["status"] == "deleted"
    assert not target.exists()
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["command"] == "[fsops] delete 1 target(s)"
    assert entry["exit_code"] == 0 and entry["verified"] is True


def test_delete_directory_requires_recursive_flag(tmp_path: Path) -> None:
    tool, _ = make_tool(tmp_path)
    folder = tmp_path / "nuclei-output"
    folder.mkdir()
    (folder / "findings.jsonl").write_text("{}", encoding="utf-8")

    blocked = tool.delete({"paths": [str(folder)]})
    assert blocked["results"][0]["status"] == "directory_needs_recursive"
    assert folder.exists()

    removed = tool.delete({"paths": [str(folder)], "recursive": True})
    assert removed["deleted_count"] == 1
    assert not folder.exists()


def test_delete_reports_missing_and_mixed_results(tmp_path: Path) -> None:
    tool, _ = make_tool(tmp_path)
    existing = tmp_path / "keep.txt"
    existing.write_text("x", encoding="utf-8")
    ghost = tmp_path / "ghost.txt"

    payload = tool.delete({"paths": [str(existing), str(ghost)]})

    statuses = {r["path"]: r["status"] for r in payload["results"]}
    assert statuses[str(existing)] == "deleted"
    assert statuses[str(ghost)] == "missing"
    assert payload["summary"].startswith("deleted 1/2")


def test_delete_refuses_protected_targets_before_touching_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool, _ = make_tool(tmp_path)
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("safe", encoding="utf-8")
    fake_root = tmp_path / "windows"
    monkeypatch.setattr(fsops.os, "name", "nt")
    monkeypatch.setattr(
        fsops,
        "protected_roots",
        lambda *a, **kw: [str(fake_root), str(tmp_path)],
    )

    payload = tool.delete({"paths": [str(fake_root), str(sentinel)]})

    statuses = {r["path"]: r["status"] for r in payload["results"]}
    assert statuses[str(fake_root)] == "refused_protected"
    assert statuses[str(sentinel)] == "deleted"
    assert payload["deleted_count"] == 1
    assert not fake_root.exists()


def test_validated_rejects_bad_shapes(tmp_path: Path) -> None:
    tool, _ = make_tool(tmp_path)

    empty = tool.delete({"paths": []})
    assert empty["error"] == "invalid_arguments"

    blank = tool.delete({"paths": ["   "]})
    assert blank["error"] == "invalid_arguments"

    too_many = tool.delete({"paths": ["x"] * (MAX_PATHS_PER_CALL + 1)})
    assert too_many["error"] == "too_many_paths"

    missing_key = tool.delete({})
    assert missing_key["error"] == "invalid_arguments"


def test_symlink_target_unlinks_link_only(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "payload.bin").write_text("bin", encoding="utf-8")
    link = tmp_path / "link-to-real"
    try:
        link.symlink_to(real_dir, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unsupported on this host/account")
    tool, _ = make_tool(tmp_path)

    payload = tool.delete({"paths": [str(link)]})

    assert payload["results"][0]["status"] == "deleted"
    assert payload["results"][0]["kind"] == "symlink_link_only"
    assert not link.exists()
    assert (real_dir / "payload.bin").exists()


def test_gate_confirms_high_risk_and_blocks_bad_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = register(monkeypatch)

    decision = gate.evaluate("file_delete", {"paths": ["/tmp/a.txt"]})
    assert decision.allowed and decision.requires_confirmation
    assert decision.risk is RiskLevel.HIGH

    bad = gate.evaluate("file_delete", {"paths": []})
    assert not bad.allowed

    oversized = gate.evaluate("file_delete", {"paths": ["p"] * (MAX_PATHS_PER_CALL + 1)})
    assert not oversized.allowed and "at most 20" in (oversized.reason or "")


def test_builder_registers_one_spec_named_file_delete() -> None:
    specs = build_fsops_tools(history=CommandHistory(), log_path=None)
    assert [s.name for s in specs] == ["file_delete"]
    assert specs[0].risk is RiskLevel.HIGH
    assert callable(specs[0].handler)


def test_history_records_failure_exit_code(tmp_path: Path) -> None:
    history = CommandHistory()
    tool = FileDeletionTool(history=history, log_path=tmp_path / "log.jsonl")
    ghost = tmp_path / "nope.txt"

    tool.delete({"paths": [str(ghost)]})

    assert history.entries[-1]["exit_code"] == 1
