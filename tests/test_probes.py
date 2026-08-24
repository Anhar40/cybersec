from __future__ import annotations

from typing import Any

from cyberaent.tools import probes


def fake_which(mapping: dict[str, str | None]):
    def _which(name: str, *args: Any, **kwargs: Any) -> str | None:
        return mapping.get(name)

    return _which


def patch_run(
    monkeypatch: Any,
    outputs: dict[tuple[str, ...], str | None],
    calls: list[list] | None = None,
) -> None:
    def _run(argv: list[str], **kwargs: Any) -> Any:
        if calls is not None:
            calls.append(list(argv))
        assert kwargs.get("shell") is False
        from types import SimpleNamespace

        text = outputs.get(tuple(argv[1:]))
        return SimpleNamespace(stdout=text or "", stderr="", returncode=0)

    monkeypatch.setattr(probes.subprocess, "run", _run)


def test_missing_tool_reports_not_installed(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes.shutil, "which", fake_which({}))
    probe = probes.probe_tool("nmap")
    assert probe.installed is False
    assert probe.path is None
    assert probe.version is None


def test_script_shim_is_presence_only(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes.shutil, "which", fake_which({"npm": r"C:\npm\npm.cmd"}))
    probe = probes.probe_tool("npm")
    assert probe.installed is True
    assert probe.version is None
    assert probe.note is not None and "presence-only" in probe.note


def test_known_probe_args_take_priority(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes.shutil, "which", fake_which({"nuclei": r"C:\bin\nuclei.exe"}))
    calls: list[list] = []
    patch_run(
        monkeypatch,
        outputs={("-version",): "Nuclei Engine 3.3.7"},
        calls=calls,
    )

    probe = probes.probe_tool("nuclei")

    assert probe.installed and probe.version == "Nuclei Engine 3.3.7"
    assert calls[0][1:] == ["-version"]
    assert len(calls) == 1


def test_falls_back_to_default_probe(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes.shutil, "which", fake_which({"git": r"C:\Git\git.exe"}))
    calls: list[list] = []
    patch_run(
        monkeypatch,
        outputs={("--version",): "git version 2.55.0"},
        calls=calls,
    )

    probe = probes.probe_tool("git")

    assert probe.installed and probe.version == "git version 2.55.0"
    assert calls[0][1:] == ["--version"]


def test_installed_but_version_unavailable(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes.shutil, "which", fake_which({"weird": r"C:\bin\weird.exe"}))

    def failing_run(argv: list[str], **kwargs: Any) -> Any:
        raise OSError("cannot run")

    monkeypatch.setattr(probes.subprocess, "run", failing_run)

    probe = probes.probe_tool("weird")

    assert probe.installed is True
    assert probe.version is None
    assert probe.note is not None and "version unavailable" in probe.note


def test_time_budget_skips_remaining_probes(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes.shutil, "which", lambda name, **kw: None)

    results = probes.probe_tools(["a", "b", "c"], time_budget_s=0)

    assert [r.note for r in results] == ["skipped (time budget exhausted)"] * 3


def test_path_report_flags_duplicates_and_missing(monkeypatch: Any, tmp_path: Any) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    entries = [
        str(real_dir),
        str(real_dir),
        r"D:\definitely\not\here",
    ]
    monkeypatch.setenv("PATH", probes.os.pathsep.join(entries))

    report = probes.path_report()

    assert report["count"] == 3
    assert report["duplicates"] == [str(real_dir)]
    assert report["missing_dirs"] == [r"D:\definitely\not\here"]
    assert isinstance(report["likely_venv_on_path"], bool)
    assert report["summary"].startswith("3 PATH entries")


def test_permission_report_privilege_summary(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes, "current_user", lambda: "anhar")
    monkeypatch.setattr(probes, "_windows_is_admin", lambda: False)
    monkeypatch.setattr(probes.sys, "platform", "win32")

    report = probes.permission_report()

    assert report["user"] == "anhar"
    assert report["privileged"] is False
    assert "standard user" in report["summary"]


def test_primary_package_manager_by_platform(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes.sys, "platform", "win32")
    monkeypatch.setattr(
        probes.shutil,
        "which",
        fake_who_map({"winget": r"C:\winget.exe", "choco": r"C:\choco.exe"}),
    )

    report = probes.scan_package_managers()

    assert report["primary"] == "winget"
    assert {m["name"] for m in report["managers"]} == {"winget", "choco"}


def fake_who_map(mapping: dict[str, str]):
    def _which(name: str, *args: Any, **kwargs: Any) -> str | None:
        return mapping.get(name)

    return _which
