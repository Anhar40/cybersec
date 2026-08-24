from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from cyberaent.tools import environment, probes

EXPECTED_TOOLS = {"environment", "check_tool", "path_info", "package_managers", "permissions"}


class SimpleUname:
    system = "Windows"
    release = "11"
    version = "10.0"
    machine = "AMD64"


def patch_platform(monkeypatch: Any) -> None:
    uname = SimpleUname()
    monkeypatch.setattr(environment.platform, "uname", lambda: uname)
    monkeypatch.setattr(environment.platform, "python_version", lambda: "3.14.6")
    monkeypatch.setattr(environment.platform, "platform", lambda: "Windows-11")
    monkeypatch.setattr(probes.platform, "uname", lambda: uname)


def fake_probe_tools(names: list[str], time_budget_s: float = 40.0) -> list[probes.ToolProbe]:
    out = [
        probes.ToolProbe(
            name="git",
            installed=True,
            path=r"C:\Git\git.exe",
            version="git version 2.55",
        )
    ]
    out.extend(probes.ToolProbe(name=n, installed=False) for n in names if n != "git")
    return out


def stub_probes(monkeypatch: Any) -> None:
    monkeypatch.setattr(probes, "is_admin", lambda: False)
    monkeypatch.setattr(probes, "current_user", lambda: "anhar")
    monkeypatch.setattr(probes, "detect_shell", lambda: "cmd.exe")
    monkeypatch.setattr(probes, "detect_distro", lambda: "Windows 11")
    monkeypatch.setattr(probes, "is_venv", lambda: False)
    monkeypatch.setattr(probes, "venv_path", lambda: None)
    monkeypatch.setattr(probes, "is_wsl", lambda: False)
    monkeypatch.setattr(probes, "is_docker", lambda: False)
    monkeypatch.setattr(probes, "path_report", lambda: {"count": 7})
    monkeypatch.setattr(
        probes,
        "scan_package_managers",
        lambda: {
            "primary": "winget",
            "managers": [{"name": "winget", "path": r"C:\winget.exe"}],
        },
    )
    monkeypatch.setattr(probes, "probe_tools", fake_probe_tools)


def make_run(outputs: dict[tuple[str, ...], str]) -> Any:
    def _run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        assert kwargs.get("shell") is False
        text = outputs.get(tuple(argv[1:]), "")
        return SimpleNamespace(stdout=text, stderr="", returncode=0)

    return _run


def test_registry_registers_all_phase2_tools() -> None:
    registry = environment.default_registry()
    assert set(registry.names()) == EXPECTED_TOOLS
    for name in EXPECTED_TOOLS:
        spec = registry.get(name)
        assert spec is not None
        assert spec.risk.value == "low"


def test_check_tool_schema_is_strict() -> None:
    schema = environment.CHECK_TOOL_SCHEMA
    assert schema["required"] == ["names"]
    names_prop = schema["properties"]["names"]
    assert names_prop["minItems"] == 1
    assert names_prop["maxItems"] == 15


def test_collect_environment_structure(monkeypatch: Any) -> None:
    patch_platform(monkeypatch)
    stub_probes(monkeypatch)

    result = environment.collect_environment()

    assert result["os"]["system"] == "Windows"
    assert result["os"]["release"] == "11"
    assert result["distro"] == "Windows 11"
    assert result["architecture"] == "AMD64"
    assert result["user"] == "anhar"
    assert result["privileged"] is False
    assert result["tool_versions"]["git"] == "git version 2.55"
    assert result["tool_versions"]["node"] is None
    assert result["package_managers"] == ["winget"]
    assert result["primary_package_manager"] == "winget"
    assert result["wsl"] is False
    assert result["docker"] is False
    assert result["path_entries"] == 7
    assert "Python 3.14.6" in result["summary"]
    assert "missing: go, node, npm" in result["summary"]
    json.dumps(result)


def test_check_tool_handler_summarizes(monkeypatch: Any) -> None:
    def local_probe_tools(names: list[str], time_budget_s: float = 40.0):
        out = []
        for n in names:
            if n == "nmap":
                out.append(
                    probes.ToolProbe(
                        name="nmap", installed=True, path=r"C:\nmap.exe", version="7.95"
                    )
                )
            else:
                out.append(probes.ToolProbe(name=n, installed=False))
        return out

    monkeypatch.setattr(environment.probes, "probe_tools", local_probe_tools)

    payload = environment.run_check_tool({"names": ["nmap", "nuclei"]})

    assert payload["tools"][0]["installed"] is True
    assert payload["tools"][0]["version"] == "7.95"
    assert payload["tools"][1]["installed"] is False
    assert "nmap" in payload["summary"]
    assert "missing: nuclei" in payload["summary"]
    json.dumps(payload)


def test_package_managers_handler(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        environment.probes,
        "scan_package_managers",
        lambda: {
            "primary": "apt",
            "managers": [
                {"name": "apt", "path": "/usr/bin/apt"},
                {"name": "dpkg", "path": "/usr/bin/dpkg"},
            ],
        },
    )

    payload = environment.run_package_managers({})

    assert payload["primary"] == "apt"
    assert "primary: apt" in payload["summary"]


def test_permissions_handler_passthrough(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        environment.probes,
        "permission_report",
        lambda: {"user": "anhar", "privileged": False, "summary": "user=anhar"},
    )

    payload = environment.run_permissions({})

    assert payload["privileged"] is False


def test_path_info_handler_passthrough(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        environment.probes,
        "path_report",
        lambda: {"count": 3, "summary": "3 PATH entries"},
    )

    payload = environment.run_path_info({})

    assert payload["count"] == 3


def test_handlers_never_crash_on_real_machine() -> None:
    cases: list[tuple[Any, dict[str, Any]]] = [
        (environment.run_path_info, {}),
        (environment.run_package_managers, {}),
        (environment.run_permissions, {}),
        (environment.run_check_tool, {"names": ["python"]}),
    ]
    for handler, args in cases:
        payload = handler(args)
        assert isinstance(payload, dict)
        json.dumps(payload, default=str)
