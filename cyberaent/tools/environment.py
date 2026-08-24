from __future__ import annotations

import platform
import sys
from collections.abc import Mapping
from typing import Any

from . import probes
from .base import RiskLevel, ToolRegistry, ToolSpec

CHECK_TOOL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["names"],
    "properties": {
        "names": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 15,
        }
    },
}

CHECK_TOOL_DESCRIPTION = (
    "Check whether specific executables are installed on the LOCAL machine and read their "
    "versions. Provide 1-15 program names, e.g. security tools (nmap, nuclei, nikto, ffuf, "
    "httpx, whatweb, dig, openssl) or dev tools (git, go, node, npm, python). Never assume a "
    "tool exists; check it with this tool instead."
)

ENVIRONMENT_DESCRIPTION = (
    "Full snapshot of the LOCAL machine: OS name/version/distro, architecture, kernel, default "
    "shell, current user and privilege level, Python interpreter details, WSL/Docker indicators, "
    "availability and version of common dev tools (git, go, node, npm), and detected package "
    "managers. Takes no arguments."
)

PATH_INFO_DESCRIPTION = (
    "Inspect the LOCAL PATH environment variable: entries in order, duplicate entries, "
    "directories that do not exist, and whether a virtualenv-style entry is present. "
    "Takes no arguments."
)

PACKAGE_MANAGERS_DESCRIPTION = (
    "Detect package managers installed on the LOCAL machine (apt, dnf, pacman, zypper, apk, "
    "brew, choco, winget, scoop) and suggest the primary one for this OS family. "
    "Takes no arguments."
)

PERMISSIONS_DESCRIPTION = (
    "Report the LOCAL privilege situation: current user, administrator/root status, sudo "
    "availability, and writability of home/cwd/temp directories. Takes no arguments."
)


def collect_environment() -> dict[str, Any]:
    uname = platform.uname()
    admin = probes.is_admin()

    versions = {p.name: p for p in probes.probe_tools(["git", "go", "node", "npm"])}
    tool_versions: dict[str, str | None] = {}
    for name, probe in versions.items():
        if not probe.installed:
            tool_versions[name] = None
        elif probe.version:
            tool_versions[name] = probe.version
        else:
            tool_versions[name] = probe.note or "installed"

    managers = probes.scan_package_managers()
    manager_names = [m["name"] for m in managers["managers"]]

    result: dict[str, Any] = {
        "os": {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "platform": platform.platform(),
        },
        "distro": probes.detect_distro(),
        "architecture": uname.machine,
        "kernel": uname.release,
        "shell": probes.detect_shell(),
        "user": probes.current_user(),
        "privileged": admin,
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "virtualenv": probes.is_venv(),
            "venv_path": probes.venv_path(),
        },
        "tool_versions": tool_versions,
        "package_managers": manager_names,
        "primary_package_manager": managers["primary"],
        "wsl": probes.is_wsl(),
        "docker": probes.is_docker(),
        "path_entries": probes.path_report()["count"],
    }

    missing = sorted(name for name, v in tool_versions.items() if v is None)
    found = sorted(name for name, v in tool_versions.items() if v is not None)
    result["summary"] = (
        f"{uname.system} {uname.release} · {uname.machine} · "
        f"Python {platform.python_version()} · admin={'yes' if admin else 'no'} · "
        f"tools: {', '.join(found) if found else 'none detected'}"
        + (f" · missing: {', '.join(missing)}" if missing else "")
    )
    return result


def run_check_tool(arguments: Mapping[str, Any]) -> dict[str, Any]:
    names = [str(n).strip() for n in arguments.get("names", [])]
    names = [n for n in names if n]
    probes_found = probes.probe_tools(names)
    results = [probe.as_dict() for probe in probes_found]

    found = [r["name"] for r in results if r["installed"]]
    absent = [r["name"] for r in results if not r["installed"]]
    summary = (
        f"installed: {', '.join(found) if found else 'none'}"
        + (f" · missing: {', '.join(absent)}" if absent else "")
    )
    return {"summary": summary, "tools": results}


def run_path_info(_arguments: Mapping[str, Any]) -> dict[str, Any]:
    return probes.path_report()


def run_package_managers(_arguments: Mapping[str, Any]) -> dict[str, Any]:
    report = probes.scan_package_managers()
    names = [m["name"] for m in report["managers"]]
    others = ", ".join(n for n in names if n != report["primary"])
    summary = f"primary: {report['primary'] or 'none detected'}"
    if others and len(names) > 1:
        summary += f" · also: {others}"
    return {"summary": summary, **report}


def run_permissions(_arguments: Mapping[str, Any]) -> dict[str, Any]:
    return probes.permission_report()


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="environment",
            description=ENVIRONMENT_DESCRIPTION,
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=lambda _args: collect_environment(),
        )
    )
    registry.register(
        ToolSpec(
            name="check_tool",
            description=CHECK_TOOL_DESCRIPTION,
            parameters=CHECK_TOOL_SCHEMA,
            risk=RiskLevel.LOW,
            handler=run_check_tool,
        )
    )
    registry.register(
        ToolSpec(
            name="path_info",
            description=PATH_INFO_DESCRIPTION,
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=run_path_info,
        )
    )
    registry.register(
        ToolSpec(
            name="package_managers",
            description=PACKAGE_MANAGERS_DESCRIPTION,
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=run_package_managers,
        )
    )
    registry.register(
        ToolSpec(
            name="permissions",
            description=PERMISSIONS_DESCRIPTION,
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=run_permissions,
        )
    )
    return registry
