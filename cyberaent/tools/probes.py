from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_SHIMS = {".cmd", ".bat", ".ps1"}

DEFAULT_PROBES: tuple[str, ...] = ("--version",)

KNOWN_PROBES: dict[str, tuple[str, ...]] = {
    "go": ("version",),
    "openssl": ("version",),
    "nuclei": ("-version",),
    "httpx": ("-version",),
    "nikto": ("-Version",),
    "ffuf": ("-V",),
    "nmap": ("--version",),
    "subfinder": ("-version",),
    "naabu": ("-version",),
    "sqlmap": ("--version",),
    "gobuster": ("version",),
    "amass": ("-version",),
    "wafw00f": ("-V",),
}

PACKAGE_MANAGERS = (
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "apk",
    "brew",
    "choco",
    "winget",
    "scoop",
)

_PRIMARY_BY_PLATFORM: dict[str, tuple[str, ...]] = {
    "win32": ("winget", "choco", "scoop"),
    "darwin": ("brew",),
    "linux": ("apt", "apt-get", "dnf", "pacman", "zypper", "apk"),
}

PROBE_TIMEOUT_S = 8.0


@dataclass(frozen=True)
class ToolProbe:
    name: str
    installed: bool
    path: str | None = None
    version: str | None = None
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "installed": self.installed,
            "path": self.path,
            "version": self.version,
            "note": self.note,
        }


def resolve_executable(name: str) -> str | None:
    return shutil.which(name)


def _first_line(*streams: str | None) -> str | None:
    for stream in streams:
        if not stream:
            continue
        line = stream.strip().splitlines()
        if line and line[0].strip():
            return line[0].strip()[:200]
    return None


def _run_capture(executable: str, args: tuple[str, ...]) -> str | None:
    try:
        proc = subprocess.run(
            [executable, *args],
            shell=False,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return _first_line(proc.stdout, proc.stderr)


def probe_tool(name: str) -> ToolProbe:
    executable = resolve_executable(name)
    if executable is None:
        return ToolProbe(name=name, installed=False)
    if Path(executable).suffix.lower() in SCRIPT_SHIMS:
        return ToolProbe(
            name=name,
            installed=True,
            path=executable,
            note="presence-only (.cmd/.bat shim, version not probed)",
        )

    seen_args: set[tuple[str, ...]] = set()
    candidates = [KNOWN_PROBES.get(name), DEFAULT_PROBES]
    for args in candidates:
        if args is None or args in seen_args:
            continue
        seen_args.add(args)
        output = _run_capture(executable, args)
        if output:
            return ToolProbe(name=name, installed=True, path=executable, version=output)

    return ToolProbe(
        name=name,
        installed=True,
        path=executable,
        note="installed; version unavailable",
    )


def probe_tools(names: list[str], time_budget_s: float = 40.0) -> list[ToolProbe]:
    deadline = time.monotonic() + time_budget_s
    probes: list[ToolProbe] = []
    for name in names:
        if time.monotonic() > deadline:
            probes.append(
                ToolProbe(name=name, installed=False, note="skipped (time budget exhausted)")
            )
            continue
        probes.append(probe_tool(name))
    return probes


def detect_shell() -> str | None:
    shell = os.environ.get("SHELL") or os.environ.get("COMSPEC")
    if not shell:
        return None
    return Path(shell).name


def current_user() -> str | None:
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME")
        return user or None


def _windows_is_admin() -> bool | None:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def is_admin() -> bool | None:
    if sys.platform == "win32":
        return _windows_is_admin()
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except OSError:
            return None
    return None


def has_sudo() -> bool | None:
    if sys.platform == "win32":
        return None
    return resolve_executable("sudo") is not None


def is_venv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def venv_path() -> str | None:
    return os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX")


def is_wsl() -> bool:
    if sys.platform != "linux":
        return False
    return "microsoft" in platform.release().lower()


def is_docker() -> bool:
    if sys.platform == "win32":
        return False
    return Path("/.dockerenv").exists()


def detect_distro() -> str | None:
    if sys.platform == "win32":
        return platform.uname().release or None
    if sys.platform == "darwin":
        version = platform.mac_ver()[0]
        return f"macOS {version}" if version else "macOS"
    release_file = Path("/etc/os-release")
    try:
        for line in release_file.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "PRETTY_NAME":
                return value.strip().strip('"') or None
    except OSError:
        return None
    return None


def scan_package_managers() -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    for manager in PACKAGE_MANAGERS:
        path = resolve_executable(manager)
        if path:
            found.append({"name": manager, "path": path})

    preferred = _PRIMARY_BY_PLATFORM.get(sys.platform, ())
    names_found = {m["name"] for m in found}
    primary = next((p for p in preferred if p in names_found), None)
    return {"primary": primary, "managers": found}


def path_report() -> dict[str, Any]:
    raw = os.environ.get("PATH", "")
    entries = [e for e in (part.strip() for part in raw.split(os.pathsep)) if e]

    counts = Counter(entries)
    duplicates = sorted(e for e, n in counts.items() if n > 1)
    missing = [e for e in entries if not Path(os.path.expandvars(e)).is_dir()]
    venv_markers = ("venv", ".venv", "virtualenv", "conda", "Scripts", "bin")
    has_venv_entry = any(marker in e.lower() for e in entries for marker in venv_markers)

    return {
        "count": len(entries),
        "entries": entries,
        "duplicates": duplicates,
        "missing_dirs": missing,
        "likely_venv_on_path": has_venv_entry,
        "summary": (
            f"{len(entries)} PATH entries · "
            f"{len(duplicates)} duplicates · {len(missing)} missing dirs"
        ),
    }


def _writable(path: str | None) -> bool | None:
    if not path:
        return None
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return None


def permission_report() -> dict[str, Any]:
    user = current_user()
    admin = is_admin()
    home = os.path.expanduser("~")

    report: dict[str, Any] = {
        "user": user,
        "privileged": admin,
        "sudo_available": has_sudo(),
        "writable_home": _writable(home),
        "writable_cwd": _writable(os.getcwd()),
        "writable_temp": _writable(tempfile.gettempdir()),
    }

    privilege = "unknown"
    if admin is True:
        privilege = "administrator/root"
    elif admin is False:
        privilege = "standard user"
    report["summary"] = f"user={user} · privileges={privilege}"

    return report
