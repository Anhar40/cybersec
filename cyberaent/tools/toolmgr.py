"""Tool Manager (PRD Phase 6): detect, install, verify, repair PATH.

All execution stays argv-only with ``shell=False``; installs are HIGH risk and
therefore always require explicit user confirmation through the safety gate.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import probes
from .base import RiskLevel, ToolSpec
from .terminal import (
    OUTPUT_CAP_CHARS,
    CommandHistory,
    append_log_line,
)

INSTALL_TIMEOUT_S = 1200
MAX_ARG_LENGTH = 200
MAX_USER_PATH_CHARS = 4000

PATH_BLOCK_BEGIN = "# >>> cyberaent path >>>"
PATH_BLOCK_END = "# <<< cyberaent path <<<"

FAKE_INSTALL_ENV = "CYBERAENT_FAKE_INSTALL"

INSTALL_PLANS: dict[str, dict[str, list[str]]] = {
    "nuclei": {
        "go": ["go", "install", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"],
        "scoop": ["scoop", "install", "nuclei"],
        "choco": ["choco", "install", "-y", "nuclei"],
    },
    "httpx": {
        "go": ["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
        "scoop": ["scoop", "install", "httpx"],
    },
    "ffuf": {
        "go": ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
        "scoop": ["scoop", "install", "ffuf"],
    },
    "subfinder": {
        "go": ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
        "scoop": ["scoop", "install", "subfinder"],
    },
    "naabu": {
        "go": ["go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"],
        "scoop": ["scoop", "install", "naabu"],
    },
    "nmap": {
        "winget": [
            "winget",
            "install",
            "-e",
            "--id",
            "Insecure.Nmap",
            "--accept-source-agreements",
            "--accept-package-agreements",
        ],
        "choco": ["choco", "install", "-y", "nmap"],
        "scoop": ["scoop", "install", "nmap"],
        "brew": ["brew", "install", "nmap"],
        "apt-get": ["apt-get", "install", "-y", "nmap"],
        "dnf": ["dnf", "install", "-y", "nmap"],
        "pacman": ["pacman", "-S", "--noconfirm", "nmap"],
        "apk": ["apk", "add", "nmap"],
    },
    "sqlmap": {
        "pip": ["pip", "install", "--user", "sqlmap"],
        "choco": ["choco", "install", "-y", "sqlmap"],
        "brew": ["brew", "install", "sqlmap"],
        "apt-get": ["apt-get", "install", "-y", "sqlmap"],
        "dnf": ["dnf", "install", "-y", "sqlmap"],
        "pacman": ["pacman", "-S", "--noconfirm", "sqlmap"],
    },
}

_EXTRA_INSTALLERS = ("go", "pip")

_PREFERRED_BY_PLATFORM: dict[str, tuple[str, ...]] = {
    "win32": ("winget", "choco", "scoop"),
    "darwin": ("brew",),
    "linux": ("apt-get", "dnf", "pacman", "apk"),
}


def available_installers() -> list[str]:
    found = [name for name in probes.PACKAGE_MANAGERS if probes.resolve_executable(name)]
    found += [name for name in _EXTRA_INSTALLERS if probes.resolve_executable(name)]
    preferred = _PREFERRED_BY_PLATFORM.get(sys.platform, ())
    ordered = [m for m in preferred if m in found]
    ordered += [m for m in found if m not in ordered]
    return ordered


def _fake_mode() -> bool:
    """Test/smoke seam: simulate installs end-to-end without touching the system."""
    return os.environ.get(FAKE_INSTALL_ENV) == "1"


def pick_plan(name: str) -> tuple[str, list[str]] | None:
    """Return (manager, argv) for the best available installer of ``name``."""
    plans = INSTALL_PLANS.get(name)
    if not plans:
        return None
    if _fake_mode():
        return "fake", ["fake-installer", name]
    for manager in available_installers():
        argv = plans.get(manager)
        if argv:
            return manager, list(argv)
    return None


def _cap(text: str | None) -> str:
    value = text or ""
    if len(value) <= OUTPUT_CAP_CHARS:
        return value
    dropped = len(value) - OUTPUT_CAP_CHARS
    return value[:OUTPUT_CAP_CHARS] + f"\n...[truncated {dropped} characters]"


def default_inventory_names() -> list[str]:
    return sorted(set(INSTALL_PLANS) | set(probes.KNOWN_PROBES))


def candidate_tool_dirs() -> list[str]:
    home = Path.home()
    raw: list[str] = [
        str(home / ".local" / "bin"),
        str(home / "go" / "bin"),
        str(home / ".cargo" / "bin"),
    ]
    if os.name == "nt":
        raw = [
            str(home / "go" / "bin"),
            str(home / ".cargo" / "bin"),
            str(home / ".local" / "bin"),
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Links"),
            os.path.expandvars(r"%APPDATA%\npm"),
        ]
        python_parent = Path(os.path.expandvars(r"%APPDATA%\Python"))
        if python_parent.is_dir():
            for scripts in sorted(python_parent.glob("Python*/Scripts")):
                raw.append(str(scripts))
    seen: set[str] = set()
    ordered: list[str] = []
    for item in raw:
        key = _path_key(item)
        if key not in seen:
            seen.add(key)
            ordered.append(item)
    return ordered


def _path_key(entry: str) -> str:
    normalized = entry.strip().rstrip("\\/")
    # Windows paths are case-insensitive; POSIX filesystems are not.
    return normalized.lower() if os.name == "nt" else normalized


def compute_missing_dirs(candidates: list[str], path_entries: list[str]) -> list[str]:
    existing = {_path_key(entry) for entry in path_entries if entry.strip()}
    missing: list[str] = []
    for candidate in candidates:
        key = _path_key(candidate)
        if key not in existing and Path(candidate).is_dir():
            missing.append(candidate)
    return missing


def _broadcast_env_change() -> None:
    try:
        import ctypes

        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", SMTO_ABORTIFHUNG, 5000, None
        )
    except Exception:
        pass


def _persist_user_path(additions: list[str]) -> dict[str, Any]:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE
    ) as key:
        try:
            value, dtype = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            value, dtype = "", winreg.REG_EXPAND_SZ
        previous = value if isinstance(value, str) else str(value)
        sep = "" if (not previous or previous.endswith(";")) else ";"
        new_value = previous + sep + ";".join(additions)
        reg_type = dtype if dtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) else winreg.REG_EXPAND_SZ
        winreg.SetValueEx(key, "Path", 0, reg_type, new_value)
    _broadcast_env_change()
    return {"previous_chars": len(previous), "new_chars": len(new_value)}


def _select_posix_profile(home: Path, environ: Mapping[str, str]) -> Path:
    shell = str(environ.get("SHELL", "")).rstrip("/")
    if shell.endswith("zsh"):
        return home / ".zshrc"
    if shell.endswith("bash"):
        return home / ".bashrc"
    bashrc = home / ".bashrc"
    return bashrc if bashrc.is_file() else home / ".profile"


def _strip_managed_block(text: str) -> tuple[str, bool]:
    begin = text.find(PATH_BLOCK_BEGIN)
    if begin == -1:
        return text, False
    end = text.find(PATH_BLOCK_END, begin)
    if end == -1:
        # Malformed block; leave it alone and append a fresh one.
        return text, False
    head = text[:begin].rstrip("\n")
    tail = text[end + len(PATH_BLOCK_END):].lstrip("\n")
    if head and tail:
        return f"{head}\n\n{tail}", True
    if head:
        return f"{head}\n", True
    if tail:
        return tail, True
    return "", True


def _render_path_block(additions: list[str]) -> str:
    exports = "".join(f'export PATH="$PATH:{d}"\n' for d in additions)
    return f"{PATH_BLOCK_BEGIN}\n{exports}{PATH_BLOCK_END}\n"


def _persist_user_path_posix(
    additions: list[str],
    *,
    home: Path,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    profile = _select_posix_profile(home, environ)
    backup: str | None = None
    if profile.is_file():
        original = profile.read_text(encoding="utf-8")
        stripped, _ = _strip_managed_block(original)
        backup_path = profile.with_name(profile.name + ".cyberaent.bak")
        if not backup_path.exists():
            backup_path.write_text(original, encoding="utf-8")
            backup = str(backup_path)
        base = stripped.rstrip("\n")
        updated = f"{base}\n\n{_render_path_block(additions)}" if base else _render_path_block(
            additions
        )
    else:
        profile.parent.mkdir(parents=True, exist_ok=True)
        updated = _render_path_block(additions)
    profile.write_text(updated, encoding="utf-8")
    return {"profile": str(profile), "added_dirs": list(additions), "backup": backup}


def _refresh_session_path(additions: list[str]) -> None:
    current = os.environ.get("PATH", "")
    entries = [e for e in current.split(os.pathsep) if e]
    fresh = [d for d in additions if d not in entries]
    if fresh:
        os.environ["PATH"] = os.pathsep.join(fresh + entries)


class ToolManager:
    def __init__(
        self,
        *,
        history: CommandHistory | None = None,
        log_path: Path | None = None,
        runner: Callable[..., Any] | None = None,
    ):
        self.history = history if history is not None else CommandHistory()
        self.log_path = log_path
        self._runner = runner

    # ------------------------------------------------------------------ detect
    def inventory(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        names = arguments.get("names")
        if isinstance(names, list):
            targets = [str(n).strip() for n in names]
        else:
            targets = default_inventory_names()
        results = probes.probe_tools(targets, time_budget_s=40.0)
        tools = [probe.as_dict() for probe in results]
        installed = sum(1 for t in tools if t["installed"])
        return {
            "tools": tools,
            "summary": f"{installed}/{len(tools)} known tools installed",
            "installed_count": installed,
            "total_count": len(tools),
        }

    # ----------------------------------------------------------------- install
    def install(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        name = str(arguments["name"]).strip().lower()
        if probes.probe_tool(name).installed:
            return {
                "error": "already_installed",
                "reason": f"'{name}' is already installed; nothing to do.",
                "summary": f"already installed · {name}",
            }
        plan = pick_plan(name)
        if plan is None:
            return {
                "error": "no_installer_available",
                "reason": f"No viable package manager found to install '{name}'.",
                "summary": f"no installer · {name}",
            }
        manager, argv = plan
        display_command = " ".join(argv)[:MAX_ARG_LENGTH]

        started = time.perf_counter()
        if os.environ.get(FAKE_INSTALL_ENV) == "1":
            exit_code, stdout, stderr = 0, "[fake-install] ok", ""
        else:
            runner = self._runner if self._runner is not None else subprocess.run
            try:
                proc = runner(
                    argv,
                    shell=False,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=INSTALL_TIMEOUT_S,
                )
                exit_code = int(proc.returncode)
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                duration = time.perf_counter() - started
                self._record(name, manager, None, duration, False, "timeout")
                return {
                    "error": "timeout",
                    "reason": (
                        f"Installation of '{name}' exceeded {INSTALL_TIMEOUT_S}s "
                        "and was terminated."
                    ),
                    "command": display_command,
                    "stdout": _cap(getattr(exc, "stdout", None)),
                    "stderr": _cap(getattr(exc, "stderr", None)),
                    "duration": round(duration, 3),
                    "summary": f"timeout · install {name}",
                }
            except OSError as exc:
                duration = time.perf_counter() - started
                self._record(name, manager, None, duration, False, "os_error")
                return {
                    "error": "execution_failed",
                    "detail": str(exc)[:300],
                    "command": display_command,
                    "summary": f"os error · install {name}",
                }

        duration = time.perf_counter() - started
        verification = probes.probe_tool(name).as_dict()
        if _fake_mode():
            verification = {
                **verification,
                "installed": True,
                "path": r"C:\fake\nuclei.exe",
                "version": "0.0.0-fake",
            }
        verified = bool(verification["installed"])
        self._record(
            name, manager, exit_code, duration, verified,
            "verified" if verified else "unverified",
        )
        payload: dict[str, Any] = {
            "tool": name,
            "package_manager": manager,
            "command": display_command,
            "exit_code": exit_code,
            "stdout": _cap(stdout),
            "stderr": _cap(stderr),
            "duration": round(duration, 3),
            "verification": verification,
            "summary": (
                f"exit={exit_code} · verified · {display_command}"
                if verified
                else f"exit={exit_code} · NOT verified · {display_command}"
            ),
        }
        if exit_code == 0 and not verified:
            payload["error"] = "verification_failed"
            payload["reason"] = (
                f"The installer reported success but '{name}' is still not resolvable on PATH. "
                "Run fix_path (dry run) to find tool directories missing from PATH."
            )
        elif exit_code != 0:
            payload["error"] = "install_failed"
            payload["reason"] = "The package manager exited with an error; inspect stderr."
        return payload

    # --------------------------------------------------------------- fix PATH
    def fix_path(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        apply_changes = bool(arguments.get("apply"))
        candidates = candidate_tool_dirs()
        entries = [
            e for e in (part.strip() for part in os.environ.get("PATH", "").split(os.pathsep)) if e
        ]
        existing_candidates = [c for c in candidates if Path(c).is_dir()]
        missing = compute_missing_dirs(candidates, entries)

        payload: dict[str, Any] = {
            "candidates": existing_candidates,
            "dirs_to_add": missing,
            "applied": False,
            "summary": (
                f"{len(missing)} tool dir(s) missing from PATH"
                if missing
                else "PATH already covers all known tool dirs"
            ),
        }
        if not apply_changes or not missing:
            return payload

        projected = len(os.environ.get("PATH", "")) + sum(len(d) + 1 for d in missing)
        if projected > MAX_USER_PATH_CHARS:
            payload["error"] = "path_too_long"
            payload["reason"] = (
                f"Appending would push the user PATH beyond {MAX_USER_PATH_CHARS} chars; "
                "clean up stale entries first."
            )
            return payload

        payload["applied"] = True
        if os.name == "nt":
            persistence = _persist_user_path(missing)
            _refresh_session_path(missing)
            payload["persistence"] = persistence
            payload["summary"] = (
                f"added {len(missing)} dir(s) to user PATH "
                "(effective now; new terminals pick it up automatically)"
            )
        else:
            persistence = _persist_user_path_posix(
                missing, home=Path.home(), environ=os.environ
            )
            _refresh_session_path(missing)
            payload["persistence"] = persistence
            payload["summary"] = (
                f"added {len(missing)} dir(s) via {persistence['profile']} "
                "(effective now; new shells read the profile)"
            )
        return payload

    # ---------------------------------------------------------------- logging
    def _record(
        self,
        tool: str,
        manager: str,
        exit_code: int | None,
        duration: float,
        verified: bool,
        status: str,
    ) -> None:
        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "command": f"[toolmgr] install {tool} via {manager}",
            "status": status,
            "exit_code": exit_code,
            "duration_s": round(duration, 3),
            "timed_out": False,
            "verified": verified,
        }
        self.history.add(entry)
        append_log_line(self.log_path, entry)


# --------------------------------------------------------------------- specs
def _gate_block_install(arguments: Mapping[str, Any]) -> str | None:
    name = arguments.get("name")
    if not isinstance(name, str) or not name.strip():
        return "'name' must be a non-empty string."
    name = name.strip().lower()
    if name not in INSTALL_PLANS:
        known = ", ".join(sorted(INSTALL_PLANS))
        return f"'{name}' has no managed install plan. Managed tools: {known}."
    probe = probes.probe_tool(name)
    if probe.installed:
        return (
            f"'{name}' is already installed ({probe.version or 'version unknown'}); "
            "nothing to install."
        )
    if pick_plan(name) is None:
        needed = ", ".join(sorted(INSTALL_PLANS[name]))
        return (
            f"No supported package manager for '{name}' is available right now "
            f"(needs one of: {needed})."
        )
    return None


def _fix_path_risk(arguments: Mapping[str, Any]) -> RiskLevel:
    return RiskLevel.HIGH if bool(arguments.get("apply")) else RiskLevel.LOW


def _fix_path_block(arguments: Mapping[str, Any]) -> str | None:
    if bool(arguments.get("apply")) and os.name not in ("nt", "posix"):
        return (
            "Persistent PATH edits are only implemented for Windows user "
            "environments and POSIX shell profiles."
        )
    return None


INVENTORY_DESCRIPTION = (
    "Detect which known security/development tools are installed locally, including "
    "their path and version. Optionally pass `names` (array, 1..30) to restrict the "
    "scan; omit it to scan every managed tool. Read-only and safe to run anytime."
)
INVENTORY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "names": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 30},
    },
}

INSTALL_DESCRIPTION = (
    "Install ONE managed security tool through a detected package manager "
    "(winget/choco/scoop/brew/apt/dnf/pacman/apk/go/pip). The gate refuses unknown "
    "tools, already-installed tools, and cases where no installer exists. This is a "
    "HIGH-risk action: the user must confirm every install. The result includes a "
    "post-install verification probe; if verification fails, suggest fix_path."
)
INSTALL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name"],
    "properties": {"name": {"type": "string"}},
}

FIX_PATH_DESCRIPTION = (
    "Report well-known tool directories (go/bin, cargo/bin, WinGet Links, pip user "
    "Scripts, …) that exist on disk but are missing from PATH. By default this is a "
    "read-only dry run. With {\"apply\": true} on Windows it permanently appends the "
    "missing directories to the USER PATH in the registry (takes effect in NEW "
    "terminals) — a HIGH-risk change that requires explicit confirmation."
)
FIX_PATH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"apply": {"type": "boolean"}},
}


def build_tool_manager_tools(
    *,
    history: CommandHistory | None = None,
    log_path: Path | None = None,
) -> list[ToolSpec]:
    manager = ToolManager(history=history, log_path=log_path)
    return [
        ToolSpec(
            name="tool_inventory",
            description=INVENTORY_DESCRIPTION,
            parameters=INVENTORY_SCHEMA,
            risk=RiskLevel.LOW,
            handler=manager.inventory,
        ),
        ToolSpec(
            name="install_tool",
            description=INSTALL_DESCRIPTION,
            parameters=INSTALL_SCHEMA,
            risk=RiskLevel.HIGH,
            handler=manager.install,
            check_args=_gate_block_install,
        ),
        ToolSpec(
            name="fix_path",
            description=FIX_PATH_DESCRIPTION,
            parameters=FIX_PATH_SCHEMA,
            risk=RiskLevel.LOW,
            handler=manager.fix_path,
            risk_for=_fix_path_risk,
            check_args=_fix_path_block,
        ),
    ]
