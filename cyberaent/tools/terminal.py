from __future__ import annotations

import json
import shutil
import subprocess
import time
from collections import deque
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import RiskLevel, ToolSpec

DEFAULT_TIMEOUT_S = 30
MAX_TIMEOUT_S = 300
MAX_ARGV_ITEMS = 64
MAX_ARG_LENGTH = 4096
MAX_TOTAL_ARG_BYTES = 64_000
OUTPUT_CAP_CHARS = 20_000

VERSION_FLAGS = {"--version", "-version", "-v", "-V", "version", "--help", "-h", "help"}

SHELL_EXECUTABLES = {
    "cmd",
    "cmd.exe",
    "command",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "bash",
    "bash.exe",
    "sh",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "wsl",
    "wsl.exe",
    "busybox",
}

DESTRUCTIVE_BASES = {
    "format",
    "format.com",
    "diskpart",
    "fdisk",
    "sfdisk",
    "cfdisk",
    "parted",
    "dd",
    "mkfs",
    "shutdown",
    "shutdown.exe",
    "reboot",
    "poweroff",
    "halt",
    "cipher",
}

INSTALLERS = {
    "apt",
    "apt-get",
    "aptitude",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "apk",
    "brew",
    "choco",
    "choco.exe",
    "winget",
    "winget.exe",
    "scoop",
    "pip",
    "pip3",
    "pipx",
    "npm",
    "yarn",
    "pnpm",
    "gem",
    "cargo",
    "uv",
}

INSTALL_ACTIONS = {
    "install",
    "uninstall",
    "remove",
    "rm",
    "add",
    "upgrade",
    "update",
    "erase",
    "purge",
    "autoremove",
    "sync",
    "-s",
}

READONLY_COMMANDS = {
    "where",
    "where.exe",
    "which",
    "whoami",
    "whoami.exe",
    "hostname",
    "hostname.exe",
    "uname",
    "systeminfo",
    "systeminfo.exe",
    "ver",
    "ipconfig",
    "ipconfig.exe",
    "ifconfig",
    "arp",
    "route",
    "ping",
    "ping.exe",
    "nslookup",
    "tasklist",
    "tasklist.exe",
    "ps",
    "ls",
    "dir",
    "cat",
    "type",
    "head",
    "tail",
    "grep",
    "findstr",
    "wc",
    "stat",
    "du",
    "df",
    "pwd",
    "printenv",
    "env",
    "id",
    "groups",
}

ACTIVE_SECURITY_TOOLS = {
    "nmap",
    "nmap.exe",
    "nikto",
    "nikto.pl",
    "nuclei",
    "nuclei.exe",
    "ffuf",
    "ffuf.exe",
    "httpx",
    "whatweb",
    "masscan",
    "dig",
    "host",
    "curl",
    "curl.exe",
    "wget",
    "wget.exe",
    "openssl",
    "openssl.exe",
    "nc",
    "ncat",
    "netcat",
    "sqlmap",
    "hydra",
    "hashcat",
    "john",
    "testssl.sh",
    "sslscan",
    "wafw00f",
    "subfinder",
    "amass",
    "naabu",
    "gobuster",
    "dirsearch",
    "wfuzz",
    "feroxbuster",
}

SCRIPT_SHIMS = {".cmd", ".bat", ".ps1"}

ROOTISH_TARGETS = {
    "/",
    "/*",
    "~",
    "~/",
    "*",
    "$home",
    "$home/",
    ".",
    "./",
}


def _base_name(executable: str) -> str:
    name = Path(executable).name.lower()
    return name


def _strip_exe(name: str) -> str:
    return name[:-4] if name.endswith(".exe") else name


def find_hard_block(argv: list[str]) -> str | None:
    base = _base_name(argv[0])
    stripped = _strip_exe(base)

    if base in SHELL_EXECUTABLES or stripped in SHELL_EXECUTABLES:
        return (
            f"Refusing to spawn a shell ('{base}'). Commands run as argv arrays without "
            "any shell; invoke the target program directly."
        )
    if base in DESTRUCTIVE_BASES or stripped in DESTRUCTIVE_BASES:
        return f"'{base}' is on the destructive-command blocklist and cannot be executed."

    tokens = [t.lower() for t in argv[1:]]

    if stripped == "rm":
        has_recursive = any(
            t in {"-r", "--recursive"}
            or (t.startswith("-") and not t.startswith("--") and "r" in t)
            for t in tokens
        )
        has_force = any(
            t == "--force" or (t.startswith("-") and not t.startswith("--") and "f" in t)
            for t in tokens
        )
        targets_rootish = any(
            t in ROOTISH_TARGETS
            or t in {"c:\\", "c:/"}
            or (len(t) <= 3 and t.endswith(":"))
            for t in tokens
        )
        if has_recursive and (has_force or targets_rootish):
            return "Refusing 'rm' with recursive force/root-style targets; this is destructive."

    if stripped in {"del", "rd", "rmdir", "erase"}:
        if any(t in {"/s", "/q", "/s/q", "/s /q"} for t in tokens) and any(
            t in {"\\", "\\*", "c:\\", "*"} for t in tokens
        ):
            return f"Refusing bulk '{stripped}' against a drive root; this is destructive."

    if stripped == "dd" and any(t.startswith("of=/dev/") for t in tokens):
        return "Refusing 'dd' writing to raw devices; this is destructive."

    if stripped == "reg" and "delete" in tokens[:3]:
        return "Refusing registry deletion via reg.exe."

    if stripped == "wevtutil" and "cl" in tokens[:2]:
        return "Refusing event-log clearing via wevtutil."

    return None


def classify_risk(argv: list[str]) -> RiskLevel:
    base = _strip_exe(_base_name(argv[0]))
    tokens = [t.lower() for t in argv[1:]]

    if tokens and all(t in VERSION_FLAGS for t in tokens):
        return RiskLevel.LOW

    if base in READONLY_COMMANDS:
        return RiskLevel.LOW

    if base in INSTALLERS:
        window = tokens[:5]
        if any(t in INSTALL_ACTIONS for t in window) or not tokens:
            return RiskLevel.HIGH
        return RiskLevel.MEDIUM

    if base in ACTIVE_SECURITY_TOOLS:
        return RiskLevel.MEDIUM

    return RiskLevel.MEDIUM


class RateLimiter:
    def __init__(self, max_per_minute: int = 20):
        self._max = max(1, max_per_minute)
        self._timestamps: deque[float] = deque()

    def allow(self, now: float | None = None) -> bool:
        moment = time.monotonic() if now is None else now
        while self._timestamps and moment - self._timestamps[0] > 60.0:
            self._timestamps.popleft()
        if len(self._timestamps) >= self._max:
            return False
        self._timestamps.append(moment)
        return True


class CommandHistory:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def add(self, entry: dict[str, Any]) -> None:
        entry = {"n": len(self.entries) + 1, **entry}
        self.entries.append(entry)

    def recent(self, count: int = 20) -> list[dict[str, Any]]:
        return list(self.entries[-count:])


def append_log_line(path: Path | None, payload: Mapping[str, Any]) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def validate_argv_shape(arguments: Mapping[str, Any]) -> str | None:
    argv_list = arguments.get("argv")
    if not isinstance(argv_list, list) or not argv_list:
        return "argv must be a non-empty array of strings"
    if not all(isinstance(item, str) and item.strip() for item in argv_list):
        return "every argv element must be a non-empty string"
    if len(argv_list) > MAX_ARGV_ITEMS:
        return f"argv allows at most {MAX_ARGV_ITEMS} items"
    if any(len(item) > MAX_ARG_LENGTH for item in argv_list):
        return f"each argv item must be at most {MAX_ARG_LENGTH} characters"
    if sum(len(item) for item in argv_list) > MAX_TOTAL_ARG_BYTES:
        return "total command length exceeds the allowed maximum"
    return None


def _decode_stream(stream: object) -> str:
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    if isinstance(stream, str):
        return stream
    return ""


def _cap_output(text: str) -> str:
    if text is None:
        return ""
    if len(text) <= OUTPUT_CAP_CHARS:
        return text
    dropped = len(text) - OUTPUT_CAP_CHARS
    return text[:OUTPUT_CAP_CHARS] + f"\n...[truncated {dropped} characters]"


class TerminalTool:
    def __init__(
        self,
        *,
        history: CommandHistory | None = None,
        log_path: Path | None = None,
        limiter: RateLimiter | None = None,
        max_commands: int = 100,
    ):
        self.history = history if history is not None else CommandHistory()
        self.log_path = log_path
        self.limiter = limiter if limiter is not None else RateLimiter()
        self.max_commands = max(1, max_commands)
        self._attempts = 0

    def block_reason(self, arguments: Mapping[str, Any]) -> str | None:
        shape_problem = validate_argv_shape(arguments)
        if shape_problem:
            return shape_problem
        argv = list(arguments["argv"])

        resolved = shutil.which(argv[0])
        hard_block = find_hard_block(argv)
        if hard_block:
            return hard_block

        if resolved is None:
            return (
                f"Executable '{argv[0]}' was not found on PATH. Run check_tool first to "
                "see what is installed."
            )
        if Path(resolved).suffix.lower() in SCRIPT_SHIMS:
            return (
                f"'{argv[0]}' resolves to a script shim ({resolved}) which cannot be "
                "executed directly without a shell. Invoke the underlying executable instead."
            )
        return None

    def risk_of(self, arguments: Mapping[str, Any]) -> RiskLevel:
        argv = arguments.get("argv")
        if isinstance(argv, list) and argv and all(isinstance(t, str) for t in argv):
            return classify_risk([str(t) for t in argv])
        return RiskLevel.HIGH

    def execute(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        argv = [str(item) for item in arguments["argv"]]
        display_command = " ".join(argv)[:200]
        timeout = self._clamp_timeout(arguments.get("timeout_sec"))

        blocked = self.block_reason(arguments)
        if blocked:
            self._record(argv, None, 0.0, False, "blocked", note=blocked)
            return {
                "error": "blocked_by_safety_gate",
                "reason": blocked,
                "summary": f"blocked · {display_command}",
            }

        executable = shutil.which(argv[0])
        assert executable is not None

        if self._attempts >= self.max_commands:
            self._record(argv, None, 0.0, False, "budget_exhausted")
            return {
                "error": "command_budget_exhausted",
                "reason": (
                    f"Session limit of {self.max_commands} executed commands reached; "
                    "summarize findings instead of running more commands."
                ),
                "summary": f"command budget exhausted · {display_command}",
            }

        if not self.limiter.allow():
            self._record(argv, None, 0.0, False, "rate_limited")
            return {
                "error": "rate_limited",
                "reason": "Too many commands in a short window; wait a moment and retry.",
                "summary": f"rate limited · {display_command}",
            }

        self._attempts += 1
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                [executable, *argv[1:]],
                shell=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - started
            stdout = _decode_stream(exc.stdout)
            stderr = _decode_stream(exc.stderr)
            self._record(argv, None, duration, True, "timeout")
            return {
                "error": "timeout",
                "reason": f"Command exceeded the {timeout}s timeout and was terminated.",
                "command": display_command,
                "exit_code": None,
                "stdout": _cap_output(stdout),
                "stderr": _cap_output(stderr),
                "duration": round(duration, 3),
                "timed_out": True,
                "summary": f"timeout after {timeout}s · {display_command}",
            }
        except OSError as exc:
            duration = time.perf_counter() - started
            self._record(argv, None, duration, False, "os_error")
            return {
                "error": "execution_failed",
                "detail": str(exc)[:300],
                "command": display_command,
                "summary": f"os error · {display_command}",
            }

        duration = time.perf_counter() - started
        self._record(argv, proc.returncode, duration, False, "executed")
        return {
            "command": display_command,
            "exit_code": proc.returncode,
            "stdout": _cap_output(proc.stdout or ""),
            "stderr": _cap_output(proc.stderr or ""),
            "duration": round(duration, 3),
            "timed_out": False,
            "summary": f"exit={proc.returncode} · {duration:.1f}s · {display_command}",
        }

    @staticmethod
    def _clamp_timeout(requested: Any) -> int:
        try:
            value = int(str(requested))
        except (TypeError, ValueError):
            return DEFAULT_TIMEOUT_S
        return max(1, min(MAX_TIMEOUT_S, value))

    def _record(
        self,
        argv: list[str],
        exit_code: int | None,
        duration: float,
        timed_out: bool,
        status: str,
        note: str | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "command": " ".join(argv)[:500],
            "status": status,
            "exit_code": exit_code,
            "duration_s": round(duration, 3),
            "timed_out": timed_out,
        }
        if note:
            entry["note"] = note[:300]
        self.history.add(entry)
        append_log_line(self.log_path, entry)


TERMINAL_DESCRIPTION = (
    "Run ONE local command with NO shell. Provide `argv` as an array where item 0 is the "
    "program name and the rest are its arguments, e.g. {\"argv\": [\"nmap\", \"-sV\", "
    "\"example.com\"]}. Optional integer `timeout_sec` (default 30, max 300). Returns exit "
    "code, stdout, stderr and duration. Rules: detect the OS first (environment tool), prefer "
    "read-only diagnostics, use absolute-safe program names, never attempt destructive or "
    "off-scope actions. High-risk commands (e.g. package installs) will ask the user first."
)

TERMINAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["argv"],
    "properties": {
        "argv": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": MAX_ARGV_ITEMS,
        },
        "timeout_sec": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_S},
    },
}


def build_terminal_tool(
    *,
    history: CommandHistory | None = None,
    log_path: Path | None = None,
    limiter: RateLimiter | None = None,
    max_commands: int = 100,
) -> ToolSpec:
    tool = TerminalTool(
        history=history, log_path=log_path, limiter=limiter, max_commands=max_commands
    )
    return ToolSpec(
        name="terminal",
        description=TERMINAL_DESCRIPTION,
        parameters=TERMINAL_SCHEMA,
        risk=RiskLevel.MEDIUM,
        handler=tool.execute,
        risk_for=tool.risk_of,
        check_args=tool.block_reason,
    )
