"""Curated filesystem deletion (PRD-safe alternative to raw ``rm``).

The model emits structured arguments (``paths`` + ``recursive``); deletion
runs in Python via :mod:`pathlib`/:mod:`shutil` — no shell, no argv passthrough.
Hard guards refuse system locations and the home/working-directory roots;
the spec is HIGH risk so the safety gate always asks the user first.
"""

from __future__ import annotations

import os
import shutil
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import RiskLevel, ToolSpec
from .terminal import CommandHistory, append_log_line

MAX_PATHS_PER_CALL = 20

_FILE_DELETE_DESCRIPTION = (
    "Delete local files or directories by absolute or ~-relative path. Structured "
    "and guarded: system locations are refused, directories need recursive=true, "
    "and every call requires explicit user confirmation before anything is removed."
)

_FILE_DELETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": MAX_PATHS_PER_CALL,
            "description": "Files or directories to delete (1..20 entries).",
        },
        "recursive": {
            "type": "boolean",
            "description": "Required true to remove directories and their contents.",
        },
    },
    "required": ["paths"],
}

_POSIX_PROTECTED = (
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/usr",
    "/var",
)


def _fold(text: str) -> str:
    return text.lower() if os.name == "nt" else text


def _resolve_entry(entry: str) -> str:
    # abspath (not Path.resolve) so a trailing symlink stays itself — deleting
    # the link must not silently retarget the real object behind it.
    expanded = os.path.expandvars(os.path.expanduser(entry.strip()))
    return os.path.abspath(expanded)


def protected_roots(
    environ: Mapping[str, str] = os.environ,
    *,
    home: Path | None = None,
    cwd: Path | None = None,
) -> list[str]:
    """Absolute locations that may never be deleted themselves."""
    home = home if home is not None else Path.home()
    cwd = cwd if cwd is not None else Path.cwd()
    roots = {str(home.resolve()), str(cwd.resolve()), str(cwd.anchor)}
    if os.name == "nt":
        for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            value = environ.get(var)
            if value:
                roots.add(str(Path(value).resolve()))
    else:
        roots.update(_POSIX_PROTECTED)
    return sorted(roots)


def classify_deletions(resolved: list[str], *, protected: list[str]) -> dict[str, str]:
    """Map each resolved path to ``"ok"`` or ``"protected"``."""
    blocked = {_fold(root) for root in protected}
    verdicts: dict[str, str] = {}
    for path in resolved:
        verdicts[path] = "protected" if _fold(path) in blocked else "ok"
    return verdicts


class FileDeletionTool:
    """Structured, guarded deletion runner."""

    def __init__(
        self,
        *,
        history: CommandHistory | None = None,
        log_path: Path | None = None,
    ):
        self.history = history if history is not None else CommandHistory()
        self.log_path = log_path

    # ------------------------------------------------------------------ public
    def delete(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        raw_paths = arguments.get("paths")
        recursive = bool(arguments.get("recursive"))
        paths = self._validated(raw_paths)
        if isinstance(paths, dict):
            return paths

        resolved = [_resolve_entry(p) for p in paths]
        verdicts = classify_deletions(resolved, protected=protected_roots())

        results: list[dict[str, Any]] = []
        deleted: list[str] = []
        for original, target in zip(paths, resolved, strict=True):
            if verdicts[target] != "ok":
                results.append({"path": original, "status": "refused_protected"})
                continue
            outcome = self._remove_one(Path(target), recursive=recursive)
            outcome["path"] = original
            results.append(outcome)
            if outcome["status"] == "deleted":
                deleted.append(target)

        duration = time.perf_counter() - started
        failures = [r for r in results if r["status"] not in ("deleted",)]
        payload: dict[str, Any] = {
            "requested": len(paths),
            "deleted_count": len(deleted),
            "recursive": recursive,
            "results": results,
            "summary": self._summarize(len(deleted), len(paths), recursive, failures),
        }
        if failures and not deleted:
            payload["error"] = "deletion_failed"
            payload["reason"] = "Nothing was deleted; inspect per-path statuses."
        self._record(len(paths), len(deleted), duration)
        return payload

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _validated(raw: Any) -> list[str] | dict[str, Any]:
        if not isinstance(raw, list) or not raw:
            return {
                "error": "invalid_arguments",
                "reason": "'paths' must be a non-empty array of path strings.",
                "summary": "invalid · file_delete",
            }
        cleaned = [p.strip() for p in (str(item) for item in raw)]
        if any(not p for p in cleaned):
            return {
                "error": "invalid_arguments",
                "reason": "Every entry in 'paths' must be a non-empty string.",
                "summary": "invalid · file_delete",
            }
        if len(cleaned) > MAX_PATHS_PER_CALL:
            return {
                "error": "too_many_paths",
                "reason": f"At most {MAX_PATHS_PER_CALL} paths per call.",
                "summary": "too many targets · file_delete",
            }
        return cleaned

    @staticmethod
    def _remove_one(target: Path, *, recursive: bool) -> dict[str, Any]:
        try:
            if target.is_symlink():
                target.unlink()
                return {"status": "deleted", "kind": "symlink_link_only"}
            if target.is_dir():
                if not recursive:
                    return {
                        "status": "directory_needs_recursive",
                        "hint": "Pass recursive=true to remove this directory.",
                    }
                shutil.rmtree(target)
                return {"status": "deleted", "kind": "directory"}
            if not target.exists():
                return {"status": "missing"}
            target.unlink()
            return {"status": "deleted", "kind": "file"}
        except OSError as exc:
            return {"status": "os_error", "detail": str(exc)[:300]}

    @staticmethod
    def _summarize(
        deleted: int, requested: int, recursive: bool, failures: list[dict[str, Any]]
    ) -> str:
        parts = [f"deleted {deleted}/{requested}"]
        if recursive:
            parts.append("recursive")
        if failures:
            kinds = sorted({str(r["status"]) for r in failures})
            parts.append(f"issues: {', '.join(kinds)}")
        return " · ".join(parts)

    def _record(self, requested: int, deleted: int, duration: float) -> None:
        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "command": f"[fsops] delete {requested} target(s)",
            "status": "deleted" if deleted else "no_deletions",
            "exit_code": 0 if deleted == requested else 1,
            "duration_s": round(duration, 3),
            "timed_out": False,
            "verified": deleted == requested,
        }
        self.history.add(entry)
        append_log_line(self.log_path, entry)


def _file_delete_block(arguments: Mapping[str, Any]) -> str | None:
    raw = arguments.get("paths")
    if not isinstance(raw, list) or not raw:
        return "'paths' must be a non-empty array of path strings."
    if len(raw) > MAX_PATHS_PER_CALL:
        return f"At most {MAX_PATHS_PER_CALL} paths per call."
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            return "Every entry in 'paths' must be a non-empty string."
    return None


def build_fsops_tools(
    *,
    history: CommandHistory | None = None,
    log_path: Path | None = None,
) -> list[ToolSpec]:
    tool = FileDeletionTool(history=history, log_path=log_path)
    spec = ToolSpec(
        name="file_delete",
        description=_FILE_DELETE_DESCRIPTION,
        parameters=_FILE_DELETE_SCHEMA,
        risk=RiskLevel.HIGH,
        handler=tool.delete,
        check_args=_file_delete_block,
    )
    return [spec]


__all__ = [
    "MAX_PATHS_PER_CALL",
    "FileDeletionTool",
    "build_fsops_tools",
    "classify_deletions",
    "protected_roots",
]
