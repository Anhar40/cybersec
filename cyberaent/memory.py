"""Persistent assessment memory (endpoints, technologies, tests, preferences).

The store survives restarts: it is a single JSON document under ``memory/`` so
a pentest can be resumed days later. Everything is deduplicated and capped so a
long session cannot grow without bound, and :meth:`SessionMemory.brief` renders
the facts worth re-reading on every turn.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

MEMORY_DIR = Path("memory")
MEMORY_FILE = MEMORY_DIR / "knowledge.json"
STATE_VERSION = 1

MAX_ENDPOINTS = 400
MAX_TECHNOLOGIES = 150
MAX_TESTS = 300
MAX_OBSERVATIONS = 200
MAX_PREFERENCES = 50
MAX_BRIEF_CHARS = 1800

MEMORY_KINDS: tuple[str, ...] = ("endpoint", "technology", "test", "observation", "preference")

_SECTIONS: tuple[str, ...] = (
    "endpoints",
    "technologies",
    "test_results",
    "observations",
    "preferences",
    "plan",
    "hypotheses",
    "graph",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _empty_state() -> dict[str, Any]:
    now = _now()
    return {
        "version": STATE_VERSION,
        "created_at": now,
        "updated_at": now,
        "endpoints": [],
        "technologies": [],
        "test_results": [],
        "observations": [],
        "preferences": [],
        "plan": {"goal": "", "steps": [], "updated_at": ""},
        "hypotheses": [],
        "graph": {"nodes": {}, "edges": {}},
    }


def _trim(items: list[Any], cap: int) -> list[Any]:
    return items[-cap:] if len(items) > cap else items


def canonical_url(raw: str) -> tuple[str, list[str]]:
    """Normalize a URL and return it together with its query parameter names."""
    text = str(raw or "").strip()
    if not text:
        return "", []
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    if not parts.netloc:
        return str(raw).strip(), []
    host = parts.netloc.lower()
    path = parts.path.rstrip("/") or "/"
    params = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True) if name})
    return f"{parts.scheme.lower()}://{host}{path}", params


class SessionMemory:
    """Durable, deduplicated knowledge gathered during assessments."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else MEMORY_FILE
        self.state: dict[str, Any] = self._load()

    # ------------------------------------------------------------- persistence
    def _load(self) -> dict[str, Any]:
        state = _empty_state()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return state
        if not isinstance(raw, dict):
            return state
        for section in _SECTIONS:
            value = raw.get(section)
            if section in ("plan", "graph"):
                if isinstance(value, dict):
                    state[section] = value
            elif isinstance(value, list):
                state[section] = value
        return state

    def save(self) -> None:
        self.state["updated_at"] = _now()
        payload = json.dumps(self.state, ensure_ascii=False, indent=2, default=str)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass

    # --------------------------------------------------------------- endpoints
    def remember_endpoint(
        self,
        *,
        url: str,
        method: str = "GET",
        params: Sequence[str] = (),
        status: Any = None,
        tech: str = "",
        auth: str = "",
        role: str = "",
        source: str = "",
    ) -> dict[str, Any] | None:
        canonical, url_params = canonical_url(url)
        if not canonical:
            return None
        verb = str(method or "GET").strip().upper()[:12]
        names = sorted({str(p).strip() for p in (*url_params, *params) if str(p).strip()})
        entries: list[dict[str, Any]] = self.state["endpoints"]
        for entry in entries:
            if (
                entry.get("method") == verb
                and entry.get("url") == canonical
                and entry.get("params") == names
            ):
                self._enrich(entry, status=status, tech=tech, auth=auth, role=role, source=source)
                entry["last_seen"] = _now()
                return entry
        entry = {
            "url": canonical,
            "method": verb,
            "params": names,
            "status": status,
            "technologies": [tech] if tech else [],
            "auth": auth,
            "role": role,
            "source": source,
            "first_seen": _now(),
            "last_seen": _now(),
        }
        entries.append(entry)
        self.state["endpoints"] = _trim(entries, MAX_ENDPOINTS)
        return entry

    @staticmethod
    def _enrich(entry: dict[str, Any], **fields: Any) -> None:
        for key, value in fields.items():
            if not value:
                continue
            if key == "tech":
                techs: list[str] = entry.setdefault("technologies", [])
                if value not in techs:
                    techs.append(value)
            else:
                entry[key] = value

    def endpoints(self, *, host: str = "") -> list[dict[str, Any]]:
        entries = self.state["endpoints"]
        if not host:
            return [dict(entry) for entry in entries]
        needle = host.lower()
        return [dict(e) for e in entries if needle in str(e.get("url", "")).lower()]

    # ---------------------------------------------------------- technologies
    def remember_technology(
        self, *, name: str, version: str = "", evidence: str = "", source: str = ""
    ) -> dict[str, Any] | None:
        clean = str(name or "").strip()
        if not clean:
            return None
        key = clean.lower()
        entries: list[dict[str, Any]] = self.state["technologies"]
        for entry in entries:
            if str(entry.get("name", "")).lower() == key:
                if version and not entry.get("version"):
                    entry["version"] = str(version).strip()[:80]
                if evidence:
                    entry["evidence"] = str(evidence)[:300]
                entry["last_seen"] = _now()
                return entry
        entry = {
            "name": clean,
            "version": str(version).strip()[:80],
            "evidence": str(evidence)[:300],
            "source": source,
            "first_seen": _now(),
            "last_seen": _now(),
        }
        entries.append(entry)
        self.state["technologies"] = _trim(entries, MAX_TECHNOLOGIES)
        return entry

    def technologies(self) -> list[dict[str, Any]]:
        return [dict(entry) for entry in self.state["technologies"]]

    # ----------------------------------------------------------- test history
    def remember_test(
        self, *, tool: str, target: str, outcome: str = "ok", note: str = "", detail: str = ""
    ) -> dict[str, Any]:
        clean_tool = str(tool or "").strip()
        clean_target = str(target or "").strip()
        entries: list[dict[str, Any]] = self.state["test_results"]
        for entry in entries:
            if entry.get("tool") == clean_tool and entry.get("target") == clean_target:
                entry["runs"] = int(entry.get("runs", 1)) + 1
                entry["outcome"] = outcome
                entry["last_run"] = _now()
                if note:
                    entry["note"] = str(note)[:300]
                return entry
        entry = {
            "tool": clean_tool,
            "target": clean_target,
            "outcome": outcome,
            "note": str(note)[:300],
            "detail": str(detail)[:300],
            "runs": 1,
            "first_run": _now(),
            "last_run": _now(),
        }
        entries.append(entry)
        self.state["test_results"] = _trim(entries, MAX_TESTS)
        return entry

    def tests(self, *, tool: str = "") -> list[dict[str, Any]]:
        entries = self.state["test_results"]
        if not tool:
            return [dict(entry) for entry in entries]
        return [dict(entry) for entry in entries if entry.get("tool") == tool]

    def test_done(self, tool: str, target: str = "") -> bool:
        needle = str(target).lower()
        for entry in self.state["test_results"]:
            if entry.get("tool") != tool:
                continue
            if not needle or needle in str(entry.get("target", "")).lower():
                return True
        return False

    def tools_already_run(self) -> set[str]:
        return {str(entry.get("tool", "")) for entry in self.state["test_results"]}

    # ---------------------------------------------------------- observations
    def remember_observation(self, *, kind: str, text: str, target: str = "") -> dict[str, Any]:
        entry = {
            "kind": str(kind or "note").strip()[:40] or "note",
            "text": str(text)[:500],
            "target": str(target)[:200],
            "recorded_at": _now(),
        }
        entries: list[dict[str, Any]] = self.state["observations"]
        entries.append(entry)
        self.state["observations"] = _trim(entries, MAX_OBSERVATIONS)
        return entry

    def observations(self, *, kind: str = "") -> list[dict[str, Any]]:
        entries = self.state["observations"]
        if not kind:
            return [dict(entry) for entry in entries]
        return [dict(entry) for entry in entries if entry.get("kind") == kind]

    def remember_preference(self, text: str) -> dict[str, Any]:
        clean = str(text or "").strip()[:300]
        entry = {"text": clean, "recorded_at": _now()}
        entries: list[dict[str, Any]] = self.state["preferences"]
        if clean and not any(e.get("text") == clean for e in entries):
            entries.append(entry)
            self.state["preferences"] = _trim(entries, MAX_PREFERENCES)
        return entry

    def preferences(self) -> list[dict[str, Any]]:
        return [dict(entry) for entry in self.state["preferences"]]

    # ------------------------------------------------------------------ misc
    def stats(self) -> dict[str, int]:
        return {
            "endpoints": len(self.state["endpoints"]),
            "technologies": len(self.state["technologies"]),
            "tests": len(self.state["test_results"]),
            "observations": len(self.state["observations"]),
            "preferences": len(self.state["preferences"]),
        }

    def recall(
        self, *, query: str = "", kinds: Iterable[str] = (), limit: int = 25
    ) -> list[dict[str, Any]]:
        """Return memory entries matching a free-text query and/or kind filter.

        Each row carries ``memory_kind`` (endpoint, technology, test,
        observation, preference) so the record's own fields are never shadowed.
        """
        wanted = {str(k) for k in kinds} if kinds else set(MEMORY_KINDS)
        needle = str(query or "").strip().lower()
        rows: list[dict[str, Any]] = []

        def collect(memory_kind: str, entries: list[dict[str, Any]]) -> None:
            if memory_kind not in wanted:
                return
            for entry in entries:
                rows.append({"memory_kind": memory_kind, **_flatten(entry)})

        collect("endpoint", self.endpoints())
        collect("technology", self.technologies())
        collect("test", self.tests())
        collect("observation", self.observations())
        collect("preference", self.preferences())
        if needle:
            rows = [row for row in rows if needle in json.dumps(row, default=str).lower()]
        return rows[: max(1, limit)]

    def brief(self) -> str:
        """Compact, deterministic recap of everything worth remembering."""
        stats = self.stats()
        plan = self.state.get("plan") or {}
        hypotheses = self.state.get("hypotheses") or []
        if not any(stats.values()) and not plan.get("goal") and not plan.get("steps"):
            if not hypotheses:
                return ""
        lines: list[str] = []
        goal = str(plan.get("goal") or "")
        steps = plan.get("steps") or []
        active = [s for s in steps if s.get("status") in ("pending", "in_progress", "blocked")]
        if goal or active:
            lines.append(f"Plan: {goal or '(unnamed)'}")
            for step in active[:6]:
                marker = {"in_progress": "->", "blocked": "!!", "pending": " ."}.get(
                    str(step.get("status")), " ."
                )
                note = str(step.get("note") or "").strip()
                suffix = f" — {note}" if note else ""
                lines.append(f"  {marker} {step.get('index')}. {step.get('title')}{suffix}")
        endpoints = self.endpoints()
        if endpoints:
            shown = endpoints[:6]
            lines.append(
                f"Known endpoints ({len(endpoints)}): "
                + ", ".join(f"{e.get('method')} {e.get('url')}" for e in shown)
            )
            params = sorted({p for e in endpoints for p in (e.get("params") or [])})[:10]
            if params:
                lines.append(f"Known parameters: {', '.join(params)}")
        techs = self.technologies()
        if techs:
            lines.append(
                "Known tech: "
                + ", ".join(f"{t.get('name')} {t.get('version')}".strip() for t in techs[:8])
            )
        open_hyp = [
            h for h in hypotheses if h.get("status") in ("proposed", "testing", "supported")
        ]
        if open_hyp:
            lines.append(
                f"Open hypotheses ({len(open_hyp)}): "
                + ", ".join(f"{h.get('id')} {h.get('statement')}" for h in open_hyp[:4])
            )
        prefs = self.preferences()
        if prefs:
            lines.append("User preferences: " + "; ".join(str(p.get("text")) for p in prefs[:4]))
        done = sorted(self.tools_already_run())
        if done:
            lines.append("Tests already run (do not repeat blindly): " + ", ".join(done[:12]))
        text = "\n".join(lines)
        return text if len(text) <= MAX_BRIEF_CHARS else text[: MAX_BRIEF_CHARS - 3] + "..."

    def clear(self) -> None:
        created = self.state.get("created_at")
        self.state = _empty_state()
        self.state["created_at"] = created or _now()


def _flatten(entry: dict[str, Any]) -> dict[str, Any]:
    return dict(entry)
