"""Intelligence hub: the object that makes the agent reason instead of react.

``IntelHub`` owns the four ledgers of an assessment — session memory, attack
surface, evidence, and hypotheses — and wires them together:

* every tool result is captured as *facts* (endpoints, technologies, headers,
  ports), so later decisions can cite evidence instead of guessing;
* findings flow through the evidence store's status taxonomy, and deciding a
  finding automatically closes the hypotheses that cited it;
* the plan, hypotheses, and coverage gaps produce a short brief that is injected
  into the model context, which is what makes long assessments coherent.

It is deliberately plain Python: no hidden network calls, no model calls, and
every method is safe to unit test in isolation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .hypotheses import HypothesisStore
from .memory import SessionMemory
from .strategy import NextAction, StrategyEngine
from .surface import AttackSurface
from .tools.evidence import EvidenceStore

PLAN_STATUSES: tuple[str, ...] = ("pending", "in_progress", "done", "blocked", "skipped")

MAX_PLAN_STEPS = 25
MAX_TITLE_LENGTH = 160
MAX_NOTE_LENGTH = 300

_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")
_ENDPOINT_KEYS = ("url", "matched_at", "host", "input")
_URL_LIST_KEYS = ("urls", "subdomains", "endpoints", "hosts")
_TECH_LIST_KEYS = ("technologies", "tech", "techs", "webserver", "cms", "javascript")
_TECH_ITEM_KEYS = ("webserver", "cms", "javascript", "technologies")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clip(value: Any, limit: int, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string.")
    text = value.strip()
    if len(text) > limit:
        raise ValueError(f"'{field}' exceeds {limit} characters.")
    return text


class IntelHub:
    """Coordinates memory, attack surface, evidence, hypotheses, and planning."""

    def __init__(
        self,
        *,
        memory: SessionMemory | None = None,
        evidence_store: EvidenceStore | None = None,
        memory_path: Path | None = None,
        scope: str = "",
    ) -> None:
        self.memory = memory if memory is not None else SessionMemory(memory_path)
        self.evidence = evidence_store if evidence_store is not None else EvidenceStore()
        self.surface = AttackSurface(self.memory)
        self.hypotheses = HypothesisStore(self.memory, finding_exists=self.finding_exists)
        self.strategy = StrategyEngine(
            memory=self.memory,
            surface=self.surface,
            evidence=self.evidence,
            hypotheses=self.hypotheses,
            scope=scope,
        )

    # ------------------------------------------------------------------ facts
    def finding_exists(self, finding_id: str) -> bool:
        needle = str(finding_id).lower()
        return any(str(f["id"]).lower() == needle for f in self.evidence.findings())

    def observe_tool_result(
        self,
        tool_name: str,
        payload: Mapping[str, Any],
        arguments: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Capture everything a tool learned into the ledgers (no-op on errors)."""
        captured: dict[str, int] = {"endpoints": 0, "technologies": 0, "observations": 0}
        target = self._target_from(tool_name, payload, arguments or {})

        if payload.get("error"):
            self.memory.remember_test(
                tool=tool_name,
                target=target,
                outcome="error",
                note=str(payload.get("summary") or payload.get("reason") or "")[:MAX_NOTE_LENGTH],
            )
            self.save()
            return {"error": True, "target": target, "captured": captured}

        summary = str(payload.get("summary") or "").strip()
        self.memory.remember_test(
            tool=tool_name,
            target=target,
            outcome="ok",
            note=summary[:MAX_NOTE_LENGTH],
        )
        if summary:
            self.memory.remember_observation(kind="tool_summary", text=summary, target=target)
            captured["observations"] += 1

        captured["endpoints"] = self._capture_endpoints(payload, arguments or {})
        captured["technologies"] = self._capture_technologies(payload, target)
        captured["observations"] += self._capture_observations(payload, target)
        self.save()
        return {"error": False, "target": target, "captured": captured}

    @staticmethod
    def _target_from(
        tool_name: str, payload: Mapping[str, Any], arguments: Mapping[str, Any]
    ) -> str:
        for key in ("url", "target"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        urls = arguments.get("urls")
        if isinstance(urls, Sequence) and not isinstance(urls, str) and urls:
            return str(urls[0]).strip()
        for key in _URL_LIST_KEYS + _ENDPOINT_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, list) and value and isinstance(value[0], str):
                return str(value[0]).strip()
        return tool_name

    def _capture_endpoints(self, payload: Mapping[str, Any], arguments: Mapping[str, Any]) -> int:
        count = 0
        candidates: list[str] = []
        for key in _ENDPOINT_KEYS + _URL_LIST_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())
            elif isinstance(value, list):
                candidates.extend(str(item).strip() for item in value if isinstance(item, str))
        for value in (arguments.get("url"), arguments.get("target")):
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())
        argument_urls = arguments.get("urls")
        if isinstance(argument_urls, Sequence) and not isinstance(argument_urls, str):
            candidates.extend(str(item).strip() for item in argument_urls if isinstance(item, str))
        status = payload.get("http_status") or payload.get("status_code")
        method = str(arguments.get("method") or "GET").upper()
        for entry in payload.get("results") or []:
            if not isinstance(entry, Mapping):
                continue
            for key in ("url", "input", "host"):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    candidates.append(value.strip())
        seen: set[str] = set()
        for candidate in candidates:
            if not _looks_like_target(candidate):
                continue
            clean = candidate.split("://", 1)[-1]
            if clean in seen:
                continue
            seen.add(clean)
            if self.surface.remember_endpoint(
                url=candidate, method=method, status=status, source=tool_source(payload)
            ):
                count += 1
        return count

    def _capture_technologies(self, payload: Mapping[str, Any], target: str) -> int:
        count = 0
        headers = payload.get("headers")
        if isinstance(headers, Mapping):
            for name in _TECH_HEADERS:
                value = headers.get(name)
                if isinstance(value, str) and value.strip():
                    if self.memory.remember_technology(
                        name=value.strip()[:80], evidence=f"HTTP header {name}", source=target
                    ):
                        count += 1
        for key in _TECH_LIST_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                if self.memory.remember_technology(name=value.strip()[:80], source=target):
                    count += 1
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        if self.memory.remember_technology(name=item.strip()[:80], source=target):
                            count += 1
        for entry in payload.get("results") or []:
            if not isinstance(entry, Mapping):
                continue
            for key in _TECH_ITEM_KEYS:
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    if self.memory.remember_technology(
                        name=value.strip()[:80],
                        evidence=f"{key} from probe",
                        source=str(entry.get("url") or entry.get("host") or target),
                    ):
                        count += 1
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            tech_name = item.strip()[:80]
                            if self.memory.remember_technology(name=tech_name, source=target):
                                count += 1
        return count

    def _capture_observations(self, payload: Mapping[str, Any], target: str) -> int:
        count = 0
        ports = payload.get("ports")
        if isinstance(ports, list) and ports:
            joined = ", ".join(str(port) for port in ports[:20])
            if self.memory.remember_observation(kind="ports", text=joined, target=target):
                count += 1
        checks = payload.get("checks")
        if isinstance(checks, list):
            failing = [
                str(entry.get("check"))
                for entry in checks
                if isinstance(entry, Mapping) and str(entry.get("status")) in ("fail", "warn")
            ]
            if failing:
                text = f"header checks needing attention: {', '.join(failing[:10])}"
                if self.memory.remember_observation(kind="headers", text=text, target=target):
                    count += 1
        return count

    # -------------------------------------------------------------- evidence
    def record_finding(self, **kwargs: Any) -> dict[str, Any]:
        result = self.evidence.add(source_tool="manual", **kwargs)
        record = result.record
        if record.get("status") == "verified":
            for closed in self.hypotheses.resolve_by_finding(str(record["id"]), supported=True):
                record.setdefault("closed_hypotheses", []).append(closed["id"])
        self.save()
        return record

    def verify_finding(self, finding_id: str, **kwargs: Any) -> dict[str, Any]:
        result = self.evidence.verify(finding_id, **kwargs)
        record = result.record
        closed = self.hypotheses.resolve_by_finding(
            str(record["id"]), supported=record["status"] == "verified"
        )
        if closed:
            record["closed_hypotheses"] = [row["id"] for row in closed]
        self.save()
        return record

    def list_findings(self, *, status: str = "") -> list[dict[str, Any]]:
        return self.evidence.findings(status=status) if status else self.evidence.findings()

    # ------------------------------------------------------------------ plans
    def set_plan(self, goal: Any, steps: Any) -> dict[str, Any]:
        clean_goal = _clip(goal, MAX_NOTE_LENGTH, "goal")
        if not isinstance(steps, Sequence) or isinstance(steps, str) or not steps:
            raise ValueError("'steps' must be a non-empty list of step titles.")
        if len(steps) > MAX_PLAN_STEPS:
            raise ValueError(f"A plan may hold at most {MAX_PLAN_STEPS} steps.")
        normalized: list[dict[str, Any]] = []
        for index, raw in enumerate(steps, start=1):
            if isinstance(raw, Mapping):
                title = _clip(raw.get("title"), MAX_TITLE_LENGTH, "step")
                status = str(raw.get("status") or "pending").lower()
                note = _clip(raw.get("note"), MAX_NOTE_LENGTH, "note")
            else:
                title = _clip(raw, MAX_TITLE_LENGTH, "step")
                status, note = "pending", ""
            if not title:
                raise ValueError("Every plan step needs a title.")
            if status not in PLAN_STATUSES:
                raise ValueError(f"Step status must be one of: {', '.join(PLAN_STATUSES)}.")
            normalized.append(
                {"index": index, "title": title, "status": status, "note": note}
            )
        plan = {"goal": clean_goal, "steps": normalized, "updated_at": _now()}
        self.memory.state["plan"] = plan
        self.save()
        return dict(plan)

    def update_step(self, index: Any, status: Any, note: Any = "") -> dict[str, Any]:
        plan = self.memory.state.get("plan") or {}
        steps = plan.get("steps") or []
        if not steps:
            raise ValueError("There is no plan yet; call set_plan first.")
        if isinstance(index, bool) or not isinstance(index, int):
            raise ValueError("'index' must be an integer step number.")
        if not 1 <= index <= len(steps):
            raise ValueError(f"Step index must be between 1 and {len(steps)}.")
        new_status = str(status or "").lower()
        if new_status not in PLAN_STATUSES:
            raise ValueError(f"Step status must be one of: {', '.join(PLAN_STATUSES)}.")
        step = steps[index - 1]
        step["status"] = new_status
        if note:
            step["note"] = _clip(note, MAX_NOTE_LENGTH, "note")
        plan["updated_at"] = _now()
        self.memory.state["plan"] = plan
        self.save()
        return dict(step)

    def plan(self) -> dict[str, Any]:
        return dict(self.memory.state.get("plan") or {"goal": "", "steps": []})

    # ----------------------------------------------------------------- extras
    def note(self, kind: Any, text: Any, target: Any = "") -> dict[str, Any]:
        clean_kind = _clip(kind, 40, "kind") or "note"
        clean_text = _clip(text, MAX_NOTE_LENGTH * 2, "text")
        if not clean_text:
            raise ValueError("'text' must not be empty.")
        record = self.memory.remember_observation(
            kind=clean_kind, text=clean_text, target=_clip(target, 200, "target")
        )
        self.save()
        return record

    def prefer(self, text: Any) -> dict[str, Any]:
        clean = _clip(text, MAX_NOTE_LENGTH, "text")
        if not clean:
            raise ValueError("'text' must not be empty.")
        record = self.memory.remember_preference(clean)
        self.save()
        return record

    def recall(self, *, query: str = "", kinds: Sequence[str] = (), limit: int = 25):
        return self.memory.recall(query=query, kinds=kinds, limit=limit)

    def remember_endpoint(self, **kwargs: Any) -> str | None:
        node = self.surface.remember_endpoint(**kwargs)
        self.save()
        return node

    def next_actions(self, *, limit: int = 6) -> list[dict[str, Any]]:
        return self.strategy.next_actions(limit=limit)

    def propose_hypothesis(self, **kwargs: Any) -> dict[str, Any]:
        record = self.hypotheses.propose(**kwargs)
        self.save()
        return record

    def set_hypothesis_status(self, hypothesis_id: str, **kwargs: Any) -> dict[str, Any]:
        record = self.hypotheses.set_status(hypothesis_id, **kwargs)
        self.save()
        return record

    # ----------------------------------------------------------------- output
    def brief(self) -> str:
        """Context block injected before the model sees the next user turn."""
        core = self.memory.brief()
        gaps = []
        for label, info in self.strategy.coverage_gaps()["gaps"].items():
            missing = info.get("missing") or []
            if missing:
                gaps.append(f"{label}: {len(missing)} pending")
        status_counts = self.evidence.status_counts()
        facts = [
            f"{len(self.memory.endpoints())} endpoints",
            f"{len(self.surface.nodes())} graph nodes",
        ]
        if status_counts:
            facts.append(
                "findings " + ", ".join(f"{count} {key}" for key, count in status_counts.items())
            )
        open_hyp = len(self.hypotheses.open())
        if open_hyp:
            facts.append(f"{open_hyp} open hypotheses")
        if not core and not status_counts and not open_hyp and not gaps:
            return ""
        if not self.memory.endpoints() and not self.surface.nodes():
            facts = [fact for fact in facts if not fact.startswith("0 ")]
        if not facts:
            return core
        footer = "Known so far: " + " · ".join(facts)
        if gaps:
            footer += "\nCoverage gaps: " + "; ".join(gaps)
        return "\n\n".join(part for part in (core, footer) if part)

    def state_summary(self) -> str:
        """One-line ledger snapshot for the UI (no prose, no Markdown)."""
        stats = self.memory.stats()
        status_counts = self.evidence.status_counts()
        parts = [
            f"{stats['endpoints']} endpoints",
            f"{len(self.surface.nodes())} graph nodes",
            f"{len(self.hypotheses.open())} open hypotheses",
        ]
        if status_counts:
            parts.append(
                "findings " + ", ".join(f"{count} {key}" for key, count in status_counts.items())
            )
        return " · ".join(parts)

    def markdown(self) -> str:
        sections = (self.surface.markdown(), self.hypotheses.markdown(), self.strategy.markdown())
        return "\n\n".join(part for part in sections if part)

    def save(self) -> None:
        self.memory.save()


def tool_source(payload: Mapping[str, Any]) -> str:
    command = payload.get("command")
    return command[:200] if isinstance(command, str) else ""


def _looks_like_target(candidate: str) -> bool:
    """Reject bare words and filesystem paths; keep URLs and dotted hosts."""
    text = candidate.strip()
    if not text:
        return False
    if "://" in text:
        return "." in text.split("://", 1)[1].split("/", 1)[0]
    head = text.split("/", 1)[0]
    return "." in head and " " not in head


__all__ = ["IntelHub", "NextAction", "PLAN_STATUSES"]
