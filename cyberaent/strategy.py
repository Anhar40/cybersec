"""Deterministic, evidence-driven next-action planner.

This module never invents targets: every suggestion must be justified by a fact
already in the ledger (an endpoint, a parameter, a fingerprint, an unverified
finding, or an open hypothesis). Suggestions are also filtered against the test
history so the agent is nudged away from repeating work it already did.

The rules are intentionally boring and inspectable. The model's job is to judge
the plan and pick tools itself; this layer only removes the "what did I already
try?" bookkeeping that models get wrong most often.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .hypotheses import HypothesisStore
from .memory import SessionMemory
from .surface import AttackSurface
from .tools.evidence import EvidenceStore

PRIORITY_HYPOTHESIS = 10
PRIORITY_VERIFY = 20
PRIORITY_HEADERS = 30
PRIORITY_TECH = 35
PRIORITY_SCAN = 40
PRIORITY_INJECTION = 45
PRIORITY_SCOPE = 60

ACTION_SEVERITIES: tuple[str, ...] = ("critical", "high")


@dataclass(frozen=True)
class NextAction:
    """One justified step: either a concrete tool call or an explicit instruction."""

    tool: str
    arguments: dict[str, Any]
    reason: str
    basis: str
    priority: int
    hypothesis_id: str = ""
    instruction: str = ""
    risk_hint: str = "low"
    key: str = field(default="", compare=False)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "priority": self.priority,
            "reason": self.reason,
            "basis": self.basis[:300],
        }
        if self.tool:
            payload["tool"] = self.tool
            payload["arguments"] = self.arguments
        if self.instruction:
            payload["instruction"] = self.instruction
        if self.hypothesis_id:
            payload["hypothesis_id"] = self.hypothesis_id
        return payload


class StrategyEngine:
    """Turns the evidence ledger into a short, deduplicated list of next steps."""

    def __init__(
        self,
        *,
        memory: SessionMemory,
        surface: AttackSurface,
        evidence: EvidenceStore,
        hypotheses: HypothesisStore,
        scope: str = "",
    ) -> None:
        self._memory = memory
        self._surface = surface
        self._evidence = evidence
        self._hypotheses = hypotheses
        self._scope = scope.strip()

    # ---------------------------------------------------------------- helpers
    def _seen(self, tool: str, target: str) -> bool:
        return self._memory.test_done(tool, target)

    @staticmethod
    def _dedupe_key(tool: str, arguments: dict[str, Any]) -> str:
        return f"{tool}|{json.dumps(arguments, sort_keys=True, default=str)}"

    def _endpoint_targets(self, *, limit: int = 3) -> list[str]:
        rows = self._memory.endpoints()
        targets: list[str] = []
        for row in rows:
            url = str(row.get("url") or "")
            if url and url not in targets:
                targets.append(url)
            if len(targets) >= limit:
                break
        if not targets and self._scope:
            targets.append(self._scope)
        return targets

    # ------------------------------------------------------------------ rules
    def _hypothesis_actions(self, limit: int) -> list[NextAction]:
        actions: list[NextAction] = []
        for item in self._hypotheses.next_tests(limit=limit):
            actions.append(
                NextAction(
                    tool="",
                    arguments={},
                    reason=f"Test hypothesis {item['hypothesis_id']} before proposing new work.",
                    basis=str(item["statement"]),
                    priority=PRIORITY_HYPOTHESIS,
                    hypothesis_id=str(item["hypothesis_id"]),
                    instruction=str(item["test_plan"]),
                    risk_hint="medium",
                )
            )
        return actions

    def _verification_actions(self, limit: int = 2) -> list[NextAction]:
        pending = [
            finding
            for finding in self._evidence.findings()
            if finding.get("status") in ("observed", "suspected")
            and str(finding.get("severity")) in ACTION_SEVERITIES
        ]
        actions: list[NextAction] = []
        for finding in pending[:limit]:
            fid = str(finding.get("id"))
            actions.append(
                NextAction(
                    tool="verify_finding",
                    arguments={"finding_id": fid, "method": "<replayed request or tool output>"},
                    reason=(
                        f"{fid} is {finding.get('status')} but high impact; prove or refute it "
                        "before it reaches the report."
                    ),
                    basis=str(finding.get("evidence") or finding.get("title") or ""),
                    priority=PRIORITY_VERIFY,
                    risk_hint="low",
                )
            )
        return actions

    def _coverage_actions(self) -> list[NextAction]:
        actions: list[NextAction] = []
        observed = self._memory.endpoints()
        if not observed:
            if self._scope:
                actions.append(
                    NextAction(
                        tool="http_probe",
                        arguments={"urls": [self._scope]},
                        reason="No endpoint has been observed yet, so nothing else is justified.",
                        basis="empty knowledge base",
                        priority=PRIORITY_SCOPE,
                        risk_hint="medium",
                    )
                )
            else:
                actions.append(
                    NextAction(
                        tool="",
                        arguments={},
                        reason="Neither a target scope nor a single endpoint is known yet.",
                        basis="empty knowledge base",
                        priority=PRIORITY_SCOPE,
                        instruction=(
                            "Ask the user for the exact target URL, then probe it with "
                            "http_probe before anything else."
                        ),
                        risk_hint="low",
                    )
                )
            if not self._scope:
                return actions
        targets = self._endpoint_targets()
        if not targets:
            return actions

        for url in targets:
            if not self._seen("header_audit", url):
                actions.append(
                    NextAction(
                        tool="header_audit",
                        arguments={"url": url},
                        reason="Response headers have not been audited for this endpoint.",
                        basis=f"endpoint {url} known, header_audit never run",
                        priority=PRIORITY_HEADERS,
                        risk_hint="medium",
                    )
                )
            if not self._seen("web_tech", url):
                actions.append(
                    NextAction(
                        tool="web_tech",
                        arguments={"url": url},
                        reason="Fingerprinting decides which attack classes are even possible.",
                        basis=f"endpoint {url} has no technology fingerprint",
                        priority=PRIORITY_TECH,
                        risk_hint="medium",
                    )
                )
            params = self._parameters_for(url)
            if params and not self._seen("sqli_probe", url):
                actions.append(
                    NextAction(
                        tool="sqli_probe",
                        arguments={"url": f"{url}?{params[0]}=1"},
                        reason="Untested parameters are the highest-yield injection surface.",
                        basis=f"parameters {', '.join(params[:5])} observed on {url}",
                        priority=PRIORITY_INJECTION,
                        risk_hint="medium",
                    )
                )
            host = _host_of(url)
            if host and not self._seen("vuln_scan", host):
                actions.append(
                    NextAction(
                        tool="vuln_scan",
                        arguments={"target": host},
                        reason="No template scan has covered this host yet.",
                        basis=f"host {host} known, vuln_scan never run",
                        priority=PRIORITY_SCAN,
                        risk_hint="medium",
                    )
                )
        return actions

    def _parameters_for(self, url: str) -> list[str]:
        needle = url.lower()
        for row in self._memory.endpoints():
            if str(row.get("url", "")).lower() != needle:
                continue
            params = row.get("params")
            if isinstance(params, list):
                return [str(p) for p in params]
        return []

    # ----------------------------------------------------------------- public
    def next_actions(self, *, limit: int = 6) -> list[dict[str, Any]]:
        candidates = (
            self._hypothesis_actions(limit=limit)
            + self._verification_actions()
            + self._coverage_actions()
        )
        seen: set[str] = set()
        ordered: list[NextAction] = []
        for action in sorted(candidates, key=lambda a: (a.priority, a.reason)):
            key = action.key or self._dedupe_key(
                action.tool or action.hypothesis_id or "instruction",
                action.arguments or {"instruction": action.instruction},
            )
            if key in seen:
                continue
            seen.add(key)
            ordered.append(action)
            if len(ordered) >= limit:
                break
        return [action.to_dict() for action in ordered]

    def coverage_gaps(self) -> dict[str, Any]:
        """Which checks are missing, for the UI panel and /plan output."""
        endpoints = self._memory.endpoints()
        checks = {
            "header_audit": "headers",
            "web_tech": "fingerprints",
            "vuln_scan": "template scans",
        }
        gaps: dict[str, Any] = {}
        for tool, label in checks.items():
            missing = [url for url in self._endpoint_targets(limit=10) if not self._seen(tool, url)]
            gaps[label] = {"tool": tool, "missing": missing}
        return {
            "endpoints": len(endpoints),
            "gaps": gaps,
            "hypotheses": self._hypotheses.stats(),
            "findings": self._evidence.status_counts(),
        }

    def markdown(self) -> str:
        actions = self.next_actions()
        if not actions:
            return "# Next actions\n\n_Nothing to do right now._\n"
        lines = ["# Next actions", ""]
        for index, action in enumerate(actions, start=1):
            head = f"{index}. {action['reason']}"
            lines.append(head)
            if action.get("tool"):
                args = json.dumps(action["arguments"], sort_keys=True)
                lines.append(f"   - tool: `{action['tool']}` `{args}`")
            if action.get("instruction"):
                lines.append(f"   - do: {action['instruction']}")
            lines.append(f"   - because: {action['basis'][:160]}")
        lines.append("")
        return "\n".join(lines)


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).netloc.lower()
