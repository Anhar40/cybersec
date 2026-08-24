"""Evidence collection and penetration-test reporting (PRD Phase 10).

The session-scoped :class:`EvidenceStore` keeps a structured ledger of
verified security findings. Tool results that already carry structure
(nuclei findings from ``vuln_scan``, failing/warning checks from
``header_audit``) are captured automatically through :func:`recording_spec`;
anything else is added by the model via the LOW-risk ``record_finding``
tool. ``generate_report`` renders the ledger into a deterministic Markdown
report written under the configured reports directory.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import RiskLevel, ToolSpec

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK: dict[str, int] = {name: rank for rank, name in enumerate(SEVERITIES)}

MAX_TITLE_LENGTH = 160
MAX_TEXT_LENGTH = 2000
MAX_REPORT_TITLE_LENGTH = 200
DEFAULT_MAX_FINDINGS = 500

_HEADER_STATUS_SEVERITY = {"fail": "medium", "warn": "low", "info": "info"}

DEFAULT_REPORT_TITLE = "Penetration Test Report"


def normalize_severity(value: Any) -> str:
    if not isinstance(value, str) or value.strip().lower() not in _SEVERITY_RANK:
        raise ValueError(f"'severity' must be one of: {', '.join(SEVERITIES)}.")
    return value.strip().lower()


def _clip(value: Any, limit: int, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string.")
    text = value.strip()
    if len(text) > limit:
        raise ValueError(f"'{field}' exceeds {limit} characters.")
    return text


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class AddResult:
    record: dict[str, Any]
    created: bool


class EvidenceStore:
    """In-memory ledger of security findings collected during a session."""

    def __init__(
        self,
        *,
        max_findings: int = DEFAULT_MAX_FINDINGS,
        clock: Callable[[], datetime] | None = None,
    ):
        self._max_findings = max(1, int(max_findings))
        self._clock = clock or _default_clock
        self._records: list[dict[str, Any]] = []

    def add(
        self,
        *,
        source_tool: Any,
        title: Any,
        severity: Any,
        target: Any = "",
        evidence: Any = "",
        remediation: Any = "",
    ) -> AddResult:
        tool = (_clip(source_tool, 40, "source_tool") or "manual").lower()
        clean_title = _clip(title, MAX_TITLE_LENGTH, "title")
        if not clean_title:
            raise ValueError("'title' must be a non-empty string.")
        sev = normalize_severity(severity)
        rec_target = _clip(target, MAX_TEXT_LENGTH, "target")
        rec_evidence = _clip(evidence, MAX_TEXT_LENGTH, "evidence")
        rec_remediation = _clip(remediation, MAX_TEXT_LENGTH, "remediation")

        key = (tool, clean_title.lower(), rec_target.lower())
        for record in self._records:
            existing_key = (
                str(record["source_tool"]),
                str(record["title"]).lower(),
                str(record["target"]).lower(),
            )
            if existing_key == key:
                return AddResult(dict(record), False)

        if len(self._records) >= self._max_findings:
            raise ValueError(
                f"The evidence store is full ({self._max_findings} findings); "
                "summarize the assessment instead of adding more."
            )
        record = {
            "id": f"F-{len(self._records) + 1:03d}",
            "recorded_at": self._clock().isoformat(timespec="seconds"),
            "source_tool": tool,
            "title": clean_title,
            "severity": sev,
            "target": rec_target,
            "evidence": rec_evidence,
            "remediation": rec_remediation,
        }
        self._records.append(record)
        return AddResult(dict(record), True)

    def observe(self, tool_name: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Auto-capture findings embedded in a successful tool result."""
        if payload.get("error"):
            return []
        created: list[dict[str, Any]] = []
        for candidate in _candidates_from_payload(tool_name, payload):
            try:
                result = self.add(**candidate)
            except ValueError:
                continue
            if result.created:
                created.append(result.record)
        return created

    def findings(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for record in self._records:
            sev = str(record["severity"])
            result[sev] = result.get(sev, 0) + 1
        return result

    def clear(self) -> int:
        removed = len(self._records)
        self._records.clear()
        return removed


def _candidates_from_payload(
    tool_name: str, payload: Mapping[str, Any]
) -> Iterator[dict[str, Any]]:
    findings = payload.get("findings")
    if isinstance(findings, list):
        for entry in findings:
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("name") or "").strip()
            template = str(entry.get("template_id") or "").strip()
            title = name or template
            if not title:
                continue
            try:
                severity = normalize_severity(entry.get("severity"))
            except ValueError:
                severity = "info"
            extracted = [str(item) for item in (entry.get("extracted") or [])][:5]
            parts = [
                part
                for part in (str(entry.get("matched_at") or "").strip(), ", ".join(extracted))
                if part
            ]
            yield {
                "source_tool": tool_name,
                "title": title[:MAX_TITLE_LENGTH],
                "severity": severity,
                "target": str(entry.get("host") or "").strip()[:MAX_TEXT_LENGTH],
                "evidence": " · ".join(parts)[:MAX_TEXT_LENGTH],
                "remediation": "",
            }

    checks = payload.get("checks")
    if isinstance(checks, list):
        for entry in checks:
            if not isinstance(entry, Mapping):
                continue
            mapped = _HEADER_STATUS_SEVERITY.get(str(entry.get("status") or "").lower())
            if mapped is None:
                continue
            check = str(entry.get("check") or "unknown-check").strip()
            yield {
                "source_tool": tool_name,
                "title": f"Security header audit: {check}",
                "severity": mapped,
                "target": "",
                "evidence": str(entry.get("detail") or "")[:MAX_TEXT_LENGTH],
                "remediation": "",
            }


def render_markdown_report(
    *,
    title: str,
    findings: Sequence[Mapping[str, Any]],
    generated_at: str,
) -> str:
    """Deterministically render the evidence ledger as a Markdown report."""
    lines: list[str] = [f"# {title}", "", f"*Generated:* {generated_at} (UTC)", ""]
    counts = Counter(str(finding.get("severity")) for finding in findings)
    lines.append(f"Findings total: {len(findings)}")
    lines.append("")

    if findings:
        lines += ["| Severity | Count |", "| --- | --- |"]
        for severity in SEVERITIES:
            if counts.get(severity):
                lines.append(f"| {severity} | {counts[severity]} |")
        unknown = sum(n for sev, n in counts.items() if sev not in SEVERITIES)
        if unknown:
            lines.append(f"| unknown | {unknown} |")
        lines += ["", "## Findings", ""]
        ordered = sorted(
            findings,
            key=lambda f: (_SEVERITY_RANK.get(str(f.get("severity")), 99), str(f.get("id"))),
        )
        for finding in ordered:
            heading = (
                f"### {finding.get('id')} · [{str(finding.get('severity')).upper()}] "
                f"{finding.get('title')}"
            )
            lines += [heading, "", f"- Source tool: `{finding.get('source_tool')}`"]
            if finding.get("target"):
                lines.append(f"- Target: `{finding['target']}`")
            lines.append("")
            if finding.get("evidence"):
                lines += ["**Evidence**", "", "````text", str(finding["evidence"]), "````", ""]
            if finding.get("remediation"):
                lines += [f"**Remediation:** {finding['remediation']}", ""]
    else:
        lines += [
            "No verified findings were recorded during this session.",
            "",
            "_Absence of findings is not proof of security; coverage was limited "
            "by scope and tooling._",
            "",
        ]

    lines += [
        "---",
        "",
        "_Generated by CyberSec Agent. All testing applied only to targets the "
        "operator explicitly authorized._",
        "",
    ]
    return "\n".join(lines)


def write_report(
    store: EvidenceStore,
    reports_dir: Path,
    *,
    title: str = DEFAULT_REPORT_TITLE,
) -> Path:
    findings = store.findings()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"report-{stamp}.md"
    generated_at = _default_clock().isoformat(timespec="seconds")
    path.write_text(
        render_markdown_report(title=title, findings=findings, generated_at=generated_at),
        encoding="utf-8",
    )
    return path


_RECORD_FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["title", "severity"],
    "properties": {
        "title": {"type": "string"},
        "severity": {"type": "string"},
        "target": {"type": "string"},
        "evidence": {"type": "string"},
        "remediation": {"type": "string"},
    },
}

_LIST_FINDINGS_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

_GENERATE_REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"title": {"type": "string"}},
}


def _check_record_finding(arguments: Mapping[str, Any]) -> str | None:
    try:
        normalize_severity(arguments.get("severity"))
        _clip(arguments.get("title"), MAX_TITLE_LENGTH, "title")
        for field in ("target", "evidence", "remediation"):
            _clip(arguments.get(field), MAX_TEXT_LENGTH, field)
    except ValueError as exc:
        return str(exc)
    return None


def _check_generate_report(arguments: Mapping[str, Any]) -> str | None:
    title = arguments.get("title")
    if title is not None:
        try:
            clean = _clip(title, MAX_REPORT_TITLE_LENGTH, "title")
        except ValueError as exc:
            return str(exc)
        if not clean:
            return "'title' must be a non-empty string when provided."
    return None


def recording_spec(spec: ToolSpec, store: EvidenceStore) -> ToolSpec:
    """Return a copy of *spec* whose successful results feed the evidence store."""
    inner = spec.handler

    def handler(arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        result = inner(arguments)
        if not result.get("error"):
            store.observe(spec.name, result)
        return result

    return replace(spec, handler=handler)


def build_evidence_tools(*, store: EvidenceStore, reports_dir: Path) -> list[ToolSpec]:
    def handle_record(arguments: Mapping[str, Any]) -> dict[str, Any]:
        result = store.add(
            source_tool="manual",
            title=arguments.get("title"),
            severity=arguments.get("severity"),
            target=arguments.get("target"),
            evidence=arguments.get("evidence"),
            remediation=arguments.get("remediation"),
        )
        label = "already recorded earlier" if not result.created else "stored"
        record = result.record
        return {
            "finding": record,
            "duplicate": not result.created,
            "summary": f"{record['id']} {label} ({record['severity']})",
        }

    def handle_list(_arguments: Mapping[str, Any]) -> dict[str, Any]:
        findings = store.findings()
        counts = store.counts()
        parts = [f"{counts[sev]} {sev}" for sev in SEVERITIES if counts.get(sev)]
        summary = (
            " · ".join(parts) + f" ({len(findings)} total)" if parts else "no findings recorded yet"
        )
        return {
            "count": len(findings),
            "severity_counts": counts,
            "findings": findings,
            "summary": summary,
        }

    def handle_report(arguments: Mapping[str, Any]) -> dict[str, Any]:
        raw_title = arguments.get("title")
        provided = isinstance(raw_title, str) and raw_title.strip()
        title = str(raw_title).strip() if provided else DEFAULT_REPORT_TITLE
        try:
            path = write_report(store, reports_dir, title=title)
        except OSError as exc:
            return {
                "error": "report_write_failed",
                "detail": f"could not write report: {exc}",
                "reason": "The reports directory may not exist or is not writable; "
                "tell the user where the report should be saved.",
            }
        findings = store.findings()
        return {
            "path": str(path),
            "finding_count": len(findings),
            "severity_counts": store.counts(),
            "summary": f"Markdown report with {len(findings)} finding(s) written to {path}",
        }

    return [
        ToolSpec(
            name="record_finding",
            description=(
                "Record ONE verified security finding into the session evidence "
                "ledger: `title`, `severity` (critical|high|medium|low|info), the "
                "affected `target`/endpoint, an `evidence` excerpt from tool output, "
                "and a concrete `remediation`. Only record what the evidence "
                "supports — vuln_scan and header_audit results are captured "
                "automatically, so use this for anything you verified yourself."
            ),
            parameters=_RECORD_FINDING_SCHEMA,
            risk=RiskLevel.LOW,
            handler=handle_record,
            check_args=_check_record_finding,
        ),
        ToolSpec(
            name="list_findings",
            description=(
                "List every finding in the session evidence ledger with per-severity "
                "counts. Use it before reporting to review what has been collected."
            ),
            parameters=_LIST_FINDINGS_SCHEMA,
            risk=RiskLevel.LOW,
            handler=handle_list,
        ),
        ToolSpec(
            name="generate_report",
            description=(
                "Generate the penetration-test report as a Markdown file from the "
                "session evidence ledger (optional custom `title`). Returns the "
                "written file path; always tell the user where the report was saved."
            ),
            parameters=_GENERATE_REPORT_SCHEMA,
            risk=RiskLevel.LOW,
            handler=handle_report,
            check_args=_check_generate_report,
        ),
    ]
