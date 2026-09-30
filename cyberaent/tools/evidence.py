"""Evidence collection and penetration-test reporting (PRD Phase 10).

The session-scoped :class:`EvidenceStore` keeps a structured ledger of security
findings. Tool results that already carry structure (nuclei findings from
``vuln_scan``, failing/warning checks from ``header_audit``) are captured
automatically through :func:`recording_spec` and land as ``observed`` records;
anything else is added by the model via the LOW-risk ``record_finding`` tool.

Findings are never implicitly trusted: each record carries a *status*
(``verified``/``observed``/``suspected``/``refuted``) and only an explicit
verification step (``verify_finding`` or a ``verification`` note) may promote a
record to ``verified``. ``generate_report`` renders the ledger into a
deterministic Markdown report that keeps confirmed, unconfirmed, and refuted
findings in separate sections under ``reports/``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .base import RiskLevel, ToolSpec

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK: dict[str, int] = {name: rank for rank, name in enumerate(SEVERITIES)}

STATUSES: tuple[str, ...] = ("verified", "observed", "suspected", "refuted")
_STATUS_RANK: dict[str, int] = {name: rank for rank, name in enumerate(STATUSES)}
DEFAULT_STATUS = "suspected"

MAX_TITLE_LENGTH = 160
MAX_TEXT_LENGTH = 2000
MAX_REPORT_TITLE_LENGTH = 200
DEFAULT_MAX_FINDINGS = 500

_HEADER_STATUS_SEVERITY = {"fail": "medium", "warn": "low", "info": "info"}

DEFAULT_REPORT_TITLE = "Penetration Test Report"

STATUS_NOTES = {
    "verified": "Confirmed by an explicit verification step.",
    "observed": "Reported by a tool; not independently verified yet.",
    "suspected": "Analyst suspicion without supporting proof.",
    "refuted": "Investigated and shown not to be an issue.",
}


def normalize_severity(value: Any) -> str:
    if not isinstance(value, str) or value.strip().lower() not in _SEVERITY_RANK:
        raise ValueError(f"'severity' must be one of: {', '.join(SEVERITIES)}.")
    return value.strip().lower()


def normalize_status(value: Any) -> str:
    if not isinstance(value, str) or value.strip().lower() not in _STATUS_RANK:
        raise ValueError(f"'status' must be one of: {', '.join(STATUSES)}.")
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


class IntelBridge(Protocol):
    """Optional intel layer that also closes hypotheses when findings change.

    Implemented by :class:`cyberaent.intel.IntelHub`; kept as a Protocol so this
    module never imports the coordinator (and cannot create an import cycle).
    """

    def record_finding(self, **fields: Any) -> dict[str, Any]: ...

    def verify_finding(self, finding_id: str, **fields: Any) -> dict[str, Any]: ...


@dataclass(frozen=True)
class AddResult:
    record: dict[str, Any]
    created: bool


@dataclass(frozen=True)
class VerifyResult:
    record: dict[str, Any]
    changed: bool


class EvidenceStore:
    """In-memory ledger of security findings collected during a session.

    Every record carries a *status* from :data:`STATUSES` so the agent can tell a
    machine observation apart from a confirmed vulnerability:

    ``observed``  a tool reported it (nuclei, header audit) — proof still missing;
    ``suspected`` the analyst believes it but has no verification yet (default);
    ``verified``  an explicit verification step was recorded;
    ``refuted``   investigated and dismissed.
    """

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
        status: Any = None,
        verification: Any = "",
    ) -> AddResult:
        tool = (_clip(source_tool, 40, "source_tool") or "manual").lower()
        clean_title = _clip(title, MAX_TITLE_LENGTH, "title")
        if not clean_title:
            raise ValueError("'title' must be a non-empty string.")
        sev = normalize_severity(severity)
        rec_target = _clip(target, MAX_TEXT_LENGTH, "target")
        rec_evidence = _clip(evidence, MAX_TEXT_LENGTH, "evidence")
        rec_remediation = _clip(remediation, MAX_TEXT_LENGTH, "remediation")
        rec_verification = _clip(verification, MAX_TEXT_LENGTH, "verification")
        if status is None:
            resolved = "verified" if rec_verification else DEFAULT_STATUS
        else:
            resolved = normalize_status(status)
        stamp = self._clock().isoformat(timespec="seconds")

        key = (tool, clean_title.lower(), rec_target.lower())
        for record in self._records:
            existing_key = (
                str(record["source_tool"]),
                str(record["title"]).lower(),
                str(record["target"]).lower(),
            )
            if existing_key == key:
                self._upgrade(record, status=resolved, verification=rec_verification)
                return AddResult(dict(record), False)

        if len(self._records) >= self._max_findings:
            raise ValueError(
                f"The evidence store is full ({self._max_findings} findings); "
                "summarize the assessment instead of adding more."
            )
        record = {
            "id": f"F-{len(self._records) + 1:03d}",
            "recorded_at": stamp,
            "updated_at": stamp,
            "source_tool": tool,
            "title": clean_title,
            "severity": sev,
            "status": resolved,
            "target": rec_target,
            "evidence": rec_evidence,
            "verification": rec_verification,
            "remediation": rec_remediation,
            "verified_at": stamp if resolved in ("verified", "refuted") else "",
        }
        self._records.append(record)
        return AddResult(dict(record), True)

    def _upgrade(self, record: dict[str, Any], *, status: str, verification: str) -> bool:
        """Promote an existing record when new proof arrives; never downgrade it."""
        stamp = self._clock().isoformat(timespec="seconds")
        changed = False
        if verification and not record.get("verification"):
            record["verification"] = verification
            changed = True
        if _STATUS_RANK.get(status, 99) < _STATUS_RANK.get(str(record.get("status")), 99):
            record["status"] = status
            record["updated_at"] = stamp
            if not record.get("verified_at"):
                record["verified_at"] = stamp
            changed = True
        return changed

    def verify(
        self,
        finding_id: Any,
        *,
        method: Any,
        confirmed: Any = True,
        evidence: Any = "",
    ) -> VerifyResult:
        """Record an explicit verification step for a finding."""
        fid = _clip(finding_id, 16, "finding_id")
        clean_method = _clip(method, MAX_TEXT_LENGTH, "method")
        if not clean_method:
            raise ValueError("'method' must describe how the finding was confirmed or refuted.")
        record = self._record(fid)
        outcome = "verified" if confirmed in (True, "true", "True", "yes", 1) else "refuted"
        stamp = self._clock().isoformat(timespec="seconds")
        record["status"] = outcome
        record["verification"] = clean_method
        if evidence:
            record["evidence"] = _clip(evidence, MAX_TEXT_LENGTH, "evidence")
        record["verified_at"] = stamp
        record["updated_at"] = stamp
        return VerifyResult(record=dict(record), changed=True)

    def _record(self, finding_id: str) -> dict[str, Any]:
        for record in self._records:
            if str(record["id"]).lower() == finding_id.lower():
                return record
        raise ValueError(f"No finding with id '{finding_id}'.")

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

    def findings(self, *, status: str = "") -> list[dict[str, Any]]:
        rows = [dict(record) for record in self._records]
        if not status:
            return rows
        wanted = normalize_status(status)
        return [record for record in rows if record.get("status") == wanted]

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for record in self._records:
            sev = str(record["severity"])
            result[sev] = result.get(sev, 0) + 1
        return result

    def status_counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for record in self._records:
            key = str(record.get("status") or DEFAULT_STATUS)
            result[key] = result.get(key, 0) + 1
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
                "status": "observed",
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
                "status": "observed",
                "target": "",
                "evidence": str(entry.get("detail") or "")[:MAX_TEXT_LENGTH],
                "remediation": "",
            }


def _finding_block(finding: Mapping[str, Any]) -> list[str]:
    status = str(finding.get("status") or DEFAULT_STATUS)
    heading = (
        f"### {finding.get('id')} · [{str(finding.get('severity')).upper()}] "
        f"{finding.get('title')}"
    )
    lines = [heading, "", f"- Source tool: `{finding.get('source_tool')}`", f"- Status: {status}"]
    if finding.get("target"):
        lines.append(f"- Target: `{finding['target']}`")
    if finding.get("verified_at"):
        lines.append(f"- Decided at: {finding['verified_at']}")
    lines.append("")
    if finding.get("verification"):
        lines += [f"**Verification:** {finding['verification']}", ""]
    if finding.get("evidence"):
        lines += ["**Evidence**", "", "````text", str(finding["evidence"]), "````", ""]
    if finding.get("remediation"):
        lines += [f"**Remediation:** {finding['remediation']}", ""]
    return lines


def _ordered(findings: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK.get(str(f.get("severity")), 99), str(f.get("id"))),
    )


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
    status_counts = Counter(
        str(finding.get("status") or DEFAULT_STATUS) for finding in findings
    )
    if status_counts:
        summary = " · ".join(
            f"{status_counts[status]} {status}" for status in STATUSES if status_counts.get(status)
        )
        lines.append(f"Status breakdown: {summary}")
    lines.append("")

    if findings:
        lines += ["| Severity | Count |", "| --- | --- |"]
        for severity in SEVERITIES:
            if counts.get(severity):
                lines.append(f"| {severity} | {counts[severity]} |")
        unknown = sum(n for sev, n in counts.items() if sev not in SEVERITIES)
        if unknown:
            lines.append(f"| unknown | {unknown} |")
        lines.append("")

        confirmed = [f for f in findings if str(f.get("status")) == "verified"]
        unconfirmed = [
            f
            for f in findings
            if str(f.get("status") or DEFAULT_STATUS) in ("observed", "suspected")
        ]
        refuted = [f for f in findings if str(f.get("status")) == "refuted"]

        if confirmed:
            lines += ["## Confirmed findings", ""]
            for finding in _ordered(confirmed):
                lines += _finding_block(finding)
        if unconfirmed:
            lines += [
                "## Unconfirmed observations",
                "",
                "_These are tool observations and analyst suspicions, not confirmed "
                "vulnerabilities. Verify before reporting them as exploitable._",
                "",
            ]
            for finding in _ordered(unconfirmed):
                lines += _finding_block(finding)
        if refuted:
            lines += [
                "## Refuted",
                "",
                "_Investigated and dismissed during this assessment._",
                "",
            ]
            for finding in _ordered(refuted):
                lines += _finding_block(finding)
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
        "verification": {"type": "string"},
        "status": {"type": "string", "enum": list(STATUSES)},
        "remediation": {"type": "string"},
    },
}

_VERIFY_FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["finding_id", "method"],
    "properties": {
        "finding_id": {"type": "string"},
        "method": {"type": "string"},
        "confirmed": {"type": "boolean"},
        "evidence": {"type": "string"},
    },
}

_LIST_FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"status": {"type": "string", "enum": list(STATUSES)}},
}

_GENERATE_REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"title": {"type": "string"}},
}


def _check_record_finding(arguments: Mapping[str, Any]) -> str | None:
    try:
        normalize_severity(arguments.get("severity"))
        _clip(arguments.get("title"), MAX_TITLE_LENGTH, "title")
        for field in ("target", "evidence", "remediation", "verification"):
            _clip(arguments.get(field), MAX_TEXT_LENGTH, field)
        status = arguments.get("status")
        if status is not None:
            normalize_status(status)
    except ValueError as exc:
        return str(exc)
    return None


def _check_verify_finding(arguments: Mapping[str, Any]) -> str | None:
    try:
        fid = _clip(arguments.get("finding_id"), 16, "finding_id")
        if not fid:
            return "'finding_id' must be a non-empty string such as 'F-001'."
        _clip(arguments.get("method"), MAX_TEXT_LENGTH, "method")
        _clip(arguments.get("evidence"), MAX_TEXT_LENGTH, "evidence")
    except ValueError as exc:
        return str(exc)
    return None


def _check_list_findings(arguments: Mapping[str, Any]) -> str | None:
    status = arguments.get("status")
    if status is None:
        return None
    try:
        normalize_status(status)
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


def build_evidence_tools(
    *,
    store: EvidenceStore,
    reports_dir: Path,
    intel: IntelBridge | None = None,
) -> list[ToolSpec]:
    def handle_record(arguments: Mapping[str, Any]) -> dict[str, Any]:
        fields = {
            "title": arguments.get("title"),
            "severity": arguments.get("severity"),
            "target": arguments.get("target"),
            "evidence": arguments.get("evidence"),
            "remediation": arguments.get("remediation"),
            "verification": arguments.get("verification"),
            "status": arguments.get("status"),
        }
        if intel is not None:
            before = len(store.findings())
            record = intel.record_finding(**fields)
            created = len(store.findings()) > before
            duplicate = not created
        else:
            result = store.add(source_tool="manual", **fields)
            record = result.record
            duplicate = not result.created
            created = result.created
        label = "already recorded earlier" if duplicate else "stored"
        return {
            "finding": record,
            "duplicate": duplicate,
            "summary": f"{record['id']} {label} ({record['severity']}, {record['status']})",
            "hint": (
                ""
                if record["status"] == "verified" or not created
                else "Pass 'verification' (or call verify_finding) to promote this to verified."
            ),
        }

    def handle_verify(arguments: Mapping[str, Any]) -> dict[str, Any]:
        try:
            if intel is not None:
                record = intel.verify_finding(
                    str(arguments.get("finding_id")),
                    method=arguments.get("method"),
                    confirmed=arguments.get("confirmed", True),
                    evidence=arguments.get("evidence"),
                )
            else:
                record = store.verify(
                    arguments.get("finding_id"),
                    method=arguments.get("method"),
                    confirmed=arguments.get("confirmed", True),
                    evidence=arguments.get("evidence"),
                ).record
        except ValueError as exc:
            return {
                "error": "verification_failed",
                "detail": str(exc),
                "reason": "Use list_findings to get a valid finding_id such as 'F-001'.",
            }
        closed = record.get("closed_hypotheses") or []
        return {
            "finding": record,
            "status": record["status"],
            "closed_hypotheses": closed,
            "summary": f"{record['id']} marked {record['status']} via {record['verification']}",
        }

    def handle_list(arguments: Mapping[str, Any]) -> dict[str, Any]:
        raw_status = arguments.get("status")
        status = normalize_status(raw_status) if raw_status else ""
        findings = store.findings(status=status)
        counts = store.counts()
        status_counts = store.status_counts()
        parts = [f"{counts[sev]} {sev}" for sev in SEVERITIES if counts.get(sev)]
        by_severity = " · ".join(parts) + f" ({len(findings)} total)" if parts else "none"
        by_status = " · ".join(
            f"{status_counts[key]} {key}" for key in STATUSES if status_counts.get(key)
        )
        return {
            "count": len(findings),
            "filter_status": status or "all",
            "severity_counts": counts,
            "status_counts": status_counts,
            "findings": findings,
            "summary": f"{by_severity}" + (f" · {by_status}" if by_status else ""),
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
        status_counts = store.status_counts()
        return {
            "path": str(path),
            "finding_count": len(findings),
            "severity_counts": store.counts(),
            "status_counts": status_counts,
            "verified_count": status_counts.get("verified", 0),
            "summary": f"Markdown report with {len(findings)} finding(s) written to {path}",
        }

    return [
        ToolSpec(
            name="record_finding",
            description=(
                "Record ONE security finding into the session evidence ledger: "
                "`title`, `severity` (critical|high|medium|low|info), the affected "
                "`target`/endpoint, an `evidence` excerpt from tool output, and a "
                "concrete `remediation`. Findings start as unconfirmed; include "
                "`verification` (how you confirmed it) to mark it verified. "
                "vuln_scan and header_audit results are captured automatically as "
                "observations, so use this for anything you analyzed yourself."
            ),
            parameters=_RECORD_FINDING_SCHEMA,
            risk=RiskLevel.LOW,
            handler=handle_record,
            check_args=_check_record_finding,
        ),
        ToolSpec(
            name="verify_finding",
            description=(
                "Promote an existing finding to `verified` (or `refuted` with "
                "`confirmed: false`) by recording the verification `method` — the "
                "exact request, parameter, or tool output that proves it. Use this "
                "instead of claiming a vulnerability is real without proof."
            ),
            parameters=_VERIFY_FINDING_SCHEMA,
            risk=RiskLevel.LOW,
            handler=handle_verify,
            check_args=_check_verify_finding,
        ),
        ToolSpec(
            name="list_findings",
            description=(
                "List findings in the session evidence ledger with per-severity and "
                "per-status (verified|observed|suspected|refuted) counts. Filter by "
                "`status` when you only need confirmed issues."
            ),
            parameters=_LIST_FINDINGS_SCHEMA,
            risk=RiskLevel.LOW,
            handler=handle_list,
            check_args=_check_list_findings,
        ),
        ToolSpec(
            name="generate_report",
            description=(
                "Generate the penetration-test report as a Markdown file from the "
                "session evidence ledger (optional custom `title`). Confirmed, "
                "unconfirmed, and refuted findings are reported in separate "
                "sections. Returns the written file path; always tell the user where "
                "the report was saved."
            ),
            parameters=_GENERATE_REPORT_SCHEMA,
            risk=RiskLevel.LOW,
            handler=handle_report,
            check_args=_check_generate_report,
        ),
    ]
