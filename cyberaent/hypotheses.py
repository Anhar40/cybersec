"""Hypothesis ledger: explicit claims that must survive or die by evidence.

An agent that only collects findings drifts into noise. A *hypothesis* is a
falsifiable statement about the target ("`/api/orders/{id}` has no ownership
check"), paired with the reasoning behind it and the test that would settle it.

Two rules are enforced by this module, because they are what separate a
reasoning agent from a guess generator:

1. ``rationale`` and ``test_plan`` are mandatory — a claim nobody thought through
   cannot be recorded.
2. ``supported`` and ``refuted`` require at least one evidence reference, and
   when a lookup function is supplied the reference must exist. A conclusion
   without proof is rejected, not silently downgraded.

Records live in the persistent session memory document, so hypotheses survive
restarts alongside the attack surface.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from .memory import SessionMemory

HYPOTHESIS_STATUSES: tuple[str, ...] = ("proposed", "testing", "supported", "refuted")
_DECIDED_STATUSES: tuple[str, ...] = ("supported", "refuted")
OPEN_STATUSES: tuple[str, ...] = ("proposed", "testing")

MAX_STATEMENT_LENGTH = 400
MAX_RATIONALE_LENGTH = 1000
MAX_TEST_PLAN_LENGTH = 1000
MAX_EVIDENCE_REFS = 20
MAX_HYPOTHESES = 200


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


def normalize_status(value: Any) -> str:
    if not isinstance(value, str) or value.strip().lower() not in HYPOTHESIS_STATUSES:
        raise ValueError(f"'status' must be one of: {', '.join(HYPOTHESIS_STATUSES)}.")
    return value.strip().lower()


def normalize_refs(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        candidates: Iterable[Any] = [part for part in value.replace(",", " ").split() if part]
    elif isinstance(value, Sequence):
        candidates = value
    else:
        raise ValueError("'evidence' must be a string or a list of finding ids.")
    refs: list[str] = []
    for item in candidates:
        if not isinstance(item, str):
            raise ValueError("'evidence' entries must be finding ids such as 'F-001'.")
        ref = item.strip()
        if not ref:
            continue
        if len(ref) > 40:
            raise ValueError("'evidence' entries must be 40 characters or fewer.")
        if ref not in refs:
            refs.append(ref)
    if len(refs) > MAX_EVIDENCE_REFS:
        raise ValueError(f"At most {MAX_EVIDENCE_REFS} evidence references are allowed.")
    return refs


class HypothesisStore:
    """Falsifiable claims with rationale, test plan, and evidence-backed verdicts."""

    def __init__(
        self,
        memory: SessionMemory,
        *,
        finding_exists: Callable[[str], bool] | None = None,
    ) -> None:
        self._memory = memory
        self._finding_exists = finding_exists

    # ------------------------------------------------------------- internals
    def _records(self) -> list[dict[str, Any]]:
        return self._memory.state.setdefault("hypotheses", [])

    def _find(self, hypothesis_id: Any) -> dict[str, Any]:
        hid = _clip(hypothesis_id, 16, "hypothesis_id")
        if not hid:
            raise ValueError("'hypothesis_id' must be a non-empty string such as 'H-001'.")
        for record in self._records():
            if str(record["id"]).lower() == hid.lower():
                return record
        raise ValueError(f"No hypothesis with id '{hid}'.")

    def _check_refs(self, refs: Sequence[str]) -> None:
        if not self._finding_exists:
            return
        for ref in refs:
            if not self._finding_exists(ref):
                raise ValueError(
                    f"Evidence reference '{ref}' does not exist. Record the finding "
                    "with record_finding first, or drop the reference."
                )

    # ---------------------------------------------------------------- writes
    def propose(
        self,
        *,
        statement: Any,
        rationale: Any,
        test_plan: Any,
        evidence: Any = None,
    ) -> dict[str, Any]:
        clean_statement = _clip(statement, MAX_STATEMENT_LENGTH, "statement")
        if not clean_statement:
            raise ValueError("'statement' must describe one falsifiable claim.")
        clean_rationale = _clip(rationale, MAX_RATIONALE_LENGTH, "rationale")
        if not clean_rationale:
            raise ValueError(
                "'rationale' is required: explain why this might be true before testing it."
            )
        clean_plan = _clip(test_plan, MAX_TEST_PLAN_LENGTH, "test_plan")
        if not clean_plan:
            raise ValueError(
                "'test_plan' is required: state the request or tool call that would settle it."
            )
        refs = normalize_refs(evidence)
        self._check_refs(refs)

        records = self._records()
        key = clean_statement.lower()
        for record in records:
            if str(record["statement"]).lower() == key:
                self._enrich(record, evidence=refs)
                return dict(record)
        if len(records) >= MAX_HYPOTHESES:
            raise ValueError(
                f"The hypothesis ledger is full ({MAX_HYPOTHESES}); resolve or drop "
                "old hypotheses instead of adding more."
            )
        stamp = _now()
        record = {
            "id": f"H-{len(records) + 1:03d}",
            "statement": clean_statement,
            "rationale": clean_rationale,
            "test_plan": clean_plan,
            "status": "proposed",
            "evidence": refs,
            "created_at": stamp,
            "updated_at": stamp,
            "decided_at": "",
        }
        records.append(record)
        return dict(record)

    def _enrich(self, record: dict[str, Any], *, evidence: Sequence[str]) -> None:
        changed = False
        for ref in evidence:
            if ref not in record["evidence"]:
                record["evidence"].append(ref)
                changed = True
        if changed:
            record["updated_at"] = _now()
            if len(record["evidence"]) > MAX_EVIDENCE_REFS:
                raise ValueError(f"At most {MAX_EVIDENCE_REFS} evidence references are allowed.")

    def attach_evidence(self, hypothesis_id: Any, evidence: Any) -> dict[str, Any]:
        record = self._find(hypothesis_id)
        refs = normalize_refs(evidence)
        if not refs:
            raise ValueError("'evidence' must contain at least one finding id.")
        self._check_refs(refs)
        self._enrich(record, evidence=refs)
        return dict(record)

    def set_status(
        self,
        hypothesis_id: Any,
        *,
        status: Any,
        evidence: Any = None,
        note: Any = "",
    ) -> dict[str, Any]:
        record = self._find(hypothesis_id)
        target = normalize_status(status)
        refs = normalize_refs(evidence)
        if refs:
            self._enrich(record, evidence=refs)
        clean_note = _clip(note, MAX_RATIONALE_LENGTH, "note")
        stamp = _now()

        if target in _DECIDED_STATUSES and not record["evidence"] and not refs:
            raise ValueError(
                f"Cannot mark '{target}' without evidence. Attach finding ids that "
                "support or disprove the claim first."
            )
        if target in _DECIDED_STATUSES:
            self._check_refs(record["evidence"])
        if target == "refuted" and clean_note:
            record["rationale"] = clean_note
        record["status"] = target
        record["updated_at"] = stamp
        record["decided_at"] = stamp if target in _DECIDED_STATUSES else ""
        return dict(record)

    def testing(self, hypothesis_id: Any) -> dict[str, Any]:
        record = self._find(hypothesis_id)
        if record["status"] in ("proposed", "testing"):
            record["status"] = "testing"
            record["updated_at"] = _now()
        return dict(record)

    def resolve_by_finding(self, finding_id: str, *, supported: bool) -> list[dict[str, Any]]:
        """Close hypotheses that cite *finding_id* when that finding is decided."""
        changed: list[dict[str, Any]] = []
        for record in self._records():
            if finding_id in record["evidence"] and record["status"] in OPEN_STATUSES:
                record["status"] = "supported" if supported else "refuted"
                record["updated_at"] = _now()
                record["decided_at"] = record["updated_at"]
                changed.append(dict(record))
        return changed

    # ---------------------------------------------------------------- reads
    def all(self, *, status: str = "") -> list[dict[str, Any]]:
        rows = [dict(record) for record in self._records()]
        if not status:
            return rows
        return [row for row in rows if row["status"] == normalize_status(status)]

    def get(self, hypothesis_id: Any) -> dict[str, Any]:
        return dict(self._find(hypothesis_id))

    def open(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records() if record["status"] in OPEN_STATUSES]

    def next_tests(self, *, limit: int = 5) -> list[dict[str, Any]]:
        """Open hypotheses ranked: already testing first, then oldest."""
        rows = [row for row in self.open() if row["test_plan"]]
        rows.sort(key=lambda row: (row["status"] != "testing", str(row["id"])))
        return [
            {
                "hypothesis_id": row["id"],
                "statement": row["statement"],
                "status": row["status"],
                "test_plan": row["test_plan"],
                "evidence": row["evidence"],
            }
            for row in rows[: max(1, limit)]
        ]

    def counts(self) -> dict[str, int]:
        result = {status: 0 for status in HYPOTHESIS_STATUSES}
        for record in self._records():
            result[str(record["status"])] = result.get(str(record["status"]), 0) + 1
        return result

    def stats(self) -> dict[str, Any]:
        counts = self.counts()
        decided = counts["supported"] + counts["refuted"]
        return {
            "total": sum(counts.values()),
            "open": len(self.open()),
            "decided": decided,
            "precision": round(counts["supported"] / decided, 2) if decided else 0.0,
            "counts": counts,
        }

    def markdown(self) -> str:
        rows = self.all()
        if not rows:
            return "# Hypotheses\n\n_No hypotheses recorded yet._\n"
        counts = self.counts()
        lines = ["# Hypotheses", ""]
        lines.append(
            " · ".join(f"{counts[s]} {s}" for s in HYPOTHESIS_STATUSES if counts.get(s))
            + f" ({len(rows)} total)"
        )
        lines += ["", "| ID | Status | Statement | Evidence |", "| --- | --- | --- | --- |"]
        for row in rows:
            refs = ", ".join(row["evidence"]) or "-"
            lines.append(f"| {row['id']} | {row['status']} | {row['statement']} | {refs} |")
        lines.append("")
        pending = [row for row in rows if row["status"] in OPEN_STATUSES and row["test_plan"]]
        if pending:
            lines += ["## Pending tests", ""]
            for row in pending:
                lines.append(f"- **{row['id']}** — {row['test_plan']}")
            lines.append("")
        return "\n".join(lines)
