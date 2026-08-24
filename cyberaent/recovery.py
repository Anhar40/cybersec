"""Failure diagnosis and recovery enrichment (PRD §10, §31–32, Phase 5).

Pure logic: classify a failed tool payload, explain the likely cause, and
attach structured recovery hints so the model can diagnose, switch strategy,
and verify instead of blindly repeating the same action.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Diagnosis:
    kind: str
    diagnosis: str
    fix_hints: tuple[str, ...]


def _combined_output(payload: Mapping[str, Any]) -> str:
    parts = [
        payload.get("stdout"),
        payload.get("stderr"),
        payload.get("detail"),
        payload.get("reason"),
    ]
    return " ".join(str(p) for p in parts if isinstance(p, str)).lower()


def _diagnosis_for_error_kind(payload: Mapping[str, Any]) -> Diagnosis | None:
    error = payload.get("error")
    if not isinstance(error, str):
        return None
    if error == "timeout":
        return Diagnosis(
            kind="timeout",
            diagnosis=(
                "The command exceeded its time limit and was terminated, so partial "
                "output may be incomplete."
            ),
            fix_hints=(
                "Raise timeout_sec for slow operations.",
                "Split the work into quicker read-only probes.",
                "Avoid interactive commands; they never finish without input.",
            ),
        )
    if error == "rate_limited":
        return Diagnosis(
            kind="rate_limited",
            diagnosis="Too many commands were issued in a short window.",
            fix_hints=(
                "Wait briefly before running more commands.",
                "Batch several questions into fewer, well-chosen commands.",
            ),
        )
    if error == "command_budget_exhausted":
        return Diagnosis(
            kind="budget_exhausted",
            diagnosis="The session command budget is used up; no further commands will run.",
            fix_hints=("Summarize the findings gathered so far instead of retrying.",),
        )
    if error == "blocked_by_safety_gate":
        return Diagnosis(
            kind="blocked_by_gate",
            diagnosis="The safety gate refused this action before execution.",
            fix_hints=(
                "Do not rephrase the same request to dodge the block.",
                "Choose an allowed, lower-risk alternative that answers the task.",
            ),
        )
    if error == "retry_limit_reached":
        return Diagnosis(
            kind="retry_exhausted",
            diagnosis="This exact action already failed at the maximum number of retries.",
            fix_hints=("Change strategy or parameters fundamentally.",),
        )
    if error == "user_declined":
        return Diagnosis(
            kind="declined_by_user",
            diagnosis="The user declined to approve this action.",
            fix_hints=("Do not retry automatically; ask the user how to proceed.",),
        )
    if error == "malformed_arguments":
        return Diagnosis(
            kind="malformed_arguments",
            diagnosis="The tool arguments were not valid JSON or violated the schema.",
            fix_hints=("Re-issue the call with valid JSON matching the parameter schema.",),
        )
    if error in {"execution_failed", "not_found"}:
        return Diagnosis(
            kind="execution_failed",
            diagnosis="The process could not be started or crashed before returning a result.",
            fix_hints=(
                "Verify the program exists with check_tool before invoking it.",
                "Check argument spelling and platform compatibility.",
            ),
        )
    if error == "not_installed":
        return Diagnosis(
            kind="not_installed",
            diagnosis="The required binary is not present on PATH, so nothing was executed.",
            fix_hints=(
                "Confirm with tool_inventory which tools are actually installed.",
                "Install it via install_tool and verify before retrying.",
                "Or switch to an installed tool that can answer the same question.",
            ),
        )
    if error in {"shim_blocked", "verification_failed"}:
        return Diagnosis(
            kind="tool_environment",
            diagnosis=(
                "The tool exists but its local installation is unusable (a .cmd/.bat "
                "shim launcher or a broken install that never verifies)."
            ),
            fix_hints=(
                "Run fix_path to find tool directories missing from PATH.",
                "Reinstall via install_tool only after telling the user why.",
            ),
        )
    return Diagnosis(kind=error, diagnosis=f"The tool reported: {error}.", fix_hints=())


_STDERR_PATTERNS: tuple[tuple[tuple[str, ...], Diagnosis], ...] = (
    (
        ("externally-managed-environment",),
        Diagnosis(
            kind="environment_policy",
            diagnosis=(
                "The system Python environment is externally managed (PEP 668); installing "
                "into it with pip will keep failing."
            ),
            fix_hints=(
                "Create an isolated virtual environment first, then install inside it.",
                "Or use a tool installer such as pipx for CLI applications.",
            ),
        ),
    ),
    (
        (
            "is not recognized",
            "not recognized as an internal or external command",
            "command not found",
            "no such file or directory",
            "system cannot find the file specified",
        ),
        Diagnosis(
            kind="missing_resource",
            diagnosis="A referenced program or file does not exist on this machine.",
            fix_hints=(
                "Confirm availability with the check_tool tool before invoking it.",
                "Detect the OS and use the platform-correct executable name.",
                "Propose an installation path only after checking package managers.",
            ),
        ),
    ),
    (
        (
            "permission denied",
            "access is denied",
            "access denied",
            "administrator",
            "elevation required",
            "operation not permitted",
            "requested operation requires elevation",
        ),
        Diagnosis(
            kind="insufficient_permissions",
            diagnosis="The operating system refused the action due to insufficient privileges.",
            fix_hints=(
                "Run the permissions tool to report current privilege level.",
                "Prefer non-privileged diagnostics; ask the user before anything elevated.",
            ),
        ),
    ),
    (
        (
            "connection refused",
            "name or service not known",
            "temporary failure in name resolution",
            "unable to resolve host",
            "could not resolve host",
            "network is unreachable",
        ),
        Diagnosis(
            kind="network_issue",
            diagnosis="A network-level failure occurred (DNS resolution or connectivity).",
            fix_hints=(
                "Verify the hostname with a DNS lookup before retrying.",
                "Check whether the target requires VPN or allowlisting.",
            ),
        ),
    ),
    (
        ("traceback (most recent call last)",),
        Diagnosis(
            kind="script_error",
            diagnosis="An interpreted script crashed with an exception traceback.",
            fix_hints=(
                "Read the final traceback line for the root cause.",
                "Fix the script arguments rather than rerunning as-is.",
            ),
        ),
    ),
)


def classify_failure(payload: Mapping[str, Any]) -> Diagnosis:
    """Map a failed tool payload to a structured diagnosis."""
    by_kind = _diagnosis_for_error_kind(payload)
    if by_kind is not None:
        return by_kind

    exit_code = payload.get("exit_code")
    combined = _combined_output(payload)
    for needles, diagnosis in _STDERR_PATTERNS:
        if any(needle in combined for needle in needles):
            return diagnosis

    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
        return Diagnosis(
            kind="nonzero_exit",
            diagnosis=f"The command exited with code {exit_code} and reported an error.",
            fix_hints=(
                "Read stderr for the concrete failure reason.",
                "Adjust flags/arguments based on that message instead of repeating.",
            ),
        )

    return Diagnosis(
        kind="unknown_failure",
        diagnosis="The tool result did not clearly indicate success.",
        fix_hints=("Inspect the full payload before deciding on the next step.",),
    )


def enrich_failure_payload(
    tool_name: str,
    payload: Mapping[str, Any],
    *,
    attempt: int,
    max_retries: int,
) -> dict[str, Any]:
    """Return a copy of ``payload`` with a structured ``recovery`` section attached."""
    diagnosis = classify_failure(payload)
    enriched = dict(payload)
    enriched["recovery"] = {
        "tool": tool_name,
        "attempt": attempt,
        "max_retries": max_retries,
        "kind": diagnosis.kind,
        "diagnosis": diagnosis.diagnosis,
        "fix_hints": list(diagnosis.fix_hints),
    }
    return enriched


def is_failed_payload(payload: Mapping[str, Any]) -> bool:
    """Mirror of the agent's failure detection, kept here for reuse/tests."""
    if isinstance(payload.get("error"), str):
        return True
    if payload.get("timed_out") is True:
        return True
    exit_code = payload.get("exit_code")
    return isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0
