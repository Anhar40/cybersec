from __future__ import annotations

from typing import Any

from cyberaent.recovery import classify_failure, enrich_failure_payload, is_failed_payload


def test_explicit_error_kinds_are_classified() -> None:
    cases = {
        "timeout": {"error": "timeout"},
        "rate_limited": {"error": "rate_limited"},
        "budget_exhausted": {"error": "command_budget_exhausted"},
        "blocked_by_gate": {"error": "blocked_by_safety_gate"},
        "retry_exhausted": {"error": "retry_limit_reached"},
        "declined_by_user": {"error": "user_declined"},
        "malformed_arguments": {"error": "malformed_arguments"},
        "execution_failed": {"error": "execution_failed"},
    }
    for expected, payload in cases.items():
        diagnosis = classify_failure(payload)
        assert diagnosis.kind == expected, f"{expected}: got {diagnosis.kind}"
        assert diagnosis.diagnosis.strip()
    hints = classify_failure({"error": "timeout"})
    assert any("timeout_sec" in hint for hint in hints.fix_hints)
    assert any("check_tool" in h for h in classify_failure({"error": "execution_failed"}).fix_hints)


def test_stderr_patterns_drive_diagnosis() -> None:
    patterns = {
        "environment_policy": "ERROR: externally-managed-environment",
        "missing_resource": "'nuclei' is not recognized as an internal or external command",
        "insufficient_permissions": "Access is denied. (os error 5)",
        "network_issue": "curl: (6) Could not resolve host: example.test",
        "script_error": "Traceback (most recent call last):\n  File ... ValueError",
    }
    for expected, stderr in patterns.items():
        payload: dict[str, Any] = {"exit_code": 1, "stdout": "", "stderr": stderr}
        assert classify_failure(payload).kind == expected, stderr


def test_generic_nonzero_exit_and_success_detection() -> None:
    generic = classify_failure({"exit_code": 3, "stdout": "", "stderr": "strange output"})
    assert generic.kind == "nonzero_exit"
    assert generic.fix_hints

    fallback = classify_failure({"exit_code": 0})
    assert fallback.kind == "unknown_failure"

    assert is_failed_payload({"exit_code": 0}) is False
    assert is_failed_payload({"exit_code": 7}) is True
    assert is_failed_payload({"timed_out": True}) is True
    assert is_failed_payload({"error": "x"}) is True
    assert is_failed_payload({"exit_code": True}) is False


def test_enrich_failure_payload_attaches_recovery_block() -> None:
    original = {"error": "timeout", "exit_code": None, "summary": "timeout after 30s"}
    enriched = enrich_failure_payload(
        "terminal", original, attempt=2, max_retries=3
    )

    assert enriched["error"] == "timeout"
    recovery = enriched["recovery"]
    assert recovery["tool"] == "terminal"
    assert recovery["attempt"] == 2
    assert recovery["max_retries"] == 3
    assert recovery["kind"] == "timeout"
    assert isinstance(recovery["diagnosis"], str) and recovery["diagnosis"]
    assert isinstance(recovery["fix_hints"], list) and recovery["fix_hints"]

    assert "recovery" not in original
