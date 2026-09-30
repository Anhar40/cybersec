"""Agent-facing tools for planning, memory, surface notes, and hypotheses.

These are the LOW-risk tools that let the model *manage its own reasoning*
instead of only firing scanners: keep a plan, record what it learned, propose a
falsifiable hypothesis, and ask what to do next. Everything they touch lives in
:class:`~cyberaent.intel.IntelHub`, which persists between turns.

Handlers never raise: validation problems come back as ``{"error": ...}`` with a
``reason`` the model can act on, matching the rest of the tool surface.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ..hypotheses import HYPOTHESIS_STATUSES
from ..intel import PLAN_STATUSES, IntelHub
from ..memory import MEMORY_KINDS
from .base import RiskLevel, ToolSpec

INTEL_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "set_plan",
        "update_plan_step",
        "remember_endpoint",
        "note_observation",
        "remember_preference",
        "propose_hypothesis",
        "update_hypothesis",
        "recall_memory",
        "next_actions",
    }
)

MAX_LIMIT = 25
DEFAULT_LIMIT = 8

_SET_PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["steps"],
    "properties": {
        "goal": {"type": "string"},
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "oneOf": [
                    {"type": "string"},
                    {
                        "type": "object",
                        "required": ["title"],
                        "properties": {
                            "title": {"type": "string"},
                            "status": {
                                "type": "string",
                                "enum": ["pending", "in_progress", "done", "blocked", "skipped"],
                            },
                            "note": {"type": "string"},
                        },
                    },
                ]
            },
        },
    },
}

_UPDATE_STEP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["index", "status"],
    "properties": {
        "index": {"type": "integer", "minimum": 1},
        "status": {
            "type": "string",
            "enum": ["pending", "in_progress", "done", "blocked", "skipped"],
        },
        "note": {"type": "string"},
    },
}

_REMEMBER_ENDPOINT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["url"],
    "properties": {
        "url": {"type": "string"},
        "method": {"type": "string"},
        "params": {"type": "array", "items": {"type": "string"}},
        "tech": {"type": "string"},
        "auth": {"type": "string"},
        "role": {"type": "string"},
        "status": {"type": ["integer", "string"]},
    },
}

_NOTE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["text"],
    "properties": {
        "kind": {"type": "string"},
        "text": {"type": "string"},
        "target": {"type": "string"},
    },
}

_PROPOSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["statement", "rationale", "test_plan"],
    "properties": {
        "statement": {"type": "string"},
        "rationale": {"type": "string"},
        "test_plan": {"type": "string"},
        "evidence": {
            "oneOf": [
                {"type": "array", "items": {"type": "string"}},
                {"type": "string"},
            ]
        },
    },
}

_UPDATE_HYPOTHESIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["hypothesis_id", "status"],
    "properties": {
        "hypothesis_id": {"type": "string"},
        "status": {
            "type": "string",
            "enum": ["proposed", "testing", "supported", "refuted"],
        },
        "evidence": {
            "oneOf": [
                {"type": "array", "items": {"type": "string"}},
                {"type": "string"},
            ]
        },
        "note": {"type": "string"},
    },
}

_RECALL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "kinds": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["endpoint", "technology", "test", "observation", "preference"],
            },
        },
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
    },
}

_NEXT_ACTIONS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT}},
}


def _guarded(fn: Callable[[Mapping[str, Any]], dict[str, Any]], reason: str) -> Callable[
    [Mapping[str, Any]], dict[str, Any]
]:
    """Turn a ValueError from the hub into a recoverable tool payload."""

    def handler(arguments: Mapping[str, Any]) -> dict[str, Any]:
        try:
            return fn(arguments)
        except ValueError as exc:
            return {"error": "invalid_arguments", "detail": str(exc), "reason": reason}

    return handler


def _limit(arguments: Mapping[str, Any], default: int) -> int:
    raw = arguments.get("limit")
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError("'limit' must be an integer.")
    return max(1, min(MAX_LIMIT, raw))


def _text(arguments: Mapping[str, Any], field: str) -> str:
    value = arguments.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{field}' must be a non-empty string.")
    return value.strip()


def _enum(arguments: Mapping[str, Any], field: str, allowed: tuple[str, ...]) -> str:
    value = arguments.get(field)
    if not isinstance(value, str) or value.strip().lower() not in allowed:
        raise ValueError(f"'{field}' must be one of: {', '.join(allowed)}.")
    return value.strip().lower()


def _check_plan_status(arguments: Mapping[str, Any]) -> str | None:
    try:
        _enum(arguments, "status", PLAN_STATUSES)
        index = arguments.get("index")
        if isinstance(index, bool) or not isinstance(index, int) or index < 1:
            return "'index' must be an integer starting at 1."
    except ValueError as exc:
        return str(exc)
    return None


def _check_set_plan(arguments: Mapping[str, Any]) -> str | None:
    steps = arguments.get("steps")
    if not isinstance(steps, list) or not steps:
        return "'steps' must be a non-empty list of step titles."
    for step in steps:
        if isinstance(step, str):
            if not step.strip():
                return "Every plan step needs a title."
        elif isinstance(step, Mapping):
            if not isinstance(step.get("title"), str) or not step["title"].strip():
                return "Every plan step object needs a 'title'."
            status = step.get("status")
            if status is not None and (
                not isinstance(status, str) or status.lower() not in PLAN_STATUSES
            ):
                return f"Step status must be one of: {', '.join(PLAN_STATUSES)}."
        else:
            return "Plan steps must be strings or objects with a 'title'."
    return None


def _check_propose(arguments: Mapping[str, Any]) -> str | None:
    for field in ("statement", "rationale", "test_plan"):
        try:
            _text(arguments, field)
        except ValueError as exc:
            return str(exc)
    return None


def _check_update_hypothesis(arguments: Mapping[str, Any]) -> str | None:
    try:
        _text(arguments, "hypothesis_id")
        _enum(arguments, "status", HYPOTHESIS_STATUSES)
    except ValueError as exc:
        return str(exc)
    return None


def _check_limit(arguments: Mapping[str, Any]) -> str | None:
    raw = arguments.get("limit")
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        return "'limit' must be an integer of at least 1."
    return None


def _check_endpoint(arguments: Mapping[str, Any]) -> str | None:
    try:
        _text(arguments, "url")
    except ValueError as exc:
        return str(exc)
    return None


def _check_text(arguments: Mapping[str, Any]) -> str | None:
    try:
        _text(arguments, "text")
    except ValueError as exc:
        return str(exc)
    return None


def _check_recall(arguments: Mapping[str, Any]) -> str | None:
    limit_error = _check_limit(arguments)
    if limit_error:
        return limit_error
    kinds = arguments.get("kinds")
    if kinds is None:
        return None
    if not isinstance(kinds, list):
        return "'kinds' must be a list of strings."
    for kind in kinds:
        if not isinstance(kind, str) or kind not in MEMORY_KINDS:
            return f"'kinds' entries must be one of: {', '.join(MEMORY_KINDS)}."
    return None


def _sequence(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part for part in value.replace(",", " ").split() if part]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ValueError(f"'{field}' must be a string or a list of strings.")


def build_intel_tools(hub: IntelHub) -> list[ToolSpec]:
    def handle_set_plan(arguments: Mapping[str, Any]) -> dict[str, Any]:
        plan = hub.set_plan(arguments.get("goal"), arguments.get("steps"))
        return {
            "plan": plan,
            "summary": f"plan saved with {len(plan['steps'])} step(s) for {plan['goal'] or 'goal'}",
        }

    def handle_update_step(arguments: Mapping[str, Any]) -> dict[str, Any]:
        step = hub.update_step(
            arguments.get("index"), arguments.get("status"), arguments.get("note")
        )
        return {"step": step, "summary": f"step {step['index']} is now {step['status']}"}

    def handle_remember_endpoint(arguments: Mapping[str, Any]) -> dict[str, Any]:
        node = hub.remember_endpoint(
            url=arguments.get("url"),
            method=str(arguments.get("method") or "GET"),
            params=_sequence(arguments.get("params"), "params"),
            tech=str(arguments.get("tech") or ""),
            auth=str(arguments.get("auth") or ""),
            role=str(arguments.get("role") or ""),
            status=arguments.get("status"),
            source="agent",
        )
        if node is None:
            return {
                "error": "invalid_arguments",
                "detail": "'url' must be a non-empty URL or host.",
                "reason": "Pass the full URL you observed, e.g. https://example.com/api?id=1.",
            }
        return {"node": node, "summary": f"remembered {node}"}

    def handle_note(arguments: Mapping[str, Any]) -> dict[str, Any]:
        record = hub.note(
            arguments.get("kind", "note"), arguments.get("text"), arguments.get("target", "")
        )
        return {"observation": record, "summary": "observation stored"}

    def handle_prefer(arguments: Mapping[str, Any]) -> dict[str, Any]:
        record = hub.prefer(arguments.get("text"))
        return {"preference": record, "summary": "preference remembered"}

    def handle_propose(arguments: Mapping[str, Any]) -> dict[str, Any]:
        record = hub.propose_hypothesis(
            statement=arguments.get("statement"),
            rationale=arguments.get("rationale"),
            test_plan=arguments.get("test_plan"),
            evidence=arguments.get("evidence"),
        )
        return {
            "hypothesis": record,
            "summary": f"{record['id']} recorded ({record['status']}): {record['statement']}",
        }

    def handle_update_hypothesis(arguments: Mapping[str, Any]) -> dict[str, Any]:
        record = hub.set_hypothesis_status(
            str(arguments.get("hypothesis_id")),
            status=arguments.get("status"),
            evidence=arguments.get("evidence"),
            note=arguments.get("note", ""),
        )
        return {"hypothesis": record, "summary": f"{record['id']} is now {record['status']}"}

    def handle_recall(arguments: Mapping[str, Any]) -> dict[str, Any]:
        rows = hub.recall(
            query=str(arguments.get("query") or ""),
            kinds=_sequence(arguments.get("kinds"), "kinds"),
            limit=_limit(arguments, DEFAULT_LIMIT),
        )
        return {
            "count": len(rows),
            "memories": rows,
            "summary": f"{len(rows)} memory entr(ies) matched",
        }

    def handle_next_actions(arguments: Mapping[str, Any]) -> dict[str, Any]:
        actions = hub.next_actions(limit=_limit(arguments, DEFAULT_LIMIT))
        return {
            "count": len(actions),
            "actions": actions,
            "summary": (
                f"{len(actions)} justified next action(s)"
                if actions
                else "nothing left to justify: run the recorded plan steps or write the report"
            ),
        }

    return [
        ToolSpec(
            name="set_plan",
            description=(
                "Save or replace the assessment plan: one `goal` plus an ordered list of "
                "`steps` (title, optional status pending|in_progress|done|blocked|skipped "
                "and note). Use it before active testing and revise it as evidence "
                "arrives; the plan is shown back to you before every turn."
            ),
            parameters=_SET_PLAN_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_set_plan,
            handler=_guarded(handle_set_plan, "Provide at least one step with a title."),
        ),
        ToolSpec(
            name="update_plan_step",
            description=(
                "Move one step of the current plan to a new `status` and optionally "
                "attach a short `note` explaining what happened. Mark a step blocked "
                "instead of silently skipping it."
            ),
            parameters=_UPDATE_STEP_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_plan_status,
            handler=_guarded(
                handle_update_step, "Use the step index (1-based) shown by set_plan."
            ),
        ),
        ToolSpec(
            name="remember_endpoint",
            description=(
                "Record ONE endpoint (and optional method, parameters, technology, auth "
                "scheme, role, HTTP status) into the persistent attack-surface graph so "
                "later turns can reason about relationships instead of re-crawling."
            ),
            parameters=_REMEMBER_ENDPOINT_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_endpoint,
            handler=handle_remember_endpoint,
        ),
        ToolSpec(
            name="note_observation",
            description=(
                "Store a short factual observation about the target (banner, quirk, "
                "odd response) so it survives into later turns and reports."
            ),
            parameters=_NOTE_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_text,
            handler=_guarded(handle_note, "'text' must describe what you actually observed."),
        ),
        ToolSpec(
            name="remember_preference",
            description=(
                "Remember how the user wants the assessment run (scope, noise tolerance, "
                "reporting style) so later turns honour it without asking again."
            ),
            parameters={
                "type": "object",
                "required": ["text"],
                "properties": {"text": {"type": "string"}},
            },
            risk=RiskLevel.LOW,
            check_args=_check_text,
            handler=_guarded(handle_prefer, "'text' must be a single preference."),
        ),
        ToolSpec(
            name="propose_hypothesis",
            description=(
                "Record ONE falsifiable hypothesis about the target together with the "
                "`rationale` (why it might be true) and the `test_plan` (the exact "
                "request or tool call that would settle it). Attach existing finding "
                "ids as `evidence`. Use this instead of guessing silently."
            ),
            parameters=_PROPOSE_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_propose,
            handler=_guarded(
                handle_propose,
                "A hypothesis needs a statement, a rationale, and a concrete test plan.",
            ),
        ),
        ToolSpec(
            name="update_hypothesis",
            description=(
                "Advance a hypothesis: `testing` while you probe it, then `supported` "
                "or `refuted`. A verdict REQUIRES finding ids as `evidence`, so a "
                "conclusion can never be asserted without proof."
            ),
            parameters=_UPDATE_HYPOTHESIS_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_update_hypothesis,
            handler=_guarded(
                handle_update_hypothesis,
                "supported/refuted need at least one existing finding id in 'evidence'.",
            ),
        ),
        ToolSpec(
            name="recall_memory",
            description=(
                "Search everything remembered so far (endpoints, technologies, tests "
                "run, observations, preferences) by free-text `query` and optional "
                "`kinds` filter. Use it instead of re-running work you already did."
            ),
            parameters=_RECALL_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_recall,
            handler=_guarded(handle_recall, "Provide 'query' text or valid 'kinds'."),
        ),
        ToolSpec(
            name="next_actions",
            description=(
                "Get the evidence-based next steps: open hypothesis tests first, then "
                "unverified high-impact findings, then coverage gaps for known "
                "endpoints. Each action states the tool, its arguments, and the "
                "evidence that justifies it. Check this when deciding what to do."
            ),
            parameters=_NEXT_ACTIONS_SCHEMA,
            risk=RiskLevel.LOW,
            check_args=_check_limit,
            handler=_guarded(handle_next_actions, "Pass an integer 'limit' or omit it."),
        ),
    ]
