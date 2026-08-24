from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from cyberaent.agent import (
    AgentFailure,
    AssistantDelta,
    AssistantText,
    SecurityAgent,
    ToolCallEnd,
    ToolCallStart,
    ToolDiagnosis,
    TurnLimitReached,
)
from cyberaent.openrouter import AssistantReply, OpenRouterError, RateLimitError, ToolCallRequest
from cyberaent.safety import SafetyGate
from cyberaent.tools.base import RiskLevel, ToolRegistry, ToolSpec


@dataclass
class Streamed:
    """A scripted turn that arrives as streamed text deltas."""

    deltas: list[str] = field(default_factory=list)
    reply: AssistantReply | None = None


class ScriptedClient:
    def __init__(self, replies: list[Any], error: OpenRouterError | None = None):
        self.replies = list(replies)
        self.error = error
        self.calls: list[tuple[list[dict[str, Any]], list[dict[str, Any]] | None]] = []

    def chat_stream(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        self.calls.append((deepcopy(messages), deepcopy(tools)))
        if self.error is not None:
            raise self.error
        if not self.replies:
            raise AssertionError("ScriptedClient ran out of scripted replies")
        item = self.replies.pop(0)
        if isinstance(item, Streamed):
            yield from item.deltas
            return item.reply or AssistantReply(content="".join(item.deltas), tool_calls=())
        return item


def make_agent(client: Any, **kwargs: Any) -> SecurityAgent:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="environment",
            description="env",
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=lambda args: {"summary": "ok-env", "data": 42},
        )
    )
    return SecurityAgent(client, registry, SafetyGate(registry), **kwargs)


def tool_reply(call_id: str, name: str, arguments_json: str = "{}") -> AssistantReply:
    call = ToolCallRequest(call_id, name, arguments_json)
    return AssistantReply(content=None, tool_calls=(call,))


def final(text: str) -> AssistantReply:
    return AssistantReply(content=text, tool_calls=())


def test_happy_path_tool_then_answer() -> None:
    client = ScriptedClient([tool_reply("c1", "environment"), final("Selesai.")])
    agent = make_agent(client)

    events = list(agent.process("cek OS saya"))

    assert events[-1] == AssistantText("Selesai.", final=True)
    assert any(isinstance(e, ToolCallStart) and e.name == "environment" for e in events)
    assert any(isinstance(e, ToolCallEnd) and e.ok and e.summary == "ok-env" for e in events)

    roles = [m["role"] for m in agent.messages]
    assert roles == ["system", "user", "assistant", "tool", "assistant"]
    tool_msg = agent.messages[3]
    assert tool_msg["tool_call_id"] == "c1"
    assert json.loads(tool_msg["content"]) == {"summary": "ok-env", "data": 42}

    first_call_messages, tools_arg = client.calls[0]
    assert tools_arg is not None and len(tools_arg) == 1
    assert tools_arg[0]["function"]["name"] == "environment"
    assert first_call_messages[0]["role"] == "system"
    assert first_call_messages[-1] == {"role": "user", "content": "cek OS saya"}


def test_narration_before_tool_call_is_not_final() -> None:
    narrated = AssistantReply(
        content="Saya cek environment dulu.",
        tool_calls=(ToolCallRequest("c1", "environment", "{}"),),
    )
    client = ScriptedClient([narrated, final("done")])
    agent = make_agent(client)
    events = list(agent.process("hi"))

    texts = [e for e in events if isinstance(e, AssistantText)]
    assert texts[0].text == "Saya cek environment dulu."
    assert texts[0].final is False
    assert texts[-1].final is True


def test_streamed_text_becomes_deltas_without_duplication() -> None:
    client = ScriptedClient(
        [
            Streamed(
                ["Saya cek ", "environment dulu."],
                reply=tool_reply("c1", "environment"),
            ),
            Streamed(["Se", "le", "sai."], reply=final("ignored-when-streamed")),
        ]
    )
    agent = make_agent(client)
    events = list(agent.process("hi"))

    deltas = [e.text for e in events if isinstance(e, AssistantDelta)]
    assert deltas == ["Saya cek ", "environment dulu.", "Se", "le", "sai."]
    assert [e for e in events if isinstance(e, AssistantText)] == []
    assert any(isinstance(e, ToolCallEnd) and e.ok for e in events)
    roles = [m["role"] for m in agent.messages]
    assert roles == ["system", "user", "assistant", "tool", "assistant"]


def test_plain_reply_still_emits_assistant_text_fallback() -> None:
    client = ScriptedClient([final("jawaban utuh")])
    agent = make_agent(client)

    events = list(agent.process("hi"))

    assert events[-1] == AssistantText("jawaban utuh", final=True)
    assert not any(isinstance(e, AssistantDelta) for e in events)


def test_malformed_arguments_feed_error_back() -> None:
    client = ScriptedClient([tool_reply("c1", "environment", "{oops"), final("recovered")])
    agent = make_agent(client)
    events = list(agent.process("hi"))

    assert any(isinstance(e, ToolCallEnd) and not e.ok for e in events)
    tool_msg = agent.messages[3]
    payload = json.loads(tool_msg["content"])
    assert payload["error"] == "malformed_arguments"
    assert events[-1] == AssistantText("recovered", final=True)


def test_unknown_tool_blocked_by_gate_and_reported_to_model() -> None:
    client = ScriptedClient([tool_reply("c1", "terminal"), final("understood")])
    agent = make_agent(client)
    list(agent.process("hi"))

    payload = json.loads(agent.messages[3]["content"])
    assert payload["error"] == "blocked_by_safety_gate"


def test_handler_failure_becomes_execution_failed_payload() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="boom",
            description="x",
            parameters={"type": "object"},
            risk=RiskLevel.LOW,
            handler=lambda args: (_ for _ in ()).throw(ValueError("kaboom")),
        )
    )
    client = ScriptedClient([tool_reply("c1", "boom"), final("ok")])
    agent = SecurityAgent(client, registry, SafetyGate(registry))
    list(agent.process("hi"))

    payload = json.loads(agent.messages[3]["content"])
    assert payload["error"] == "execution_failed"
    assert "kaboom" in payload["detail"]


def test_high_risk_requires_confirmation_and_decline_stops_execution() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="danger",
            description="x",
            parameters={"type": "object"},
            risk=RiskLevel.HIGH,
            handler=lambda args: {"ran": True},
        )
    )

    decline_client = ScriptedClient([tool_reply("c1", "danger"), final("stopped")])
    decline_agent = SecurityAgent(
        decline_client, registry, SafetyGate(registry), confirm=lambda _r: False
    )
    list(decline_agent.process("go"))
    payload = json.loads(decline_agent.messages[3]["content"])
    assert payload["error"] == "user_declined"

    approve_client = ScriptedClient([tool_reply("c2", "danger"), final("done")])
    approve_agent = SecurityAgent(
        approve_client, registry, SafetyGate(registry), confirm=lambda _r: True
    )
    list(approve_agent.process("go"))
    approved_payload = json.loads(approve_agent.messages[3]["content"])
    assert approved_payload == {"ran": True}


def test_turn_limit_keeps_history_valid() -> None:
    replies = [
        tool_reply(f"c{i}", "environment") for i in range(4)
    ] + [final("never reached")]
    client = ScriptedClient(replies[:-1])
    agent = make_agent(client, max_tool_rounds=2)

    events = list(agent.process("hi"))
    limits = [e for e in events if isinstance(e, TurnLimitReached)]
    assert len(limits) == 1
    assert limits[0].limit == 2

    assistant_calls = {
        call["id"]
        for message in agent.messages
        if message.get("role") == "assistant"
        for call in message.get("tool_calls") or []
    }
    answered_ids = {
        m["tool_call_id"] for m in agent.messages if m.get("role") == "tool"
    }
    assert assistant_calls == answered_ids


def test_api_failure_yields_event_without_corrupting_history() -> None:
    client = ScriptedClient([], error=RateLimitError("429 too many requests"))
    agent = make_agent(client)
    events = list(agent.process("hi"))

    failures = [e for e in events if isinstance(e, AgentFailure)]
    assert len(failures) == 1
    assert failures[0].error.kind == "rate_limit"
    assert [m["role"] for m in agent.messages] == ["system", "user"]


def test_repair_after_interrupt_appends_cancellation_for_pending_calls() -> None:
    agent = make_agent(ScriptedClient([]))
    agent.messages.append({"role": "user", "content": "hi"})
    agent.messages.append(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "c9",
                    "type": "function",
                    "function": {"name": "environment", "arguments": "{}"},
                }
            ],
        }
    )
    before = len(agent.messages)
    agent.repair_after_interrupt()

    assert len(agent.messages) == before + 1
    repair = agent.messages[-1]
    assert repair["role"] == "tool"
    assert repair["tool_call_id"] == "c9"
    assert json.loads(repair["content"]) == {"error": "cancelled_by_user"}


def test_reset_restores_fresh_context() -> None:
    agent = make_agent(ScriptedClient([final("x")]))
    list(agent.process("hello"))
    assert len(agent.messages) > 2

    agent.reset()
    assert agent.messages == [{"role": "system", "content": agent.messages[0]["content"]}]
    assert len(agent.messages) == 1


def make_flaky_registry(calls: list[int]) -> ToolRegistry:
    def flaky(_args: Any) -> dict[str, Any]:
        calls.append(1)
        raise ValueError("still broken")

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="flaky",
            description="x",
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=flaky,
        )
    )
    return registry


def test_identical_failing_action_capped_at_three() -> None:
    calls: list[int] = []
    registry = make_flaky_registry(calls)
    replies = [
        tool_reply("c1", "flaky"),
        tool_reply("c2", "flaky"),
        tool_reply("c3", "flaky"),
        tool_reply("c4", "flaky"),
        final("gave up"),
    ]
    agent = SecurityAgent(ScriptedClient(replies), registry, SafetyGate(registry))

    events = list(agent.process("try"))

    assert len(calls) == 3
    payloads = [
        json.loads(m["content"]) for m in agent.messages if m.get("role") == "tool"
    ]
    assert [p.get("error") for p in payloads] == [
        "execution_failed",
        "execution_failed",
        "execution_failed",
        "retry_limit_reached",
    ]
    refusal = payloads[-1]
    assert "3 times" in refusal["reason"]
    ends = [e for e in events if isinstance(e, ToolCallEnd)]
    assert len(ends) == 4
    assert not ends[-1].ok
    assert ends[-1].summary == "retry limit reached"


def test_nonzero_exit_counts_toward_retry_cap() -> None:
    calls: list[int] = []

    def termish(_args: Any) -> dict[str, Any]:
        calls.append(1)
        return {"exit_code": 7, "stdout": "", "stderr": "boom"}

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="termish",
            description="x",
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=termish,
        )
    )
    replies = [tool_reply(f"c{i}", "termish") for i in range(1, 5)] + [final("stop")]
    agent = SecurityAgent(ScriptedClient(replies), registry, SafetyGate(registry))

    events = list(agent.process("go"))

    assert len(calls) == 3
    payloads = [
        json.loads(m["content"]) for m in agent.messages if m.get("role") == "tool"
    ]
    assert payloads[-1]["error"] == "retry_limit_reached"
    ends = [e for e in events if isinstance(e, ToolCallEnd)]
    assert [e.ok for e in ends] == [False, False, False, False]


def test_failure_counter_resets_between_turns() -> None:
    calls: list[int] = []
    registry = make_flaky_registry(calls)
    client = ScriptedClient(
        [
            tool_reply("c1", "flaky"),
            final("t1 done"),
            tool_reply("c2", "flaky"),
            final("t2 done"),
        ]
    )
    agent = SecurityAgent(client, registry, SafetyGate(registry))

    list(agent.process("turn one"))
    list(agent.process("turn two"))

    payloads = [
        json.loads(m["content"]) for m in agent.messages if m.get("role") == "tool"
    ]
    assert [p.get("error") for p in payloads] == [
        "execution_failed",
        "execution_failed",
    ]
    assert len(calls) == 2


def test_successful_repeat_not_blocked() -> None:
    client = ScriptedClient(
        [tool_reply("c1", "environment"), tool_reply("c2", "environment"), final("done")]
    )
    agent = make_agent(client)

    list(agent.process("hi"))

    payloads = [
        json.loads(m["content"]) for m in agent.messages if m.get("role") == "tool"
    ]
    assert payloads == [{"summary": "ok-env", "data": 42}, {"summary": "ok-env", "data": 42}]


def test_failed_tool_payload_gets_recovery_enrichment() -> None:
    def flaky(args: Mapping[str, Any]) -> dict[str, Any]:
        if not args.get("fix"):
            return {"exit_code": 2, "stdout": "", "stderr": "boom happened"}
        return {"exit_code": 0, "stdout": "fixed output"}

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="flaky",
            description="x",
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=flaky,
        )
    )
    client = ScriptedClient(
        [
            tool_reply("c1", "flaky", "{}"),
            tool_reply("c2", "flaky", '{"fix": true}'),
            final("recovered"),
        ]
    )
    agent = SecurityAgent(client, registry, SafetyGate(registry))

    events = list(agent.process("go"))

    payloads = [
        json.loads(m["content"]) for m in agent.messages if m.get("role") == "tool"
    ]
    first_recovery = payloads[0]["recovery"]
    assert payloads[0]["exit_code"] == 2
    assert first_recovery["attempt"] == 1
    assert first_recovery["max_retries"] == 3
    assert first_recovery["kind"] == "nonzero_exit"
    assert first_recovery["fix_hints"]
    assert "recovery" not in payloads[1]

    diagnoses = [e for e in events if isinstance(e, ToolDiagnosis)]
    assert len(diagnoses) == 1
    assert diagnoses[0].kind == "nonzero_exit"
    assert agent.recovery_summary() == {"failures_detected": 1, "actions_recovered": 1}


def test_identical_failure_attempt_number_increments() -> None:
    calls: list[int] = []
    registry = make_flaky_registry(calls)
    replies = [tool_reply("c1", "flaky"), tool_reply("c2", "flaky"), final("stop")]
    agent = SecurityAgent(ScriptedClient(replies), registry, SafetyGate(registry))

    list(agent.process("go"))

    attempts = [
        json.loads(m["content"])["recovery"]["attempt"]
        for m in agent.messages
        if m.get("role") == "tool"
    ]
    assert attempts == [1, 2]
    assert agent.recovery_summary() == {"failures_detected": 2, "actions_recovered": 0}


def test_tool_start_carries_risk_and_detail() -> None:
    client = ScriptedClient([tool_reply("c1", "environment", "{}"), final("ok")])
    agent = make_agent(client)
    events = list(agent.process("hi"))
    start = next(e for e in events if isinstance(e, ToolCallStart))
    assert (start.risk, start.detail) == ("low", "{}")

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="danger",
            description="x",
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.HIGH,
            handler=lambda args: {"ran": True},
        )
    )
    high_client = ScriptedClient([tool_reply("c2", "danger", '{"k": "v"}'), final("ok")])
    high_agent = SecurityAgent(
        high_client, registry, SafetyGate(registry), confirm=lambda _r: True
    )
    high_events = list(high_agent.process("go"))
    high_start = next(e for e in high_events if isinstance(e, ToolCallStart))
    assert high_start.risk == "high"
    assert json.loads(high_start.detail or "{}") == {"k": "v"}
