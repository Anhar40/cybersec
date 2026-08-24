from __future__ import annotations

from cyberaent.safety import Decision, SafetyGate, validate_arguments
from cyberaent.tools.base import RiskLevel, ToolRegistry, ToolSpec


def make_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="environment",
            description="env",
            parameters={"type": "object", "properties": {}},
            risk=RiskLevel.LOW,
            handler=lambda args: {"ok": True},
        )
    )
    return registry


def add_risky_tool(registry: ToolRegistry, name: str, risk: RiskLevel) -> None:
    parameters = {
        "type": "object",
        "required": ["target"],
        "properties": {"target": {"type": "string"}},
    }
    registry.register(
        ToolSpec(
            name=name,
            description="risky",
            parameters=parameters,
            risk=risk,
            handler=lambda args: {"ok": True},
        )
    )


def test_low_risk_auto_approved() -> None:
    gate = SafetyGate(make_registry())
    decision = gate.evaluate("environment", {})
    assert decision.allowed
    assert not decision.requires_confirmation


def test_unknown_tool_blocked_with_available_list() -> None:
    gate = SafetyGate(make_registry())
    decision = gate.evaluate("terminal", {})
    assert not decision.allowed
    assert "environment" in decision.reason


def test_non_object_arguments_rejected() -> None:
    gate = SafetyGate(make_registry())
    decision = gate.evaluate("environment", ["not", "an", "object"])
    assert not decision.allowed
    assert "JSON object" in decision.reason


def test_missing_required_argument_blocked() -> None:
    registry = make_registry()
    add_risky_tool(registry, "scan", RiskLevel.MEDIUM)
    gate = SafetyGate(registry)
    decision = gate.evaluate("scan", {})
    assert not decision.allowed
    assert "target" in decision.reason


def test_wrong_argument_type_blocked() -> None:
    registry = make_registry()
    add_risky_tool(registry, "scan", RiskLevel.MEDIUM)
    gate = SafetyGate(registry)
    decision = gate.evaluate("scan", {"target": 123})
    assert not decision.allowed
    assert "string" in decision.reason


def test_medium_and_high_risk_require_confirmation() -> None:
    for risk in (RiskLevel.MEDIUM, RiskLevel.HIGH):
        registry = make_registry()
        add_risky_tool(registry, "action", risk)
        gate = SafetyGate(registry)
        decision = gate.evaluate("action", {"target": "example.com"})
        assert isinstance(decision, Decision)
        assert decision.allowed
        assert decision.requires_confirmation
        assert risk.value in decision.reason


def test_validate_arguments_reports_multiple_problems() -> None:
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
    }
    problems = validate_arguments({"b": "x"}, schema)
    assert any("missing required argument 'a'" in p for p in problems)
    assert any("must be of type integer" in p for p in problems)


def test_validate_array_constraints() -> None:
    schema = {
        "type": "object",
        "required": ["names"],
        "properties": {
            "names": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "maxItems": 2,
            }
        },
    }

    assert validate_arguments({"names": ["nmap"]}, schema) == []
    assert validate_arguments({"names": []}, schema)
    too_many = validate_arguments({"names": ["a", "b", "c"]}, schema)
    assert any("at most 2" in p for p in too_many)
    wrong_item = validate_arguments({"names": [1]}, schema)
    assert any("must be of type string" in p for p in wrong_item)


def test_boolean_is_not_accepted_as_integer() -> None:
    schema = {"type": "object", "properties": {"count": {"type": "integer"}}}
    problems = validate_arguments({"count": True}, schema)
    assert any("must be of type integer" in p for p in problems)
