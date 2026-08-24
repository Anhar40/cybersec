from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .tools.base import RiskLevel, ToolRegistry

_TYPE_CHECKS: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    requires_confirmation: bool = False
    reason: str = ""
    risk: RiskLevel | None = None

    @classmethod
    def blocked(cls, reason: str) -> Decision:
        return cls(allowed=False, reason=reason)


def validate_arguments(arguments: Any, schema: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if not isinstance(arguments, dict):
        return ["arguments must be a JSON object"]

    required = schema.get("required", [])
    properties = schema.get("properties", {})
    for name in required:
        if name not in arguments:
            problems.append(f"missing required argument '{name}'")

    for name, value in arguments.items():
        prop_schema = properties.get(name)
        if not isinstance(prop_schema, dict):
            continue
        expected = prop_schema.get("type")
        checks = _TYPE_CHECKS.get(str(expected))
        if checks and not isinstance(value, checks):
            problems.append(f"argument '{name}' must be of type {expected}")
            continue
        if expected == "integer" and isinstance(value, bool):
            problems.append(f"argument '{name}' must be of type integer")
            continue
        if expected == "array" and isinstance(value, list):
            problems.extend(_validate_array(name, value, prop_schema))
            continue
        if expected in ("integer", "number") and isinstance(value, (int, float)):
            problems.extend(_validate_number_bounds(name, value, prop_schema))
    return problems


def _validate_number_bounds(name: str, value: int | float, schema: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if isinstance(minimum, (int, float)) and value < minimum:
        problems.append(f"argument '{name}' must be >= {minimum}")
    if isinstance(maximum, (int, float)) and value > maximum:
        problems.append(f"argument '{name}' must be <= {maximum}")
    return problems


def _validate_array(name: str, value: list[Any], schema: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    min_items = schema.get("minItems")
    max_items = schema.get("maxItems")
    if isinstance(min_items, int) and len(value) < min_items:
        problems.append(f"argument '{name}' needs at least {min_items} item(s)")
    if isinstance(max_items, int) and len(value) > max_items:
        problems.append(f"argument '{name}' allows at most {max_items} item(s)")

    items = schema.get("items")
    if isinstance(items, dict):
        expected = items.get("type")
        checks = _TYPE_CHECKS.get(str(expected))
        if checks:
            for i, item in enumerate(value):
                valid_type = isinstance(item, checks) and not (
                    expected == "integer" and isinstance(item, bool)
                )
                if not valid_type:
                    problems.append(f"argument '{name}'[{i}] must be of type {expected}")
                    break
    return problems


class SafetyGate:
    def __init__(self, registry: ToolRegistry):
        self._registry = registry

    def evaluate(self, tool_name: str, arguments: Any) -> Decision:
        spec = self._registry.get(tool_name)
        if spec is None:
            available = ", ".join(self._registry.names()) or "none"
            return Decision.blocked(f"Unknown tool '{tool_name}'. Available tools: {available}.")

        problems = validate_arguments(arguments, spec.parameters)
        if problems:
            return Decision.blocked(f"Invalid arguments for '{tool_name}': " + "; ".join(problems))

        if spec.check_args is not None:
            issue = spec.check_args(arguments)
            if issue:
                return Decision.blocked(issue)

        risk = spec.risk_for(arguments) if spec.risk_for is not None else spec.risk

        if risk is RiskLevel.LOW:
            return Decision(allowed=True, risk=risk)

        return Decision(
            allowed=True,
            requires_confirmation=True,
            reason=f"'{tool_name}' is a {risk.value}-risk action and needs explicit approval.",
            risk=risk,
        )
