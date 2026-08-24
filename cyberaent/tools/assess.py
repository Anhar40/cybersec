"""Vulnerability Assessment tools (PRD Phase 9).

``sqli_probe`` wraps sqlmap in a strictly controlled profile: low level/risk
caps, non-interactive batch mode, and a required query-string injection point.
The model passes plain parameters only; argv is assembled here and executed
through the shared :class:`~cyberaent.tools.websec.WebToolRunner`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .base import RiskLevel, ToolSpec
from .terminal import CommandHistory
from .websec import (
    MAX_URL_LENGTH,
    ArgPlan,
    WebToolRunner,
    WebToolSpec,
    gate_check_for,
)

MAX_DATA_LENGTH = 2000


def _validate_injection_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("'url' must be a non-empty http(s) URL with a query string.")
    raw = value.strip()
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError(f"'url' exceeds {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        raise ValueError("'url' must not contain whitespace or control characters.")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"'url' must use http:// or https:// (got '{parsed.scheme}').")
    if not parsed.hostname:
        raise ValueError("'url' needs a host name.")
    if parsed.username or parsed.password:
        raise ValueError("'url' must not embed credentials (user:pass@host).")
    if not parsed.query:
        raise ValueError(
            "'url' must contain a query-string parameter to test, "
            "e.g. https://host/item?id=1"
        )
    return raw


def _build_sqli_probe(args: Mapping[str, Any]) -> ArgPlan:
    url = _validate_injection_url(args.get("url"))
    level = args.get("level", 1)
    if not isinstance(level, int) or isinstance(level, bool) or not 1 <= level <= 2:
        raise ValueError("'level' must be an integer within 1..2 (controlled profile).")
    threads = args.get("threads", 2)
    if not isinstance(threads, int) or isinstance(threads, bool) or not 1 <= threads <= 3:
        raise ValueError("'threads' must be an integer within 1..3 (controlled profile).")
    data = args.get("data")
    if data is not None:
        if not isinstance(data, str) or len(data) > MAX_DATA_LENGTH:
            raise ValueError(f"'data' must be a string of at most {MAX_DATA_LENGTH} chars.")
        if any(ch.isspace() and ch != " " for ch in data):
            raise ValueError("'data' must not contain control characters or newlines.")
    argv = [
        "sqlmap",
        "--batch",
        "--level",
        str(level),
        "--risk",
        "1",
        "--threads",
        str(threads),
        "-u",
        url,
    ]
    if data is not None:
        argv += ["--data", data]
    if bool(args.get("forms")):
        argv.append("--forms")
    return ArgPlan(argv=argv)


SQLI_SPEC = WebToolSpec(
    tool_name="sqli_probe",
    binary="sqlmap",
    description=(
        "Controlled SQL-injection assessment with sqlmap on ONE authorized "
        "endpoint that has a query-string parameter (e.g. /item?id=1). Fixed "
        "safe profile: --batch non-interactive, risk=1, level<=2, threads<=3; "
        "optionally pass POST `data` (<=2000 chars) or enable `forms`. Never "
        "use it to dump or modify data — stop at confirming/refuting the flaw."
    ),
    schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "level": {"type": "integer"},
            "threads": {"type": "integer"},
            "data": {"type": "string"},
            "forms": {"type": "boolean"},
            "timeout_sec": {"type": "integer"},
        },
    },
    builder=_build_sqli_probe,
    default_timeout_s=900,
)


class AssessToolbox:
    """Thin wrapper so sqli runs through the exact shared websec pipeline."""

    def __init__(
        self,
        *,
        history: CommandHistory | None = None,
        log_path: Path | None = None,
        runner: Callable[..., Any] | None = None,
    ):
        self._inner = WebToolRunner(history=history, log_path=log_path, runner=runner)

    def execute(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return self._inner.execute(SQLI_SPEC, arguments)


def build_vulnerability_tools(
    *,
    history: CommandHistory | None = None,
    log_path: Path | None = None,
    runner: Callable[..., Any] | None = None,
) -> list[ToolSpec]:
    toolbox = AssessToolbox(history=history, log_path=log_path, runner=runner)

    def handler(arguments: Mapping[str, Any]) -> dict[str, Any]:
        return toolbox.execute(arguments)

    return [
        ToolSpec(
            name=SQLI_SPEC.tool_name,
            description=SQLI_SPEC.description,
            parameters=SQLI_SPEC.schema,
            risk=RiskLevel.MEDIUM,
            handler=handler,
            check_args=gate_check_for(SQLI_SPEC),
        )
    ]
