from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from rich.console import Console

from cyberaent.agent import AssistantDelta, IntelUpdated
from cyberaent.app import SLASH_COMMANDS, handle_command
from cyberaent.config import Settings
from cyberaent.openrouter import (
    AuthError,
    BadRequestError,
    BadResponseError,
    RateLimitError,
    ServerError,
    TimeoutFailure,
)
from cyberaent.ui import ConsoleUI, describe_error


def test_slash_commands_recognized() -> None:
    assert handle_command("/help") == "/help"
    assert handle_command("  /CLEAR ") == "/clear"
    assert handle_command("/exit") == "/exit"
    assert handle_command("/quit") == "/quit"
    assert handle_command("/findings") == "/findings"
    assert handle_command("/report") == "/report"
    for command in ("/plan", "/surface", "/memory", "/hypotheses", "/next"):
        assert handle_command(command) == command
        assert command in SLASH_COMMANDS


def test_plain_text_is_not_a_command() -> None:
    assert handle_command("scan example.com") is None
    assert handle_command("") is None


@pytest.mark.parametrize(
    ("error", "expected_fragment"),
    [
        (AuthError("bad key", 401), "API key"),
        (RateLimitError("429", 429), "rate limit"),
        (ServerError("500", 500), "server error"),
        (TimeoutFailure("t"), "timed out"),
        (BadResponseError("x"), "malformed"),
        (BadRequestError("y", 400), "rejected"),
    ],
)
def test_error_copy_maps_kinds(error: Exception, expected_fragment: str) -> None:
    text = describe_error(error)  # type: ignore[arg-type]
    assert expected_fragment.lower() in text.lower()
    assert str(error) in text


def test_settings_roundtrip_for_app() -> None:
    settings = Settings(api_key="k", model="m")
    assert settings.base_url.startswith("https://")


def test_render_events_streams_deltas_into_markdown() -> None:
    console = Console(record=True, width=100)
    ui = ConsoleUI(console=console)

    def events() -> Iterator[Any]:
        yield AssistantDelta("halo ")
        yield AssistantDelta("dunia")

    ui.render_events(events())

    assert "halo dunia" in console.export_text()


def test_render_events_flushes_stream_before_tool_panel() -> None:
    console = Console(record=True, width=100)
    ui = ConsoleUI(console=console)

    def events() -> Iterator[Any]:
        yield AssistantDelta("mengecek...")
        from cyberaent.agent import ToolCallEnd

        yield ToolCallEnd(name="environment", ok=True, summary="ok")

    ui.render_events(events())

    output = console.export_text()
    assert "mengecek..." in output
    assert "environment" in output


def test_long_stream_prints_content_exactly_once_in_terminal_mode() -> None:
    console = Console(
        record=True,
        force_terminal=True,
        color_system=None,
        width=80,
        height=10,
    )
    ui = ConsoleUI(console=console)

    def events() -> Iterator[Any]:
        yield AssistantDelta("HEADMARKER unik di awal jawaban\n")
        for index in range(60):
            yield AssistantDelta(f"baris {index} berisi teks jawaban streaming\n")
        yield AssistantDelta("TAILMARKER penutup jawaban\n")

    ui.render_events(events())

    output = console.export_text(styles=False)
    assert output.count("HEADMARKER") == 1
    assert output.count("TAILMARKER") == 1


# ------------------------------------------------------------------- intel panels
def test_intel_updated_event_is_rendered() -> None:
    console = Console(record=True, width=100)
    ui = ConsoleUI(console=console)

    def events() -> Iterator[Any]:
        yield IntelUpdated("set_plan", "plan saved with 3 step(s)", "2 endpoints · 0 graph nodes")

    ui.render_events(events())

    output = console.export_text(styles=False)
    assert "intel" in output
    assert "plan saved with 3 step(s)" in output
    assert "2 endpoints" in output


def test_show_plan_marks_step_states() -> None:
    console = Console(record=True, width=100)
    ui = ConsoleUI(console=console)

    ui.show_plan({})
    assert "No plan yet" in console.export_text(styles=False)

    ui.show_plan(
        {
            "goal": "assess x.test",
            "steps": [
                {"index": 1, "title": "recon", "status": "done"},
                {"index": 2, "title": "headers", "status": "blocked", "note": "no route"},
            ],
        }
    )
    output = console.export_text(styles=False)
    assert "assess x.test" in output
    assert "recon" in output
    assert "no route" in output


def test_show_hypotheses_table() -> None:
    console = Console(record=True, width=120)
    ui = ConsoleUI(console=console)

    ui.show_hypotheses([], {})
    assert "No hypotheses" in console.export_text(styles=False)

    ui.show_hypotheses(
        [{"id": "H-001", "statement": "IDOR in orders", "status": "testing", "evidence": []}],
        {"counts": {"testing": 1, "proposed": 0, "supported": 0, "refuted": 0}},
    )
    output = console.export_text(styles=False)
    assert "H-001" in output
    assert "IDOR in orders" in output
    assert "1 testing" in output


def test_show_memory_lists_endpoints() -> None:
    console = Console(record=True, width=120)
    ui = ConsoleUI(console=console)

    ui.show_memory({"endpoints": 0}, [])
    assert "No endpoints" in console.export_text(styles=False)

    ui.show_memory(
        {"endpoints": 1},
        [{"method": "GET", "url": "https://x.test/a", "params": ["id"], "technologies": ["nginx"]}],
    )
    output = console.export_text(styles=False)
    assert "https://x.test/a" in output
    assert "nginx" in output
    assert "id" in output


def test_help_lists_intel_commands() -> None:
    console = Console(record=True, width=200)
    ConsoleUI(console=console).help()
    output = console.export_text(styles=False)
    for command in ("/plan", "/surface", "/memory", "/hypotheses", "/next"):
        assert command in output
