from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from rich.console import Console

from cyberaent.agent import AssistantDelta
from cyberaent.app import handle_command
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
