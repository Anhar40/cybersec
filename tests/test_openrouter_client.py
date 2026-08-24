from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from cyberaent.config import Settings
from cyberaent.openrouter import (
    AssistantReply,
    AuthError,
    BadRequestError,
    BadResponseError,
    ConnectionFailure,
    OpenRouterClient,
    RateLimitError,
    ServerError,
    TimeoutFailure,
)

OK_BODY = {"choices": [{"message": {"role": "assistant", "content": "hello there"}}]}


def make_client(
    handler: Any,
    *,
    max_retries: int = 3,
    sleeps: list[float] | None = None,
) -> OpenRouterClient:
    settings = Settings(api_key="secret-key", model="test-model", max_retries=max_retries)
    return OpenRouterClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleep=(sleeps.append if sleeps is not None else (lambda _d: None)),
        rng=lambda: 0.0,
    )


def chat(client: OpenRouterClient, **kwargs: Any) -> AssistantReply:
    return client.chat([{"role": "user", "content": "hi"}], **kwargs)


def test_plain_completion() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer secret-key"
        payload = json.loads(request.content)
        assert payload["model"] == "test-model"
        return httpx.Response(200, json=OK_BODY)

    reply = chat(make_client(handler))
    assert reply.content == "hello there"
    assert reply.tool_calls == ()


def test_tool_call_parsing_with_dict_arguments() -> None:
    body = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "environment",
                                "arguments": {"a": 1},
                            },
                        }
                    ],
                }
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    reply = chat(make_client(handler))
    assert reply.content is None
    assert len(reply.tool_calls) == 1
    call = reply.tool_calls[0]
    assert call.id == "call_1"
    assert call.name == "environment"
    assert json.loads(call.arguments_json) == {"a": 1}


def test_content_parts_are_joined() -> None:
    parts = [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]
    body = {"choices": [{"message": {"role": "assistant", "content": parts}}]}
    reply = chat(make_client(lambda request: httpx.Response(200, json=body)))
    assert reply.content == "ab"


def test_auth_error_does_not_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": {"message": "invalid key"}})

    with pytest.raises(AuthError):
        chat(make_client(handler))
    assert calls["n"] == 1


def test_rate_limit_honors_retry_then_succeeds() -> None:
    sleeps: list[float] = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] <= 2:
            retry_headers = {"retry-after": "3"}
            return httpx.Response(
                429, json={"error": {"message": "slow down"}}, headers=retry_headers
            )
        return httpx.Response(200, json=OK_BODY)

    reply = chat(make_client(handler, sleeps=sleeps))
    assert reply.content == "hello there"
    assert sleeps == [3.0, 3.0]


def test_rate_limit_exhaustion_raises() -> None:
    sleeps: list[float] = []
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, json={"error": {"message": "slow down"}})

    with pytest.raises(RateLimitError):
        chat(make_client(handler, max_retries=2, sleeps=sleeps))
    assert calls["n"] == 3
    assert len(sleeps) == 2


def test_server_error_retry_then_success() -> None:
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(503, text="upstream")
        return httpx.Response(200, json=OK_BODY)

    reply = chat(make_client(handler))
    assert reply.content == "hello there"


def test_timeout_is_retried_and_mapped() -> None:
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            raise httpx.ConnectTimeout("too slow")
        return httpx.Response(200, json=OK_BODY)

    reply = chat(make_client(handler))
    assert reply.content == "hello there"

    def always_slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("too slow")

    with pytest.raises(TimeoutFailure) as exc:
        chat(make_client(always_slow, max_retries=1))
    assert exc.value.kind == "timeout"


def test_connection_error_mapping() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ConnectionFailure) as exc:
        chat(make_client(handler, max_retries=0))
    assert exc.value.kind == "connection"


def test_malformed_json_body_raises_bad_response() -> None:
    resp = httpx.Response(200, text="{not-json", headers={"content-type": "application/json"})
    with pytest.raises(BadResponseError):
        chat(make_client(lambda request: resp))


def test_malformed_json_is_retried_then_succeeds() -> None:
    state = {"n": 0}
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(
                200, text="{not-json", headers={"content-type": "application/json"}
            )
        return httpx.Response(200, json=OK_BODY)

    reply = chat(make_client(handler, sleeps=sleeps))
    assert reply.content == "hello there"
    assert state["n"] == 2
    assert len(sleeps) == 1


def test_structural_bad_response_retries_before_raising() -> None:
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        return httpx.Response(200, json={"object": "chat.completion"})

    with pytest.raises(BadResponseError):
        chat(make_client(handler, max_retries=2))
    assert state["n"] == 3


def test_missing_choices_raises_bad_response() -> None:
    with pytest.raises(BadResponseError):
        chat(make_client(lambda request: httpx.Response(200, json={"object": "chat.completion"})))


def test_empty_assistant_message_raises_bad_response() -> None:
    body = {"choices": [{"message": {"role": "assistant", "content": None}}]}
    with pytest.raises(BadResponseError):
        chat(make_client(lambda request: httpx.Response(200, json=body)))


def test_bad_request_does_not_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, json={"error": {"message": "unknown model"}})

    with pytest.raises(BadRequestError):
        chat(make_client(handler))
    assert calls["n"] == 1


def test_server_error_exhaustion_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "boom"}})

    with pytest.raises(ServerError):
        chat(make_client(handler, max_retries=1))


# ------------------------------------------------------------------- streaming
SSE_HEADERS = {"content-type": "text/event-stream"}


def sse_response(*chunks: str) -> httpx.Response:
    lines: list[str] = []
    for chunk in chunks:
        lines.append(f"data: {chunk}")
        lines.append("")
    lines.append("data: [DONE]")
    lines.append("")
    return httpx.Response(200, content="\n".join(lines).encode(), headers=SSE_HEADERS)


def text_chunk(text: str) -> str:
    return json.dumps({"choices": [{"delta": {"content": text}, "finish_reason": None}]})


def tool_chunk(index: int, **function: Any) -> str:
    call: dict[str, Any] = {"index": index}
    if "id" in function:
        call["id"] = function.pop("id")
    if function:
        call["function"] = function
    return json.dumps({"choices": [{"delta": {"tool_calls": [call]}, "finish_reason": None}]})


def run_stream(
    client: OpenRouterClient, **kwargs: Any
) -> tuple[list[str], AssistantReply]:
    gen = client.chat_stream([{"role": "user", "content": "hi"}], **kwargs)
    deltas: list[str] = []
    while True:
        try:
            deltas.append(next(gen))
        except StopIteration as stop:
            return deltas, stop.value


def test_stream_plain_completion_yields_deltas() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["stream"] is True
        return sse_response(text_chunk("hel"), text_chunk("lo"))

    deltas, reply = run_stream(make_client(handler))
    assert deltas == ["hel", "lo"]
    assert reply.content == "hello"
    assert reply.tool_calls == ()


def test_stream_accumulates_split_tool_calls() -> None:
    chunks = (
        tool_chunk(0, id="call_9", name="envi"),
        tool_chunk(0, name="ronment", arguments='{"a'),
        tool_chunk(0, arguments="\": 1}"),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return sse_response(*chunks)

    deltas, reply = run_stream(make_client(handler))
    assert deltas == []
    assert len(reply.tool_calls) == 1
    call = reply.tool_calls[0]
    assert call.id == "call_9"
    assert call.name == "environment"
    assert json.loads(call.arguments_json) == {"a": 1}


def test_stream_tolerates_comments_and_bad_lines() -> None:
    body = "\n".join(
        [
            ": OPENROUTER PROCESSING",
            "",
            "data: not-json",
            "event: ping",
            f"data: {text_chunk('ok')}",
            "",
            "data: [DONE]",
            "",
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body.encode(), headers=SSE_HEADERS)

    deltas, reply = run_stream(make_client(handler))
    assert deltas == ["ok"]
    assert reply.content == "ok"


def test_stream_rate_limit_retries_then_succeeds() -> None:
    sleeps: list[float] = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(
                429, json={"error": {"message": "slow down"}}, headers={"retry-after": "2"}
            )
        return sse_response(text_chunk("hello there"))

    deltas, reply = run_stream(make_client(handler, sleeps=sleeps))
    assert state["n"] == 2
    assert sleeps == [2.0]
    assert reply.content == "hello there"


def test_stream_empty_body_retries_then_raises() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=b"data: [DONE]\n\n", headers=SSE_HEADERS)

    with pytest.raises(BadResponseError):
        run_stream(make_client(handler, max_retries=2))
    assert calls["n"] == 3


def test_stream_transport_error_retries_then_succeeds() -> None:
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            raise httpx.ReadError("reset mid-flight")
        return sse_response(text_chunk("recovered"))

    deltas, reply = run_stream(make_client(handler))
    assert state["n"] == 2
    assert deltas == ["recovered"]
    assert reply.content == "recovered"


def test_stream_error_after_emission_raises_immediately() -> None:
    def flaky_body() -> Any:
        yield b'data: {"choices": [{"delta": {"content": "partial"}}]}\n\n'
        raise httpx.ReadError("connection reset after first chunk")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=flaky_body(), headers=SSE_HEADERS)

    gen = make_client(handler).chat_stream([{"role": "user", "content": "hi"}])
    first = next(gen)
    assert first == "partial"
    with pytest.raises(ConnectionFailure):
        next(gen)


def test_stream_auth_error_does_not_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": {"message": "invalid key"}})

    with pytest.raises(AuthError):
        run_stream(make_client(handler))
    assert calls["n"] == 1
