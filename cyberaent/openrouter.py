from __future__ import annotations

import json
import random
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings


class OpenRouterError(RuntimeError):
    def __init__(self, message: str, *, kind: str = "api", status_code: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code


class AuthError(OpenRouterError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message, kind="auth", status_code=status_code)


class RateLimitError(OpenRouterError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message, kind="rate_limit", status_code=status_code)


class ServerError(OpenRouterError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message, kind="server", status_code=status_code)


class BadRequestError(OpenRouterError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message, kind="bad_request", status_code=status_code)


class TransportFailure(OpenRouterError):
    pass


class TimeoutFailure(TransportFailure):
    def __init__(self, message: str):
        super().__init__(message, kind="timeout")


class ConnectionFailure(TransportFailure):
    def __init__(self, message: str):
        super().__init__(message, kind="connection")


class BadResponseError(OpenRouterError):
    def __init__(self, message: str):
        super().__init__(message, kind="bad_response")


RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class ToolCallRequest:
    id: str
    name: str
    arguments_json: str


@dataclass(frozen=True)
class AssistantReply:
    content: str | None
    tool_calls: tuple[ToolCallRequest, ...]


def _extract_text(content: Any) -> str | None:
    if content is None:
        return None
    if isinstance(content, str):
        return content or None
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        joined = "".join(parts)
        return joined or None
    return str(content) or None


def _parse_tool_calls(message: dict[str, Any]) -> tuple[ToolCallRequest, ...]:
    raw = message.get("tool_calls")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise BadResponseError("tool_calls must be a list")
    calls: list[ToolCallRequest] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise BadResponseError(f"tool call #{i} is not an object")
        function = item.get("function") or {}
        if not isinstance(function, dict):
            raise BadResponseError(f"tool call #{i} has invalid function payload")
        name = function.get("name")
        if not isinstance(name, str) or not name.strip():
            raise BadResponseError(f"tool call #{i} is missing a function name")
        arguments = function.get("arguments", "{}")
        if isinstance(arguments, (dict, list)):
            arguments = json.dumps(arguments)
        if not isinstance(arguments, str):
            raise BadResponseError(f"tool call #{i} has non-string arguments")
        call_id = item.get("id") or f"call_{i}"
        calls.append(ToolCallRequest(id=str(call_id), name=name.strip(), arguments_json=arguments))
    return tuple(calls)


def _error_message(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return (resp.text or "")[:300] or f"HTTP {resp.status_code}"
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and isinstance(err.get("message"), str):
            return err["message"][:300]
        if isinstance(err, str):
            return err[:300]
        if isinstance(data.get("message"), str):
            return data["message"][:300]
    return (resp.text or "")[:300] or f"HTTP {resp.status_code}"


def _error_from_response(resp: httpx.Response) -> OpenRouterError:
    detail = _error_message(resp)
    code = resp.status_code
    if code in (401, 403):
        return AuthError(f"Authentication failed (HTTP {code}): {detail}", code)
    if code == 429:
        return RateLimitError(f"Rate limited by provider (HTTP 429): {detail}", code)
    if 500 <= code <= 599:
        return ServerError(f"Provider server error (HTTP {code}): {detail}", code)
    return BadRequestError(f"Request rejected (HTTP {code}): {detail}", code)


class OpenRouterClient:
    """Minimal OpenAI-compatible chat client for OpenRouter with retry/backoff."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ):
        self._settings = settings
        self._sleep = sleep
        self._rng = rng
        self._client = httpx.Client(
            timeout=httpx.Timeout(settings.request_timeout, connect=settings.connect_timeout),
            transport=transport,
            headers={
                "Authorization": f"Bearer {settings.api_key}",
                "Content-Type": "application/json",
                "X-Title": "CyberSec Terminal Agent",
            },
        )

    def close(self) -> None:
        self._client.close()

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AssistantReply:
        url = f"{self._settings.base_url}/chat/completions"
        payload: dict[str, Any] = {"model": self._settings.model, "messages": messages}
        if tools:
            payload["tools"] = tools

        attempts = self._settings.max_retries + 1
        last_error: OpenRouterError | None = None

        for attempt in range(attempts):
            try:
                resp = self._client.post(url, json=payload)
            except httpx.TimeoutException as exc:
                last_error = TimeoutFailure(f"Request timed out: {exc}")
            except httpx.TransportError as exc:
                last_error = ConnectionFailure(f"Connection error: {exc}")
            else:
                if resp.status_code == 200:
                    try:
                        return self._parse_reply(resp)
                    except BadResponseError as exc:
                        last_error = exc
                        if attempt < attempts - 1:
                            self._sleep(self._retry_delay(attempt))
                            continue
                        raise
                error = _error_from_response(resp)
                if resp.status_code in RETRYABLE_STATUS and attempt < attempts - 1:
                    last_error = error
                    self._sleep(self._retry_delay(attempt, self._retry_after(resp)))
                    continue
                raise error

            if attempt < attempts - 1:
                self._sleep(self._retry_delay(attempt))

        assert last_error is not None
        raise last_error

    def _retry_after(self, resp: httpx.Response) -> float | None:
        value = resp.headers.get("retry-after")
        if value is None:
            return None
        try:
            return max(0.0, min(60.0, float(value)))
        except ValueError:
            return None

    def _retry_delay(self, attempt: int, retry_after: float | None = None) -> float:
        if retry_after is not None:
            base = retry_after
        else:
            base = min(1.0 * (2**attempt), 8.0)
        return base + self._rng() * 0.25 * base

    def _parse_reply(self, resp: httpx.Response) -> AssistantReply:
        try:
            data = resp.json()
        except ValueError as exc:
            raise BadResponseError(f"Malformed JSON in response body: {exc}") from exc
        if not isinstance(data, dict):
            raise BadResponseError("Response JSON is not an object")

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise BadResponseError("Response has no choices")
        first = choices[0]
        if not isinstance(first, dict):
            raise BadResponseError("First choice is not an object")
        message = first.get("message")
        if not isinstance(message, dict):
            raise BadResponseError("Choice is missing the assistant message")

        content = _extract_text(message.get("content"))
        try:
            tool_calls = _parse_tool_calls(message)
        except BadResponseError:
            raise
        if content is None and not tool_calls:
            raise BadResponseError("Assistant message has neither text nor tool calls")
        return AssistantReply(content=content, tool_calls=tool_calls)

    def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> Generator[str, None, AssistantReply]:
        """Stream a chat completion: yields text deltas as they arrive.

        Returns the fully assembled :class:`AssistantReply` (content joined from
        the streamed deltas plus any accumulated tool calls) when the stream
        finishes. Retry policy matches :meth:`chat`: retryable HTTP statuses,
        transport failures and structurally empty streams are retried with
        backoff — but only while nothing has been yielded yet, so the consumer
        never sees duplicated text.
        """
        url = f"{self._settings.base_url}/chat/completions"
        payload: dict[str, Any] = {
            "model": self._settings.model,
            "messages": messages,
            "stream": True,
        }
        if tools:
            payload["tools"] = tools

        attempts = self._settings.max_retries + 1
        last_error: OpenRouterError | None = None
        emitted = False

        for attempt in range(attempts):
            final_attempt = attempt >= attempts - 1
            parts: list[str] = []
            calls: dict[int, dict[str, Any]] = {}
            failure: OpenRouterError | None = None

            try:
                with self._client.stream("POST", url, json=payload) as response:
                    if response.status_code != 200:
                        response.read()
                        error = _error_from_response(response)
                        if (
                            response.status_code in RETRYABLE_STATUS
                            and not emitted
                            and not final_attempt
                        ):
                            last_error = error
                            self._sleep(
                                self._retry_delay(attempt, self._retry_after(response))
                            )
                            continue
                        raise error

                    for raw_line in response.iter_lines():
                        line = raw_line.strip()
                        if not line.startswith("data:"):
                            continue
                        data = line[len("data:") :].strip()
                        if data == "[DONE]":
                            break
                        if not data:
                            continue
                        try:
                            chunk = json.loads(data)
                        except ValueError:
                            continue
                        piece = _consume_chunk(chunk, calls)
                        if piece:
                            parts.append(piece)
                            emitted = True
                            yield piece

            except httpx.TimeoutException as exc:
                failure = TimeoutFailure(f"Stream timed out: {exc}")
            except httpx.TransportError as exc:
                failure = ConnectionFailure(f"Connection error during stream: {exc}")

            if failure is None:
                try:
                    return _assemble_stream_reply(parts, calls)
                except BadResponseError as exc:
                    failure = exc

            if emitted or final_attempt:
                assert failure is not None
                raise failure
            last_error = failure
            self._sleep(self._retry_delay(attempt))

        assert last_error is not None
        raise last_error


def _consume_chunk(chunk: Any, calls: dict[int, dict[str, Any]]) -> str:
    """Fold one SSE chunk into ``calls``; return its text delta (may be empty)."""
    if not isinstance(chunk, dict):
        return ""
    choices = chunk.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""

    piece = ""
    delta = first.get("delta")
    if isinstance(delta, dict):
        text = _extract_text(delta.get("content"))
        if text:
            piece = text
        raw_calls = delta.get("tool_calls")
        if isinstance(raw_calls, list):
            for item in raw_calls:
                if not isinstance(item, dict):
                    continue
                index_raw = item.get("index")
                try:
                    index = int(index_raw) if index_raw is not None else len(calls)
                except (TypeError, ValueError):
                    continue
                slot = calls.setdefault(index, {"id": "", "name": "", "arguments": []})
                call_id = item.get("id")
                if isinstance(call_id, str) and call_id:
                    slot["id"] = call_id
                function = item.get("function") or {}
                if isinstance(function, dict):
                    name = function.get("name")
                    if isinstance(name, str) and name:
                        slot["name"] += name
                    arguments = function.get("arguments")
                    if isinstance(arguments, str):
                        slot["arguments"].append(arguments)
    return piece


def _assemble_stream_reply(
    parts: list[str], calls: dict[int, dict[str, Any]]
) -> AssistantReply:
    built: list[ToolCallRequest] = []
    for i, (_, slot) in enumerate(sorted(calls.items())):
        name = str(slot["name"]).strip()
        if not name:
            raise BadResponseError(f"streamed tool call #{i} is missing a function name")
        arguments = "".join(str(piece) for piece in slot["arguments"]) or "{}"
        built.append(
            ToolCallRequest(
                id=str(slot["id"]) or f"call_{i}",
                name=name,
                arguments_json=arguments,
            )
        )
    content = "".join(parts) or None
    if content is None and not built:
        raise BadResponseError("Stream ended without text or tool calls")
    return AssistantReply(content=content, tool_calls=tuple(built))
