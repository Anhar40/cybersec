from __future__ import annotations

import json
from collections.abc import Callable, Generator, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from .openrouter import AssistantReply, OpenRouterError
from .recovery import enrich_failure_payload, is_failed_payload
from .safety import SafetyGate
from .tools.base import ToolRegistry

SYSTEM_PROMPT = """\
You are CyberSec Agent, a senior web-security engineer with about ten years of \
professional experience, operating inside a conversational terminal.

Personality: calm, analytical, systematic, honest, patient, practical.

Rules:
- Explain important decisions briefly BEFORE acting. Show concise action reasoning; \
never reveal hidden chain-of-thought.
- Never claim that a command or tool succeeded without evidence from its result. \
Report failures honestly.
- When you need facts about the LOCAL machine, use your tools instead of guessing:
  `environment` for a full snapshot; `check_tool` to test whether specific programs \
(e.g. nmap, nuclei, go) are installed; `path_info`, `package_managers`, `permissions` \
for focused details.
- Manage security tooling with the dedicated tools: `tool_inventory` scans which known \
tools are installed (with versions); `install_tool` installs ONE managed tool through a \
detected package manager — it always asks the user first, and a declined install must \
never be retried or worked around; `fix_path` reports tool directories missing from \
PATH and can permanently add them (Windows user PATH, or a guarded block in the POSIX \
shell profile) only with explicit approval. After installing, verify before claiming \
success.
- For web reconnaissance use the curated web-security tools instead of raw terminal \
commands: `http_request` (curl), `port_scan` (nmap), `http_probe` (httpx), `web_tech` \
(whatweb), `nikto_scan` (nikto), `vuln_scan` (nuclei), `dir_fuzz` (ffuf), `dns_lookup` \
(dig), `tls_info` (openssl). They take plain parameters — never raw flags — and each \
one asks the user before it touches the network. Only scan targets the user has \
authorized, start with the quietest tool that answers the question, and fall back to \
`terminal` only when no curated tool fits.
- Structure reconnaissance as a staged plan: start passive (`dns_lookup`, \
`subdomain_enum`, then `http_probe` across discovered hosts), then go deep per host \
with `header_audit`, `web_tech` and `tls_info` before any active scanning. Present a \
short numbered plan first and adapt it as evidence arrives; report each stage's \
findings before moving on.
- Vulnerability assessment is CONTROLLED by default: prefer `vuln_scan` (nuclei) with \
a `severity` filter and report its structured findings sorted by severity. Only run \
`sqli_probe` when the user explicitly asked for SQL-injection testing of that exact \
endpoint; it runs a fixed safe profile (risk=1, level<=2, non-interactive). For every \
vulnerability you report include the evidence (tool output excerpt or finding entry), \
the affected endpoint, and a concrete remediation suggestion. Never attempt to dump, \
modify, or destroy data on the target.
- Keep an evidence ledger during assessments: record each issue you verified with \
`record_finding` (title, severity critical|high|medium|low|info, target, evidence excerpt, \
remediation) — only what the evidence supports. Findings from `vuln_scan` and failing \
checks from `header_audit` are captured automatically; still verify them before calling \
them real vulnerabilities. Use `list_findings` to review the ledger, and when the user \
asks for a report (`buatkan laporan`, "write the pentest report") call `generate_report`, \
then tell the user where the Markdown file was saved.
- The `terminal` tool runs ONE local command with NO shell: pass `argv` as an array \
(program first, then arguments), e.g. {"argv": ["nmap", "-sV", "example.com"]}. \
Detect the OS before writing OS-specific commands. Prefer read-only diagnostics first. \
Medium-risk commands (active scanning) and high-risk commands (e.g. installs) will ask \
the user for confirmation; never try to bypass a block — adjust your approach instead.
- Deleting files or folders goes ONLY through `file_delete` with structured arguments \
({"paths": [...], "recursive": true|false}) — never `rm`, `del`, or `Remove-Item` via \
the terminal. It always asks the user before removing anything. Confirm the exact list \
of paths with the user when they did not state them explicitly, and refuse requests to \
wipe system directories, whole drives, or other people's data.
- Never repeat an identical command that already failed; change parameters, gather \
more information, or switch strategy instead.
- When a tool fails, read the `recovery` section of its result first: it names the \
failure kind, the likely cause, and concrete fix hints. Diagnose out loud in one \
sentence, adjust your approach, and verify the fix with a follow-up check before \
declaring success. Never claim recovery without evidence.
- Stay strictly within the target scope authorized by the user. Refuse destructive, \
unauthorized, or unethical requests and offer safe alternatives instead.
- Mirror the user's language: reply in English or Bahasa Indonesia depending on what \
they used.
- Keep answers focused, technical, and free of filler.
"""

MAX_RETRIES_PER_ACTION = 3


@dataclass(frozen=True)
class AssistantText:
    text: str
    final: bool


@dataclass(frozen=True)
class AssistantDelta:
    """Incremental piece of assistant text from a streamed reply."""

    text: str


@dataclass(frozen=True)
class ToolCallStart:
    name: str
    risk: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ToolCallEnd:
    name: str
    ok: bool
    summary: str | None


@dataclass(frozen=True)
class ToolDiagnosis:
    name: str
    kind: str
    message: str


@dataclass(frozen=True)
class ConfirmationRequest:
    name: str
    reason: str


@dataclass(frozen=True)
class TurnLimitReached:
    limit: int


@dataclass(frozen=True)
class AgentFailure:
    error: OpenRouterError


Event = (
    AssistantText
    | AssistantDelta
    | ToolCallStart
    | ToolCallEnd
    | ToolDiagnosis
    | ConfirmationRequest
    | TurnLimitReached
    | AgentFailure
)


class ChatClient(Protocol):
    def chat_stream(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> Generator[str, None, AssistantReply]: ...


ConfirmCallback = Callable[[ConfirmationRequest], bool]


def _raw_tool_call(call_id: str, name: str, arguments_json: str) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": arguments_json},
    }


class SecurityAgent:
    def __init__(
        self,
        client: ChatClient,
        registry: ToolRegistry,
        gate: SafetyGate,
        *,
        max_tool_rounds: int = 5,
        confirm: ConfirmCallback | None = None,
    ):
        self._client = client
        self._registry = registry
        self._gate = gate
        self._max_tool_rounds = max_tool_rounds
        self._confirm = confirm or (lambda _req: False)
        self._failures: dict[str, int] = {}
        self._failures_seen = 0
        self._recoveries = 0
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]

    def recovery_summary(self) -> dict[str, int]:
        """Recovery-cycle stats for the most recent process() turn."""
        return {
            "failures_detected": self._failures_seen,
            "actions_recovered": self._recoveries,
        }

    def reset(self) -> None:
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def repair_after_interrupt(self) -> None:
        """Close dangling tool calls so history stays valid for the next API call."""
        pending: dict[str, bool] = {}
        for message in reversed(list(self.messages)):
            role = message.get("role")
            if role == "tool" and isinstance(message.get("tool_call_id"), str):
                pending[message["tool_call_id"]] = True
            elif role == "assistant":
                for call in message.get("tool_calls") or []:
                    call_id = call.get("id") if isinstance(call, dict) else None
                    if isinstance(call_id, str) and not pending.get(call_id):
                        self.messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call_id,
                                "content": json.dumps({"error": "cancelled_by_user"}),
                            }
                        )
                break

    def process(self, user_text: str) -> Iterator[Event]:
        self._failures.clear()
        self._failures_seen = 0
        self._recoveries = 0
        self.messages.append({"role": "user", "content": user_text})
        rounds = 0

        while True:
            stream = self._client.chat_stream(
                self.messages, tools=self._registry.openai_specs() or None
            )
            emitted: list[str] = []
            while True:
                try:
                    delta = next(stream)
                except StopIteration as stop:
                    reply = cast(AssistantReply, stop.value)
                    break
                except OpenRouterError as exc:
                    yield AgentFailure(exc)
                    return
                if delta:
                    emitted.append(delta)
                    yield AssistantDelta(delta)

            if not emitted and reply.content:
                # Client returned the reply without streaming any text.
                yield AssistantText(reply.content, final=not reply.tool_calls)

            if not reply.tool_calls:
                self.messages.append({"role": "assistant", "content": reply.content or ""})
                return

            rounds += 1
            if rounds > self._max_tool_rounds:
                self.messages.append(
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            _raw_tool_call(tc.id, tc.name, tc.arguments_json)
                            for tc in reply.tool_calls
                        ],
                    }
                )
                for tc in reply.tool_calls:
                    self.messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": json.dumps(
                                {"error": "turn_limit_reached", "detail": "not executed"}
                            ),
                        }
                    )
                yield TurnLimitReached(self._max_tool_rounds)
                return

            self.messages.append(
                {
                    "role": "assistant",
                    "content": reply.content or "",
                    "tool_calls": [
                        _raw_tool_call(tc.id, tc.name, tc.arguments_json) for tc in reply.tool_calls
                    ],
                }
            )

            for tc in reply.tool_calls:
                payload = yield from self._run_tool_call_iter(tc)
                self.messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(payload, ensure_ascii=False, default=str),
                    }
                )

    @staticmethod
    def _args_preview(arguments: Any) -> str:
        try:
            preview = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            preview = str(arguments)
        return preview[:120]

    def _action_key(self, name: str, arguments: Any) -> str:
        try:
            canonical = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            canonical = str(arguments)
        return f"{name}:{canonical[:2000]}"

    def _note_failure(self, action_key: str) -> None:
        self._failures[action_key] = self._failures.get(action_key, 0) + 1
        self._failures_seen += 1

    def _run_tool_call_iter(
        self, tc: Any
    ) -> Generator[Event, None, dict[str, Any]]:
        """Yield live events for one tool call; the final payload comes from StopIteration."""
        arguments: Any = None
        try:
            arguments = json.loads(tc.arguments_json) if tc.arguments_json.strip() else {}
        except json.JSONDecodeError as exc:
            payload = {
                "error": "malformed_arguments",
                "detail": f"invalid JSON arguments: {exc}",
            }
            yield ToolCallStart(tc.name, detail=self._args_preview(tc.arguments_json))
            yield ToolCallEnd(tc.name, ok=False, summary="malformed JSON arguments")
            return self._with_recovery(tc.name, payload)

        decision = self._gate.evaluate(tc.name, arguments)
        spec = self._registry.get(tc.name)
        risk = decision.risk if decision.risk is not None else (spec.risk if spec else None)
        yield ToolCallStart(
            tc.name, risk=risk.value if risk is not None else None,
            detail=self._args_preview(arguments),
        )

        if not decision.allowed:
            yield ToolCallEnd(tc.name, ok=False, summary="blocked by safety gate")
            blocked_payload = self._with_recovery(
                tc.name, {"error": "blocked_by_safety_gate", "reason": decision.reason}
            )
            diagnosis = blocked_payload["recovery"]
            yield ToolDiagnosis(
                tc.name, kind=str(diagnosis["kind"]), message=str(diagnosis["diagnosis"])
            )
            return blocked_payload

        action_key = self._action_key(tc.name, arguments)
        prior_failures = self._failures.get(action_key, 0)
        if prior_failures >= MAX_RETRIES_PER_ACTION:
            reason = (
                f"This exact action already failed {prior_failures} times this turn "
                f"(max retries {MAX_RETRIES_PER_ACTION}). Change parameters or strategy "
                "instead of repeating it."
            )
            yield ToolCallEnd(tc.name, ok=False, summary="retry limit reached")
            return self._with_recovery(
                tc.name, {"error": "retry_limit_reached", "reason": reason}
            )

        if decision.requires_confirmation:
            approved = self._confirm(ConfirmationRequest(name=tc.name, reason=decision.reason))
            if not approved:
                yield ToolCallEnd(tc.name, ok=False, summary="declined by user")
                return self._with_recovery(
                    tc.name, {"error": "user_declined", "reason": decision.reason}
                )

        assert spec is not None
        try:
            result = spec.handler(arguments if isinstance(arguments, Mapping) else {})
            if not isinstance(result, Mapping):
                raise TypeError("tool handler returned a non-object result")
            payload = dict(result)
        except Exception as exc:
            self._note_failure(action_key)
            failure = {"error": "execution_failed", "detail": str(exc)[:300]}
            yield ToolCallEnd(tc.name, ok=False, summary=None)
            return self._with_recovery(tc.name, failure, attempt=prior_failures + 1)

        failed = is_failed_payload(payload)
        if failed:
            self._note_failure(action_key)
        elif self._failures_seen > 0:
            self._recoveries += 1

        raw_summary = payload.get("summary")
        summary = raw_summary if isinstance(raw_summary, str) else None
        yield ToolCallEnd(tc.name, ok=not failed, summary=summary)
        if not failed:
            return payload
        enriched = self._with_recovery(tc.name, payload, attempt=prior_failures + 1)
        diagnosis = enriched["recovery"]
        yield ToolDiagnosis(
            tc.name, kind=str(diagnosis["kind"]), message=str(diagnosis["diagnosis"])
        )
        return enriched

    def _with_recovery(
        self,
        tool_name: str,
        payload: dict[str, Any],
        *,
        attempt: int | None = None,
    ) -> dict[str, Any]:
        return enrich_failure_payload(
            tool_name,
            payload,
            attempt=attempt if attempt is not None else 1,
            max_retries=MAX_RETRIES_PER_ACTION,
        )
