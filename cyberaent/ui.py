from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from rich.console import Console, RenderableType
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from .agent import (
    AgentFailure,
    AssistantDelta,
    AssistantText,
    ConfirmationRequest,
    Event,
    ToolCallEnd,
    ToolCallStart,
    ToolDiagnosis,
    TurnLimitReached,
)
from .openrouter import OpenRouterError

ERROR_COPY: dict[str, str] = {
    "auth": "OpenRouter rejected the API key. Check OPENROUTER_API_KEY and try again.",
    "rate_limit": "OpenRouter rate limit reached (HTTP 429) even after retries. "
    "Wait a moment, then send your message again.",
    "server": "The provider had a server error and retries were exhausted. "
    "Try again shortly or switch OPENROUTER_MODEL.",
    "timeout": "The request to OpenRouter timed out after retries. "
    "Check your connection or raise OPENROUTER_TIMEOUT_SECONDS.",
    "connection": "Could not reach OpenRouter after retries. "
    "Check internet connectivity, DNS, and proxy settings.",
    "bad_response": "OpenRouter returned a malformed response. "
    "This is usually temporary; retry, or try a different OPENROUTER_MODEL.",
    "bad_request": "OpenRouter rejected the request. The model id may be invalid "
    "or the payload unsupported. Verify OPENROUTER_MODEL.",
    "api": "Unexpected OpenRouter error.",
}


def describe_error(err: OpenRouterError) -> str:
    base = ERROR_COPY.get(err.kind, ERROR_COPY["api"])
    status = f" (HTTP {err.status_code})" if err.status_code else ""
    return f"{base}{status}\nDetail: {err}"


class ConsoleUI:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def banner(self, *, model: str, base_url: str) -> None:
        body = (
            f"""[bold cyan]
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
[/bold cyan]"""
            f"Model : {model}\n"
            f"API   : {base_url}\n"
            f"DEV By: ANHAR\n\n"
            f"Type your security task in natural language.\n"
            f"[dim]/help /history /findings /report /clear /exit[/dim]"
        )
        self.console.print(
            Panel(body, title="[bold cyan]CYBERSEC AI AGENT[/bold cyan]", border_style="cyan")
        )

    def help(self) -> None:
        self.console.print(
            "[dim]Commands: /help show this help · /history recent commands · "
            "/findings evidence ledger · /report write Markdown report · "
            "/clear reset conversation · /exit quit. Everything else is natural language.[/dim]"
        )

    def show_findings(
        self, findings: list[dict[str, Any]], counts: dict[str, int]
    ) -> None:
        if not findings:
            self.console.print("[dim]No findings recorded yet.[/]")
            return
        order = ("critical", "high", "medium", "low", "info")
        summary = " · ".join(f"{counts[s]} {s}" for s in order if counts.get(s))
        self.console.print(f"[bold]Evidence ledger[/] [dim]({summary})[/]")
        table = Table(title="Findings")
        table.add_column("id", style="dim")
        table.add_column("severity")
        table.add_column("source", style="dim")
        table.add_column("target", overflow="fold")
        table.add_column("title", overflow="fold")
        severity_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }
        for finding in findings:
            severity = str(finding.get("severity", ""))
            table.add_row(
                str(finding.get("id", "")),
                Text(severity, style=severity_style.get(severity, "white")),
                str(finding.get("source_tool", "")),
                str(finding.get("target", "")) or "—",
                str(finding.get("title", "")),
            )
        self.console.print(table)

    def show_history(self, entries: list[dict[str, Any]]) -> None:
        if not entries:
            self.console.print("[dim]No commands executed yet.[/]")
            return
        table = Table(title="Command history")
        table.add_column("#", justify="right", style="dim")
        table.add_column("time", style="dim")
        table.add_column("command", overflow="fold")
        table.add_column("status")
        table.add_column("exit", justify="right")
        table.add_column("dur", justify="right")
        for entry in entries:
            status = str(entry.get("status", ""))
            style = "green" if status == "executed" else "yellow"
            table.add_row(
                str(entry.get("n", "")),
                str(entry.get("time", "")).replace("T", " ")[:19],
                str(entry.get("command", ""))[:80],
                Text(status, style=style),
                "—" if entry.get("exit_code") is None else str(entry["exit_code"]),
                f"{entry.get('duration_s', 0):.1f}s",
            )
        self.console.print(table)

    def prompt(self) -> str:
        return self.console.input("[bold cyan]You > [/]")

    def render_events(self, events: Iterator[Event]) -> None:
        buffer: list[str] = []
        live: Live | None = None

        def tail_view() -> Markdown:
            # Live falls back to re-printing the WHOLE frame once it is taller
            # than the terminal, which would duplicate the answer on every
            # delta. Keep the preview to a small tail so in-place mode never
            # breaks; the full markdown is printed once at flush time.
            text = "".join(buffer)
            max_lines = max(4, self.console.size.height - 8)
            lines = text.splitlines()
            if len(lines) > max_lines:
                text = "\n".join(["[…]"] + lines[-max_lines:])
            return Markdown(text)

        def view() -> RenderableType:
            if buffer:
                return tail_view()
            return Spinner("dots", style="dim", text=Text("Thinking…", style="dim"))

        def start_live() -> None:
            nonlocal live
            live = Live(
                view(),
                console=self.console,
                refresh_per_second=12,
                vertical_overflow="crop",
            )
            live.start()

        def quiet_stop() -> None:
            nonlocal live
            if live is not None:
                # Blank the final frame so stopping never re-prints the
                # preview into the scrollback.
                live.update(Text(""))
                live.stop()
                live = None

        def flush_and_print() -> None:
            if buffer:
                quiet_stop()
                self.console.print(Markdown("".join(buffer)))
                buffer.clear()
            else:
                quiet_stop()

        try:
            for event in events:
                if isinstance(event, AssistantDelta):
                    if live is None:
                        start_live()
                    buffer.append(event.text)
                    assert live is not None
                    live.update(view())
                    continue
                flush_and_print()
                self._render(event)
            flush_and_print()
        finally:
            quiet_stop()

    def _render(self, event: Event) -> None:
        if isinstance(event, AssistantText):
            style = "" if event.final else "dim"
            text = event.text if event.text.strip() else "(no content)"
            self.console.print(Markdown(text), style=style)
        elif isinstance(event, ToolCallStart):
            self._render_tool_start(event)
        elif isinstance(event, ToolCallEnd):
            mark = "[green]✓[/]" if event.ok else "[red]✗[/]"
            detail = f" — {event.summary}" if event.summary else ""
            self.console.print(f"{mark} [bold]{event.name}[/] finished{detail}")
        elif isinstance(event, ToolDiagnosis):
            body = Text()
            body.append("Kind   : ").append(event.kind, style="bold yellow")
            body.append("\nCause  : ").append(event.message)
            self.console.print(
                Panel(body, title="DIAGNOSIS", border_style="yellow", padding=(0, 1))
            )
        elif isinstance(event, ConfirmationRequest):
            self.console.print(Panel(event.reason, title="Confirmation required", style="yellow"))
        elif isinstance(event, TurnLimitReached):
            self.console.print(
                f"[red]Stopped after {event.limit} tool rounds.[/] "
                "Ask me to continue if you want more."
            )
        elif isinstance(event, AgentFailure):
            self.console.print(f"[red]Agent error[/]\n{describe_error(event.error)}")

    def _render_tool_start(self, event: ToolCallStart) -> None:
        if not event.risk and not event.detail:
            self.console.print(f"[yellow]→ tool:[/] {event.name}")
            return
        body = Text()
        body.append("Tool    : ").append(event.name)
        if event.detail:
            body.append("\nCommand : ").append(event.detail, style="white")
        risk_label = (event.risk or "unknown").upper()
        risk_style = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(risk_label, "white")
        body.append("\nRisk    : ").append(risk_label, style=risk_style)
        body.append("\nStatus  : ").append("RUNNING", style="bold cyan")
        self.console.print(
            Panel(body, title="TOOL EXECUTION", border_style="cyan", padding=(0, 1))
        )

    def confirm(self, request: ConfirmationRequest) -> bool:
        answer = self.console.input(f"[yellow]Proceed with {request.name}? \\[y/N][/] ")
        return answer.strip().lower() in {"y", "yes"}
