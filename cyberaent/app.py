from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

from .agent import ConfirmationRequest, Event, SecurityAgent
from .config import ConfigError, Settings, load_dotenv
from .openrouter import OpenRouterClient
from .safety import SafetyGate
from .tools.assess import build_vulnerability_tools
from .tools.environment import default_registry
from .tools.evidence import (
    DEFAULT_REPORT_TITLE,
    EvidenceStore,
    build_evidence_tools,
    recording_spec,
    write_report,
)
from .tools.fsops import build_fsops_tools
from .tools.recon import build_web_recon_tools
from .tools.terminal import CommandHistory, build_terminal_tool
from .tools.toolmgr import build_tool_manager_tools
from .tools.websec import build_web_security_tools
from .ui import ConsoleUI

SLASH_COMMANDS = {"/help", "/clear", "/exit", "/quit", "/history", "/findings", "/report"}
REPORTS_DIR = Path("reports")


def handle_command(text: str) -> str | None:
    """Return the command name if text is a slash command, else None."""
    stripped = text.strip()
    if not stripped.startswith("/"):
        return None
    return stripped.lower()


def run_turn(agent: SecurityAgent, ui: ConsoleUI, user_text: str) -> Iterator[Event]:
    try:
        yield from agent.process(user_text)
    except KeyboardInterrupt:
        agent.repair_after_interrupt()
        ui.console.print("\n[yellow]Turn cancelled.[/]")


def main(argv: list[str] | None = None) -> int:
    load_dotenv()

    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"Configuration error:\n{exc}", file=sys.stderr)
        return 2

    client = OpenRouterClient(settings)
    registry = default_registry()
    history = CommandHistory()
    evidence = EvidenceStore()
    log_path = Path("logs/commands.jsonl")
    registry.register(build_terminal_tool(history=history, log_path=log_path))
    for spec in build_tool_manager_tools(history=history, log_path=log_path):
        registry.register(spec)
    for spec in build_fsops_tools(history=history, log_path=log_path):
        registry.register(spec)
    for source in (
        build_web_security_tools(history=history, log_path=log_path),
        build_web_recon_tools(history=history, log_path=log_path),
        build_vulnerability_tools(history=history, log_path=log_path),
    ):
        for spec in source:
            registry.register(recording_spec(spec, evidence))
    for spec in build_evidence_tools(store=evidence, reports_dir=REPORTS_DIR):
        registry.register(spec)
    gate = SafetyGate(registry)

    ui = ConsoleUI()
    ui.banner(model=settings.model, base_url=settings.base_url)

    def confirm(request: ConfirmationRequest) -> bool:
        return ui.confirm(request)

    agent = SecurityAgent(client, registry, gate, confirm=confirm)

    while True:
        try:
            text = ui.prompt()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        text = text.strip()
        if not text:
            continue

        command = handle_command(text)
        if command in {"/exit", "/quit"}:
            break
        if command == "/help":
            ui.help()
            continue
        if command == "/history":
            ui.show_history(history.recent(50))
            continue
        if command == "/clear":
            agent.reset()
            ui.console.print("[dim]Conversation cleared.[/]")
            continue
        if command == "/findings":
            ui.show_findings(evidence.findings(), evidence.counts())
            continue
        if command == "/report":
            try:
                path = write_report(evidence, REPORTS_DIR, title=DEFAULT_REPORT_TITLE)
            except OSError as exc:
                ui.console.print(f"[red]Report failed:[/] {exc}")
                continue
            ui.console.print(
                f"[green]Report written:[/] {path} "
                f"({len(evidence.findings())} finding(s))"
            )
            continue

        try:
            ui.render_events(run_turn(agent, ui, text))
        except KeyboardInterrupt:
            pass

    client.close()
    return 0
