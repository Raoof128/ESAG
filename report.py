"""Output helpers for CLI and JSON reporting."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict

from rich.console import Console
from rich.table import Table

from risk import RiskReport

console = Console()


def render_terminal(report: RiskReport) -> None:
    """Render a colorized summary to stdout."""

    table = Table(title="Email Authentication Summary")
    table.add_column("Control", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta")

    spf_status = report.spf.record or "Missing"
    dmarc_status = report.dmarc.record or "Missing"

    dkim_status = "Published" if report.dkim.record else "Missing"

    table.add_row("SPF", spf_status)
    table.add_row("DMARC", dmarc_status)
    table.add_row(f"DKIM ({report.dkim.selector})", dkim_status)

    console.print(table)
    console.print(f"[bold]Overall risk:[/bold] {report.risk_level.value}")

    if report.findings:
        console.print("\n[bold]Findings[/bold]")
        for finding in report.findings:
            console.print(f"- [{finding.level.value}] {finding.message}")


def to_json(report: RiskReport) -> str:
    """Return a JSON serialized report suitable for machine consumption."""

    def default(obj: Any) -> Any:
        if hasattr(obj, "value"):
            return obj.value
        return obj

    payload: Dict[str, Any] = asdict(report)
    payload["risk_level"] = report.risk_level.value
    return json.dumps(payload, default=default, indent=2)
