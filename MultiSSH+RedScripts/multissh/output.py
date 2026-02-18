from __future__ import annotations
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .models import CommandResult, BatchResult


console = Console()


def print_result_streaming(result: CommandResult) -> None:
    """Print a single host result as it arrives."""
    status = "✅" if result.success else "❌"
    host = result.host.display_name

    # Show tunnel info if applicable
    tunnel_info = ""
    if result.host.jump_host:
        tunnel_info = f" (via {result.host.jump_host.hostname})"

    if result.error:
        console.print(
            f"  {status} [{host}]{tunnel_info} ERROR: {result.error}",
            style="red",
        )
    else:
        header_style = "green" if result.success else "red"
        console.print(
            f"  {status} [{host}]{tunnel_info} "
            f"(exit={result.exit_code}, {result.duration:.2f}s)",
            style=header_style,
        )
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                console.print(f"     │ {line}")
        if result.stderr.strip():
            for line in result.stderr.strip().splitlines():
                console.print(f"     │ {line}", style="yellow")


def print_batch_result(batch: BatchResult) -> None:
    """Print a full batch result as a formatted table."""
    table = Table(
        title=f"Command: {batch.command}",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Host", style="cyan", min_width=20)
    table.add_column("Tunnel", style="dim", min_width=15)
    table.add_column("Status", justify="center", min_width=8)
    table.add_column("Exit", justify="center", min_width=6)
    table.add_column("Duration", justify="right", min_width=10)
    table.add_column("Output", min_width=40)

    for r in batch.results:
        status = Text("OK", style="green") if r.success else Text("FAIL", style="red")
        output = r.stdout.strip()[:200] if r.stdout else (r.error or "")
        if r.stderr:
            output += f"\n[stderr] {r.stderr.strip()[:100]}"
        tunnel = r.host.jump_host.hostname if r.host.jump_host else "direct"

        table.add_row(
            r.host.display_name,
            tunnel,
            status,
            str(r.exit_code),
            f"{r.duration:.2f}s",
            output,
        )

    console.print(table)
    console.print(
        Panel(
            f"Total: {batch.total_hosts} | "
            f"[green]Success: {batch.successful}[/green] | "
            f"[red]Failed: {batch.failed}[/red] | "
            f"Duration: {batch.total_duration:.2f}s",
            title="Summary",
            box=box.ROUNDED,
        )
    )