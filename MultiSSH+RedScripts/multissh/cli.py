from __future__ import annotations
import asyncio
import os
import sys

import click
from rich.console import Console

from .config import load_config, load_inventory_from_file
from .manager import SessionManager, ExecutionMode
from .output import print_result_streaming, print_batch_result, console
from .models import CommandResult


@click.group()
@click.option("--config", "-c", type=click.Path(exists=True), help="YAML config file")
@click.option("--hosts-file", "-H", type=click.Path(exists=True), help="Simple hosts file")
@click.option("--concurrency", "-n", default=50, help="Max concurrent connections")
@click.option("--log-dir", "-l", default="./multissh_logs", help="Log output directory")
@click.option("--no-log", is_flag=True, default=False, help="Disable file logging")
@click.pass_context
def cli(ctx, config, hosts_file, concurrency, log_dir, no_log):
    """MultiSSH - Run commands across multiple SSH hosts simultaneously."""
    ctx.ensure_object(dict)
    ctx.obj["concurrency"] = concurrency
    ctx.obj["log_dir"] = log_dir
    ctx.obj["enable_logging"] = not no_log

    hosts = []
    if config:
        hosts = load_config(config)
    elif hosts_file:
        hosts = load_inventory_from_file(hosts_file)

    ctx.obj["hosts"] = hosts


# ── run ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("command")
@click.option("--tags", "-t", multiple=True, help="Filter hosts by tags")
@click.option(
    "--mode", "-m",
    type=click.Choice(["parallel", "sequential", "rolling"]),
    default="parallel",
)
@click.option("--rolling-window", "-w", default=5, help="Batch size for rolling mode")
@click.option("--timeout", default=30.0, help="Per-command timeout in seconds")
@click.option("--stop-on-error", is_flag=True, help="Stop on first failure")
@click.option("--stream/--no-stream", default=True, help="Stream results as they arrive")
@click.option("--sudo", is_flag=True, help="Run command with sudo")
@click.option("--sudo-password", default=None, help="Sudo password (overrides config)")
@click.option(
    "--prompt", "-p", multiple=True, type=(str, str),
    help="Interactive prompt/response pairs: -p 'Continue? [y/N]' 'y'",
)
@click.pass_context
def run(ctx, command, tags, mode, rolling_window, timeout, stop_on_error, stream, sudo, sudo_password, prompt):
    """Execute a command on all connected hosts."""
    interactive_prompts = dict(prompt) if prompt else None

    asyncio.run(
        _run_command(
            hosts=ctx.obj["hosts"],
            concurrency=ctx.obj["concurrency"],
            log_dir=ctx.obj["log_dir"],
            enable_logging=ctx.obj["enable_logging"],
            command=command,
            tags=list(tags) or None,
            mode=ExecutionMode(mode),
            rolling_window=rolling_window,
            timeout=timeout,
            stop_on_error=stop_on_error,
            stream=stream,
            sudo=sudo,
            sudo_password=sudo_password,
            interactive_prompts=interactive_prompts,
        )
    )


async def _run_command(
    hosts, concurrency, log_dir, enable_logging,
    command, tags, mode, rolling_window, timeout,
    stop_on_error, stream, sudo, sudo_password, interactive_prompts,
):
    async with SessionManager(
        max_concurrency=concurrency,
        log_dir=log_dir,
        enable_logging=enable_logging,
    ) as mgr:
        mgr.add_hosts(hosts)

        if stream:
            async def _stream_cb(result: CommandResult):
                print_result_streaming(result)
            mgr.on_result(_stream_cb)

        console.print("\n[bold cyan]Connecting to hosts...[/bold cyan]")
        conn_results = await mgr.connect_all(tags=tags)
        for host, ok in conn_results.items():
            status = "[green]connected[/green]" if ok else "[red]failed[/red]"
            console.print(f"  {host}: {status}")

        connected = sum(1 for v in conn_results.values() if v)
        if connected == 0:
            console.print("[red]No hosts connected. Aborting.[/red]")
            sys.exit(1)

        prefix = "[sudo] " if sudo else ""
        console.print(f"\n[bold cyan]Running:[/bold cyan] {prefix}{command}\n")

        batch = await mgr.run(
            command,
            tags=tags,
            mode=mode,
            rolling_window=rolling_window,
            timeout=timeout,
            stop_on_error=stop_on_error,
            sudo=sudo,
            sudo_password=sudo_password,
            interactive_prompts=interactive_prompts,
        )

        if not stream:
            print_batch_result(batch)
        else:
            console.print(
                f"\n[bold]Done:[/bold] {batch.successful}/{batch.total_hosts} succeeded "
                f"in {batch.total_duration:.2f}s"
            )

        if enable_logging:
            console.print(f"[dim]Logs written to {log_dir}/[/dim]")


# ── interactive ──────────────────────────────────────────────────

@cli.command()
@click.option("--compact", is_flag=True, default=False, help="Show only status, hide stdout/stderr")
@click.option("--errors-only", is_flag=True, default=False, help="Show only failed hosts")
@click.option("--first", "-f", default=0, type=int, help="Show output from only the first N hosts (0=all)")
@click.pass_context
def interactive(ctx, compact, errors_only, first):
    """Start an interactive multi-SSH shell."""
    asyncio.run(
        _interactive_shell(
            ctx.obj["hosts"],
            ctx.obj["concurrency"],
            ctx.obj["log_dir"],
            ctx.obj["enable_logging"],
            compact=compact,
            errors_only=errors_only,
            first_n=first,
        )
    )


async def _interactive_shell(hosts, concurrency, log_dir, enable_logging,
                              compact=False, errors_only=False, first_n=0):
    async with SessionManager(
        max_concurrency=concurrency,
        log_dir=log_dir,
        enable_logging=enable_logging,
    ) as mgr:
        mgr.add_hosts(hosts)

        console.print("[bold cyan]Connecting to all hosts...[/bold cyan]")
        conn_results = await mgr.connect_all()
        for host, ok in conn_results.items():
            status = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(f"  {status} {host}")

        connected = sum(1 for v in conn_results.values() if v)
        console.print(f"\n[bold green]{connected} hosts ready.[/bold green]")
        console.print(
            "Type commands to run on all hosts.\n"
            "  :sudo <cmd>     — run with sudo\n"
            "  :status         — show connection status\n"
            "  :reconnect      — reconnect all failed hosts\n"
            "  :compact        — toggle compact mode (hide stdout)\n"
            "  :errors         — toggle errors-only mode\n"
            "  :first <N>      — show only first N hosts (0=all)\n"
            "  :quit           — exit\n"
        )

        # Track display modes as mutable state
        display = {"compact": compact, "errors_only": errors_only, "first_n": first_n}

        async def _stream_cb(result: CommandResult):
            _print_interactive_result(result, display)

        mgr.on_result(_stream_cb)

        while True:
            try:
                mode_info = []
                if display["compact"]:
                    mode_info.append("compact")
                if display["errors_only"]:
                    mode_info.append("errors-only")
                if display["first_n"] > 0:
                    mode_info.append(f"first:{display['first_n']}")
                mode_str = f" ({', '.join(mode_info)})" if mode_info else ""

                cmd = input(f"[multissh ({connected} hosts){mode_str}] $ ")
            except (EOFError, KeyboardInterrupt):
                console.print("\nGoodbye!")
                break

            cmd = cmd.strip()
            if not cmd:
                continue

            if cmd in (":quit", ":exit", ":q"):
                break

            if cmd == ":compact":
                display["compact"] = not display["compact"]
                state = "ON" if display["compact"] else "OFF"
                console.print(f"  [yellow]Compact mode: {state}[/yellow]")
                continue

            if cmd == ":errors":
                display["errors_only"] = not display["errors_only"]
                state = "ON" if display["errors_only"] else "OFF"
                console.print(f"  [yellow]Errors-only mode: {state}[/yellow]")
                continue

            if cmd.startswith(":first"):
                parts = cmd.split()
                n = int(parts[1]) if len(parts) > 1 else 0
                display["first_n"] = n
                if n == 0:
                    console.print("  [yellow]Showing all hosts[/yellow]")
                else:
                    console.print(f"  [yellow]Showing first {n} hosts[/yellow]")
                continue

            if cmd == ":status":
                for name, ok in mgr.status().items():
                    s = "[green]connected[/green]" if ok else "[red]disconnected[/red]"
                    console.print(f"  {name}: {s}")
                continue

            if cmd == ":reconnect":
                console.print("[cyan]Reconnecting failed hosts...[/cyan]")
                for name, is_conn in mgr.status().items():
                    if not is_conn:
                        ok = await mgr.reconnect(name)
                        s = "[green]✓[/green]" if ok else "[red]✗[/red]"
                        console.print(f"  {s} {name}")
                connected = sum(1 for v in mgr.status().values() if v)
                continue

            use_sudo = False
            if cmd.startswith(":sudo "):
                use_sudo = True
                cmd = cmd[6:]

            # Reset counter for :first mode
            display["_count"] = 0

            batch = await mgr.run(cmd, sudo=use_sudo)
            console.print(
                f"  [dim]({batch.successful}/{batch.total_hosts} ok, "
                f"{batch.total_duration:.2f}s)[/dim]\n"
            )


# Counter for interactive first-N tracking
_interactive_host_count = 0


def _print_interactive_result(result: CommandResult, display: dict):
    """Print a single result with display filtering."""
    # Errors-only: skip successful results
    if display["errors_only"] and result.success:
        return

    # First-N: limit output
    if display["first_n"] > 0:
        display["_count"] = display.get("_count", 0) + 1
        if display["_count"] > display["first_n"]:
            if display["_count"] == display["first_n"] + 1:
                console.print(f"  [dim]... ({display['first_n']} shown, remaining hidden)[/dim]")
            return

    # Compact mode: just host + status
    if display["compact"]:
        host_name = result.host if isinstance(result.host, str) else result.host.display_name
        if result.success:
            console.print(f"  [green]✓[/green] {host_name} [dim](exit {result.exit_code})[/dim]")
        else:
            error = result.error or result.stderr or ""
            short_err = error[:80] + "..." if len(error) > 80 else error
            console.print(f"  [red]✗[/red] {host_name}: {short_err}")
        return

    # Full output — use existing streaming printer
    print_result_streaming(result)


# ── upload ───────────────────────────────────────────────────────

@cli.command()
@click.argument("local_path")
@click.argument("remote_path")
@click.option("--tags", "-t", multiple=True, help="Filter hosts by tags")
@click.pass_context
def upload(ctx, local_path, remote_path, tags):
    """Upload a file to all hosts."""
    asyncio.run(
        _upload_file(
            ctx.obj["hosts"],
            ctx.obj["concurrency"],
            ctx.obj["log_dir"],
            ctx.obj["enable_logging"],
            local_path,
            remote_path,
            list(tags) if tags else None,
        )
    )


async def _upload_file(hosts, concurrency, log_dir, enable_logging, local_path, remote_path, tags):
    async with SessionManager(
        max_concurrency=concurrency,
        log_dir=log_dir,
        enable_logging=enable_logging,
    ) as mgr:
        mgr.add_hosts(hosts)

        console.print(f"\n[bold]Connecting to {len(hosts)} hosts...[/bold]")
        conn_results = await mgr.connect_all(tags=tags)

        connected = sum(1 for v in conn_results.values() if v)
        failed = sum(1 for v in conn_results.values() if not v)

        if connected == 0:
            console.print("[bold red]No hosts connected. Aborting.[/bold red]")
            return

        console.print(
            f"[green]✅ {connected} connected[/green]"
            + (f", [red]❌ {failed} failed[/red]" if failed else "")
        )

        console.print(f"\n[bold]Uploading [cyan]{local_path}[/cyan] → [cyan]{remote_path}[/cyan][/bold]\n")

        # Upload to each connected host
        target_hosts = mgr.get_hosts(tags) if hasattr(mgr, 'get_hosts') else hosts
        results = {}

        for host in target_hosts:
            name = host.display_name
            if name not in mgr._sessions:
                continue
            session = mgr._sessions[name]
            if not session.connected:
                results[name] = False
                continue
            try:
                ok = await session.upload(local_path, remote_path)
                results[name] = ok
            except Exception:
                results[name] = False

        for host_name, success in results.items():
            if success:
                console.print(f"  [green]✅ {host_name}[/green]")
            else:
                console.print(f"  [red]❌ {host_name}[/red]")

        ok = sum(1 for v in results.values() if v)
        fail = sum(1 for v in results.values() if not v)
        console.print(f"\n[bold]Upload complete: {ok} succeeded, {fail} failed[/bold]")


# ── download ─────────────────────────────────────────────────────

@cli.command()
@click.argument("remote_path")
@click.argument("local_dir")
@click.option("--tags", "-t", multiple=True, help="Filter hosts by tags")
@click.pass_context
def download(ctx, remote_path, local_dir, tags):
    """Download a file from all hosts into a local directory."""
    asyncio.run(
        _download_file(
            ctx.obj["hosts"],
            ctx.obj["concurrency"],
            ctx.obj["log_dir"],
            ctx.obj["enable_logging"],
            remote_path,
            local_dir,
            list(tags) if tags else None,
        )
    )


async def _download_file(hosts, concurrency, log_dir, enable_logging, remote_path, local_dir, tags):
    async with SessionManager(
        max_concurrency=concurrency,
        log_dir=log_dir,
        enable_logging=enable_logging,
    ) as mgr:
        mgr.add_hosts(hosts)

        console.print(f"\n[bold]Connecting to {len(hosts)} hosts...[/bold]")
        conn_results = await mgr.connect_all(tags=tags)

        connected = sum(1 for v in conn_results.values() if v)
        if connected == 0:
            console.print("[bold red]No hosts connected. Aborting.[/bold red]")
            return

        console.print(f"\n[bold]Downloading [cyan]{remote_path}[/cyan] from all hosts → [cyan]{local_dir}/[/cyan][/bold]\n")
        os.makedirs(local_dir, exist_ok=True)

        target_hosts = mgr.get_hosts(tags) if hasattr(mgr, 'get_hosts') else hosts
        for host in target_hosts:
            name = host.display_name
            if name not in mgr._sessions:
                continue
            session = mgr._sessions[name]
            if not session.connected:
                continue
            safe_name = name.replace(":", "_").replace("/", "_").replace("@", "_")
            dest = os.path.join(local_dir, f"{safe_name}_{os.path.basename(remote_path)}")
            try:
                ok = await session.download(remote_path, dest)
                if ok:
                    console.print(f"  [green]✅ {name} → {dest}[/green]")
                else:
                    console.print(f"  [red]❌ {name}[/red]")
            except Exception as e:
                console.print(f"  [red]❌ {name}: {e}[/red]")


# ── check ────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def check(ctx):
    """Test connectivity to all configured hosts."""
    asyncio.run(
        _check_hosts(
            ctx.obj["hosts"],
            ctx.obj["concurrency"],
            ctx.obj["log_dir"],
            ctx.obj["enable_logging"],
        )
    )


async def _check_hosts(hosts, concurrency, log_dir, enable_logging):
    async with SessionManager(
        max_concurrency=concurrency,
        log_dir=log_dir,
        enable_logging=enable_logging,
    ) as mgr:
        mgr.add_hosts(hosts)
        results = await mgr.connect_all()
        for host, ok in sorted(results.items()):
            status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
            console.print(f"  {status}  {host}")


# ── entry point ──────────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
