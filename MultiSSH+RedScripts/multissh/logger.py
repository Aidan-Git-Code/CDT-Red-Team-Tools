from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import asyncio
import aiofiles

from .models import CommandResult, BatchResult


class SessionLogger:
    """
    Logs command results to per-host log files and an aggregate JSON log.

    Directory layout:
        log_dir/
        ├── hosts/
        │   ├── web-1.log
        │   ├── web-2.log
        │   └── db-primary.log
        ├── aggregate.jsonl          # One JSON object per CommandResult
        └── sessions.log             # Human-readable session log
    """

    def __init__(self, log_dir: str | Path = "./multissh_logs"):
        self.log_dir = Path(log_dir)
        self.hosts_dir = self.log_dir / "hosts"
        self.aggregate_path = self.log_dir / "aggregate.jsonl"
        self.session_log_path = self.log_dir / "sessions.log"
        self._lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self) -> None:
        """Create log directories."""
        if self._initialized:
            return
        self.hosts_dir.mkdir(parents=True, exist_ok=True)
        self._initialized = True

    def _sanitize_filename(self, name: str) -> str:
        """Convert a host display name into a safe filename."""
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Per-host log ─────────────────────────────────────────────

    async def log_result(self, result: CommandResult) -> None:
        """Write a single command result to the per-host log and aggregate log."""
        await self.initialize()

        host_file = self.hosts_dir / f"{self._sanitize_filename(result.host.display_name)}.log"
        ts = self._timestamp()

        # Human-readable per-host log
        lines = [
            f"\n{'='*72}",
            f"[{ts}] Command: {result.command}",
            f"Exit Code: {result.exit_code} | Success: {result.success} | Duration: {result.duration:.2f}s",
        ]
        if result.error:
            lines.append(f"Error: {result.error}")
        if result.stdout.strip():
            lines.append("--- STDOUT ---")
            lines.append(result.stdout.rstrip())
        if result.stderr.strip():
            lines.append("--- STDERR ---")
            lines.append(result.stderr.rstrip())
        lines.append(f"{'='*72}")
        host_entry = "\n".join(lines) + "\n"

        async with self._lock:
            async with aiofiles.open(host_file, mode="a") as f:
                await f.write(host_entry)

        # Machine-readable aggregate JSONL
        json_record = {
            "timestamp": ts,
            "host": result.host.display_name,
            "hostname": result.host.hostname,
            "command": result.command,
            "exit_code": result.exit_code,
            "success": result.success,
            "duration": result.duration,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": result.error,
        }

        async with self._lock:
            async with aiofiles.open(self.aggregate_path, mode="a") as f:
                await f.write(json.dumps(json_record) + "\n")

    # ── Batch log ────────────────────────────────────────────────

    async def log_batch(self, batch: BatchResult) -> None:
        """Log an entire batch result."""
        for result in batch.results:
            await self.log_result(result)

        await self._log_session_entry(batch)

    async def _log_session_entry(self, batch: BatchResult) -> None:
        """Append a summary line to the session log."""
        await self.initialize()
        ts = self._timestamp()
        summary = (
            f"[{ts}] CMD: {batch.command!r} | "
            f"Hosts: {batch.total_hosts} | "
            f"OK: {batch.successful} | "
            f"FAIL: {batch.failed} | "
            f"Duration: {batch.total_duration:.2f}s\n"
        )
        async with self._lock:
            async with aiofiles.open(self.session_log_path, mode="a") as f:
                await f.write(summary)

    # ── Connection events ────────────────────────────────────────

    async def log_connection_event(
        self,
        host_name: str,
        event: str,
        detail: Optional[str] = None,
    ) -> None:
        """Log connect/disconnect/error events."""
        await self.initialize()
        ts = self._timestamp()
        msg = f"[{ts}] [{host_name}] {event}"
        if detail:
            msg += f" — {detail}"
        msg += "\n"

        async with self._lock:
            async with aiofiles.open(self.session_log_path, mode="a") as f:
                await f.write(msg)