from __future__ import annotations
import asyncio
import time
from typing import Optional, Callable, Awaitable
from enum import Enum

from .models import HostConfig, CommandResult, BatchResult
from .session import SSHSession
from .logger import SessionLogger


class ExecutionMode(Enum):
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    ROLLING = "rolling"


class SessionManager:
    def __init__(
        self,
        max_concurrency: int = 50,
        default_timeout: float = 30.0,
        log_dir: Optional[str] = None,
        enable_logging: bool = True,
    ):
        self._sessions: dict[str, SSHSession] = {}
        self._hosts: dict[str, HostConfig] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._default_timeout = default_timeout
        self._on_result: Optional[Callable[[CommandResult], Awaitable[None]]] = None

        self._logging_enabled = enable_logging
        self._logger: Optional[SessionLogger] = None
        if enable_logging:
            self._logger = SessionLogger(log_dir or "./multissh_logs")

    # ── Host Management ──────────────────────────────────────

    def add_host(self, host: HostConfig) -> None:
        key = host.display_name
        self._hosts[key] = host

    def add_hosts(self, hosts: list[HostConfig]) -> None:
        for h in hosts:
            self.add_host(h)

    def remove_host(self, label: str) -> None:
        self._hosts.pop(label, None)
        self._sessions.pop(label, None)

    def get_hosts(self, tags: Optional[list[str]] = None) -> list[HostConfig]:
        if tags is None:
            return list(self._hosts.values())
        return [
            h for h in self._hosts.values()
            if any(t in h.tags for t in tags)
        ]

    # ── Connection Management ────────────────────────────────

    async def connect_all(
        self,
        tags: Optional[list[str]] = None,
    ) -> dict[str, bool]:
        hosts = self.get_hosts(tags)
        results: dict[str, bool] = {}

        async def _connect_one(host: HostConfig) -> tuple[str, bool]:
            async with self._semaphore:
                session = SSHSession(host)
                try:
                    await session.connect()
                    self._sessions[host.display_name] = session
                    if self._logger:
                        tunnel_info = None
                        if host.jump_host:
                            tunnel_info = f"via jump host {host.jump_host.hostname}"
                        await self._logger.log_connection_event(
                            host.display_name, "CONNECTED", tunnel_info
                        )
                    return host.display_name, True
                except ConnectionError as e:
                    if self._logger:
                        await self._logger.log_connection_event(
                            host.display_name, "CONNECTION_FAILED", str(e)
                        )
                    return host.display_name, False

        tasks = [_connect_one(h) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            name, success = await coro
            results[name] = success

        return results

    async def disconnect_all(self) -> None:
        tasks = [s.disconnect() for s in self._sessions.values()]
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._logger:
            for name in self._sessions:
                await self._logger.log_connection_event(name, "DISCONNECTED")
        self._sessions.clear()

    async def reconnect(self, host_label: str) -> bool:
        if host_label in self._sessions:
            await self._sessions[host_label].disconnect()
        if host_label in self._hosts:
            session = SSHSession(self._hosts[host_label])
            try:
                await session.connect()
                self._sessions[host_label] = session
                if self._logger:
                    await self._logger.log_connection_event(
                        host_label, "RECONNECTED"
                    )
                return True
            except ConnectionError:
                return False
        return False

    # ── Command Execution ────────────────────────────────────

    def on_result(self, callback: Callable[[CommandResult], Awaitable[None]]) -> None:
        self._on_result = callback

    async def _execute_on_session(
        self,
        session: SSHSession,
        command: str,
        timeout: Optional[float] = None,
        sudo: bool = False,
        sudo_password: Optional[str] = None,
        interactive_prompts: Optional[dict[str, str]] = None,
    ) -> CommandResult:
        async with self._semaphore:
            result = await session.execute(
                command,
                timeout=timeout,
                sudo=sudo,
                sudo_password=sudo_password,
                interactive_prompts=interactive_prompts,
            )
            if self._on_result:
                await self._on_result(result)
            if self._logger:
                await self._logger.log_result(result)
            return result

    async def run(
        self,
        command: str,
        tags: Optional[list[str]] = None,
        mode: ExecutionMode = ExecutionMode.PARALLEL,
        rolling_window: int = 5,
        timeout: Optional[float] = None,
        stop_on_error: bool = False,
        sudo: bool = False,
        sudo_password: Optional[str] = None,
        interactive_prompts: Optional[dict[str, str]] = None,
    ) -> BatchResult:
        start = time.monotonic()
        target_hosts = self.get_hosts(tags)
        target_sessions = [
            self._sessions[h.display_name]
            for h in target_hosts
            if h.display_name in self._sessions
        ]

        exec_kwargs = dict(
            command=command,
            timeout=timeout,
            sudo=sudo,
            sudo_password=sudo_password,
            interactive_prompts=interactive_prompts,
        )

        results: list[CommandResult] = []

        match mode:
            case ExecutionMode.PARALLEL:
                results = await self._run_parallel(target_sessions, exec_kwargs)
            case ExecutionMode.SEQUENTIAL:
                results = await self._run_sequential(
                    target_sessions, exec_kwargs, stop_on_error
                )
            case ExecutionMode.ROLLING:
                results = await self._run_rolling(
                    target_sessions, exec_kwargs, rolling_window, stop_on_error
                )

        duration = time.monotonic() - start
        successful = sum(1 for r in results if r.success)

        batch = BatchResult(
            command=command,
            results=results,
            total_hosts=len(target_sessions),
            successful=successful,
            failed=len(results) - successful,
            total_duration=duration,
        )

        if self._logger:
            await self._logger.log_batch(batch)

        return batch

    async def _run_parallel(
        self,
        sessions: list[SSHSession],
        kwargs: dict,
    ) -> list[CommandResult]:
        tasks = [self._execute_on_session(s, **kwargs) for s in sessions]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    async def _run_sequential(
        self,
        sessions: list[SSHSession],
        kwargs: dict,
        stop_on_error: bool,
    ) -> list[CommandResult]:
        results = []
        for session in sessions:
            result = await self._execute_on_session(session, **kwargs)
            results.append(result)
            if stop_on_error and not result.success:
                break
        return results

    async def _run_rolling(
        self,
        sessions: list[SSHSession],
        kwargs: dict,
        window: int,
        stop_on_error: bool,
    ) -> list[CommandResult]:
        results = []
        for i in range(0, len(sessions), window):
            batch = sessions[i : i + window]
            tasks = [self._execute_on_session(s, **kwargs) for s in batch]
            batch_results = await asyncio.gather(*tasks)
            results.extend(batch_results)
            if stop_on_error and any(not r.success for r in batch_results):
                break
        return results

    # ── File Transfer ────────────────────────────────────────

    async def upload_all(
        self,
        local_path: str,
        remote_path: str,
        tags: Optional[list[str]] = None,
    ) -> dict[str, bool]:
        target_hosts = self.get_hosts(tags)

        async def _upload(session: SSHSession) -> tuple[str, bool]:
            async with self._semaphore:
                ok = await session.upload(local_path, remote_path)
                return session.host.display_name, ok

        sessions = [
            self._sessions[h.display_name]
            for h in target_hosts
            if h.display_name in self._sessions
        ]
        tasks = [_upload(s) for s in sessions]
        return dict(await asyncio.gather(*tasks))

    # ── Context Manager ──────────────────────────────────────

    async def __aenter__(self) -> SessionManager:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.disconnect_all()

    # ── Status ───────────────────────────────────────────────

    def status(self) -> dict[str, bool]:
        return {
            name: session.connected
            for name, session in self._sessions.items()
        }