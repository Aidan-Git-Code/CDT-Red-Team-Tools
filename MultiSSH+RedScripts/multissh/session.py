from __future__ import annotations
import asyncio
import time
from typing import Optional

import asyncssh

from .models import HostConfig, CommandResult, AuthMethod, JumpHostConfig


class SSHSession:
    """Manages a single persistent SSH connection with sudo and tunnel support."""

    def __init__(self, host: HostConfig):
        self.host = host
        self._conn: Optional[asyncssh.SSHClientConnection] = None
        self._tunnel_conn: Optional[asyncssh.SSHClientConnection] = None
        self._lock = asyncio.Lock()
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected and self._conn is not None

    # ── Connection helpers ───────────────────────────────────────

    @staticmethod
    def _build_connect_kwargs(
        hostname: str,
        port: int,
        username: str,
        auth_method: AuthMethod,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        passphrase: Optional[str] = None,
        connect_timeout: float = 10.0,
    ) -> dict:
        """Build the kwargs dict for asyncssh.connect()."""
        kwargs: dict = {
            "host": hostname,
            "port": port,
            "username": username,
            "known_hosts": None,
            "login_timeout": connect_timeout,
        }

        match auth_method:
            case AuthMethod.PASSWORD:
                kwargs["password"] = password
                kwargs["client_keys"] = []
            case AuthMethod.KEY:
                if key_path:
                    kwargs["client_keys"] = [key_path]
                if passphrase:
                    kwargs["passphrase"] = passphrase
            case AuthMethod.AGENT:
                pass  # asyncssh uses agent by default

        return kwargs

    async def _open_tunnel(self, jump: JumpHostConfig) -> asyncssh.SSHClientConnection:
        """Open the SSH connection to the jump/bastion host."""
        kwargs = self._build_connect_kwargs(
            hostname=jump.hostname,
            port=jump.port,
            username=jump.username,
            auth_method=jump.auth_method,
            password=jump.password,
            key_path=jump.key_path,
            passphrase=jump.passphrase,
        )
        return await asyncssh.connect(**kwargs)

    async def connect(self) -> None:
        """Establish the SSH connection, optionally through a jump host."""
        async with self._lock:
            if self._connected:
                return

            tunnel = None

            # If a jump host is configured, connect to it first
            if self.host.jump_host:
                try:
                    self._tunnel_conn = await self._open_tunnel(self.host.jump_host)
                    tunnel = self._tunnel_conn
                except (asyncssh.Error, OSError) as e:
                    raise ConnectionError(
                        f"Failed to connect to jump host "
                        f"{self.host.jump_host.hostname}: {e}"
                    ) from e

            kwargs = self._build_connect_kwargs(
                hostname=self.host.hostname,
                port=self.host.port,
                username=self.host.username,
                auth_method=self.host.auth_method,
                password=self.host.password,
                key_path=self.host.key_path,
                passphrase=self.host.passphrase,
                connect_timeout=self.host.connect_timeout,
            )

            # asyncssh natively supports tunneling via the `tunnel` param
            if tunnel is not None:
                kwargs["tunnel"] = tunnel

            try:
                self._conn = await asyncssh.connect(**kwargs)
                self._connected = True
            except (asyncssh.Error, OSError) as e:
                self._connected = False
                # Clean up tunnel if target connection fails
                if self._tunnel_conn:
                    self._tunnel_conn.close()
                    self._tunnel_conn = None
                raise ConnectionError(
                    f"Failed to connect to {self.host.display_name}: {e}"
                ) from e

    # ── Command execution ────────────────────────────────────────

    async def execute(
        self,
        command: str,
        timeout: Optional[float] = None,
        sudo: bool = False,
        sudo_password: Optional[str] = None,
        interactive_prompts: Optional[dict[str, str]] = None,
    ) -> CommandResult:
        """
        Execute a command on this session.

        Args:
            command:              Shell command string.
            timeout:              Timeout in seconds (overrides host default).
            sudo:                 Wrap command with sudo.
            sudo_password:        Explicit sudo password (falls back to host config).
            interactive_prompts:  Dict mapping expected prompt substrings to
                                  responses, e.g. {"Continue? [y/N]": "y"}.
        """
        if not self.connected:
            return CommandResult(
                host=self.host,
                command=command,
                error="Not connected",
                success=False,
            )

        timeout = timeout or self.host.command_timeout

        # Determine the actual command to run
        actual_command, needs_stdin_password = self._prepare_command(
            command, sudo, sudo_password
        )

        start = time.monotonic()

        try:
            if interactive_prompts or needs_stdin_password:
                result = await self._execute_interactive(
                    actual_command,
                    timeout,
                    sudo_password=sudo_password or self.host.effective_sudo_password,
                    needs_sudo_password=needs_stdin_password,
                    prompts=interactive_prompts or {},
                )
            else:
                result = await self._execute_simple(actual_command, timeout)

            result.duration = time.monotonic() - start
            return result

        except asyncio.TimeoutError:
            duration = time.monotonic() - start
            return CommandResult(
                host=self.host,
                command=command,
                error=f"Command timed out after {timeout}s",
                success=False,
                duration=duration,
            )
        except (asyncssh.Error, OSError) as e:
            duration = time.monotonic() - start
            self._connected = False
            return CommandResult(
                host=self.host,
                command=command,
                error=str(e),
                success=False,
                duration=duration,
            )

    def _prepare_command(
        self,
        command: str,
        sudo: bool,
        sudo_password: Optional[str],
    ) -> tuple[str, bool]:
        """
        Wrap the command with sudo if requested.
        Returns (actual_command, needs_stdin_password).
        """
        if not sudo:
            return command, False

        password = sudo_password or self.host.effective_sudo_password

        if password:
            # Use -S to read password from stdin, -p '' to suppress the
            # default prompt (we feed the password ourselves)
            return f"sudo -S -p '' {command}", True
        else:
            # No password — assume NOPASSWD in sudoers
            return f"sudo {command}", False

    async def _execute_simple(
        self,
        command: str,
        timeout: float,
    ) -> CommandResult:
        """Run a non-interactive command."""
        result = await asyncio.wait_for(
            self._conn.run(command, check=False),
            timeout=timeout,
        )
        return CommandResult(
            host=self.host,
            command=command,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            exit_code=result.exit_status or 0,
            success=(result.exit_status == 0),
        )

    async def _execute_interactive(
        self,
        command: str,
        timeout: float,
        sudo_password: Optional[str] = None,
        needs_sudo_password: bool = False,
        prompts: Optional[dict[str, str]] = None,
    ) -> CommandResult:
        """
        Run a command that requires interactive stdin responses.

        This opens a full PTY session so that sudo and other programs
        that check for a terminal work correctly.
        """
        prompts = prompts or {}
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        async def _drive_session():
            """Interact with the remote process via a PTY channel."""
            async with self._conn.create_process(
                command,
                term_type="xterm",
                term_size=(200, 50),
                # Request a PTY so sudo and interactive programs work
            ) as proc:

                # Phase 1: feed sudo password if needed
                if needs_sudo_password and sudo_password:
                    # Give the remote process a moment to print the prompt
                    await asyncio.sleep(0.3)
                    proc.stdin.write(sudo_password + "\n")

                # Phase 2: watch stdout for interactive prompts
                while True:
                    try:
                        chunk = await asyncio.wait_for(
                            proc.stdout.read(65536),
                            timeout=2.0,
                        )
                    except asyncio.TimeoutError:
                        # No more output — check if process exited
                        if proc.exit_status is not None:
                            break
                        continue

                    if not chunk:
                        break

                    stdout_chunks.append(chunk)

                    # Check for any matching interactive prompts
                    for prompt_pattern, response in prompts.items():
                        if prompt_pattern.lower() in chunk.lower():
                            proc.stdin.write(response + "\n")

                # Drain stderr
                try:
                    remaining_err = await asyncio.wait_for(
                        proc.stderr.read(65536),
                        timeout=1.0,
                    )
                    if remaining_err:
                        stderr_chunks.append(remaining_err)
                except asyncio.TimeoutError:
                    pass

                await proc.wait()
                return proc.exit_status

        exit_code = await asyncio.wait_for(_drive_session(), timeout=timeout)
        exit_code = exit_code if exit_code is not None else -1

        full_stdout = "".join(stdout_chunks)
        full_stderr = "".join(stderr_chunks)

        # Strip the echoed sudo password line from stdout if present
        if needs_sudo_password and sudo_password:
            lines = full_stdout.splitlines(keepends=True)
            # Remove the first line if it's blank or the password echo
            if lines and lines[0].strip() == "":
                lines = lines[1:]
            full_stdout = "".join(lines)

        return CommandResult(
            host=self.host,
            command=command,
            stdout=full_stdout,
            stderr=full_stderr,
            exit_code=exit_code,
            success=(exit_code == 0),
        )

    # ── File transfer ────────────────────────────────────────────

    async def upload(self, local_path: str, remote_path: str) -> bool:
        if not self.connected:
            return False
        try:
            async with self._conn.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)
            return True
        except (asyncssh.Error, OSError):
            return False

    async def download(self, remote_path: str, local_path: str) -> bool:
        if not self.connected:
            return False
        try:
            async with self._conn.start_sftp_client() as sftp:
                await sftp.get(remote_path, local_path)
            return True
        except (asyncssh.Error, OSError):
            return False

    # ── Lifecycle ────────────────────────────────────────────────

    async def disconnect(self) -> None:
        async with self._lock:
            if self._conn:
                self._conn.close()
                await self._conn.wait_closed()
            self._conn = None

            if self._tunnel_conn:
                self._tunnel_conn.close()
                await self._tunnel_conn.wait_closed()
            self._tunnel_conn = None

            self._connected = False

    async def __aenter__(self) -> SSHSession:
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.disconnect()