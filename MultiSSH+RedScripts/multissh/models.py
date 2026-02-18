from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import time


class AuthMethod(Enum):
    KEY = "key"
    PASSWORD = "password"
    AGENT = "agent"


@dataclass
class JumpHostConfig:
    """Configuration for an SSH jump / bastion host."""
    hostname: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_path: Optional[str] = None
    passphrase: Optional[str] = None
    auth_method: AuthMethod = AuthMethod.AGENT


@dataclass
class HostConfig:
    """Configuration for a single SSH host."""
    hostname: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_path: Optional[str] = None
    passphrase: Optional[str] = None
    auth_method: AuthMethod = AuthMethod.AGENT
    connect_timeout: float = 10.0
    command_timeout: float = 30.0
    tags: list[str] = field(default_factory=list)
    label: Optional[str] = None

    # Sudo settings
    sudo_password: Optional[str] = None  # Falls back to `password` if None

    # Jump host / tunnel
    jump_host: Optional[JumpHostConfig] = None

    @property
    def display_name(self) -> str:
        return self.label or f"{self.username}@{self.hostname}:{self.port}"

    @property
    def effective_sudo_password(self) -> Optional[str]:
        return self.sudo_password or self.password


@dataclass
class CommandResult:
    """Result of executing a command on a single host."""
    host: HostConfig
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    success: bool = False
    error: Optional[str] = None
    duration: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class BatchResult:
    """Aggregated result of executing a command across multiple hosts."""
    command: str
    results: list[CommandResult] = field(default_factory=list)
    total_hosts: int = 0
    successful: int = 0
    failed: int = 0
    total_duration: float = 0.0

    def summary(self) -> dict:
        return {
            "command": self.command,
            "total": self.total_hosts,
            "successful": self.successful,
            "failed": self.failed,
            "duration": f"{self.total_duration:.2f}s",
        }