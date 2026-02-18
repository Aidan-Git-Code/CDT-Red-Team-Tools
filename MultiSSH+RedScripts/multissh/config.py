from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Any

import yaml

from .models import HostConfig, JumpHostConfig, AuthMethod


_ENV_VAR_PATTERN = re.compile(r"\$\{(\w+)\}")


def _resolve_env_vars(value: Any) -> Any:
    """Replace ${VAR_NAME} with environment variable values."""
    if not isinstance(value, str):
        return value
    def _replacer(match):
        var_name = match.group(1)
        env_val = os.environ.get(var_name)
        if env_val is None:
            raise ValueError(
                f"Environment variable '{var_name}' is not set "
                f"(referenced in config)"
            )
        return env_val
    return _ENV_VAR_PATTERN.sub(_replacer, value)


def _resolve_dict(d: dict) -> dict:
    """Recursively resolve env vars in a dict."""
    return {k: _resolve_env_vars(v) if isinstance(v, str) else v for k, v in d.items()}


def _parse_jump_host(entry: dict) -> JumpHostConfig | None:
    """Extract jump host config from a host entry if present."""
    jh_hostname = entry.get("jump_host")
    if not jh_hostname:
        return None

    return JumpHostConfig(
        hostname=jh_hostname,
        port=int(entry.get("jump_port", 22)),
        username=entry.get("jump_username", "root"),
        password=entry.get("jump_password"),
        key_path=entry.get("jump_key_path"),
        passphrase=entry.get("jump_passphrase"),
        auth_method=AuthMethod(entry.get("jump_auth_method", "agent")),
    )


def load_config(path: str | Path) -> list[HostConfig]:
    """Load host configurations from a YAML file."""
    path = Path(path)
    with open(path) as f:
        data = yaml.safe_load(f)

    hosts: list[HostConfig] = []
    defaults: dict[str, Any] = data.get("defaults", {})

    for entry in data.get("hosts", []):
        merged = _resolve_dict({**defaults, **entry})
        jump = _parse_jump_host(merged)

        hosts.append(
            HostConfig(
                hostname=merged["hostname"],
                port=int(merged.get("port", 22)),
                username=merged.get("username", "root"),
                password=merged.get("password"),
                key_path=merged.get("key_path"),
                passphrase=merged.get("passphrase"),
                auth_method=AuthMethod(merged.get("auth_method", "agent")),
                connect_timeout=float(merged.get("connect_timeout", 10.0)),
                command_timeout=float(merged.get("command_timeout", 30.0)),
                tags=merged.get("tags", []),
                label=merged.get("label"),
                sudo_password=merged.get("sudo_password"),
                jump_host=jump,
            )
        )

    return hosts


def load_inventory_from_file(path: str | Path) -> list[HostConfig]:
    """
    Load a simple hosts file (one host per line).
    Format: hostname[:port] [user] [key_path_or_password]
    """
    hosts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            host_part = parts[0]

            hostname, _, port_str = host_part.partition(":")
            port = int(port_str) if port_str else 22

            hosts.append(
                HostConfig(
                    hostname=hostname,
                    port=port,
                    username=parts[1] if len(parts) > 1 else "root",
                    key_path=parts[2] if len(parts) > 2 else None,
                    auth_method=AuthMethod.KEY if len(parts) > 2 else AuthMethod.AGENT,
                )
            )

    return hosts