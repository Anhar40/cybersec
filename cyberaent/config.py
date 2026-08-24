from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


class ConfigError(RuntimeError):
    pass


def load_dotenv(path: str | Path = ".env", environ: dict[str, str] | None = None) -> None:
    """Populate an environment mapping from a .env file without overriding existing vars."""
    p = Path(path)
    if not p.is_file():
        return
    env = os.environ if environ is None else environ
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            env.setdefault(key, value)


def _float_env(env: Mapping[str, str], name: str, default: float) -> float:
    try:
        return float(env[name].strip())
    except (KeyError, ValueError):
        return default


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    try:
        return int(env[name].strip())
    except (KeyError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    api_key: str
    model: str
    base_url: str = DEFAULT_BASE_URL
    request_timeout: float = 120.0
    connect_timeout: float = 15.0
    max_retries: int = 3

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if environ is None else environ

        api_key = env.get("OPENROUTER_API_KEY", "").strip()
        if not api_key:
            raise ConfigError(
                "OPENROUTER_API_KEY is not set.\n"
                "Set it in your environment or in a .env file "
                "(see .env.example)."
            )

        model = env.get("OPENROUTER_MODEL", "").strip()
        if not model:
            raise ConfigError(
                "OPENROUTER_MODEL is not set.\n"
                "Set it to any OpenRouter model id, e.g. "
                "'openai/gpt-4o-mini' or 'anthropic/claude-3.5-sonnet'."
            )

        base_url = env.get("OPENROUTER_BASE_URL", "").strip() or DEFAULT_BASE_URL

        return cls(
            api_key=api_key,
            model=model,
            base_url=base_url.rstrip("/"),
            request_timeout=_float_env(env, "OPENROUTER_TIMEOUT_SECONDS", 120.0),
            connect_timeout=15.0,
            max_retries=max(0, _int_env(env, "OPENROUTER_MAX_RETRIES", 3)),
        )
