from __future__ import annotations

import pytest

from cyberaent.config import DEFAULT_BASE_URL, ConfigError, Settings, load_dotenv

BASE = {"OPENROUTER_API_KEY": "test-key", "OPENROUTER_MODEL": "test-model"}


def test_missing_api_key_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        Settings.from_env({"OPENROUTER_MODEL": "m"})
    assert "OPENROUTER_API_KEY" in str(exc.value)


def test_missing_model_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        Settings.from_env({"OPENROUTER_API_KEY": "k"})
    assert "OPENROUTER_MODEL" in str(exc.value)


def test_defaults() -> None:
    settings = Settings.from_env(BASE)
    assert settings.api_key == "test-key"
    assert settings.model == "test-model"
    assert settings.base_url == DEFAULT_BASE_URL
    assert settings.request_timeout == 120.0
    assert settings.max_retries == 3


def test_overrides_and_strips_base_url() -> None:
    env = {
        **BASE,
        "OPENROUTER_BASE_URL": "https://proxy.example/v1/",
        "OPENROUTER_TIMEOUT_SECONDS": "30",
        "OPENROUTER_MAX_RETRIES": "1",
    }
    settings = Settings.from_env(env)
    assert settings.base_url == "https://proxy.example/v1"
    assert settings.request_timeout == 30.0
    assert settings.max_retries == 1


def test_invalid_numeric_overrides_fall_back() -> None:
    env = {**BASE, "OPENROUTER_TIMEOUT_SECONDS": "abc", "OPENROUTER_MAX_RETRIES": "-5"}
    settings = Settings.from_env(env)
    assert settings.request_timeout == 120.0
    assert settings.max_retries == 0


def test_load_dotenv_parses_and_preserves_existing(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "DOTENV_A=hello world",
                'DOTENV_B="quoted value"',
                "DOTENV_C=existing",  # must not override pre-set value below
            ]
        ),
        encoding="utf-8",
    )
    environ: dict[str, str] = {"DOTENV_C": "preset"}
    load_dotenv(env_file, environ)
    assert environ["DOTENV_A"] == "hello world"
    assert environ["DOTENV_B"] == "quoted value"
    assert environ["DOTENV_C"] == "preset"


def test_load_dotenv_missing_file_is_noop() -> None:
    environ: dict[str, str] = {}
    load_dotenv("does-not-exist.env", environ)
    assert environ == {}
