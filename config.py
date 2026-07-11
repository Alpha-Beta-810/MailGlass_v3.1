"""
config.py
----------
Centralized configuration, replacing scattered hardcoded values and
module-level ``os.getenv()`` calls.

Precedence (lowest to highest): built-in defaults -> ``config.json`` (if
present) -> environment variables -> explicit CLI flags.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "config.json"

# Maps ENV_VAR_NAME -> Settings attribute name.
_ENV_VAR_MAP = {
    "EMAILS_DIR": "emails_dir",
    "WHITELIST_FILE": "whitelist_file",
    "MODEL_PATH": "model_path",
    "ATTACHMENTS_DIR": "attachments_dir",
    "RESOLVE_REDIRECTS": "resolve_redirects",
    "CHECK_DOMAIN_AGE": "check_domain_age",
    "PHISHTANK_API_KEY": "phishtank_api_key",
    "VIRUSTOTAL_API_KEY": "virustotal_api_key",
    "OUTPUT_CSV": "output_csv",
    "OUTPUT_JSON": "output_json",
    "LOG_LEVEL": "log_level",
}

_TRUE_STRINGS = {"1", "true", "yes", "on"}


@dataclass
class Settings:
    """All tunable knobs for a single run of the detector."""

    emails_dir: str = "emails"
    whitelist_file: str = "whitelist.json"
    model_path: str = "phishing_email_model_fixed.pkl"
    attachments_dir: str = "attachments"
    resolve_redirects: bool = False
    check_domain_age: bool = False
    phishtank_api_key: str = ""
    virustotal_api_key: str = ""
    output_csv: Optional[str] = None
    output_json: Optional[str] = None
    log_level: str = "INFO"

    def as_dict(self) -> dict:
        return asdict(self)


def _load_json_overrides(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read config file %s (%s); ignoring it.", path, exc)
        return {}


def _coerce(value: str, current: object) -> object:
    """Coerce a string env-var value to match the type of the current default."""
    if isinstance(current, bool):
        return str(value).strip().lower() in _TRUE_STRINGS
    return value


def load_settings(config_path: str = DEFAULT_CONFIG_PATH, cli_overrides: Optional[dict] = None) -> Settings:
    """Build a :class:`Settings` instance from defaults, config file, env, and CLI.

    Args:
        config_path: Path to an optional JSON config file.
        cli_overrides: Dict of explicit CLI-flag values; any key with a
            non-None value wins over everything else.

    Returns:
        A fully-resolved Settings instance.
    """
    settings = Settings()

    for key, value in _load_json_overrides(config_path).items():
        if hasattr(settings, key):
            setattr(settings, key, value)

    for env_var, attr in _ENV_VAR_MAP.items():
        raw = os.getenv(env_var)
        if raw is None:
            continue
        setattr(settings, attr, _coerce(raw, getattr(settings, attr)))

    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None and hasattr(settings, key):
                setattr(settings, key, value)

    return settings
