"""
Settings loaded from environment variables (and an optional .env file).

Every setting has a safe default; in particular the agent starts in dry-run
mode and never auto-blocks unless explicitly enabled. See .env.example for
the full list.
"""

import ipaddress
import logging
import os
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _parse_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError(f"expected one of {sorted(_TRUE | _FALSE)}")


def _parse_list(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass
class Settings:
    """Runtime configuration for SOCAgent and the API server."""

    # Response behavior (safe defaults: observe only)
    dry_run: bool = True
    auto_block_critical: bool = False

    # Alerting
    slack_webhook: Optional[str] = None
    webhook_urls: List[str] = field(default_factory=list)
    alert_cooldown_seconds: float = 300.0

    # Blocking
    allowlist: List[str] = field(default_factory=list)
    blocklist_file: Optional[str] = None

    # Detection
    model_path: Optional[str] = None
    thresholds: Dict[str, float] = field(default_factory=dict)

    # Logging
    log_level: str = "INFO"

    # API server
    api_host: str = "127.0.0.1"  # local only by default
    api_port: int = 8000
    max_upload_mb: int = 500
    api_key: Optional[str] = None  # required unless bound to loopback
    cors_origins: List[str] = field(default_factory=list)
    cors_origin_regex: Optional[str] = None

    MIN_API_KEY_LENGTH = 32

    @property
    def api_is_local_only(self) -> bool:
        """True if the API binds to a loopback address only."""
        if self.api_host == "localhost":
            return True
        try:
            return ipaddress.ip_address(self.api_host).is_loopback
        except ValueError:
            return False

    def validate_api_security(self) -> None:
        """
        Refuse insecure API configurations at startup.

        Raises:
            ValueError: If the API would be reachable without a key, the key
                is too short, or a CORS origin is not a plain https origin
        """
        if self.api_key is None and not self.api_is_local_only:
            raise ValueError(
                f"SOC_API_HOST={self.api_host} accepts remote connections but "
                f"SOC_API_KEY is not set. Set an API key (e.g. "
                f"`python -c \"import secrets; print(secrets.token_urlsafe(32))\"`) "
                f"or bind to 127.0.0.1."
            )
        if self.api_key is not None and len(self.api_key) < self.MIN_API_KEY_LENGTH:
            raise ValueError(
                f"SOC_API_KEY must be at least {self.MIN_API_KEY_LENGTH} characters"
            )
        for origin in self.cors_origins:
            parts = urlsplit(origin)
            local = parts.hostname in ("localhost", "127.0.0.1")
            if (origin == "*" or parts.path not in ("", "/") or not parts.hostname
                    or not (parts.scheme == "https" or (parts.scheme == "http" and local))):
                raise ValueError(
                    f"Invalid SOC_CORS_ORIGINS entry {origin!r}: use exact origins "
                    f"like https://my-dashboard.vercel.app (http only for localhost)"
                )

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        """
        Build settings from environment variables.

        Args:
            env: Mapping to read from (defaults to os.environ)

        Returns:
            Settings instance

        Raises:
            ValueError: If a variable has an invalid value (the message
                names the variable)
        """
        env = os.environ if env is None else env

        def get(name: str, parse: Callable[[str], T], default: T) -> T:
            raw = env.get(name)
            if raw is None or raw.strip() == "":
                return default
            try:
                return parse(raw)
            except ValueError as e:
                raise ValueError(f"Invalid value for {name}={raw!r}: {e}") from None

        thresholds = {}
        for level in ("MEDIUM", "HIGH", "CRITICAL"):
            value = get(f"SOC_THRESHOLD_{level}", float, None)
            if value is not None:
                thresholds[level] = value

        log_level = get("SOC_LOG_LEVEL", str, "INFO").strip().upper()
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"Invalid value for SOC_LOG_LEVEL={log_level!r}")

        cooldown = get("SOC_ALERT_COOLDOWN_SECONDS", float, 300.0)
        if cooldown < 0:
            raise ValueError("SOC_ALERT_COOLDOWN_SECONDS must be >= 0")

        api_port = get("SOC_API_PORT", int, 8000)
        if not 0 < api_port < 65536:
            raise ValueError("SOC_API_PORT must be between 1 and 65535")
        max_upload_mb = get("SOC_MAX_UPLOAD_MB", int, 500)
        if max_upload_mb <= 0:
            raise ValueError("SOC_MAX_UPLOAD_MB must be > 0")

        return cls(
            dry_run=get("SOC_DRY_RUN", _parse_bool, True),
            auto_block_critical=get("SOC_AUTO_BLOCK_CRITICAL", _parse_bool, False),
            slack_webhook=get("SLACK_WEBHOOK_URL", str.strip, None),
            webhook_urls=get("SOC_WEBHOOK_URLS", _parse_list, []),
            alert_cooldown_seconds=cooldown,
            allowlist=get("BLOCK_ALLOWLIST", _parse_list, []),
            blocklist_file=get("BLOCKLIST_FILE", str.strip, None),
            model_path=get("SOC_MODEL_PATH", str.strip, None),
            thresholds=thresholds,
            log_level=log_level,
            api_host=get("SOC_API_HOST", str.strip, "127.0.0.1"),
            api_port=api_port,
            max_upload_mb=max_upload_mb,
            api_key=get("SOC_API_KEY", str.strip, None),
            cors_origins=[o.rstrip("/") for o in get("SOC_CORS_ORIGINS", _parse_list, [])],
            cors_origin_regex=get("SOC_CORS_ORIGIN_REGEX", str.strip, None),
        )

    def describe(self) -> Dict[str, object]:
        """Settings summary safe to log or show in a UI (no secrets)."""
        return {
            "dry_run": self.dry_run,
            "auto_block_critical": self.auto_block_critical,
            "slack_configured": bool(self.slack_webhook),
            "webhook_count": len(self.webhook_urls),
            "alert_cooldown_seconds": self.alert_cooldown_seconds,
            "allowlist": list(self.allowlist),
            "blocklist_file": self.blocklist_file,
            "model_path": self.model_path,
            "thresholds": dict(self.thresholds),
            "log_level": self.log_level,
            "max_upload_mb": self.max_upload_mb,
            "api_key_configured": self.api_key is not None,
            "cors_origins": list(self.cors_origins),
        }


def load_settings(env_file: Optional[str] = ".env") -> Settings:
    """
    Load settings, first reading env_file if python-dotenv is installed.

    Variables already set in the real environment take precedence over the
    file, so deployments can override individual values.

    Args:
        env_file: Path to a .env file, or None to skip

    Returns:
        Settings instance
    """
    if env_file and os.path.isfile(env_file):
        try:
            from dotenv import load_dotenv
        except ImportError:
            logger.warning(f"Found {env_file} but python-dotenv is not installed; ignoring it")
        else:
            load_dotenv(env_file, override=False)
    return Settings.from_env()
