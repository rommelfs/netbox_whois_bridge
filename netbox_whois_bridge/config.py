"""Runtime configuration loaded from environment variables."""

from dataclasses import dataclass
from typing import Mapping, Optional


class ConfigError(ValueError):
    """Raised when environment configuration is invalid."""


def env_bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def env_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    min_value: Optional[int] = None,
) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if min_value is not None and value < min_value:
        raise ConfigError(f"{name} must be >= {min_value}")
    return value


@dataclass(frozen=True)
class Config:
    netbox_url: str
    netbox_token: str
    netbox_verify: bool
    whois_bind: str
    whois_port: int
    whois_verbose: bool
    whois_verbose_inband: bool
    whois_show_errors: bool
    whois_output: str
    cluster_fqdn_cf_keys: list[str]
    cluster_fqdn_suffix: str
    log_snippet_max: int
    http_timeout: int
    cache_ttl: int
    whois_max_workers: int
    whois_max_query_bytes: int
    whois_client_timeout: int

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Config":
        output = env.get("WHOIS_OUTPUT", "table").lower()
        if output not in ("table", "json"):
            raise ConfigError("WHOIS_OUTPUT must be 'table' or 'json'")

        keys = [
            item.strip()
            for item in env.get(
                "CLUSTER_FQDN_CF_KEYS",
                "dns_name,fqdn,cluster_dns,hostname",
            ).split(",")
            if item.strip()
        ]

        return cls(
            netbox_url=env.get("NETBOX_URL", "").rstrip("/"),
            netbox_token=env.get("NETBOX_TOKEN", ""),
            netbox_verify=env_bool(env, "NETBOX_VERIFY", True),
            whois_bind=env.get("WHOIS_BIND", "0.0.0.0"),
            whois_port=env_int(env, "WHOIS_PORT", 43, 1),
            whois_verbose=env_bool(env, "WHOIS_VERBOSE", False),
            whois_verbose_inband=env_bool(env, "WHOIS_VERBOSE_INBAND", False),
            whois_show_errors=env_bool(env, "WHOIS_SHOW_ERRORS", False),
            whois_output=output,
            cluster_fqdn_cf_keys=keys,
            cluster_fqdn_suffix=env.get("CLUSTER_FQDN_SUFFIX", "").strip(),
            log_snippet_max=env_int(env, "LOG_SNIPPET_MAX", 120, 1),
            http_timeout=env_int(env, "HTTP_TIMEOUT", 15, 1),
            cache_ttl=env_int(env, "CACHE_TTL", 60, 0),
            whois_max_workers=env_int(env, "WHOIS_MAX_WORKERS", 20, 1),
            whois_max_query_bytes=env_int(env, "WHOIS_MAX_QUERY_BYTES", 8192, 64),
            whois_client_timeout=env_int(env, "WHOIS_CLIENT_TIMEOUT", 30, 1),
        )

    def validate_required(self) -> None:
        if not self.netbox_url or not self.netbox_token:
            raise ConfigError("set NETBOX_URL and NETBOX_TOKEN")
