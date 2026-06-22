"""Small shared helpers for extracting and formatting NetBox data."""

import ipaddress
from typing import Any, Optional


def clean(value: str) -> str:
    return (value or "").strip().rstrip(".")


def trunc(value: Optional[str], length: int) -> Optional[str]:
    if not value:
        return value
    return value if len(value) <= length else value[: max(0, length - 1)] + "..."


def extract_name(ref: Any) -> Optional[str]:
    if isinstance(ref, dict):
        return ref.get("name") or ref.get("display") or ref.get("label")
    if isinstance(ref, (str, int, float)):
        return str(ref)
    return None


def extract_label_or_value(ref: Any) -> Optional[str]:
    if isinstance(ref, dict):
        return ref.get("label") or ref.get("name") or ref.get("display") or ref.get("value")
    if isinstance(ref, (str, int, float)):
        return str(ref)
    return None


def is_ip_like(query: str) -> bool:
    try:
        ipaddress.ip_network(query.strip(), strict=False)
        return True
    except ValueError:
        return False


def normalize_ip_query(query: str) -> list[str]:
    query = query.strip()
    candidates = [query]
    try:
        ip = ipaddress.ip_address(query)
        candidates.append(f"{query}/32" if ip.version == 4 else f"{query}/128")
    except ValueError:
        pass
    return list(dict.fromkeys(candidates))
