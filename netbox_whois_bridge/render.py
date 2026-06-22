"""Human-readable response rendering."""

from datetime import datetime
from typing import Any, Optional

from .utils import trunc


ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
}


class Palette:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def paint(self, value: Any, style: str) -> str:
        text = str(value)
        if not self.enabled:
            return text
        return f"{ANSI[style]}{text}{ANSI['reset']}"

    def heading(self, value: Any) -> str:
        return self.paint(value, "bold")

    def label(self, value: Any) -> str:
        return self.paint(value, "cyan")

    def muted(self, value: Any) -> str:
        return self.paint(value, "dim")

    def url(self, value: Any) -> str:
        return self.paint(value, "blue")

    def ok(self, value: Any) -> str:
        return self.paint(value, "green")

    def warn(self, value: Any) -> str:
        return self.paint(value, "yellow")

    def error(self, value: Any) -> str:
        return self.paint(value, "red")


def pretty_print(result: dict, log_snippet_max: int = 120, color: bool = False) -> str:
    palette = Palette(color)
    if "error" in result:
        return f"{palette.error('ERROR')}: {result['error']}"

    lines: list[str] = []
    subject_type = result.get("type") or "object"
    name = result.get("name") or "(unnamed)"

    lines.append(f"{palette.heading(subject_type.upper())} {palette.heading(name)}")
    if result.get("url"):
        lines.append(f"{palette.label('URL')}        {palette.url(result['url'])}")
    if result.get("dns_names"):
        lines.append(f"{palette.label('DNS')}        {', '.join(result['dns_names'])}")

    summary = _summary_line(result)
    if summary:
        lines.append(f"{palette.label('Summary')}    {summary}")

    if subject_type == "vm":
        _append_vm_sections(lines, result, palette)
    elif subject_type == "device":
        _append_device_sections(lines, result, palette)
    elif subject_type == "cluster":
        _append_cluster_section(lines, result, palette)

    _append_network(lines, result, palette)
    _append_interfaces(lines, result, palette)
    _append_logs(lines, result, palette, log_snippet_max)
    _append_timestamps(lines, result, palette)

    return "\n".join(lines)


def _summary_line(result: dict) -> Optional[str]:
    subject_type = result.get("type")
    if subject_type == "vm":
        parts = []
        cluster = result.get("cluster") or {}
        if cluster.get("name"):
            parts.append(f"cluster {cluster['name']}")
        if result.get("host_device"):
            parts.append(f"host {result['host_device']}")
        rack = result.get("rack") or {}
        if rack.get("rack"):
            rack_text = f"rack {rack['rack']}"
            if rack.get("rack_position") is not None:
                rack_text += f" U{_format_position(rack['rack_position'])}"
            if rack.get("rack_face"):
                rack_text += f" {rack['rack_face']}"
            parts.append(rack_text)
        return " | ".join(parts) or None

    if subject_type == "device":
        parts = []
        if result.get("role"):
            parts.append(result["role"])
        if result.get("site"):
            parts.append(f"site {result['site']}")
        rack = result.get("rack") or {}
        if rack.get("rack"):
            parts.append(f"rack {rack['rack']}")
        return " | ".join(parts) or None

    if subject_type == "cluster":
        parts = []
        if result.get("fqdn"):
            parts.append(result["fqdn"])
        if result.get("site"):
            parts.append(f"site {result['site']}")
        if result.get("vm_count") is not None:
            parts.append(f"{result['vm_count']} VMs")
        return " | ".join(parts) or None

    return None


def _append_vm_sections(lines: list[str], result: dict, palette: Palette) -> None:
    cluster = result.get("cluster") or {}
    if cluster.get("name") or cluster.get("fqdn") or cluster.get("url"):
        lines += ["", palette.heading("Cluster")]
        _append_field(lines, palette, "Name", cluster.get("name"))
        _append_field(lines, palette, "FQDN", cluster.get("fqdn"))
        _append_field(lines, palette, "URL", cluster.get("url"), is_url=True)

    if result.get("host_device") or result.get("host_device_url"):
        lines += ["", palette.heading("Host")]
        _append_field(lines, palette, "Device", result.get("host_device"))
        _append_field(lines, palette, "URL", result.get("host_device_url"), is_url=True)

    rack = result.get("rack") or {}
    if any(rack.get(key) is not None for key in ("rack", "rack_position", "rack_face", "site", "location")):
        lines += ["", palette.heading("Placement")]
        _append_field(lines, palette, "Rack", rack.get("rack"))
        _append_field(lines, palette, "Position", _format_position(rack.get("rack_position")))
        _append_field(lines, palette, "Face", rack.get("rack_face"))
        _append_field(lines, palette, "Site", rack.get("site"))
        _append_field(lines, palette, "Location", rack.get("location"))


def _append_device_sections(lines: list[str], result: dict, palette: Palette) -> None:
    lines += ["", palette.heading("Device")]
    _append_field(lines, palette, "Role", result.get("role"))
    _append_field(lines, palette, "Site", result.get("site"))
    _append_field(lines, palette, "Location", result.get("location"))
    _append_field(lines, palette, "Platform", result.get("platform"))
    _append_field(lines, palette, "Tenant", result.get("tenant"))

    rack = result.get("rack") or {}
    if rack.get("rack"):
        lines += ["", palette.heading("Placement")]
        _append_field(lines, palette, "Rack", rack.get("rack"))
        _append_field(lines, palette, "Position", _format_position(rack.get("rack_position")))
        _append_field(lines, palette, "Face", rack.get("rack_face"))

    if result.get("clusters"):
        lines += ["", palette.heading("Clusters")]
        for cluster in result["clusters"]:
            detail = []
            if cluster.get("fqdn"):
                detail.append(f"fqdn {cluster['fqdn']}")
            lines.append(_bullet(palette, cluster.get("name"), detail, cluster.get("url")))

    if result.get("hosted_vms"):
        lines += ["", palette.heading(f"Hosted VMs ({len(result['hosted_vms'])})")]
        for vm in result["hosted_vms"]:
            detail = []
            if vm.get("dns_name"):
                detail.append(vm["dns_name"])
            cluster = vm.get("cluster") or {}
            if cluster.get("name"):
                detail.append(f"cluster {cluster['name']}")
            lines.append(_bullet(palette, vm.get("name"), detail, vm.get("url")))


def _append_cluster_section(lines: list[str], result: dict, palette: Palette) -> None:
    lines += ["", palette.heading("Cluster")]
    _append_field(lines, palette, "FQDN", result.get("fqdn"))
    _append_field(lines, palette, "Site", result.get("site"))
    _append_field(lines, palette, "VMs", result.get("vm_count"))

    if result.get("vms"):
        lines += ["", palette.heading("Virtual Machines")]
        for vm in result["vms"]:
            detail = [vm["dns_name"]] if vm.get("dns_name") else []
            lines.append(_bullet(palette, vm.get("name"), detail, vm.get("url")))


def _append_network(lines: list[str], result: dict, palette: Palette) -> None:
    if not any((result.get("primary_ip4"), result.get("primary_ip6"), result.get("ips"), result.get("mac_addresses"))):
        return

    lines += ["", palette.heading("Network")]
    _append_field(lines, palette, "Primary IPv4", result.get("primary_ip4"))
    _append_field(lines, palette, "Primary IPv6", result.get("primary_ip6"))

    if result.get("ips"):
        lines.append(f"{palette.label('Addresses')}")
        for ip in result["ips"]:
            detail = []
            if ip.get("family"):
                detail.append(ip["family"])
            if ip.get("dns_name"):
                detail.append(f"dns {ip['dns_name']}")
            if ip.get("description"):
                detail.append(ip["description"])
            lines.append(_bullet(palette, ip.get("address"), detail))

    if result.get("mac_addresses"):
        lines.append(f"{palette.label('MACs')}")
        for mac in result["mac_addresses"]:
            lines.append(_bullet(palette, mac))


def _append_interfaces(lines: list[str], result: dict, palette: Palette) -> None:
    if not result.get("interfaces"):
        return

    lines += ["", palette.heading(f"Interfaces ({len(result['interfaces'])})")]
    for iface in result["interfaces"]:
        detail = []
        if iface.get("mac_address"):
            detail.append(f"MAC {iface['mac_address']}")
        if iface.get("enabled") is not None:
            status = palette.ok("enabled") if iface.get("enabled") else palette.warn("disabled")
            detail.append(status)
        if iface.get("mtu"):
            detail.append(f"mtu {iface['mtu']}")
        if iface.get("description"):
            detail.append(iface["description"])
        lines.append(_bullet(palette, iface.get("name"), detail))


def _append_logs(lines: list[str], result: dict, palette: Palette, log_snippet_max: int) -> None:
    if not result.get("logs"):
        return

    lines += ["", palette.heading("Logs")]
    for entry in result["logs"]:
        timestamp = _format_timestamp(entry.get("created"))
        body = entry.get("message") or f"{entry.get('source') or ''} event"
        snippet = trunc(body, log_snippet_max)
        who = f" by {entry.get('user')}" if entry.get("user") else ""
        lines.append(f"  - {palette.muted(timestamp)} {snippet}{who}")


def _append_timestamps(lines: list[str], result: dict, palette: Palette) -> None:
    if not result.get("created") and not result.get("last_updated"):
        return

    lines += ["", palette.heading("Lifecycle")]
    _append_field(lines, palette, "Created", _format_timestamp(result.get("created")))
    _append_field(lines, palette, "Updated", _format_timestamp(result.get("last_updated")))


def _append_field(
    lines: list[str],
    palette: Palette,
    label: str,
    value: Any,
    is_url: bool = False,
) -> None:
    if value is None or value == "":
        return
    rendered = palette.url(value) if is_url else str(value)
    lines.append(f"  {_label(palette, label)} {rendered}")


def _bullet(
    palette: Palette,
    value: Any,
    detail: Optional[list[str]] = None,
    url: Optional[str] = None,
) -> str:
    text = f"  - {value or '(unnamed)'}"
    if detail:
        text += f" ({', '.join(detail)})"
    if url:
        text += f"\n    {palette.url(url)}"
    return text


def _label(palette: Palette, label: str, width: int = 17) -> str:
    raw = f"{label}:"
    padding = " " * max(1, width - len(raw))
    return f"{palette.label(raw)}{padding}"


def _format_timestamp(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return timestamp.strftime("%Y-%m-%d %H:%M:%S %z")
    except Exception:
        return value


def _format_position(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value
