"""Human-readable response rendering."""

from datetime import datetime

from .utils import trunc


def pretty_print(result: dict, log_snippet_max: int = 120) -> str:
    if "error" in result:
        return f"ERROR: {result['error']}"

    lines = []
    subject_type = result.get("type")
    lines.append(f"Type:        {subject_type}")
    lines.append(f"Name:        {result.get('name')}")
    if result.get("url"):
        lines.append(f"URL:         {result['url']}")
    if result.get("dns_names"):
        lines.append(f"DNS Names:   {', '.join(result['dns_names'])}")

    if subject_type == "vm":
        cluster = result.get("cluster") or {}
        if cluster:
            line = (
                f"Cluster:     {cluster.get('name')}"
                if cluster.get("name")
                else "Cluster:     (unknown)"
            )
            if cluster.get("fqdn"):
                line += f" (fqdn: {cluster['fqdn']})"
            if cluster.get("url"):
                line += f"\n             {cluster['url']}"
            lines.append(line)
        if result.get("host_device"):
            line = f"Host Device: {result['host_device']}"
            if result.get("host_device_url"):
                line += f"\n             {result['host_device_url']}"
            lines.append(line)

    if subject_type == "device":
        if result.get("role"):
            lines.append(f"Device Role: {result.get('role')}")
        if result.get("site"):
            lines.append(f"Site:        {result['site']}")

    if subject_type in ("vm", "device"):
        rack = result.get("rack") or {}
        if rack.get("rack"):
            lines.append(
                f"Rack:        {rack['rack']} "
                f"(pos {rack.get('rack_position')}, face: {rack.get('rack_face')})"
            )

    if result.get("primary_ip4") or result.get("primary_ip6"):
        lines.append(
            f"Primary IPs: IPv4={result.get('primary_ip4')}, "
            f"IPv6={result.get('primary_ip6')}"
        )

    if result.get("ips"):
        lines += ["", "IPs:"]
        for ip in result["ips"]:
            line = f"  - {ip['address']}"
            if ip.get("family"):
                line += f" ({ip['family']})"
            if ip.get("dns_name"):
                line += f" dns: {ip['dns_name']}"
            if ip.get("description"):
                line += f" - {ip['description']}"
            lines.append(line)

    if result.get("mac_addresses"):
        lines += ["", "MAC Addresses:"]
        lines.extend(f"  - {mac}" for mac in result["mac_addresses"])

    if result.get("interfaces"):
        lines += ["", "Interfaces:"]
        for iface in result["interfaces"]:
            line = f"  - {iface['name']}"
            if iface.get("mac_address"):
                line += f" (MAC {iface['mac_address']})"
            if iface.get("enabled") is not None:
                line += f", enabled={iface['enabled']}"
            if iface.get("mtu"):
                line += f", mtu={iface['mtu']}"
            lines.append(line)

    if subject_type == "device":
        _append_device_sections(lines, result)

    if subject_type == "cluster":
        _append_cluster_section(lines, result)

    if result.get("logs"):
        lines += ["", "Logs (latest 5):"]
        for entry in result["logs"]:
            timestamp = entry.get("created")
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).strftime(
                    "%Y-%m-%d %H:%M:%S %z"
                )
            except Exception:
                pass
            body = entry.get("message") or f"{entry.get('source') or ''} event"
            snippet = trunc(body, log_snippet_max)
            who = f" by {entry.get('user')}" if entry.get("user") else ""
            lines.append(f"  - [{timestamp}] {snippet}{who}")

    if result.get("created") or result.get("last_updated"):
        lines.append("")
        lines.append(f"Created:     {result.get('created')}")
        lines.append(f"Updated:     {result.get('last_updated')}")

    return "\n".join(lines)


def _append_device_sections(lines: list[str], result: dict) -> None:
    if result.get("clusters"):
        lines += ["", "Clusters:"]
        for cluster in result["clusters"]:
            line = f"  - {cluster.get('name')}"
            if cluster.get("fqdn"):
                line += f" (fqdn: {cluster['fqdn']})"
            if cluster.get("url"):
                line += f"\n             {cluster['url']}"
            lines.append(line)

    if result.get("hosted_vms"):
        lines += ["", f"Hosted VMs:  {len(result['hosted_vms'])}"]
        for vm in result["hosted_vms"]:
            line = f"  - {vm.get('name')}"
            if vm.get("dns_name"):
                line += f" ({vm['dns_name']})"
            if vm.get("url"):
                line += f"\n             {vm['url']}"
            cluster = vm.get("cluster") or {}
            if cluster.get("name"):
                line += f"\n             cluster: {cluster['name']}"
                if cluster.get("fqdn"):
                    line += f" (fqdn: {cluster['fqdn']})"
            lines.append(line)


def _append_cluster_section(lines: list[str], result: dict) -> None:
    if result.get("fqdn"):
        lines.append(f"FQDN:        {result['fqdn']}")
    if result.get("site"):
        lines.append(f"Site:        {result['site']}")
    lines.append(f"VM count:    {result.get('vm_count')}")
    if result.get("vms"):
        lines += ["", "VMs:"]
        for vm in result["vms"]:
            line = f"  - {vm.get('name')}"
            if vm.get("dns_name"):
                line += f" ({vm['dns_name']})"
            if vm.get("url"):
                line += f"\n             {vm['url']}"
            lines.append(line)
