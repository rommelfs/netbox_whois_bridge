"""Resolve WHOIS queries into structured VM, device, or cluster data."""

import json
from typing import Optional

from .config import Config
from .netbox import HTTPError, NetBoxClient
from .utils import extract_label_or_value, extract_name, is_ip_like, normalize_ip_query, clean


TYPE_MAP = {
    "vm": "virtualization.virtualmachine",
    "device": "dcim.device",
    "cluster": "virtualization.cluster",
}


class Resolver:
    def __init__(self, config: Config, client: NetBoxClient):
        self.config = config
        self.client = client

    def cluster_fqdn(self, cluster: dict, dbg: Optional[list[str]] = None) -> Optional[str]:
        custom_fields = cluster.get("custom_fields") or {}
        for key in self.config.cluster_fqdn_cf_keys:
            value = custom_fields.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        name = (cluster.get("name") or "").strip()
        if not name:
            return None
        if "." in name:
            return name
        discovered = self.cluster_fqdn_from_ipam(name, dbg)
        if discovered:
            return discovered
        if self.config.cluster_fqdn_suffix:
            suffix = self.config.cluster_fqdn_suffix
            return f"{name}{suffix if suffix.startswith('.') else '.' + suffix}"
        return None

    def cluster_fqdn_from_ipam(self, name: str, dbg: Optional[list[str]]) -> Optional[str]:
        try:
            ips = self.client.paged_get(
                "/api/ipam/ip-addresses/",
                {"q": name, "limit": 20},
                dbg,
            )
        except HTTPError:
            return None

        candidates = []
        for ip in ips:
            dns_name = (ip.get("dns_name") or "").strip().rstrip(".")
            if "." in dns_name:
                candidates.append(dns_name)
        if not candidates:
            return None

        lowered = name.lower()
        for dns_name in candidates:
            if dns_name.split(".", 1)[0].lower() == lowered:
                return dns_name
        return None

    def ipam_find_ips_by_dns(self, dns: str, dbg: list[str]) -> list[dict]:
        return self.client.paged_get("/api/ipam/ip-addresses/", {"dns_name": dns}, dbg)

    def ipam_find_ips_by_address(self, query: str, dbg: list[str]) -> list[dict]:
        ips: list[dict] = []
        for candidate in normalize_ip_query(query):
            try:
                data = self.client.api_get(
                    "/api/ipam/ip-addresses/",
                    {"address": candidate, "limit": 50},
                    dbg,
                )
                ips += data.get("results", [])
            except HTTPError:
                pass

        if not ips:
            try:
                data = self.client.api_get(
                    "/api/ipam/ip-addresses/",
                    {"q": query, "limit": 50},
                    dbg,
                )
                ips += data.get("results", [])
            except HTTPError:
                pass

        self.client.dlog(f"ipam_find_ips_by_address({query}) -> {len(ips)}", dbg)
        return ips

    def vm_from_ip(self, ip: dict, dbg: list[str]) -> Optional[dict]:
        assigned_object = ip.get("assigned_object") or {}
        assigned_type = ip.get("assigned_object_type")
        assigned_id = ip.get("assigned_object_id")
        vm_ref = assigned_object.get("virtual_machine")

        if isinstance(vm_ref, dict):
            return self.client.fetch_by_url_or_id(
                vm_ref.get("url"),
                f"/api/virtualization/virtual-machines/{vm_ref.get('id')}/",
                dbg,
            )

        if assigned_type == "virtualization.vminterface" and assigned_id:
            for path in (
                f"/api/virtualization/interfaces/{assigned_id}/",
                f"/api/virtualization/virtual-machine-interfaces/{assigned_id}/",
            ):
                try:
                    iface = self.client.api_get(path, dbg=dbg)
                    vm_ref = iface.get("virtual_machine")
                    if isinstance(vm_ref, dict):
                        return self.client.fetch_by_url_or_id(
                            vm_ref.get("url"),
                            f"/api/virtualization/virtual-machines/{vm_ref.get('id')}/",
                            dbg,
                        )
                except HTTPError:
                    continue

        assigned_url = assigned_object.get("url")
        if assigned_url:
            try:
                path = self.client.api_path_from_url(assigned_url)
                if not path:
                    return None
                assigned = self.client.api_get(path, dbg=dbg)
                vm_ref = assigned.get("virtual_machine")
                if isinstance(vm_ref, dict):
                    return self.client.fetch_by_url_or_id(
                        vm_ref.get("url"),
                        f"/api/virtualization/virtual-machines/{vm_ref.get('id')}/",
                        dbg,
                    )
            except HTTPError:
                pass
        return None

    def device_from_ip(self, ip: dict, dbg: list[str]) -> Optional[dict]:
        assigned_object = ip.get("assigned_object") or {}
        assigned_type = ip.get("assigned_object_type")
        assigned_id = ip.get("assigned_object_id")
        device_ref = assigned_object.get("device")

        if isinstance(device_ref, dict):
            return self.client.fetch_by_url_or_id(
                device_ref.get("url"),
                f"/api/dcim/devices/{device_ref.get('id')}/",
                dbg,
            )

        if assigned_type == "dcim.interface" and assigned_id:
            try:
                iface = self.client.api_get(f"/api/dcim/interfaces/{assigned_id}/", dbg=dbg)
                device_ref = iface.get("device")
                if isinstance(device_ref, dict):
                    return self.client.fetch_by_url_or_id(
                        device_ref.get("url"),
                        f"/api/dcim/devices/{device_ref.get('id')}/",
                        dbg,
                    )
            except HTTPError:
                pass

        assigned_url = assigned_object.get("url")
        if assigned_url:
            try:
                path = self.client.api_path_from_url(assigned_url)
                if not path:
                    return None
                assigned = self.client.api_get(path, dbg=dbg)
                device_ref = assigned.get("device")
                if isinstance(device_ref, dict):
                    return self.client.fetch_by_url_or_id(
                        device_ref.get("url"),
                        f"/api/dcim/devices/{device_ref.get('id')}/",
                        dbg,
                    )
            except HTTPError:
                pass
        return None

    def vm_by_name(self, name: str, dbg: list[str]) -> Optional[dict]:
        for ip in self.ipam_find_ips_by_dns(name, dbg):
            vm = self.vm_from_ip(ip, dbg)
            if vm:
                return vm

        try:
            data = self.client.api_get(
                "/api/virtualization/virtual-machines/",
                {"name": name, "limit": 2},
                dbg,
            )
            if data.get("count", 0) == 1:
                return self.client.first_result(data)
        except HTTPError:
            pass
        return None

    def device_by_name(self, name: str, dbg: list[str]) -> Optional[dict]:
        try:
            data = self.client.api_get("/api/dcim/devices/", {"name": name, "limit": 2}, dbg)
            if data.get("count", 0) == 1:
                return self.client.first_result(data)
        except HTTPError:
            pass
        return None

    def cluster_by_name(self, name: str, dbg: list[str]) -> Optional[dict]:
        try:
            data = self.client.api_get(
                "/api/virtualization/clusters/",
                {"name": name, "limit": 2},
                dbg,
            )
            exact = self._single_or_ambiguous("cluster", name, data)
            if exact:
                return exact

            data = self.client.api_get(
                "/api/virtualization/clusters/",
                {"q": name, "limit": 3},
                dbg,
            )
            return self._single_or_ambiguous("cluster", name, data)
        except HTTPError:
            return None

    @staticmethod
    def _single_or_ambiguous(kind: str, query: str, data: dict) -> Optional[dict]:
        if data.get("count", 0) == 1:
            return NetBoxClient.first_result(data)
        if data.get("count", 0) > 1:
            return {
                "_ambiguous": True,
                "kind": kind,
                "query": query,
                "matches": [item.get("name") for item in data.get("results", []) if item.get("name")],
            }
        return None

    def list_vm_interfaces(self, vm_id: int, dbg: list[str]) -> list[dict]:
        return self.client.paged_get("/api/virtualization/interfaces/", {"virtual_machine_id": vm_id}, dbg)

    def list_device_interfaces(self, device_id: int, dbg: list[str]) -> list[dict]:
        return self.client.paged_get("/api/dcim/interfaces/", {"device_id": device_id}, dbg)

    def list_ips_for_vm(self, vm_id: int, dbg: list[str]) -> list[dict]:
        return self.client.paged_get("/api/ipam/ip-addresses/", {"virtual_machine_id": vm_id}, dbg)

    def list_ips_for_device(self, device_id: int, dbg: list[str]) -> list[dict]:
        return self.client.paged_get("/api/ipam/ip-addresses/", {"device_id": device_id}, dbg)

    def list_vms_for_device(self, device_id: int, dbg: list[str]) -> list[dict]:
        return self.client.paged_get(
            "/api/virtualization/virtual-machines/",
            {"device_id": device_id},
            dbg,
        )

    def get_journal(self, object_type: str, object_id: int, dbg: list[str]) -> list[dict]:
        try:
            entries = self.client.paged_get(
                "/api/extras/journal-entries/",
                {"assigned_object_type": object_type, "assigned_object_id": object_id, "limit": 50},
                dbg,
            )
        except HTTPError:
            entries = []

        entries.sort(key=lambda entry: entry.get("created") or "", reverse=True)
        output = []
        for entry in entries[:5]:
            message = entry.get("comments")
            if isinstance(message, dict):
                message = message.get("text") or message.get("message") or json.dumps(message)
            if not isinstance(message, str):
                message = str(message) if message is not None else None
            output.append(
                {
                    "created": entry.get("created"),
                    "user": extract_name(entry.get("created_by")),
                    "message": (message or "").strip() or None,
                    "source": "journal",
                }
            )
        return output

    def get_object_changes(self, object_type: str, object_id: int, dbg: list[str]) -> list[dict]:
        try:
            changes = self.client.paged_get(
                "/api/extras/object-changes/",
                {"changed_object_type": object_type, "object_id": object_id, "limit": 50},
                dbg,
            )
        except HTTPError:
            try:
                changes = self.client.paged_get(
                    "/api/extras/object-changes/",
                    {"object_type": object_type, "object_id": object_id, "limit": 50},
                    dbg,
                )
            except HTTPError:
                changes = []

        changes.sort(key=lambda change: change.get("time") or "", reverse=True)
        output = []
        for change in changes[:5]:
            action = change.get("action")
            if isinstance(action, dict):
                action = extract_label_or_value(action)
            if not isinstance(action, str):
                action = str(action) if action is not None else "change"
            output.append(
                {
                    "created": change.get("time"),
                    "user": extract_name(change.get("user")),
                    "message": f"{action} change",
                    "source": "changes",
                }
            )
        return output

    def collect_logs(self, subject_type: str, subject_id: int, dbg: list[str]) -> list[dict]:
        object_type = TYPE_MAP.get(subject_type)
        if not object_type or not subject_id:
            return []
        logs = self.get_journal(object_type, subject_id, dbg)
        return logs or self.get_object_changes(object_type, subject_id, dbg)

    @staticmethod
    def summarize_ips(ips: list[dict]) -> list[dict]:
        output = []
        seen = set()
        for ip in ips:
            address = ip.get("address")
            if not address or address in seen:
                continue
            seen.add(address)
            output.append(
                {
                    "address": address,
                    "family": extract_label_or_value(ip.get("family")),
                    "dns_name": (ip.get("dns_name") or "").strip() or None,
                    "description": ip.get("description") or None,
                }
            )
        return output

    @staticmethod
    def summarize_interfaces(interfaces: list[dict]) -> list[dict]:
        return [
            {
                "id": iface.get("id"),
                "name": iface.get("name"),
                "type": extract_label_or_value(iface.get("type")),
                "mac_address": (iface.get("mac_address") or "").upper()
                if iface.get("mac_address")
                else None,
                "enabled": iface.get("enabled"),
                "mtu": iface.get("mtu"),
                "description": iface.get("description") or None,
            }
            for iface in interfaces
        ]

    def common_metadata(self, obj: dict) -> dict:
        def address_of(value):
            if isinstance(value, dict):
                return value.get("address")
            return value if isinstance(value, str) else None

        return {
            "site": extract_name(obj.get("site")),
            "location": extract_name(obj.get("location")),
            "role": extract_name(obj.get("role")),
            "platform": extract_name(obj.get("platform")),
            "tenant": extract_name(obj.get("tenant")),
            "primary_ip4": address_of(obj.get("primary_ip4")),
            "primary_ip6": address_of(obj.get("primary_ip6")),
            "created": obj.get("created"),
            "last_updated": obj.get("last_updated"),
            "url": self.client.display_url_of(obj),
        }

    @staticmethod
    def rack_block_for_device(device: dict) -> dict:
        rack_ref = device.get("rack")
        face_ref = device.get("face")
        if face_ref is None and isinstance(rack_ref, dict):
            face_ref = rack_ref.get("face")
        return {
            "rack": extract_name(rack_ref),
            "rack_position": device.get("position"),
            "rack_face": extract_label_or_value(face_ref),
            "site": extract_name(device.get("site")),
            "location": extract_name(device.get("location")),
        }

    def cluster_summary_from_stub(self, cluster_stub: Optional[dict], dbg: list[str]) -> Optional[dict]:
        if not isinstance(cluster_stub, dict):
            return None
        cluster = self.client.fetch_by_url_or_id(
            cluster_stub.get("url"),
            f"/api/virtualization/clusters/{cluster_stub.get('id')}/"
            if cluster_stub.get("id")
            else None,
            dbg,
        )
        if not isinstance(cluster, dict):
            return None
        return {
            "id": cluster.get("id"),
            "name": cluster.get("name"),
            "fqdn": self.cluster_fqdn(cluster, dbg),
            "url": self.client.display_url_of(cluster),
        }

    def build_vm_struct(self, vm: dict, dbg: list[str]) -> dict:
        vm_id = vm.get("id")
        interfaces = self.list_vm_interfaces(vm_id, dbg)
        ips = self.list_ips_for_vm(vm_id, dbg)

        cluster_stub = vm.get("cluster") or {}
        cluster = self.client.fetch_by_url_or_id(
            cluster_stub.get("url"),
            f"/api/virtualization/clusters/{cluster_stub.get('id')}/"
            if cluster_stub.get("id")
            else None,
            dbg,
        )

        host_stub = vm.get("device") or {}
        host = (
            self.client.fetch_by_url_or_id(
                host_stub.get("url"),
                f"/api/dcim/devices/{host_stub.get('id')}/" if host_stub.get("id") else None,
                dbg,
            )
            if host_stub
            else None
        )

        rack = (
            self.rack_block_for_device(host)
            if host
            else {
                "rack": None,
                "rack_position": None,
                "rack_face": None,
                "site": extract_name(vm.get("site")),
                "location": None,
            }
        )

        dns_names = set()
        if vm.get("dns_name"):
            dns_names.add(vm["dns_name"])
        if vm.get("name") and "." in vm["name"]:
            dns_names.add(vm["name"])
        for ip in ips:
            if ip.get("dns_name"):
                dns_names.add(ip["dns_name"])

        macs = [iface.get("mac_address") for iface in interfaces if iface.get("mac_address")]
        result = {
            "type": "vm",
            "id": vm_id,
            "name": vm.get("name"),
            "dns_names": sorted(dns_names),
            "cluster": {
                "name": cluster.get("name") if cluster else None,
                "fqdn": self.cluster_fqdn(cluster, dbg) if cluster else None,
                "id": cluster.get("id") if cluster else None,
                "url": self.client.display_url_of(cluster),
            },
            "host_device": host.get("name") if host else None,
            "host_device_url": self.client.display_url_of(host) if host else None,
            "ips": self.summarize_ips(ips),
            "mac_addresses": sorted({mac.upper() for mac in macs}) if macs else [],
            "rack": rack,
            "interfaces": self.summarize_interfaces(interfaces),
            **self.common_metadata(vm),
        }
        result["logs"] = self.collect_logs("vm", vm_id, dbg)
        return result

    def build_device_struct(self, device: dict, dbg: list[str]) -> dict:
        device_id = device.get("id")
        interfaces = self.list_device_interfaces(device_id, dbg)
        ips = self.list_ips_for_device(device_id, dbg)
        hosted_vms = self.list_vms_for_device(device_id, dbg)

        clusters: dict[int, dict] = {}
        hosted_vm_rows = []
        for vm in hosted_vms:
            cluster_summary = self.cluster_summary_from_stub(vm.get("cluster"), dbg)
            if cluster_summary and isinstance(cluster_summary.get("id"), int):
                clusters[cluster_summary["id"]] = cluster_summary
            hosted_vm_rows.append(
                {
                    "id": vm.get("id"),
                    "name": vm.get("name"),
                    "dns_name": vm.get("dns_name"),
                    "url": self.client.display_url_of(vm),
                    "cluster": cluster_summary,
                }
            )

        macs = [iface.get("mac_address") for iface in interfaces if iface.get("mac_address")]
        dns_names = {ip.get("dns_name") for ip in ips if ip.get("dns_name")}
        if device.get("name") and "." in device["name"]:
            dns_names.add(device["name"])

        result = {
            "type": "device",
            "id": device_id,
            "name": device.get("name"),
            "dns_names": sorted(dns_names),
            "ips": self.summarize_ips(ips),
            "mac_addresses": sorted({mac.upper() for mac in macs}) if macs else [],
            "rack": self.rack_block_for_device(device),
            "interfaces": self.summarize_interfaces(interfaces),
            "clusters": sorted(clusters.values(), key=lambda cluster: cluster.get("name") or ""),
            "hosted_vms": hosted_vm_rows,
            **self.common_metadata(device),
        }
        result["logs"] = self.collect_logs("device", device_id, dbg)
        return result

    def build_cluster_struct(self, cluster: dict, dbg: list[str]) -> dict:
        vms = self.client.paged_get(
            "/api/virtualization/virtual-machines/",
            {"cluster_id": cluster["id"]},
            dbg,
        )
        result = {
            "type": "cluster",
            "id": cluster.get("id"),
            "name": cluster.get("name"),
            "fqdn": self.cluster_fqdn(cluster, dbg),
            "site": extract_name(cluster.get("site")),
            "vm_count": len(vms),
            "vms": [
                {
                    "id": vm.get("id"),
                    "name": vm.get("name"),
                    "dns_name": vm.get("dns_name"),
                    "url": self.client.display_url_of(vm),
                }
                for vm in vms
            ],
            "url": self.client.display_url_of(cluster),
        }
        result["logs"] = self.collect_logs("cluster", cluster.get("id"), dbg)
        return result

    def resolve_subject(self, query: str, dbg: list[str]) -> dict:
        value = clean(query)

        if is_ip_like(value):
            ips = self.ipam_find_ips_by_address(value, dbg)
            if not ips and "." in value:
                ips = self.ipam_find_ips_by_dns(value, dbg)
            if not ips:
                return {"error": f"NOTFOUND ip '{value}'"}
            for ip in ips:
                vm = self.vm_from_ip(ip, dbg)
                if vm:
                    return self.build_vm_struct(vm, dbg)
            for ip in ips:
                device = self.device_from_ip(ip, dbg)
                if device:
                    return self.build_device_struct(device, dbg)
            return {"error": f"NOTFOUND parent for ip '{value}'"}

        vm = self.vm_by_name(value, dbg)
        if vm:
            return self.build_vm_struct(vm, dbg)

        device = self.device_by_name(value, dbg)
        if device:
            return self.build_device_struct(device, dbg)

        cluster = self.cluster_by_name(value, dbg)
        if cluster:
            if cluster.get("_ambiguous"):
                matches = ", ".join(cluster.get("matches") or [])
                suffix = f": {matches}" if matches else ""
                return {"error": f"AMBIGUOUS {cluster.get('kind')} '{value}'{suffix}"}
            return self.build_cluster_struct(cluster, dbg)

        ips = self.ipam_find_ips_by_dns(value, dbg)
        for ip in ips:
            vm = self.vm_from_ip(ip, dbg)
            if vm:
                return self.build_vm_struct(vm, dbg)
        for ip in ips:
            device = self.device_from_ip(ip, dbg)
            if device:
                return self.build_device_struct(device, dbg)

        return {"error": f"NOTFOUND '{value}'"}
