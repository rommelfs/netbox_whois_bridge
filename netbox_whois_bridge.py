#!/usr/bin/env python3
"""
Structured NetBox WHOIS bridge (pretty-printed by default)

Queries (WHOIS-style, one line per request):
  - <vm-or-device-name>
  - <vm FQDN or DNS name>
  - <IP address v4/v6>  (bare or with CIDR)
  - <cluster name>      (recognized automatically — no 'cluster' verb)

Append ' json' to any query to get JSON output for that one request.

Default output: table-like text (pretty print)
Optional output: JSON (set WHOIS_OUTPUT=json or append ' json' to the query)

Env vars:
  NETBOX_URL                (required)
  NETBOX_TOKEN              (required)
  NETBOX_VERIFY=true|false  (default: true)
  WHOIS_BIND=0.0.0.0        (default)
  WHOIS_PORT=43             (default; run as root or use a high port)
  WHOIS_VERBOSE=1           (stderr debug)
  WHOIS_VERBOSE_INBAND=1    (prefix '# ' debug lines in client response)
  WHOIS_OUTPUT=table|json   (default: table)

  CLUSTER_FQDN_CF_KEYS="dns_name,fqdn,cluster_dns,hostname"
  CLUSTER_FQDN_SUFFIX=".example.org"  (fallback when cluster.name isn't an FQDN)
  LOG_SNIPPET_MAX=120       (truncate log message to this many chars; default 120)
"""
import os, sys, socket, threading, time, ipaddress, json
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
try:
    import requests
except ModuleNotFoundError:
    print("ERROR: missing dependency 'requests'. Install with: python3 -m pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)
from datetime import datetime

# ── Config ─────────────────────────────────────────────────────────────────────
NETBOX_URL      = os.environ.get("NETBOX_URL", "").rstrip("/")
NETBOX_TOKEN    = os.environ.get("NETBOX_TOKEN", "")
def env_bool(name: str, default: bool=False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")

def env_int(name: str, default: int, min_value: Optional[int]=None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        print(f"ERROR: {name} must be an integer", file=sys.stderr)
        sys.exit(1)
    if min_value is not None and val < min_value:
        print(f"ERROR: {name} must be >= {min_value}", file=sys.stderr)
        sys.exit(1)
    return val

NETBOX_VERIFY   = env_bool("NETBOX_VERIFY", True)
WHOIS_BIND      = os.environ.get("WHOIS_BIND", "0.0.0.0")
WHOIS_PORT      = env_int("WHOIS_PORT", 43, 1)  # default to 43
WHOIS_VERBOSE   = env_bool("WHOIS_VERBOSE", False)
WHOIS_VERBOSE_INBAND = env_bool("WHOIS_VERBOSE_INBAND", False)
WHOIS_SHOW_ERRORS = env_bool("WHOIS_SHOW_ERRORS", False)
WHOIS_OUTPUT    = os.environ.get("WHOIS_OUTPUT", "table").lower()  # "table" or "json"
if WHOIS_OUTPUT not in ("table", "json"):
    print("ERROR: WHOIS_OUTPUT must be 'table' or 'json'", file=sys.stderr)
    sys.exit(1)

CLUSTER_FQDN_CF_KEYS = [s.strip() for s in os.environ.get(
    "CLUSTER_FQDN_CF_KEYS",
    "dns_name,fqdn,cluster_dns,hostname"
).split(",") if s.strip()]

CLUSTER_FQDN_SUFFIX = os.environ.get("CLUSTER_FQDN_SUFFIX", "").strip()
LOG_SNIPPET_MAX     = env_int("LOG_SNIPPET_MAX", 120, 1)

HTTP_TIMEOUT   = env_int("HTTP_TIMEOUT", 15, 1)
CACHE_TTL      = env_int("CACHE_TTL", 60, 0)  # seconds; set 0 to disable
WHOIS_MAX_WORKERS = env_int("WHOIS_MAX_WORKERS", 20, 1)
WHOIS_MAX_QUERY_BYTES = env_int("WHOIS_MAX_QUERY_BYTES", 8192, 64)
WHOIS_CLIENT_TIMEOUT = env_int("WHOIS_CLIENT_TIMEOUT", 30, 1)

if not NETBOX_URL or not NETBOX_TOKEN:
    print("ERROR: set NETBOX_URL and NETBOX_TOKEN", file=sys.stderr)
    sys.exit(1)

_thread_local = threading.local()

def http_session() -> requests.Session:
    sess = getattr(_thread_local, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.headers.update({"Authorization": f"Token {NETBOX_TOKEN}", "Accept": "application/json"})
        sess.verify = NETBOX_VERIFY
        _thread_local.session = sess
    return sess

# ── Cache & logging ────────────────────────────────────────────────────────────
_cache: Dict[str, Tuple[float, Any]] = {}
_cache_lock = threading.RLock()
def cache_get(k):
    if CACHE_TTL <= 0: return None
    with _cache_lock:
        it = _cache.get(k)
    if not it: return None
    ts, val = it
    if time.time() - ts > CACHE_TTL:
        with _cache_lock:
            _cache.pop(k, None)
        return None
    return val
def cache_put(k, v):
    if CACHE_TTL > 0:
        with _cache_lock:
            _cache[k] = (time.time(), v)

def dlog(msg: str, dbg: Optional[List[str]], inband: bool=True):
    if WHOIS_VERBOSE:
        print(f"[WHOIS] {msg}", file=sys.stderr, flush=True)
    if inband and WHOIS_VERBOSE_INBAND and dbg is not None:
        dbg.append(f"# {msg}")

def clean(s: str) -> str:
    return (s or "").strip().rstrip(".")

def trunc(s: Optional[str], n: int) -> Optional[str]:
    if not s: return s
    return s if len(s) <= n else s[: max(0, n-1)] + "…"

# ── HTTP helpers ───────────────────────────────────────────────────────────────
def api_get(path: str, params: Dict=None, dbg: List[str]=None) -> Dict:
    key = f"GET:{path}:{sorted((params or {}).items())}"
    c = cache_get(key)
    if c is not None:
        dlog(f"cache HIT {path} {params}", dbg)
        return c
    url = f"{NETBOX_URL}{path}"
    dlog(f"GET {url} params={params}", dbg)
    r = http_session().get(url, params=params or {}, timeout=HTTP_TIMEOUT)
    try:
        r.raise_for_status()
    except requests.HTTPError:
        dlog(f"HTTP {r.status_code} {url}", dbg)
        dlog(f"HTTP body={r.text[:200]}", dbg, inband=False)
        raise
    data = r.json()
    cache_put(key, data)
    return data

def paged_get(path: str, params: Dict=None, dbg: List[str]=None) -> List[Dict]:
    params = dict(params or {})
    params.setdefault("limit", 200); params.setdefault("offset", 0)
    out: List[Dict] = []
    while True:
        d = api_get(path, params, dbg)
        out += d.get("results", [])
        if not d.get("next"): break
        params["offset"] += params["limit"]
    dlog(f"paged_get {path}: fetched {len(out)} items", dbg)
    return out

def first_result(d: Dict) -> Optional[Dict]:
    return d.get("results", [None])[0] if d.get("count", 0) > 0 else None

# ── URL & ID helpers ───────────────────────────────────────────────────────────
def api_path_from_url(api_url: Optional[str]) -> Optional[str]:
    if not api_url:
        return None
    if api_url.startswith("/api/"):
        return api_url

    base = urlparse(NETBOX_URL)
    parsed = urlparse(api_url)
    if not parsed.scheme and not parsed.netloc:
        return api_url if api_url.startswith("/api/") else None
    if parsed.scheme != base.scheme or parsed.netloc != base.netloc:
        return None
    return parsed.path if parsed.path.startswith("/api/") else None

def ui_url_from_api_url(api_url: Optional[str]) -> Optional[str]:
    if not api_url: return None
    rel = api_path_from_url(api_url)
    if not rel:
        return None
    if rel.startswith("/api/"):
        rel = rel[len("/api/"):]
    return f"{NETBOX_URL}/{rel}".rstrip("/")

def display_url_of(obj: Optional[Dict]) -> Optional[str]:
    if not isinstance(obj, dict):
        return None
    return obj.get("display_url") or ui_url_from_api_url(obj.get("url"))

def fetch_by_url_or_id(url: Optional[str], fallback_path: Optional[str], dbg: List[str]) -> Optional[Dict]:
    if url:
        path = api_path_from_url(url)
        if path:
            return api_get(path, dbg=dbg)
        dlog(f"ignored non-NetBox API URL {url}", dbg)
    if fallback_path:
        return api_get(fallback_path, dbg=dbg)
    return None

# ── Safe extractors for mixed scalar/dict refs ─────────────────────────────────
def extract_name(ref) -> Optional[str]:
    if isinstance(ref, dict):
        return ref.get("name") or ref.get("display") or ref.get("label")
    if isinstance(ref, (str, int, float)):
        return str(ref)
    return None

def extract_label_or_value(ref) -> Optional[str]:
    if isinstance(ref, dict):
        return ref.get("label") or ref.get("name") or ref.get("display") or ref.get("value")
    if isinstance(ref, (str, int, float)):
        return str(ref)
    return None

# ── IP parsing helpers ─────────────────────────────────────────────────────────
def is_ip_like(q: str) -> bool:
    q = q.strip()
    try:
        ipaddress.ip_network(q, strict=False)  # bare or with CIDR
        return True
    except Exception:
        return False

def normalize_ip_query(q: str) -> List[str]:
    q = q.strip()
    normals = [q]
    try:
        ip = ipaddress.ip_address(q)
        normals.append(f"{q}/32" if ip.version == 4 else f"{q}/128")
    except Exception:
        pass
    return list(dict.fromkeys(normals))  # dedupe, preserve order

# ── Cluster helpers ────────────────────────────────────────────────────────────
def cluster_fqdn(cluster: Dict) -> Optional[str]:
    cf = cluster.get("custom_fields") or {}
    for key in CLUSTER_FQDN_CF_KEYS:
        val = cf.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    nm = (cluster.get("name") or "").strip()
    if not nm:
        return None
    if "." in nm:
        return nm
    if CLUSTER_FQDN_SUFFIX:
        return f"{nm}{CLUSTER_FQDN_SUFFIX if CLUSTER_FQDN_SUFFIX.startswith('.') else '.' + CLUSTER_FQDN_SUFFIX}"
    return nm  # last resort: non-FQDN name

# ── Map IP → parent (VM or Device) ────────────────────────────────────────────
def ipam_find_ips_by_dns(dns: str, dbg: List[str]) -> List[Dict]:
    return paged_get("/api/ipam/ip-addresses/", {"dns_name": dns}, dbg)

def ipam_find_ips_by_address(q: str, dbg: List[str]) -> List[Dict]:
    ips: List[Dict] = []
    for candidate in normalize_ip_query(q):
        try:
            d = api_get("/api/ipam/ip-addresses/", {"address": candidate, "limit": 50}, dbg)
            ips += d.get("results", [])
        except requests.HTTPError:
            pass
    if not ips:
        try:
            d = api_get("/api/ipam/ip-addresses/", {"q": q, "limit": 50}, dbg)
            ips += d.get("results", [])
        except requests.HTTPError:
            pass
    dlog(f"ipam_find_ips_by_address({q}) -> {len(ips)}", dbg)
    return ips

def vm_from_ip(ip: Dict, dbg: List[str]) -> Optional[Dict]:
    ao = ip.get("assigned_object") or {}
    aotype = ip.get("assigned_object_type")
    aoid   = ip.get("assigned_object_id")
    vm_ref = ao.get("virtual_machine")
    if isinstance(vm_ref, dict):
        return fetch_by_url_or_id(vm_ref.get("url"), f"/api/virtualization/virtual-machines/{vm_ref.get('id')}/", dbg)
    if aotype == "virtualization.vminterface" and aoid:
        for path in (f"/api/virtualization/interfaces/{aoid}/",
                     f"/api/virtualization/virtual-machine-interfaces/{aoid}/"):
            try:
                iface = api_get(path, dbg=dbg)
                vm_ref = iface.get("virtual_machine")
                if isinstance(vm_ref, dict):
                    return fetch_by_url_or_id(vm_ref.get("url"),
                                              f"/api/virtualization/virtual-machines/{vm_ref.get('id')}/",
                                              dbg)
            except requests.HTTPError:
                continue
    ao_url = ao.get("url")
    if ao_url:
        try:
            path = api_path_from_url(ao_url)
            if not path:
                return None
            ao_obj = api_get(path, dbg=dbg)
            vm_ref = ao_obj.get("virtual_machine")
            if isinstance(vm_ref, dict):
                return fetch_by_url_or_id(vm_ref.get("url"),
                                          f"/api/virtualization/virtual-machines/{vm_ref.get('id')}/",
                                          dbg)
        except requests.HTTPError:
            pass
    return None

def device_from_ip(ip: Dict, dbg: List[str]) -> Optional[Dict]:
    ao = ip.get("assigned_object") or {}
    aotype = ip.get("assigned_object_type")
    aoid   = ip.get("assigned_object_id")
    dev_ref = ao.get("device")
    if isinstance(dev_ref, dict):
        return fetch_by_url_or_id(dev_ref.get("url"), f"/api/dcim/devices/{dev_ref.get('id')}/", dbg)
    if aotype == "dcim.interface" and aoid:
        try:
            iface = api_get(f"/api/dcim/interfaces/{aoid}/", dbg=dbg)
            dev_ref = iface.get("device")
            if isinstance(dev_ref, dict):
                return fetch_by_url_or_id(dev_ref.get("url"), f"/api/dcim/devices/{dev_ref.get('id')}/", dbg)
        except requests.HTTPError:
            pass
    ao_url = ao.get("url")
    if ao_url:
        try:
            path = api_path_from_url(ao_url)
            if not path:
                return None
            ao_obj = api_get(path, dbg=dbg)
            dev_ref = ao_obj.get("device")
            if isinstance(dev_ref, dict):
                return fetch_by_url_or_id(dev_ref.get("url"),
                                          f"/api/dcim/devices/{dev_ref.get('id')}/",
                                          dbg)
        except requests.HTTPError:
            pass
    return None

# ── Lookups by name / FQDN ─────────────────────────────────────────────────────
def vm_by_name(name: str, dbg: List[str]) -> Optional[Dict]:
    # In some installs, VM filter by dns_name isn't usable; rely on IPAM dns_name to map → VM.
    ips = ipam_find_ips_by_dns(name, dbg)
    for ip in ips:
        vm = vm_from_ip(ip, dbg)
        if vm: return vm
    # Best-effort: exact VM name
    try:
        d = api_get("/api/virtualization/virtual-machines/", {"name": name, "limit": 2}, dbg)
        if d.get("count", 0) == 1:
            return first_result(d)
    except requests.HTTPError:
        pass
    return None

def device_by_name(name: str, dbg: List[str]) -> Optional[Dict]:
    try:
        d = api_get("/api/dcim/devices/", {"name": name, "limit": 2}, dbg)
        if d.get("count", 0) == 1:
            return first_result(d)
    except requests.HTTPError:
        pass
    return None

def cluster_by_name(name: str, dbg: List[str]) -> Optional[Dict]:
    try:
        d = api_get("/api/virtualization/clusters/", {"name": name, "limit": 2}, dbg)
        if d.get("count", 0) == 1:
            return first_result(d)
        if d.get("count", 0) > 1:
            return {
                "_ambiguous": True,
                "kind": "cluster",
                "query": name,
                "matches": [c.get("name") for c in d.get("results", []) if c.get("name")],
            }

        d = api_get("/api/virtualization/clusters/", {"q": name, "limit": 3}, dbg)
        if d.get("count", 0) == 1:
            return first_result(d)
        if d.get("count", 0) > 1:
            return {
                "_ambiguous": True,
                "kind": "cluster",
                "query": name,
                "matches": [c.get("name") for c in d.get("results", []) if c.get("name")],
            }
        return None
    except requests.HTTPError:
        return None

# ── Interfaces, IPs & device-hosted VMs ────────────────────────────────────────
def list_vm_interfaces(vm_id: int, dbg: List[str]) -> List[Dict]:
    return paged_get("/api/virtualization/interfaces/", {"virtual_machine_id": vm_id}, dbg)

def list_device_interfaces(dev_id: int, dbg: List[str]) -> List[Dict]:
    return paged_get("/api/dcim/interfaces/", {"device_id": dev_id}, dbg)

def list_ips_for_vm(vm_id: int, dbg: List[str]) -> List[Dict]:
    return paged_get("/api/ipam/ip-addresses/", {"virtual_machine_id": vm_id}, dbg)

def list_ips_for_device(device_id: int, dbg: List[str]) -> List[Dict]:
    return paged_get("/api/ipam/ip-addresses/", {"device_id": device_id}, dbg)

def list_vms_for_device(device_id: int, dbg: List[str]) -> List[Dict]:
    # All VMs pinned to this host device
    return paged_get("/api/virtualization/virtual-machines/", {"device_id": device_id}, dbg)

# ── Logs: Journal entries (preferred) and Object Changes (fallback) ────────────
TYPE_MAP = {
    "vm":      "virtualization.virtualmachine",
    "device":  "dcim.device",
    "cluster": "virtualization.cluster",
}

def get_journal(obj_type: str, obj_id: int, dbg: List[str]) -> List[Dict]:
    try:
        entries = paged_get(
            "/api/extras/journal-entries/",
            {"assigned_object_type": obj_type, "assigned_object_id": obj_id, "limit": 50},
            dbg,
        )
    except requests.HTTPError:
        entries = []
    entries.sort(key=lambda e: e.get("created") or "", reverse=True)
    out = []
    for e in entries[:5]:
        who = extract_name(e.get("created_by"))
        msg = e.get("comments")
        if isinstance(msg, dict):
            msg = msg.get("text") or msg.get("message") or json.dumps(msg)
        if not isinstance(msg, str):
            msg = str(msg) if msg is not None else None
        out.append({
            "created": e.get("created"),
            "user": who,
            "message": (msg or "").strip() or None,
            "source": "journal",
        })
    return out

def get_object_changes(obj_type: str, obj_id: int, dbg: List[str]) -> List[Dict]:
    try:
        changes = paged_get(
            "/api/extras/object-changes/",
            {"changed_object_type": obj_type, "object_id": obj_id, "limit": 50},
            dbg,
        )
    except requests.HTTPError:
        try:
            changes = paged_get(
                "/api/extras/object-changes/",
                {"object_type": obj_type, "object_id": obj_id, "limit": 50},
                dbg,
            )
        except requests.HTTPError:
            changes = []
    changes.sort(key=lambda c: c.get("time") or "", reverse=True)
    out = []
    for c in changes[:5]:
        who = extract_name(c.get("user"))
        action = c.get("action")
        if isinstance(action, dict):
            action = extract_label_or_value(action)
        if not isinstance(action, str):
            action = str(action) if action is not None else "change"
        out.append({
            "created": c.get("time"),
            "user": who,
            "message": f"{action} change",
            "source": "changes",
        })
    return out

def collect_logs(subject_type: str, subject_id: int, dbg: List[str]) -> List[Dict]:
    obj_type = TYPE_MAP.get(subject_type)
    if not obj_type or not subject_id:
        return []
    logs = get_journal(obj_type, subject_id, dbg)
    if not logs:
        logs = get_object_changes(obj_type, subject_id, dbg)
    return logs

# ── Structured builders ────────────────────────────────────────────────────────
def summarize_ips(ips: List[Dict]) -> List[Dict]:
    out = []
    seen = set()
    for ip in ips:
        addr = ip.get("address")
        if not addr or addr in seen:
            continue
        seen.add(addr)
        out.append({
            "address": addr,
            "family": extract_label_or_value(ip.get("family")),
            "dns_name": (ip.get("dns_name") or "").strip() or None,
            "description": ip.get("description") or None,
        })
    return out

def summarize_interfaces(ifaces: List[Dict]) -> List[Dict]:
    out = []
    for itf in ifaces:
        out.append({
            "id": itf.get("id"),
            "name": itf.get("name"),
            "type": extract_label_or_value(itf.get("type")),
            "mac_address": (itf.get("mac_address") or "").upper() if itf.get("mac_address") else None,
            "enabled": itf.get("enabled"),
            "mtu": itf.get("mtu"),
            "description": itf.get("description") or None,
        })
    return out

def common_metadata(obj: Dict) -> Dict:
    site_name     = extract_name(obj.get("site"))
    location_name = extract_name(obj.get("location"))
    role_name     = extract_name(obj.get("role"))
    platform_name = extract_name(obj.get("platform"))
    tenant_name   = extract_name(obj.get("tenant"))

    def addr_of(x):
        if isinstance(x, dict):
            return x.get("address")
        return x if isinstance(x, str) else None

    return {
        "site": site_name,
        "location": location_name,
        "role": role_name,
        "platform": platform_name,
        "tenant": tenant_name,
        "primary_ip4": addr_of(obj.get("primary_ip4")),
        "primary_ip6": addr_of(obj.get("primary_ip6")),
        "created": obj.get("created"), "last_updated": obj.get("last_updated"),
        "url": display_url_of(obj),
    }

def rack_block_for_device(device: Dict) -> Dict:
    rack_ref = device.get("rack")
    rack_name = extract_name(rack_ref)
    face_ref = device.get("face")
    if face_ref is None and isinstance(rack_ref, dict):
        face_ref = rack_ref.get("face")
    face_label = extract_label_or_value(face_ref)
    site_name     = extract_name(device.get("site"))
    location_name = extract_name(device.get("location"))
    return {
        "rack": rack_name,
        "rack_position": device.get("position"),
        "rack_face": face_label,
        "site": site_name,
        "location": location_name,
    }

def cluster_summary_from_stub(cluster_stub: Optional[Dict], dbg: List[str]) -> Optional[Dict]:
    if not isinstance(cluster_stub, dict):
        return None
    c = fetch_by_url_or_id(cluster_stub.get("url"),
                           f"/api/virtualization/clusters/{cluster_stub.get('id')}/" if cluster_stub.get("id") else None,
                           dbg)
    if not isinstance(c, dict):
        return None
    return {
        "id": c.get("id"),
        "name": c.get("name"),
        "fqdn": cluster_fqdn(c),
        "url": display_url_of(c),
    }

def build_vm_struct(vm: Dict, dbg: List[str]) -> Dict:
    vm_id = vm.get("id")
    vifs = list_vm_interfaces(vm_id, dbg)
    macs = [it.get("mac_address") for it in vifs if it.get("mac_address")]
    ips  = list_ips_for_vm(vm_id, dbg)

    cluster_stub = vm.get("cluster") or {}
    cluster = fetch_by_url_or_id(cluster_stub.get("url"),
                                 f"/api/virtualization/clusters/{cluster_stub.get('id')}/" if cluster_stub.get("id") else None,
                                 dbg)
    cluster_name = cluster.get("name") if cluster else None
    cluster_dns = cluster_fqdn(cluster) if cluster else None
    cluster_url = display_url_of(cluster)

    host_stub = vm.get("device") or {}
    host = fetch_by_url_or_id(host_stub.get("url"),
                              f"/api/dcim/devices/{host_stub.get('id')}/" if host_stub.get("id") else None,
                              dbg) if host_stub else None

    rack_block = rack_block_for_device(host) if host else {
        "rack": None, "rack_position": None, "rack_face": None,
        "site": extract_name(vm.get("site")),
        "location": None
    }

    dns_names = set()
    if vm.get("dns_name"): dns_names.add(vm["dns_name"])
    if vm.get("name") and "." in vm["name"]: dns_names.add(vm["name"])
    for ip in ips:
        if ip.get("dns_name"): dns_names.add(ip["dns_name"])

    res = {
        "type": "vm",
        "id": vm_id,
        "name": vm.get("name"),
        "dns_names": sorted(dns_names),
        "cluster": {
            "name": cluster_name,
            "fqdn": cluster_dns,
            "id": cluster.get("id") if cluster else None,
            "url": cluster_url,
        },
        "host_device": host.get("name") if host else None,
        "host_device_url": display_url_of(host) if host else None,
        "ips": summarize_ips(ips),
        "mac_addresses": sorted({m.upper() for m in macs}) if macs else [],
        "rack": rack_block,
        "interfaces": summarize_interfaces(vifs),
        **common_metadata(vm),
    }
    res["logs"] = collect_logs("vm", vm_id, dbg)
    return res

def build_device_struct(dev: Dict, dbg: List[str]) -> Dict:
    dev_id = dev.get("id")
    difs = list_device_interfaces(dev_id, dbg)
    macs = [it.get("mac_address") for it in difs if it.get("mac_address")]
    ips  = list_ips_for_device(dev_id, dbg)

    # NEW: find VMs hosted on this device and their clusters
    hosted_vms = list_vms_for_device(dev_id, dbg)
    clusters: Dict[int, Dict] = {}
    hosted_vm_rows = []
    for v in hosted_vms:
        csum = cluster_summary_from_stub(v.get("cluster"), dbg)
        if csum and isinstance(csum.get("id"), int):
            clusters[csum["id"]] = csum
        hosted_vm_rows.append({
            "id": v.get("id"),
            "name": v.get("name"),
            "dns_name": v.get("dns_name"),
            "url": display_url_of(v),
            "cluster": csum,
        })


    res = {
        "type": "device",
        "id": dev_id,
        "name": dev.get("name"),
        "dns_names": sorted({ip.get("dns_name") for ip in ips if ip.get("dns_name")} |
                            ({dev["name"]} if dev.get("name") and "." in dev["name"] else set())),
        "ips": summarize_ips(ips),
        "mac_addresses": sorted({m.upper() for m in macs}) if macs else [],
        "rack": rack_block_for_device(dev),
        "interfaces": summarize_interfaces(difs),
        "clusters": sorted(clusters.values(), key=lambda c: c.get("name") or ""),
        "hosted_vms": hosted_vm_rows,
        **common_metadata(dev),
    }
    res["logs"] = collect_logs("device", dev_id, dbg)
    return res

def build_cluster_struct(cluster: Dict, dbg: List[str]) -> Dict:
    vms = paged_get("/api/virtualization/virtual-machines/", {"cluster_id": cluster["id"]}, dbg)
    res = {
        "type": "cluster",
        "id": cluster.get("id"),
        "name": cluster.get("name"),
        "fqdn": cluster_fqdn(cluster),
        "site": extract_name(cluster.get("site")),
        "vm_count": len(vms),
        "vms": [{"id": v.get("id"), "name": v.get("name"), "dns_name": v.get("dns_name"), "url": display_url_of(v)} for v in vms],
        "url": display_url_of(cluster),
    }
    res["logs"] = collect_logs("cluster", cluster.get("id"), dbg)
    return res

# ── Top-level resolver ─────────────────────────────────────────────────────────
def resolve_subject(query: str, dbg: List[str]) -> Dict:
    q = clean(query)

    # IP query?
    if is_ip_like(q):
        ips = ipam_find_ips_by_address(q, dbg)
        if not ips and "." in q:
            ips = ipam_find_ips_by_dns(q, dbg)
        if not ips:
            return {"error": f"NOTFOUND ip '{q}'"}
        for ip in ips:
            vm = vm_from_ip(ip, dbg)
            if vm: return build_vm_struct(vm, dbg)
        for ip in ips:
            dev = device_from_ip(ip, dbg)
            if dev: return build_device_struct(dev, dbg)
        return {"error": f"NOTFOUND parent for ip '{q}'"}

    # Name/FQDN → VM, then device, then cluster
    vm = vm_by_name(q, dbg)
    if vm:
        return build_vm_struct(vm, dbg)

    dev = device_by_name(q, dbg)
    if dev:
        return build_device_struct(dev, dbg)

    cl = cluster_by_name(q, dbg)
    if cl:
        if cl.get("_ambiguous"):
            matches = ", ".join(cl.get("matches") or [])
            suffix = f": {matches}" if matches else ""
            return {"error": f"AMBIGUOUS {cl.get('kind')} '{q}'{suffix}"}
        return build_cluster_struct(cl, dbg)

    # Last resort: treat as dns_name and map
    ips = ipam_find_ips_by_dns(q, dbg)
    for ip in ips:
        vm = vm_from_ip(ip, dbg)
        if vm: return build_vm_struct(vm, dbg)
    for ip in ips:
        dev = device_from_ip(ip, dbg)
        if dev: return build_device_struct(dev, dbg)

    return {"error": f"NOTFOUND '{q}'"}

# ── Pretty printer ─────────────────────────────────────────────────────────────
def pretty_print(res: Dict) -> str:
    if "error" in res:
        return f"ERROR: {res['error']}"

    lines = []
    t = res.get("type")
    lines.append(f"Type:        {t}")
    lines.append(f"Name:        {res.get('name')}")
    if res.get("url"):
        lines.append(f"URL:         {res['url']}")
    if res.get("dns_names"):
        lines.append(f"DNS Names:   {', '.join(res['dns_names'])}")

    if t == "vm":
        cl = res.get("cluster") or {}
        if cl:
            cl_fqdn = cl.get("fqdn")
            base = f"Cluster:     {cl.get('name')}" if cl.get("name") else "Cluster:     (unknown)"
            if cl_fqdn:
                base += f" (fqdn: {cl_fqdn})"
            if cl.get("url"):
                base += f"\n             {cl['url']}"
            lines.append(base)
        if res.get("host_device"):
            host_line = f"Host Device: {res['host_device']}"
            if res.get("host_device_url"):
                host_line += f"\n             {res['host_device_url']}"
            lines.append(host_line)

    if t == "device":
        if res.get("role"):
            lines.append(f"Device Role: {res.get('role')}")
        if res.get("site"):
            lines.append(f"Site:        {res['site']}")

    if t in ("vm", "device"):
        rack = res.get("rack") or {}
        if rack.get("rack"):
            pos = rack.get("rack_position")
            face = rack.get("rack_face")
            lines.append(f"Rack:        {rack['rack']} (pos {pos}, face: {face})")

    # Primary IPs
    if res.get("primary_ip4") or res.get("primary_ip6"):
        lines.append(f"Primary IPs: IPv4={res.get('primary_ip4')}, IPv6={res.get('primary_ip6')}")

    if res.get("ips"):
        lines.append("")
        lines.append("IPs:")
        for ip in res["ips"]:
            ln = f"  - {ip['address']}"
            if ip.get("family"): ln += f" ({ip['family']})"
            if ip.get("dns_name"): ln += f" dns: {ip['dns_name']}"
            if ip.get("description"): ln += f" — {ip['description']}"
            lines.append(ln)

    if res.get("mac_addresses"):
        lines.append("")
        lines.append("MAC Addresses:")
        for m in res["mac_addresses"]:
            lines.append(f"  - {m}")

    if res.get("interfaces"):
        lines.append("")
        lines.append("Interfaces:")
        for it in res["interfaces"]:
            ln = f"  - {it['name']}"
            if it.get("mac_address"):
                ln += f" (MAC {it['mac_address']})"
            if it.get("enabled") is not None:
                ln += f", enabled={it['enabled']}"
            if it.get("mtu"):
                ln += f", mtu={it['mtu']}"
            lines.append(ln)

    # Device-specific: show clusters and hosted VMs
    if t == "device":
        if res.get("clusters"):
            lines.append("")
            lines.append("Clusters:")
            for c in res["clusters"]:
                base = f"  - {c.get('name')}"
                if c.get("fqdn"):
                    base += f" (fqdn: {c['fqdn']})"
                if c.get("url"):
                    base += f"\n             {c['url']}"
                lines.append(base)
        if res.get("hosted_vms"):
            lines.append("")
            lines.append(f"Hosted VMs:  {len(res['hosted_vms'])}")
            for v in res["hosted_vms"]:
                ln = f"  - {v.get('name')}"
                if v.get("dns_name"):
                    ln += f" ({v['dns_name']})"
                if v.get("url"):
                    ln += f"\n             {v['url']}"
                c = v.get("cluster") or {}
                if c.get("name"):
                    ln += f"\n             cluster: {c['name']}"
                    if c.get("fqdn"):
                        ln += f" (fqdn: {c['fqdn']})"
                lines.append(ln)

    # Cluster-specific expansion
    if t == "cluster":
        if res.get("fqdn"):
            lines.append(f"FQDN:        {res['fqdn']}")
        if res.get("site"):
            lines.append(f"Site:        {res['site']}")
        lines.append(f"VM count:    {res.get('vm_count')}")
        if res.get("vms"):
            lines.append("")
            lines.append("VMs:")
            for vm in res["vms"]:
                ln = f"  - {vm.get('name')}"
                if vm.get("dns_name"): ln += f" ({vm['dns_name']})"
                if vm.get("url"): ln += f"\n             {vm['url']}"
                lines.append(ln)

    # Logs (latest 5)
    if res.get("logs"):
        lines.append("")
        lines.append("Logs (latest 5):")
        for e in res["logs"]:
            ts = e.get("created")
            try:
                ts = datetime.fromisoformat(ts.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M:%S %z")
            except Exception:
                pass
            msg = e.get("message") or ""
            user = e.get("user") or ""
            src  = e.get("source") or ""
            body = msg or f"{src} event"
            snippet = trunc(body, LOG_SNIPPET_MAX)
            who = f" by {user}" if user else ""
            lines.append(f"  - [{ts}] {snippet}{who}")

    # Timestamps
    if res.get("created") or res.get("last_updated"):
        lines.append("")
        lines.append(f"Created:     {res.get('created')}")
        lines.append(f"Updated:     {res.get('last_updated')}")

    return "\n".join(lines)

# ── WHOIS server ───────────────────────────────────────────────────────────────
HELP_TEXT = (
    "Structured NetBox WHOIS\n"
    "Query examples:\n"
    "  <vm-or-device-name>\n"
    "  <vm FQDN or DNS name>\n"
    "  <IP address (v4/v6)>\n"
    "  <cluster name>\n"
    "Add ' json' at the end of a query for JSON output.\n"
)

_connection_slots = threading.BoundedSemaphore(WHOIS_MAX_WORKERS)

def handle_client(conn: socket.socket, addr):
    dbg: List[str] = []
    output_mode = WHOIS_OUTPUT
    try:
        conn.settimeout(WHOIS_CLIENT_TIMEOUT)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk: break
            buf += chunk
            if len(buf) > WHOIS_MAX_QUERY_BYTES: break

        raw_line = buf.decode("utf-8", errors="ignore")
        line = clean(raw_line)


        # Help
        if not line or line.lower() in ("help","?"):
            if WHOIS_VERBOSE_INBAND:
                conn.sendall(("\n".join(["# help"] + [f"# {ln}" for ln in HELP_TEXT.splitlines()]) + "\n").encode())
            else:
                conn.sendall((HELP_TEXT + "\n").encode())
            return

        # Per-request output override: trailing ' json'
        if line.lower().endswith(" json"):
            output_mode = "json"
            line = clean(line[:-5])  # strip the trailing " json"

        res = resolve_subject(line, dbg)

        if WHOIS_VERBOSE_INBAND and dbg:
            conn.sendall(("\n".join(dbg) + "\n").encode())

        if output_mode == "json":
            conn.sendall((json.dumps(res, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode())
        else:
            conn.sendall((pretty_print(res) + "\n").encode())

    except Exception as e:

        try:
            dlog(f"request error from {addr}: {e.__class__.__name__}: {e}", dbg, inband=False)
            if WHOIS_VERBOSE_INBAND and dbg:
                conn.sendall(("\n".join(dbg) + "\n").encode())
            msg = f"ERROR {e}" if WHOIS_SHOW_ERRORS else "internal error"
            err = {"error": msg}
            if output_mode == "json":
                conn.sendall(json.dumps(err, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n")
            else:
                conn.sendall((f"ERROR: {msg}\n").encode())
        except Exception:
            pass
    finally:
        try: conn.close()
        except Exception: pass

def handle_client_limited(conn: socket.socket, addr):
    try:
        handle_client(conn, addr)
    finally:
        _connection_slots.release()

def serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((WHOIS_BIND, WHOIS_PORT))
    s.listen(50)
    print(f"[WHOIS] listening on {WHOIS_BIND}:{WHOIS_PORT} max_workers={WHOIS_MAX_WORKERS}")
    while True:
        conn, addr = s.accept()
        if not _connection_slots.acquire(blocking=False):
            try:
                conn.sendall(b"ERROR: server busy\n")
            finally:
                conn.close()
            continue
        threading.Thread(target=handle_client_limited, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    try:
        serve()
    except KeyboardInterrupt:
        print("Shutting down...")
