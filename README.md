# NetBox WHOIS Bridge

Small WHOIS-style TCP bridge for internal NetBox lookups. It accepts one-line
queries for VM names, device names, DNS names, IP addresses, and cluster names,
then returns either pretty text or JSON.

## Internal Use Assumption

This service is intended for trusted internal networks only. It does not
authenticate WHOIS clients and can expose NetBox inventory data such as IP
addresses, MAC addresses, rack placement, hosted VMs, cluster membership, and
recent log snippets. Keep it behind internal routing, firewall rules, or a
service boundary you control.

The default bind address remains `0.0.0.0` because the expected deployment is an
internal-only host or container network. For local-only use, set
`WHOIS_BIND=127.0.0.1`.

`WHOIS_VERBOSE_INBAND=1` sends debug lines back to the WHOIS client. Use it only
for temporary troubleshooting on trusted clients.

## Requirements

- Python 3.9+
- A NetBox API token with read permissions for the objects you want to expose
- Python dependencies from `requirements.txt`

Install dependencies:

```sh
python3 -m pip install -r requirements.txt
```

## Configuration

Required:

```sh
export NETBOX_URL="https://netbox.example"
export NETBOX_TOKEN="..."
```

Common options:

```sh
export NETBOX_VERIFY=true
export WHOIS_BIND=0.0.0.0
export WHOIS_PORT=43
export WHOIS_OUTPUT=table
export WHOIS_MAX_WORKERS=20
export WHOIS_CLIENT_TIMEOUT=30
export WHOIS_MAX_QUERY_BYTES=8192
export HTTP_TIMEOUT=15
export CACHE_TTL=60
```

Cluster FQDN handling:

```sh
export CLUSTER_FQDN_CF_KEYS="dns_name,fqdn,cluster_dns,hostname"
export CLUSTER_FQDN_SUFFIX=".example.org"
```

Debugging:

```sh
export WHOIS_VERBOSE=1
export WHOIS_VERBOSE_INBAND=0
export WHOIS_SHOW_ERRORS=0
```

## Running

Use a high port during development:

```sh
WHOIS_PORT=8043 python3 netbox_whois_bridge.py
```

Query examples:

```sh
whois -h 127.0.0.1 -p 8043 vm-name
whois -h 127.0.0.1 -p 8043 192.0.2.10
whois -h 127.0.0.1 -p 8043 cluster-name
whois -h 127.0.0.1 -p 8043 "vm-name json"
```

## Tests

The unit tests cover local parsing and resolver behavior without requiring a
live NetBox instance:

```sh
python3 -m unittest
```

## Notes

- Port 43 usually requires root privileges or a service manager capability.
- `CACHE_TTL=0` disables the in-process response cache.
- Ambiguous cluster searches return an explicit error instead of selecting the
  first fuzzy match.
- Client-facing exceptions are generic by default. Set `WHOIS_SHOW_ERRORS=1`
  only during trusted troubleshooting.
