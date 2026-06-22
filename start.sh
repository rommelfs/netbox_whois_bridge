#!/usr/bin/env sh
set -eu

: "${NETBOX_URL:=https://netbox.circl.lu}"
: "${NETBOX_TOKEN:?Set NETBOX_TOKEN before starting, for example: export NETBOX_TOKEN=...}"

export NETBOX_URL
export NETBOX_TOKEN

exec python3 "$(dirname "$0")/netbox_whois_bridge.py"
