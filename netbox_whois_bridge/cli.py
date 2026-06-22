"""Command line entrypoint."""

import os
import sys

from .config import Config, ConfigError
from .netbox import NetBoxClient
from .resolver import Resolver
from .server import WhoisServer


def build_server(env: dict[str, str] | None = None) -> WhoisServer:
    config = Config.from_env(env or os.environ)
    config.validate_required()
    client = NetBoxClient(config)
    resolver = Resolver(config, client)
    return WhoisServer(config, resolver)


def main() -> int:
    try:
        server = build_server()
        server.serve()
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Shutting down...")
        return 0
    return 0
