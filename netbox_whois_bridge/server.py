"""Simple threaded WHOIS TCP server."""

import json
import socket
import threading

from .config import Config
from .render import pretty_print
from .resolver import Resolver
from .utils import clean


HELP_TEXT = (
    "Structured NetBox WHOIS\n"
    "Query examples:\n"
    "  <vm-or-device-name>\n"
    "  <vm FQDN or DNS name>\n"
    "  <IP address (v4/v6)>\n"
    "  <cluster name>\n"
    "Add ' json' at the end of a query for JSON output.\n"
    "Add ' color' or ' plain' for ANSI-colored or plain text output.\n"
)


class WhoisServer:
    def __init__(self, config: Config, resolver: Resolver):
        self.config = config
        self.resolver = resolver
        self._connection_slots = threading.BoundedSemaphore(config.whois_max_workers)

    def handle_client(self, conn: socket.socket, addr) -> None:
        dbg: list[str] = []
        output_mode = self.config.whois_output
        color = self.config.whois_color == "always"
        try:
            conn.settimeout(self.config.whois_client_timeout)
            raw = self._read_query(conn)
            line = clean(raw.decode("utf-8", errors="ignore"))

            if not line or line.lower() in ("help", "?"):
                self._send_help(conn)
                return

            line, output_mode, color = self._parse_query_flags(line, output_mode, color)

            result = self.resolver.resolve_subject(line, dbg)

            if self.config.whois_verbose_inband and dbg:
                conn.sendall(("\n".join(dbg) + "\n").encode())

            if output_mode == "json":
                conn.sendall((json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode())
            else:
                conn.sendall((pretty_print(result, self.config.log_snippet_max, color=color) + "\n").encode())
        except Exception as exc:
            self._send_error(conn, addr, dbg, output_mode, exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _read_query(self, conn: socket.socket) -> bytes:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > self.config.whois_max_query_bytes:
                break
        return buf

    def _parse_query_flags(self, line: str, output_mode: str, color: bool) -> tuple[str, str, bool]:
        while True:
            lowered = line.lower()
            if lowered.endswith(" json"):
                output_mode = "json"
                line = clean(line[:-5])
            elif lowered.endswith(" color"):
                color = True
                line = clean(line[:-6])
            elif lowered.endswith(" plain"):
                color = False
                line = clean(line[:-6])
            else:
                return line, output_mode, color

    def _send_help(self, conn: socket.socket) -> None:
        if self.config.whois_verbose_inband:
            payload = "\n".join(["# help"] + [f"# {line}" for line in HELP_TEXT.splitlines()]) + "\n"
        else:
            payload = HELP_TEXT + "\n"
        conn.sendall(payload.encode())

    def _send_error(self, conn: socket.socket, addr, dbg: list[str], output_mode: str, exc: Exception) -> None:
        try:
            self.resolver.client.dlog(
                f"request error from {addr}: {exc.__class__.__name__}: {exc}",
                dbg,
                inband=False,
            )
            if self.config.whois_verbose_inband and dbg:
                conn.sendall(("\n".join(dbg) + "\n").encode())
            message = f"ERROR {exc}" if self.config.whois_show_errors else "internal error"
            if output_mode == "json":
                conn.sendall(
                    json.dumps({"error": message}, ensure_ascii=False, sort_keys=True, indent=2).encode()
                    + b"\n"
                )
            else:
                conn.sendall((f"ERROR: {message}\n").encode())
        except Exception:
            pass

    def _handle_client_limited(self, conn: socket.socket, addr) -> None:
        try:
            self.handle_client(conn, addr)
        finally:
            self._connection_slots.release()

    def serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.whois_bind, self.config.whois_port))
        sock.listen(50)
        print(
            f"[WHOIS] listening on {self.config.whois_bind}:{self.config.whois_port} "
            f"max_workers={self.config.whois_max_workers}"
        )

        while True:
            conn, addr = sock.accept()
            if not self._connection_slots.acquire(blocking=False):
                try:
                    conn.sendall(b"ERROR: server busy\n")
                finally:
                    conn.close()
                continue
            threading.Thread(target=self._handle_client_limited, args=(conn, addr), daemon=True).start()
