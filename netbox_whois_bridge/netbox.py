"""NetBox API client with simple paging and in-process caching."""

import sys
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse

from .config import Config

try:
    import requests
except ModuleNotFoundError as exc:
    print(
        "ERROR: missing dependency 'requests'. Install with: "
        "python3 -m pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

HTTPError = requests.HTTPError


class NetBoxClient:
    def __init__(self, config: Config):
        self.config = config
        self._cache: dict[str, tuple[float, Any]] = {}
        self._cache_lock = threading.RLock()
        self._thread_local = threading.local()

    def dlog(self, message: str, dbg: Optional[list[str]], inband: bool = True) -> None:
        if self.config.whois_verbose:
            print(f"[WHOIS] {message}", file=sys.stderr, flush=True)
        if inband and self.config.whois_verbose_inband and dbg is not None:
            dbg.append(f"# {message}")

    def _session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "Authorization": f"Token {self.config.netbox_token}",
                    "Accept": "application/json",
                }
            )
            session.verify = self.config.netbox_verify
            self._thread_local.session = session
        return session

    def _cache_get(self, key: str) -> Any:
        if self.config.cache_ttl <= 0:
            return None
        with self._cache_lock:
            item = self._cache.get(key)
        if not item:
            return None
        timestamp, value = item
        if time.time() - timestamp > self.config.cache_ttl:
            with self._cache_lock:
                self._cache.pop(key, None)
            return None
        return value

    def _cache_put(self, key: str, value: Any) -> None:
        if self.config.cache_ttl <= 0:
            return
        with self._cache_lock:
            self._cache[key] = (time.time(), value)

    def api_get(self, path: str, params: Optional[dict] = None, dbg: Optional[list[str]] = None) -> dict:
        key = f"GET:{path}:{sorted((params or {}).items())}"
        cached = self._cache_get(key)
        if cached is not None:
            self.dlog(f"cache HIT {path} {params}", dbg)
            return cached

        url = f"{self.config.netbox_url}{path}"
        self.dlog(f"GET {url} params={params}", dbg)
        response = self._session().get(url, params=params or {}, timeout=self.config.http_timeout)
        try:
            response.raise_for_status()
        except requests.HTTPError:
            self.dlog(f"HTTP {response.status_code} {url}", dbg)
            self.dlog(f"HTTP body={response.text[:200]}", dbg, inband=False)
            raise

        data = response.json()
        self._cache_put(key, data)
        return data

    def paged_get(self, path: str, params: Optional[dict] = None, dbg: Optional[list[str]] = None) -> list[dict]:
        page_params = dict(params or {})
        page_params.setdefault("limit", 200)
        page_params.setdefault("offset", 0)
        items: list[dict] = []

        while True:
            data = self.api_get(path, page_params, dbg)
            items += data.get("results", [])
            if not data.get("next"):
                break
            page_params["offset"] += page_params["limit"]

        self.dlog(f"paged_get {path}: fetched {len(items)} items", dbg)
        return items

    @staticmethod
    def first_result(data: dict) -> Optional[dict]:
        return data.get("results", [None])[0] if data.get("count", 0) > 0 else None

    def api_path_from_url(self, api_url: Optional[str]) -> Optional[str]:
        if not api_url:
            return None
        if api_url.startswith("/api/"):
            return api_url

        base = urlparse(self.config.netbox_url)
        parsed = urlparse(api_url)
        if not parsed.scheme and not parsed.netloc:
            return api_url if api_url.startswith("/api/") else None
        if parsed.scheme != base.scheme or parsed.netloc != base.netloc:
            return None

        base_path = base.path.rstrip("/")
        path = parsed.path
        if base_path and path.startswith(f"{base_path}/api/"):
            return path[len(base_path) :]
        return path if path.startswith("/api/") else None

    def ui_url_from_api_url(self, api_url: Optional[str]) -> Optional[str]:
        path = self.api_path_from_url(api_url)
        if not path:
            return None
        if path.startswith("/api/"):
            path = path[len("/api/") :]
        return f"{self.config.netbox_url}/{path}".rstrip("/")

    def display_url_of(self, obj: Optional[dict]) -> Optional[str]:
        if not isinstance(obj, dict):
            return None
        return obj.get("display_url") or self.ui_url_from_api_url(obj.get("url"))

    def fetch_by_url_or_id(
        self,
        url: Optional[str],
        fallback_path: Optional[str],
        dbg: list[str],
    ) -> Optional[dict]:
        if url:
            path = self.api_path_from_url(url)
            if path:
                return self.api_get(path, dbg=dbg)
            self.dlog(f"ignored non-NetBox API URL {url}", dbg)
        if fallback_path:
            return self.api_get(fallback_path, dbg=dbg)
        return None
