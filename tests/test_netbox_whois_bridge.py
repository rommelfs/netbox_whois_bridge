import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "netbox_whois_bridge.py"


def load_module():
    fake_requests = types.ModuleType("requests")

    class HTTPError(Exception):
        pass

    class Session:
        def __init__(self):
            self.headers = {}
            self.verify = True

        def get(self, *args, **kwargs):
            raise AssertionError("unexpected HTTP call in unit test")

    fake_requests.HTTPError = HTTPError
    fake_requests.Session = Session

    old_requests = sys.modules.get("requests")
    old_env = {key: os.environ.get(key) for key in ("NETBOX_URL", "NETBOX_TOKEN")}
    sys.modules["requests"] = fake_requests
    os.environ["NETBOX_URL"] = "https://netbox.example"
    os.environ["NETBOX_TOKEN"] = "test-token"

    try:
        spec = importlib.util.spec_from_file_location("netbox_whois_bridge_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = old_requests
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class NetboxWhoisBridgeTests(unittest.TestCase):
    def test_ip_detection_accepts_only_valid_ip_networks(self):
        module = load_module()

        self.assertTrue(module.is_ip_like("192.0.2.10"))
        self.assertTrue(module.is_ip_like("192.0.2.10/32"))
        self.assertTrue(module.is_ip_like("2001:db8::1"))
        self.assertTrue(module.is_ip_like("2001:db8::/64"))

        self.assertFalse(module.is_ip_like("db01"))
        self.assertFalse(module.is_ip_like("face"))
        self.assertFalse(module.is_ip_like("deadbeef"))
        self.assertFalse(module.is_ip_like("host.example.com"))

    def test_api_path_from_url_accepts_only_same_netbox_api_urls(self):
        module = load_module()

        self.assertEqual(
            module.api_path_from_url("https://netbox.example/api/dcim/devices/1/"),
            "/api/dcim/devices/1/",
        )
        self.assertEqual(
            module.api_path_from_url("/api/virtualization/virtual-machines/1/"),
            "/api/virtualization/virtual-machines/1/",
        )
        self.assertIsNone(module.api_path_from_url("https://other.example/api/dcim/devices/1/"))
        self.assertIsNone(module.api_path_from_url("/dcim/devices/1/"))

    def test_cluster_q_search_reports_ambiguity(self):
        module = load_module()

        def fake_api_get(path, params=None, dbg=None):
            if params and "name" in params:
                return {"count": 0, "results": []}
            return {"count": 2, "results": [{"name": "cluster-a"}, {"name": "cluster-b"}]}

        module.api_get = fake_api_get

        result = module.cluster_by_name("cluster", [])

        self.assertTrue(result["_ambiguous"])
        self.assertEqual(result["matches"], ["cluster-a", "cluster-b"])


if __name__ == "__main__":
    unittest.main()
