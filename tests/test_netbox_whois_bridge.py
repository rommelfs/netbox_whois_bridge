import sys
import types
import unittest


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
sys.modules.setdefault("requests", fake_requests)

from netbox_whois_bridge.config import Config
from netbox_whois_bridge.netbox import NetBoxClient
from netbox_whois_bridge.resolver import Resolver
from netbox_whois_bridge.utils import is_ip_like


class FakeClient:
    def __init__(self, api_get):
        self.api_get = api_get


class NetboxWhoisBridgeTests(unittest.TestCase):
    def test_ip_detection_accepts_only_valid_ip_networks(self):
        self.assertTrue(is_ip_like("192.0.2.10"))
        self.assertTrue(is_ip_like("192.0.2.10/32"))
        self.assertTrue(is_ip_like("2001:db8::1"))
        self.assertTrue(is_ip_like("2001:db8::/64"))

        self.assertFalse(is_ip_like("db01"))
        self.assertFalse(is_ip_like("face"))
        self.assertFalse(is_ip_like("deadbeef"))
        self.assertFalse(is_ip_like("host.example.com"))

    def test_api_path_from_url_accepts_only_same_netbox_api_urls(self):
        config = Config.from_env(
            {
                "NETBOX_URL": "https://netbox.example",
                "NETBOX_TOKEN": "test-token",
            }
        )
        client = NetBoxClient(config)

        self.assertEqual(
            client.api_path_from_url("https://netbox.example/api/dcim/devices/1/"),
            "/api/dcim/devices/1/",
        )
        self.assertEqual(
            client.api_path_from_url("/api/virtualization/virtual-machines/1/"),
            "/api/virtualization/virtual-machines/1/",
        )
        self.assertIsNone(client.api_path_from_url("https://other.example/api/dcim/devices/1/"))
        self.assertIsNone(client.api_path_from_url("/dcim/devices/1/"))

    def test_cluster_q_search_reports_ambiguity(self):
        def fake_api_get(path, params=None, dbg=None):
            if params and "name" in params:
                return {"count": 0, "results": []}
            return {"count": 2, "results": [{"name": "cluster-a"}, {"name": "cluster-b"}]}

        resolver = Resolver(config=None, client=FakeClient(fake_api_get))

        result = resolver.cluster_by_name("cluster", [])

        self.assertTrue(result["_ambiguous"])
        self.assertEqual(result["matches"], ["cluster-a", "cluster-b"])


if __name__ == "__main__":
    unittest.main()
