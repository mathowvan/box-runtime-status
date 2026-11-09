import http.client
import io
import json
import math
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import runtime_status as app


class FormattingTests(unittest.TestCase):
    def test_format_bytes_binary_units_and_unavailable_values(self):
        cases = [
            (0, "0 B"), (1, "1 B"), (1023, "1023 B"),
            (1024, "1.00 KB"), (1048576, "1.00 MB"),
            (1073741824, "1.00 GB"), (322239832064, "300.11 GB"),
            (None, "不可用"), (-1, "不可用"), (math.inf, "不可用"),
            (math.nan, "不可用"), (True, "不可用"),
            ("not-a-number", "不可用"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(app.format_bytes(value), expected)

    def test_percent_handles_missing_and_invalid_values(self):
        self.assertIsNone(app.percent(None, 100))
        self.assertIsNone(app.percent(1, 0))
        self.assertIsNone(app.percent(-1, 100))
        self.assertIsNone(app.percent(math.inf, 100))
        self.assertEqual(app.percent(1, 4), 25.0)
        self.assertEqual(app.percent(200, 100), 100.0)


class CollectionTests(unittest.TestCase):
    def test_cgroup_memory_reads_v2_and_v1_without_leaking_file_contents(self):
        values = {
            "/sys/fs/cgroup/memory.current": "2048",
            "/sys/fs/cgroup/memory.max": "4096",
        }
        with mock.patch.object(app, "read_text", side_effect=lambda path, limit=128: values.get(path)), \
             mock.patch.object(app, "disk_usage", return_value=mock.Mock(used=20, free=80, total=100)), \
             mock.patch.object(app, "get_hostname", return_value="box-host"), \
             mock.patch.object(app, "get_local_ip", return_value="10.0.0.2"), \
             mock.patch.object(app, "get_public_egress_ip", return_value="203.0.113.8"), \
             mock.patch.object(app, "collect_environment", return_value={"SERVER_PORT": "8000"}):
            data = app.collect_status()
        self.assertEqual(data["memory"], {"used_bytes": 2048, "limit_bytes": 4096})
        self.assertNotIn("/sys/fs/cgroup", json.dumps(data))

    def test_cgroup_unlimited_invalid_or_unavailable_values(self):
        values = {
            "/sys/fs/cgroup/memory.current": "invalid",
            "/sys/fs/cgroup/memory/memory.usage_in_bytes": "0",
            "/sys/fs/cgroup/memory.max": "max",
            "/sys/fs/cgroup/memory/memory.limit_in_bytes": str(1 << 62),
        }
        with mock.patch.object(app, "read_text", side_effect=lambda path, limit=128: values.get(path)):
            self.assertEqual(app._first_integer(app._MEMORY_USED_FILES, allow_zero=True), 0)
            self.assertIsNone(app._first_integer(app._MEMORY_LIMIT_FILES, allow_zero=False))

    def test_environment_allowlist_normalizes_values_and_omits_unlisted_keys(self):
        secret_marker = "TEST_PRIVATE_VALUE_7f8a"
        environ = {
            "SERVER_PORT": "08000",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "off",
            "TZ": "UTC",
            "DATABASE_URL": secret_marker,
            "AWS_SECRET_ACCESS_KEY": secret_marker,
            "PATH": "/sensitive/path",
        }

        result = app.collect_environment(environ)

        self.assertEqual(set(app.SAFE_ENVIRONMENT_VARIABLES), {
            "SERVER_PORT", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "TZ",
        })
        self.assertEqual(result, {
            "SERVER_PORT": "8000",
            "PYTHONUNBUFFERED": True,
            "PYTHONDONTWRITEBYTECODE": False,
            "TZ": "UTC",
        })
        self.assertNotIn(secret_marker, json.dumps(result))
        self.assertNotIn("PATH", result)
        self.assertNotIn("DATABASE_URL", result)

    def test_environment_rejects_unrecognized_or_malformed_values(self):
        secret_marker = "DO_NOT_EXPOSE_ABC123"
        environ = {
            "SERVER_PORT": secret_marker,
            "PYTHONUNBUFFERED": secret_marker,
            "PYTHONDONTWRITEBYTECODE": "maybe-" + secret_marker,
            "TZ": "../" + secret_marker,
            "API_TOKEN": secret_marker,
        }
        self.assertEqual(app.collect_environment(environ), {})

    def test_status_contains_added_fields_and_only_allowlisted_environment(self):
        secret_marker = "TEST_PRIVATE_VALUE_7f8a"
        environ = {
            "SERVER_PORT": "8000",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "0",
            "TZ": "UTC",
            "UNRELATED_PRIVATE_VALUE": secret_marker,
            "API_KEY": secret_marker,
        }
        with mock.patch.dict(os.environ, environ, clear=True), \
             mock.patch.object(app, "read_text", return_value=None), \
             mock.patch.object(app, "disk_usage", return_value=mock.Mock(used=20, free=80, total=100)), \
             mock.patch.object(app, "get_hostname", return_value="status-host"), \
             mock.patch.object(app, "get_local_ip", return_value="10.1.2.3"), \
             mock.patch.object(app, "get_public_egress_ip", return_value="203.0.113.9"), \
             mock.patch.object(app, "_STARTED_AT", 90), \
             mock.patch.object(app.time, "monotonic", return_value=95):
            data = app.collect_status()

        self.assertEqual(set(data), {
            "generated_at_utc", "service_uptime_seconds", "hostname", "local_ip",
            "public_egress_ip", "environment", "memory", "disk",
        })
        self.assertEqual(data["hostname"], "status-host")
        self.assertEqual(data["local_ip"], "10.1.2.3")
        self.assertEqual(data["public_egress_ip"], "203.0.113.9")
        self.assertEqual(data["service_uptime_seconds"], 5)
        self.assertEqual(data["disk"], {"used_bytes": 20, "available_bytes": 80, "total_bytes": 100})
        self.assertEqual(data["environment"], {
            "SERVER_PORT": "8000",
            "PYTHONUNBUFFERED": True,
            "PYTHONDONTWRITEBYTECODE": False,
            "TZ": "UTC",
        })
        serialized = json.dumps(data)
        self.assertNotIn(secret_marker, serialized)
        self.assertNotIn("UNRELATED_PRIVATE_VALUE", serialized)
        self.assertNotIn("API_KEY", serialized)

    def test_public_ip_response_is_validated_and_uses_fixed_endpoint(self):
        with mock.patch.object(app, "urlopen", return_value=io.BytesIO(b"203.0.113.8\n")) as opened:
            self.assertEqual(app.get_public_egress_ip(), "203.0.113.8")
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.ipify.org")
        self.assertEqual(opened.call_args.kwargs, {"timeout": 2})

        with mock.patch.object(app, "urlopen", return_value=io.BytesIO(b"NOT_AN_IP_SECRET")):
            self.assertIsNone(app.get_public_egress_ip())

    def test_collection_tolerates_unreadable_disk(self):
        with mock.patch.object(app, "read_text", return_value=None), \
             mock.patch.object(app, "disk_usage", side_effect=OSError("unavailable")), \
             mock.patch.object(app, "get_hostname", return_value=None), \
             mock.patch.object(app, "get_local_ip", return_value=None), \
             mock.patch.object(app, "get_public_egress_ip", return_value=None), \
             mock.patch.object(app, "collect_environment", return_value={}):
            data = app.collect_status()
        self.assertEqual(data["disk"], {"used_bytes": None, "available_bytes": None, "total_bytes": None})

    def test_cache_returns_independent_snapshot(self):
        app._CACHE.update(at=0.0, data=None)
        sample = {"generated_at_utc": "2030-01-01T00:00:00Z", "service_uptime_seconds": 2,
                  "memory": {"used_bytes": 1, "limit_bytes": 2},
                  "disk": {"used_bytes": 1, "available_bytes": 9, "total_bytes": 10}}
        try:
            with mock.patch.object(app.time, "monotonic", return_value=100), \
                 mock.patch.object(app, "collect_status", return_value=sample) as collect:
                first = app.status()
                first["memory"]["used_bytes"] = 999
                second = app.status()
            self.assertEqual(second["memory"]["used_bytes"], 1)
            collect.assert_called_once()
        finally:
            app._CACHE.update(at=0.0, data=None)


class HtmlTests(unittest.TestCase):
    def test_html_escapes_values_and_renders_added_details(self):
        data = {
            "generated_at_utc": "2030-01-02T03:04:05Z<script>",
            "service_uptime_seconds": 12,
            "hostname": "<host>",
            "local_ip": "10.0.0.2",
            "public_egress_ip": "203.0.113.8",
            "environment": {"SERVER_PORT": "8000", "PYTHONUNBUFFERED": True},
            "memory": {"used_bytes": 1073741824, "limit_bytes": 2147483648},
            "disk": {"used_bytes": 2, "available_bytes": 8, "total_bytes": 10},
        }
        page = app.render_page(data)
        self.assertIn("1.00 GB", page)
        self.assertIn("50.0%", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;host&gt;", page)
        self.assertNotIn("<host>", page)
        self.assertIn("10.0.0.2", page)
        self.assertIn("203.0.113.8", page)
        self.assertIn("8000", page)
        self.assertIn("Python 无缓冲输出", page)
        self.assertIn("是", page)
        self.assertIn("api.ipify.org", page)
        self.assertIn("color-scheme:dark", page)
        self.assertIn("/api/status", page)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read()
        headers = dict(response.getheaders())
        status_code = response.status
        connection.close()
        return status_code, headers, body

    @mock.patch.object(app, "status", return_value={
        "generated_at_utc": "2030-01-02T03:04:05Z", "service_uptime_seconds": 42,
        "hostname": "api-host", "local_ip": "10.0.0.2", "public_egress_ip": "203.0.113.8",
        "environment": {"SERVER_PORT": "8000"},
        "memory": {"used_bytes": 1024, "limit_bytes": 2048},
        "disk": {"used_bytes": 2, "available_bytes": 8, "total_bytes": 10},
    })
    def test_json_api_and_security_headers(self, _status):
        code, headers, body = self.request("GET", "/api/status")
        data = json.loads(body)
        self.assertEqual(code, 200)
        self.assertEqual(data["service_uptime_seconds"], 42)
        self.assertEqual(data["disk"]["used_bytes"], 2)
        self.assertEqual(data["hostname"], "api-host")
        self.assertEqual(data["local_ip"], "10.0.0.2")
        self.assertEqual(data["public_egress_ip"], "203.0.113.8")
        self.assertEqual(data["environment"]["SERVER_PORT"], "8000")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_health_route_and_method_errors(self):
        code, _, body = self.request("GET", "/healthz")
        self.assertEqual((code, body), (200, b"ok\n"))
        self.assertEqual(self.request("GET", "/missing")[0], 404)
        self.assertEqual(self.request("POST", "/")[0], 405)

    @mock.patch.object(app, "status", return_value={
        "generated_at_utc": "2030-01-02T03:04:05Z", "service_uptime_seconds": 1,
        "hostname": "api-host", "local_ip": "10.0.0.2", "public_egress_ip": None,
        "environment": {"SERVER_PORT": "8000"},
        "memory": {"used_bytes": None, "limit_bytes": None},
        "disk": {"used_bytes": None, "available_bytes": None, "total_bytes": None},
    })
    def test_root_returns_html(self, _status):
        code, headers, body = self.request("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("运行环境状态".encode(), body)
        self.assertIn("api-host".encode(), body)


if __name__ == "__main__":
    unittest.main()
