import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import setup_sqli_demo as demo


class FakeRestClient:
    def __init__(self, responses):
        self.responses = responses
        self.writes = []

    def request(self, method, path, payload=None, expected=(200,)):
        if method == "GET":
            return self.responses.get(path, (404, None))
        self.writes.append((method, path, payload))
        return expected[0], None


class DemoSetupTests(unittest.TestCase):
    def test_requires_a_local_target_and_preserves_the_application_path(self):
        self.assertEqual(demo.local_target("http://127.0.0.1:8080/maps/"), "http://127.0.0.1:8080/maps")
        for target in ("https://example.org/maps", "ftp://localhost/maps", "http://admin:secret@localhost/maps", "http://localhost/maps?token=secret"):
            with self.assertRaises(ValueError):
                demo.local_target(target)

    def test_creates_only_the_named_demo_resources(self):
        client = FakeRestClient({})
        demo.publish_demo(client)
        self.assertEqual(len(client.writes), 4)
        methods = [method for method, _, _ in client.writes]
        self.assertEqual(methods, ["POST", "PUT", "POST", "POST"])
        store = client.writes[2][2]["dataStore"]
        parameters = {entry["@key"]: entry["$"] for entry in store["connectionParameters"]["entry"]}
        self.assertEqual(parameters["user"], "geoscan_reader")
        self.assertEqual(parameters["preparedStatements"], "true")
        self.assertEqual(client.writes[3][2]["featureType"]["nativeName"], "items")

    def test_rerunning_does_not_overwrite_existing_demo_configuration(self):
        workspace = f"workspaces/{demo.WORKSPACE}"
        store = f"{workspace}/datastores/{demo.STORE}"
        entries = [{"@key": key, "$": value} for key, value in demo.store_parameters().items()]
        client = FakeRestClient({
            workspace + ".json": (200, {"workspace": {"name": demo.WORKSPACE}}),
            f"namespaces/{demo.WORKSPACE}.json": (200, {"namespace": {"uri": demo.NAMESPACE}}),
            store + ".json": (200, {"dataStore": {"connectionParameters": {"entry": entries}}}),
            store + "/featuretypes/items.json": (200, {"featureType": {"nativeName": "items"}}),
        })
        demo.publish_demo(client)
        self.assertEqual(client.writes, [])

    def test_stops_if_the_workspace_name_belongs_to_another_configuration(self):
        client = FakeRestClient({
            f"workspaces/{demo.WORKSPACE}.json": (200, {}),
            f"namespaces/{demo.WORKSPACE}.json": (200, {"namespace": {"uri": "https://example.org/existing"}}),
        })
        with self.assertRaisesRegex(RuntimeError, "already belongs"):
            demo.publish_demo(client)
        self.assertEqual(client.writes, [])

    def test_http_errors_do_not_disclose_server_error_bodies(self):
        client = demo.RestClient(demo.DEFAULT_TARGET, "admin", "synthetic-admin-password")
        error = urllib.error.HTTPError("http://localhost/rest/workspaces", 500, "failure", {}, io.BytesIO(b"sensitive server error body"))
        with patch.object(client.opener, "open", side_effect=error):
            with self.assertRaises(RuntimeError) as result:
                client.request("GET", "workspaces.json")
        self.assertIn("HTTP 500", str(result.exception))
        self.assertNotIn("sensitive", str(result.exception))
        self.assertNotIn("synthetic-admin-password", str(result.exception))

    def test_authenticated_requests_cannot_follow_redirects(self):
        handler = demo.NoRedirects()
        self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "http://other.invalid/"))


if __name__ == "__main__":
    unittest.main()
