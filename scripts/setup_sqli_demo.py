#!/usr/bin/env python3
"""Publish synthetic PostGIS data to the local GeoServer learning lab."""

import argparse
import base64
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

WORKSPACE = "geoscan_sqli_demo"
STORE = "postgis_demo"
NAMESPACE = "https://geoscan.local/sqli-demo"
DEFAULT_TARGET = "http://127.0.0.1:8080/geoserver"


def local_target(value):
    target = urllib.parse.urlsplit(value.strip())
    if (
        target.scheme not in ("http", "https")
        or target.hostname not in ("127.0.0.1", "localhost", "::1")
        or target.username is not None
        or target.password is not None
        or target.query
        or target.fragment
    ):
        raise ValueError("Demo setup requires a local HTTP/HTTPS application URL without credentials or query parameters")
    return value.strip().rstrip("/")


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RestClient:
    def __init__(self, target, username, password):
        self.target = local_target(target)
        self.authorization = "Basic " + base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects)

    def request(self, method, path, payload=None, expected=(200,)):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.target}/rest/{path}",
            data=body,
            method=method,
            headers={
                "Authorization": self.authorization,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=15) as response:
                if response.status not in expected:
                    raise RuntimeError(f"REST {method} {path}: HTTP {response.status}")
                if method != "GET":
                    return response.status, None
                data = response.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise RuntimeError("REST response exceeded the size limit")
                return response.status, json.loads(data)
        except urllib.error.HTTPError as error:
            if error.code == 404 and 404 in expected:
                return 404, None
            # Error bodies may contain configuration secrets; print only status.
            raise RuntimeError(f"REST {method} {path}: HTTP {error.code}") from None
        except (urllib.error.URLError, OSError):
            raise RuntimeError("Could not connect to the local GeoServer; start Docker Compose and wait for GeoServer") from None


def store_parameters():
    return {
        "dbtype": "postgis",
        "host": "postgis-demo",
        "port": "5432",
        "database": "geoscan_demo",
        "schema": "geoscan",
        "user": "geoscan_reader",
        "passwd": "geoscan-demo-readonly",
        "preparedStatements": "true",
        "Expose primary keys": "true",
    }


def publish_demo(client):
    workspace_path = f"workspaces/{WORKSPACE}"
    status, _ = client.request("GET", workspace_path + ".json", expected=(200, 404))
    if status == 404:
        client.request("POST", "workspaces", {"workspace": {"name": WORKSPACE}}, expected=(201,))
        client.request("PUT", f"namespaces/{WORKSPACE}", {"namespace": {"prefix": WORKSPACE, "uri": NAMESPACE}})
    else:
        _, namespace = client.request("GET", f"namespaces/{WORKSPACE}.json")
        if namespace.get("namespace", {}).get("uri") != NAMESPACE:
            raise RuntimeError("The demo workspace name already belongs to another configuration; setup stopped")

    store_path = f"{workspace_path}/datastores/{STORE}"
    status, existing = client.request("GET", store_path + ".json", expected=(200, 404))
    parameters = store_parameters()
    if status == 404:
        entries = [{"@key": key, "$": value} for key, value in parameters.items()]
        client.request("POST", workspace_path + "/datastores", {
            "dataStore": {"name": STORE, "connectionParameters": {"entry": entries}}
        }, expected=(201,))
    else:
        entries = existing.get("dataStore", {}).get("connectionParameters", {}).get("entry", [])
        stored = {entry["@key"]: entry.get("$") for entry in entries}
        for key in ("dbtype", "host", "database", "schema", "user"):
            if stored.get(key) != parameters[key]:
                raise RuntimeError("The demo datastore name already belongs to another configuration; setup stopped")

    feature_path = f"{store_path}/featuretypes/items"
    status, existing = client.request("GET", feature_path + ".json", expected=(200, 404))
    if status == 404:
        client.request("POST", store_path + "/featuretypes", {
            "featureType": {
                "name": "items", "nativeName": "items", "title": "GeoScan SQLi demo",
                "srs": "EPSG:4326", "enabled": True, "advertised": False,
            }
        }, expected=(201,))
    elif existing.get("featureType", {}).get("nativeName") != "items":
        raise RuntimeError("The demo feature name already belongs to another configuration; setup stopped")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()
    try:
        target = local_target(args.target)
        if not args.username or ":" in args.username or any(ord(ch) < 32 for ch in args.username):
            raise ValueError("Provide a valid GeoServer username")
        password = os.environ.get("GEOSCAN_PASSWORD")
        if not password:
            if not sys.stdin.isatty() or not sys.stderr.isatty():
                raise ValueError("Run setup in a terminal or supply GEOSCAN_PASSWORD in the environment")
            password = getpass.getpass("GeoServer administrator password (hidden): ")
        if not password:
            raise ValueError("Password cannot be blank")
        publish_demo(RestClient(target, args.username, password))
    except (ValueError, RuntimeError, KeyError) as error:
        print(f"Demo setup failed: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nDemo setup cancelled", file=sys.stderr)
        return 1
    print(f"Demo layer ready: {WORKSPACE}:items (String property: json_data)")
    print("Run geoscan scan with the same target. The checks remain unauthenticated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
