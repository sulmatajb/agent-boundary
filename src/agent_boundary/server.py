"""Authenticated durable intent broker, with a separately authenticated tool sink."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .errors import BoundaryError
from .store import Store
from .transport import StrictHTTPServer, StrictJSONHandler, request_json, strict_json, validate_base_url, validate_token


def _deliver(store, action, sink_url, sink_token):
    if sink_url is None:
        return None
    payload = {field: action[field] for field in ("action_id", "operation", "resource", "value")}
    try:
        result = request_json(sink_url + "/apply", sink_token, payload=payload)
        # This is a trusted adapter, but unexpected replies must never be recorded as success.
        fields = {"resource", "version"}
        if action["operation"] == "document.read":
            fields.add("content")
        if (set(result) != fields
                or result["resource"] != action["resource"]
                or ("content" in fields and type(result["content"]) is not str)
                or type(result["version"]) is not int or result["version"] < 0):
            return None
        store.complete(action["action_id"], result)
        return result
    except (BoundaryError, OSError, TimeoutError):
        # Reservation remains durably charged. A later retry uses the same action ID.
        return None


def create_server(store, host="127.0.0.1", port=0, sink_url=None, sink_token=None):
    if (sink_url is None) != (sink_token is None):
        raise ValueError("Sink URL and credential must both be configured, or both omitted.")
    if sink_url is not None:
        sink_url = validate_base_url(sink_url)
        sink_token = validate_token(sink_token)

    class Handler(StrictJSONHandler):
        def _identity(self):
            return store.authenticate(self.require_bearer())

        def do_GET(self):
            try:
                self.ensure_no_body()
                if self.path == "/health":
                    self.send_json(200, {"status": "ok"})
                    return
                identity = self._identity()
                if self.path != "/v1/audit":
                    raise BoundaryError("not_found", "Route not found.", 404)
                self.send_json(200, store.audit_page(identity["principal"]))
            except BoundaryError as exc:
                self.fail(exc)
            except Exception:
                self.send_json(500, {"error": {"code": "internal_error", "message": "Request failed."}})

        def do_POST(self):
            try:
                identity = self._identity()
                actor = identity["principal"]
                if self.path == "/v1/root":
                    body = self.read_json_object({"owner", "scopes", "budget"})
                    result = {"capability": store.issue_root(actor=actor, **body)}
                elif self.path == "/v1/delegate":
                    body = self.read_json_object({"capability", "owner", "scopes", "budget"})
                    result = {"capability": store.delegate(actor=actor, **body)}
                elif self.path == "/v1/revoke":
                    body = self.read_json_object({"capability"})
                    store.revoke(actor=actor, **body)
                    result = {"revoked": True}
                elif self.path == "/v1/execute":
                    body = self.read_json_object({"capability", "request_id", "operation", "resource", "value"})
                    result = store.reserve(actor=actor, **body)
                    if result["status"] == "pending":
                        delivered = _deliver(store, result, sink_url, sink_token)
                        if delivered is not None:
                            result = {**result, "status": "completed", "result": delivered}
                elif self.path == "/v1/audit-page":
                    body = self.read_json_object({"offset", "limit"})
                    result = store.audit_page(actor=actor, **body)
                elif self.path == "/v1/drain":
                    self.read_json_object(set())
                    if not identity["admin"]:
                        raise BoundaryError("forbidden", "Administrator access is required.", 403)
                    actions = store.dispatch_batch(100)
                    completed = sum(_deliver(store, action, sink_url, sink_token) is not None for action in actions)
                    pending = store.pending_count()
                    result = {"attempted": len(actions), "completed": completed, "pending": pending}
                else:
                    raise BoundaryError("not_found", "Route not found.", 404)
                self.send_json(200, result)
            except BoundaryError as exc:
                self.fail(exc)
            except Exception:
                self.send_json(500, {"error": {"code": "internal_error", "message": "Request failed."}})

    return StrictHTTPServer((host, port), Handler)


def bootstrap_credentials(store, path):
    data = strict_json(Path(path).read_bytes())
    if type(data) is not list or not data:
        raise ValueError("Credentials file must contain a nonempty JSON list.")
    seen = set()
    for entry in data:
        if (type(entry) is not dict or set(entry) != {"principal", "token", "admin"}
                or type(entry["principal"]) is not str or type(entry["admin"]) is not bool
                or entry["principal"] in seen):
            raise ValueError("Each credential must contain a unique principal, token, and boolean admin.")
        seen.add(entry["principal"])
        validate_token(entry["token"])
        try:
            identity = store.authenticate(entry["token"])
        except BoundaryError:
            store.register(entry["principal"], entry["token"], admin=entry["admin"])
        else:
            if identity != {"principal": entry["principal"], "admin": entry["admin"]}:
                raise ValueError("Existing credential identity does not match bootstrap configuration.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--sink-url", required=True)
    parser.add_argument("--sink-token-file", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    store = Store(args.db)
    try:
        bootstrap_credentials(store, args.credentials)
        sink_token = Path(args.sink_token_file).read_text(encoding="utf-8").strip()
        server = create_server(store, args.host, args.port, args.sink_url, sink_token)
    except (BoundaryError, ValueError, OSError):
        parser.error("Broker configuration or credential bootstrap failed.")
    print(json.dumps({"ready": True, "host": args.host, "port": server.server_address[1]}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
