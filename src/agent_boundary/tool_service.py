"""A real document adapter with atomic, durable delivery deduplication.

This service is deliberately small: resources are logical names from a fixed
catalogue, and appends are literal text. It has no path, command, or URL tool.
Its bearer credential belongs to the broker dispatcher, never to workers.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from http.server import ThreadingHTTPServer

from .errors import BoundaryError
from .receipts import MAX_DOCUMENT_BYTES
from .transport import StrictHTTPServer, StrictJSONHandler, validate_token


_RESOURCES = {"source", "draft", "private"}
_OPERATIONS = {"document.read", "document.append"}
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_SEED = {"source": "Sample source text.", "draft": "", "private": "CANARY_PRIVATE"}


def _validate(action_id: str, operation: str, resource: str, value: str | None) -> None:
    if type(action_id) is not str or _IDENTIFIER.fullmatch(action_id) is None:
        raise BoundaryError("invalid_action", "Invalid action identifier", 400)
    if type(operation) is not str or operation not in _OPERATIONS:
        raise BoundaryError("invalid_operation", "Unknown operation", 400)
    if type(resource) is not str or resource not in _RESOURCES:
        raise BoundaryError("invalid_resource", "Unknown resource", 400)
    if operation == "document.read":
        if value is not None:
            raise BoundaryError("invalid_value", "Read value must be null", 400)
    elif type(value) is not str or len(value) > 4096:
        raise BoundaryError("invalid_value", "Append value must be a string of at most 4096 characters", 400)
    # Surrogate code points are not valid Unicode scalar values and cannot be
    # written to SQLite's UTF-8 text columns. Reject them before admission here.
    if type(value) is str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise BoundaryError("invalid_value", "Append value must be valid Unicode", 400) from None


class ToolStore:
    """Separate durable state for documents and delivery outcomes.

    The ledger and document mutation commit in the same SQLite transaction.
    A replay returns the stored result, including an old read result, rather
    than executing the operation again against the current document.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ValueError("ToolStore requires a durable filesystem path")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS documents ("
                "resource TEXT PRIMARY KEY, content TEXT NOT NULL, "
                "version INTEGER NOT NULL CHECK(version >= 0))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS operations ("
                "action_id TEXT PRIMARY KEY, operation TEXT NOT NULL, "
                "resource TEXT NOT NULL REFERENCES documents(resource), "
                "value TEXT, result TEXT NOT NULL)"
            )
            for resource, content in _SEED.items():
                connection.execute(
                    "INSERT OR IGNORE INTO documents(resource, content, version) VALUES (?, ?, 0)",
                    (resource, content),
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def apply(self, action_id: str, operation: str, resource: str, value: str | None) -> dict:
        _validate(action_id, operation, resource, value)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT operation, resource, value, result FROM operations WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            if existing is not None:
                if (existing["operation"], existing["resource"], existing["value"]) != (operation, resource, value):
                    raise BoundaryError("replay_conflict", "Action identifier is already bound to another payload", 409)
                result = json.loads(existing["result"])
                connection.commit()
                return result
            row = connection.execute(
                "SELECT content, version FROM documents WHERE resource = ?", (resource,)
            ).fetchone()
            if row is None:
                raise BoundaryError("unavailable", "Document is unavailable", 503)
            content, version = row["content"], row["version"]
            if operation == "document.append":
                if len(content.encode("utf-8")) + len(value.encode("utf-8")) > MAX_DOCUMENT_BYTES:
                    raise BoundaryError("document_full", "Document exceeds the 64 KiB UTF-8 limit", 409)
                content += value
                version += 1
                connection.execute(
                    "UPDATE documents SET content = ?, version = ? WHERE resource = ?",
                    (content, version, resource),
                )
            # Append authority does not imply read authority. Returning prior
            # content here would turn even an empty append into a forbidden read.
            result = {"resource": resource, "version": version}
            if operation == "document.read":
                if len(content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
                    raise BoundaryError("document_full", "Document exceeds the 64 KiB UTF-8 limit", 409)
                result["content"] = content
            connection.execute(
                "INSERT INTO operations(action_id, operation, resource, value, result) VALUES (?, ?, ?, ?, ?)",
                (action_id, operation, resource, value, json.dumps(result, ensure_ascii=True, separators=(",", ":"))),
            )
            connection.commit()
            return result
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def snapshot(self) -> dict:
        """Trusted local audit only; intentionally not exposed over HTTP."""
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            documents = {
                row["resource"]: {"content": row["content"], "version": row["version"]}
                for row in connection.execute("SELECT resource, content, version FROM documents ORDER BY resource")
            }
            operations = [
                {
                    "action_id": row["action_id"],
                    "operation": row["operation"],
                    "resource": row["resource"],
                    "value": row["value"],
                    "result": json.loads(row["result"]),
                }
                for row in connection.execute("SELECT * FROM operations ORDER BY action_id")
            ]
            connection.commit()
            return {"documents": documents, "operations": operations}
        finally:
            connection.close()


def create_tool_server(
    store: ToolStore, token: str, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    try:
        validate_token(token)
    except BoundaryError:
        raise ValueError("Service credential must be a valid bearer token") from None
    token_digest = hashlib.sha256(token.encode("ascii")).digest()

    class ToolHandler(StrictJSONHandler):
        def do_GET(self) -> None:
            try:
                self.ensure_no_body()
                if self.path != "/health":
                    raise BoundaryError("not_found", "Unknown route", 404)
                self.send_json(200, {"status": "ok"})
            except BoundaryError as error:
                self.fail(error)

        def do_POST(self) -> None:
            try:
                if self.path != "/apply":
                    raise BoundaryError("not_found", "Unknown route", 404)
                supplied = self.require_bearer()
                digest = hashlib.sha256(supplied.encode("utf-8")).digest()
                if not hmac.compare_digest(digest, token_digest):
                    raise BoundaryError("unauthorized", "Invalid service credential", 401)
                body = self.read_json_object({"action_id", "operation", "resource", "value"})
                result = store.apply(body["action_id"], body["operation"], body["resource"], body["value"])
                self.send_json(200, result)
            except BoundaryError as error:
                self.fail(error)
            except Exception:
                # Do not emit tracebacks, request payloads, or credentials.
                self.fail(BoundaryError("internal_error", "Tool service failed", 500))

    server = StrictHTTPServer((host, port), ToolHandler)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8766, type=int)
    args = parser.parse_args()
    try:
        token = args.token_file.read_text(encoding="utf-8").strip()
        server = create_tool_server(ToolStore(args.db), token, args.host, args.port)
    except (OSError, ValueError, sqlite3.Error):
        parser.exit(1, "Unable to initialize tool service; check configuration.\n")
    try:
        print(json.dumps({"ready": True, "host": server.server_address[0], "port": server.server_address[1]}), flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
