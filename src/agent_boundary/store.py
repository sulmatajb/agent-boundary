"""Durable capability authority and admitted-action outbox.

Only this process's trusted bootstrap and dispatcher call register, pending, and
complete. Public methods receive an actor established by authentication, never a
caller-supplied actor field. Authorization linearizes when reserve commits.
"""

from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import sqlite3

from .errors import BoundaryError


RESOURCES = frozenset({"source", "draft", "private"})
OPERATIONS = frozenset({"document.read", "document.append"})
MAX_CAPABILITIES = 4096
MAX_DEPTH = 32
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def _fail(code, message, status=403):
    raise BoundaryError(code, message, status)


def _identifier(value, field):
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _fail("invalid_input", f"Invalid {field}.", 400)
    return value


def _text(value, field):
    if type(value) is not str:
        _fail("invalid_input", f"{field} must be a string.", 400)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _fail("invalid_input", f"{field} must be valid Unicode.", 400)
    return value


def _credential_digest(credential):
    _text(credential, "credential")
    if not 1 <= len(credential) <= 4096:
        _fail("invalid_input", "Invalid credential length.", 400)
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def _budget(budget):
    if type(budget) is not int or not 0 <= budget <= 100000:
        _fail("invalid_input", "Budget must be an integer from 0 to 100000.", 400)
    return budget


def _scopes(scopes):
    if type(scopes) is not list or not scopes:
        _fail("invalid_input", "Scopes must be a nonempty list.", 400)
    pairs = set()
    for pair in scopes:
        if type(pair) is not list or len(pair) != 2:
            _fail("invalid_input", "Each scope must be a two-string list.", 400)
        operation, resource = pair
        if (type(operation) is not str or type(resource) is not str
                or operation not in OPERATIONS or resource not in RESOURCES):
            _fail("invalid_input", "Unknown scope.", 400)
        if (operation, resource) in pairs:
            _fail("invalid_input", "Duplicate scope.", 400)
        pairs.add((operation, resource))
    return sorted(pairs)


def _payload(operation, resource, value):
    if type(operation) is not str or operation not in OPERATIONS:
        _fail("invalid_input", "Unknown operation.", 400)
    if type(resource) is not str or resource not in RESOURCES:
        _fail("invalid_input", "Unknown resource.", 400)
    if operation == "document.read":
        if value is not None:
            _fail("invalid_input", "Reads require a null value.", 400)
    else:
        _text(value, "value")
        if len(value) > 4096:
            _fail("invalid_input", "Append value exceeds 4096 characters.", 400)


def _json_result(value):
    """Accept only detached, exact JSON types; never custom encoders or NaN."""
    if type(value) is not dict:
        _fail("invalid_input", "Result must be a JSON object.", 400)

    def validate(item, depth=0):
        if depth > 64:
            _fail("invalid_input", "Result nesting is too deep.", 400)
        kind = type(item)
        if kind is str:
            _text(item, "result text")
        elif item is None or kind in (bool, int):
            pass
        elif kind is float:
            if not math.isfinite(item):
                _fail("invalid_input", "Result numbers must be finite.", 400)
        elif kind is list:
            for child in item:
                validate(child, depth + 1)
        elif kind is dict:
            for key, child in item.items():
                _text(key, "result key")
                validate(child, depth + 1)
        else:
            _fail("invalid_input", "Result must contain only JSON types.", 400)

    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Store:
    """One durable SQLite file, one connection per transaction.

    Delegation shares ancestor quotas without reserving them. Spent counts every
    admitted action, including unresolved outcomes, and is never refunded.
    """

    def __init__(self, path: str | Path):
        if not isinstance(path, (str, Path)) or not str(path) or str(path) == ":memory:":
            _fail("invalid_input", "A persistent database path is required.", 400)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS principals (
                    name TEXT PRIMARY KEY,
                    credential_digest TEXT NOT NULL UNIQUE,
                    admin INTEGER NOT NULL CHECK (admin IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS capabilities (
                    id TEXT PRIMARY KEY,
                    principal TEXT NOT NULL REFERENCES principals(name),
                    parent TEXT REFERENCES capabilities(id),
                    scopes TEXT NOT NULL,
                    quota INTEGER NOT NULL CHECK (quota BETWEEN 0 AND 100000),
                    spent INTEGER NOT NULL DEFAULT 0 CHECK (spent >= 0 AND spent <= quota),
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    capability TEXT NOT NULL REFERENCES capabilities(id),
                    request_id TEXT NOT NULL,
                    principal TEXT NOT NULL REFERENCES principals(name),
                    operation TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    value TEXT,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'completed')),
                    result TEXT,
                    UNIQUE (capability, request_id),
                    CHECK ((status = 'pending' AND result IS NULL)
                        OR (status = 'completed' AND result IS NOT NULL))
                );
                CREATE INDEX IF NOT EXISTS pending_actions ON actions(status);
                CREATE TABLE IF NOT EXISTS delivery_attempts (
                    action_id TEXT PRIMARY KEY REFERENCES actions(action_id),
                    attempts INTEGER NOT NULL CHECK (attempts >= 0)
                );
                COMMIT;
            """)
        finally:
            connection.close()

    def _connect(self):
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _transaction(self, mutation=False):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if mutation else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _principal(connection, principal):
        _identifier(principal, "principal")
        row = connection.execute("SELECT * FROM principals WHERE name = ?", (principal,)).fetchone()
        if row is None:
            _fail("unknown_principal", "Unknown principal.")
        return row

    @classmethod
    def _admin(cls, connection, actor):
        if not cls._principal(connection, actor)["admin"]:
            _fail("forbidden", "Administrator authority required.")

    @staticmethod
    def _capability(connection, capability):
        _identifier(capability, "capability")
        row = connection.execute("SELECT * FROM capabilities WHERE id = ?", (capability,)).fetchone()
        if row is None:
            _fail("unknown_capability", "Unknown capability.")
        return row

    @classmethod
    def _owned(cls, connection, actor, capability):
        cls._principal(connection, actor)
        row = cls._capability(connection, capability)
        if row["principal"] != actor:
            _fail("forbidden", "Capability belongs to another principal.")
        return row

    @classmethod
    def _lineage(cls, connection, capability):
        lineage, seen = [], set()
        row = capability
        while row is not None:
            if row["id"] in seen or len(lineage) >= MAX_DEPTH:
                _fail("invalid_lineage", "Capability lineage is invalid.")
            seen.add(row["id"])
            lineage.append(row)
            row = cls._capability(connection, row["parent"]) if row["parent"] else None
        return lineage

    @staticmethod
    def _live(lineage):
        if any(row["revoked"] for row in lineage):
            _fail("revoked", "Capability lineage has been revoked.")

    @staticmethod
    def _capacity(connection):
        if connection.execute("SELECT COUNT(*) FROM capabilities").fetchone()[0] >= MAX_CAPABILITIES:
            _fail("capability_limit", "Capability limit reached.", 409)

    @staticmethod
    def _action(row, replayed=None):
        result = dict(row)
        result["result"] = json.loads(result["result"]) if result["result"] is not None else None
        if replayed is not None:
            result = {key: result[key] for key in (
                "action_id", "status", "operation", "resource", "value", "result")}
            result["replayed"] = replayed
        return result

    def register(self, principal: str, credential: str, admin: bool = False) -> None:
        _identifier(principal, "principal")
        digest = _credential_digest(credential)
        if type(admin) is not bool:
            _fail("invalid_input", "Admin must be a boolean.", 400)
        with self._transaction(mutation=True) as connection:
            try:
                connection.execute("INSERT INTO principals VALUES (?, ?, ?)", (principal, digest, int(admin)))
            except sqlite3.IntegrityError:
                _fail("duplicate_principal", "Principal or credential already registered.", 409)

    def authenticate(self, credential: str) -> dict:
        digest = _credential_digest(credential)
        with self._transaction() as connection:
            row = connection.execute("SELECT name, admin FROM principals WHERE credential_digest = ?", (digest,)).fetchone()
            if row is None:
                _fail("unauthorized", "Invalid credential.", 401)
            return {"principal": row["name"], "admin": bool(row["admin"])}

    def issue_root(self, actor: str, owner: str, scopes: list[list[str]], budget: int) -> str:
        checked_scopes = _scopes(scopes)
        _budget(budget)
        with self._transaction(mutation=True) as connection:
            self._admin(connection, actor)
            self._principal(connection, owner)
            self._capacity(connection)
            capability = "cap_" + secrets.token_hex(24)
            connection.execute(
                "INSERT INTO capabilities(id, principal, parent, scopes, quota) VALUES (?, ?, NULL, ?, ?)",
                (capability, owner, json.dumps(checked_scopes), budget))
            return capability

    def delegate(self, actor: str, capability: str, owner: str, scopes: list[list[str]], budget: int) -> str:
        checked_scopes = _scopes(scopes)
        _budget(budget)
        with self._transaction(mutation=True) as connection:
            parent = self._owned(connection, actor, capability)
            self._principal(connection, owner)
            lineage = self._lineage(connection, parent)
            self._live(lineage)
            if len(lineage) >= MAX_DEPTH:
                _fail("depth_limit", "Capability depth limit reached.", 409)
            if not set(checked_scopes).issubset({tuple(pair) for pair in json.loads(parent["scopes"])}):
                _fail("scope_denied", "Delegation cannot broaden scopes.")
            if any(budget > row["quota"] - row["spent"] for row in lineage):
                _fail("budget_exceeded", "Delegation exceeds remaining ancestor quota.")
            self._capacity(connection)
            child = "cap_" + secrets.token_hex(24)
            connection.execute(
                "INSERT INTO capabilities(id, principal, parent, scopes, quota) VALUES (?, ?, ?, ?, ?)",
                (child, owner, capability, json.dumps(checked_scopes), budget))
            return child

    def revoke(self, actor: str, capability: str) -> None:
        with self._transaction(mutation=True) as connection:
            principal = self._principal(connection, actor)
            row = self._capability(connection, capability)
            if not principal["admin"] and row["principal"] != actor:
                _fail("forbidden", "Only the owner or administrator can revoke.")
            connection.execute("UPDATE capabilities SET revoked = 1 WHERE id = ?", (capability,))

    def reserve(self, actor: str, capability: str, request_id: str, operation: str,
                resource: str, value: str | None = None) -> dict:
        _identifier(request_id, "request_id")
        _payload(operation, resource, value)
        with self._transaction(mutation=True) as connection:
            leaf = self._owned(connection, actor, capability)
            existing = connection.execute(
                "SELECT * FROM actions WHERE capability = ? AND request_id = ?", (capability, request_id)).fetchone()
            if existing is not None:
                if (existing["operation"], existing["resource"], existing["value"]) != (operation, resource, value):
                    _fail("request_conflict", "Request ID is already bound to a different payload.", 409)
                return self._action(existing, replayed=True)
            lineage = self._lineage(connection, leaf)
            self._live(lineage)
            for row in lineage:
                if [operation, resource] not in json.loads(row["scopes"]):
                    _fail("scope_denied", "Operation and resource are outside the capability scope.")
                if row["spent"] >= row["quota"]:
                    _fail("budget_exceeded", "Capability lineage quota is exhausted.")
            action_id = "act_" + secrets.token_hex(24)
            for row in lineage:
                connection.execute("UPDATE capabilities SET spent = spent + 1 WHERE id = ?", (row["id"],))
            connection.execute(
                "INSERT INTO actions(action_id, capability, request_id, principal, operation, resource, value, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                (action_id, capability, request_id, actor, operation, resource, value))
            row = connection.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()
            return self._action(row, replayed=False)

    def pending(self, limit: int = 100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100000:
            _fail("invalid_input", "Pending limit must be an integer from 1 to 100000.", 400)
        with self._transaction() as connection:
            rows = connection.execute("SELECT * FROM actions WHERE status = 'pending' ORDER BY rowid LIMIT ?", (limit,)).fetchall()
            return [self._action(row) for row in rows]

    def complete(self, action_id: str, result: dict) -> None:
        _identifier(action_id, "action_id")
        encoded = _json_result(result)
        with self._transaction(mutation=True) as connection:
            row = connection.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()
            if row is None:
                _fail("unknown_action", "Unknown action.", 404)
            if row["status"] == "completed":
                if row["result"] != encoded:
                    _fail("result_conflict", "Completed action has a different result.", 409)
                return
            connection.execute("UPDATE actions SET status = 'completed', result = ? WHERE action_id = ?", (encoded, action_id))

    def dispatch_batch(self, limit: int = 100) -> list[dict]:
        """Durably rotate recovery attempts so poison intents cannot block a batch.

        This is scheduling, not an exclusive delivery lease. Racing dispatchers
        remain safe because the adapter deduplicates the durable action ID.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            _fail("invalid_input", "Dispatch limit must be an integer from 1 to 1000.", 400)
        with self._transaction(mutation=True) as connection:
            rows = connection.execute(
                "SELECT actions.* FROM actions LEFT JOIN delivery_attempts USING(action_id) "
                "WHERE status = 'pending' ORDER BY COALESCE(attempts, 0), actions.rowid LIMIT ?",
                (limit,)).fetchall()
            for row in rows:
                connection.execute(
                    "INSERT INTO delivery_attempts(action_id, attempts) VALUES (?, 1) "
                    "ON CONFLICT(action_id) DO UPDATE SET attempts = attempts + 1", (row["action_id"],))
            return [self._action(row) for row in rows]

    def pending_count(self) -> int:
        """Count unresolved intents without loading stored document snapshots."""
        with self._transaction() as connection:
            return connection.execute("SELECT COUNT(*) FROM actions WHERE status = 'pending'").fetchone()[0]

    def audit_page(self, actor: str, offset: int = 0, limit: int = 100) -> dict:
        """Bounded HTTP audit metadata; complete payloads remain trusted-local only.

        Actions are append-only and ordered by rowid, so an offset never shifts
        because a later action is completed or a new action is admitted.
        """
        if type(offset) is not int or not 0 <= offset <= 2**63 - 1:
            _fail("invalid_input", "Audit offset must be a nonnegative 64-bit integer.", 400)
        if type(limit) is not int or not 1 <= limit <= 1000:
            _fail("invalid_input", "Audit limit must be an integer from 1 to 1000.", 400)
        with self._transaction() as connection:
            self._admin(connection, actor)
            capabilities = {}
            for row in connection.execute("SELECT * FROM capabilities ORDER BY rowid"):
                capabilities[row["id"]] = {
                    "principal": row["principal"], "parent": row["parent"],
                    "scopes": json.loads(row["scopes"]), "limit": row["quota"],
                    "spent": row["spent"], "revoked": bool(row["revoked"])}
            actions = [dict(row) for row in connection.execute(
                "SELECT action_id, capability, request_id, principal, operation, resource, status "
                "FROM actions ORDER BY rowid LIMIT ? OFFSET ?", (limit, offset))]
            total = connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
            next_offset = offset + len(actions)
            principals = [row["name"] for row in connection.execute("SELECT name FROM principals ORDER BY name")]
            return {"capabilities": capabilities, "actions": actions, "principals": principals,
                    "total_actions": total, "next_offset": next_offset if next_offset < total else None}

    def snapshot(self, actor: str) -> dict:
        with self._transaction() as connection:
            self._admin(connection, actor)
            capabilities = {}
            for row in connection.execute("SELECT * FROM capabilities ORDER BY rowid"):
                capabilities[row["id"]] = {
                    "principal": row["principal"], "parent": row["parent"],
                    "scopes": json.loads(row["scopes"]), "limit": row["quota"],
                    "spent": row["spent"], "revoked": bool(row["revoked"])}
            actions = [self._action(row) for row in connection.execute("SELECT * FROM actions ORDER BY rowid")]
            principals = [row["name"] for row in connection.execute("SELECT name FROM principals ORDER BY name")]
            return {"capabilities": capabilities, "actions": actions, "principals": principals}
