"""Receipt contract shared by durable delivery and the supervisor.

A false result is ambiguous after dispatch, never evidence that the tool was
not contacted. Callers must preserve pending state and its admission charge.
"""

from .catalogue import FIXTURE_SECRET_NAMES

MAX_DOCUMENT_BYTES = 64 * 1024


def is_document_receipt(result: object, operation: str, resource: str) -> bool:
    """Accept only the documented receipt for the requested document action.

    A false result is ambiguous after dispatch, never evidence of a denied or
    uncommitted action. Callers must preserve pending state and its admission charge.
    """
    if type(result) is not dict or operation not in {"document.read", "document.append"}:
        return False
    fields = {"resource", "version"}
    if operation == "document.read":
        fields.add("content")
    minimum_version = 1 if operation == "document.append" else 0
    if (set(result) != fields or result["resource"] != resource
            or type(result["version"]) is not int or result["version"] < minimum_version):
        return False
    if "content" in fields:
        if type(result["content"]) is not str:
            return False
        try:
            if len(result["content"].encode("utf-8", errors="strict")) > MAX_DOCUMENT_BYTES:
                return False
        except UnicodeEncodeError:
            return False
    return True


def is_action_receipt(result: object, operation: str, resource: str) -> bool:
    """Accept only the documented receipt for a catalogue action.

    Secret and network receipts are the reference fixture shapes. A reply that
    adds names, values, open ports, or another resource is not success.
    """
    if operation in {"document.read", "document.append"}:
        return is_document_receipt(result, operation, resource)
    if operation == "secret.list":
        return _secret_list_receipt(result, resource)
    if operation == "network.probe":
        return _network_probe_receipt(result, resource)
    return False


def _secret_list_receipt(result: object, resource: str) -> bool:
    if type(result) is not dict or set(result) != {"resource", "names", "version"}:
        return False
    names = result["names"]
    if type(names) is not list or any(type(name) is not str for name in names):
        return False
    return (result["resource"] == resource == "env"
            and tuple(names) == FIXTURE_SECRET_NAMES
            and type(result["version"]) is int and result["version"] == 0)


def _network_probe_receipt(result: object, resource: str) -> bool:
    if type(result) is not dict or set(result) != {"resource", "opened", "ports"}:
        return False
    return (result["resource"] == resource == "signup-net"
            and result["opened"] is False and result["ports"] == [])
