"""Document receipt contract shared by durable delivery and the supervisor."""

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
