"""Small synchronous authenticated broker client (no provider API required)."""
from .transport import request_json, validate_base_url, validate_token


class BrokerClient:
    def __init__(self, base_url, token, timeout=5):
        self.base_url = validate_base_url(base_url)
        self.token = validate_token(token)
        self.timeout = timeout

    def _call(self, route, payload=None, method="POST"):
        return request_json(self.base_url + route, self.token, method=method,
                            payload=payload, timeout=self.timeout)

    def root(self, owner, scopes, budget):
        return self._call("/v1/root", {"owner": owner, "scopes": scopes, "budget": budget})

    def delegate(self, capability, owner, scopes, budget):
        return self._call("/v1/delegate", {"capability": capability, "owner": owner,
                                         "scopes": scopes, "budget": budget})

    def revoke(self, capability):
        return self._call("/v1/revoke", {"capability": capability})

    def execute(self, capability, request_id, operation, resource, value=None):
        return self._call("/v1/execute", {"capability": capability, "request_id": request_id,
                                        "operation": operation, "resource": resource, "value": value})

    def audit(self, offset=None, limit=100):
        if offset is None and type(limit) is int and limit == 100:
            return self._call("/v1/audit", method="GET")
        return self._call("/v1/audit-page", {"offset": 0 if offset is None else offset, "limit": limit})

    def drain(self):
        return self._call("/v1/drain", {})
