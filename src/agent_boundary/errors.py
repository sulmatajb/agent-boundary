"""Public, non-sensitive errors shared by the broker and its adapters."""


class BoundaryError(Exception):
    """A fail-closed request rejection that can safely cross the HTTP boundary."""

    def __init__(self, code: str, message: str, status: int = 403):
        self.code = code
        self.status = status
        self.message = message
        super().__init__(message)
