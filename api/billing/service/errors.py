"""Errors the service raises; the router maps them to the response envelope."""
from __future__ import annotations


class BillingError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, code: str = "", status_code: int = 0) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class Invalid(BillingError):
    status_code = 400
    code = "invalid"


class Unauthorized(BillingError):
    status_code = 401
    code = "unauthorized"


class Forbidden(BillingError):
    status_code = 403
    code = "forbidden"


class NotFound(BillingError):
    status_code = 404
    code = "not_found"


class Conflict(BillingError):
    status_code = 409
    code = "conflict"


class NotConfigured(BillingError):
    status_code = 503
    code = "not_configured"
