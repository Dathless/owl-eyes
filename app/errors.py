"""Public errors use fixed messages; exception details and raw inputs stay private."""

from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.schemas import ErrorInfo, ErrorResponse

HTTP_ERRORS = {
    400: ("invalid_request", "Invalid request."),
    401: ("authentication_required", "Authentication required."),
    403: ("request_forbidden", "Request is forbidden."),
    404: ("not_found", "Resource not found."),
    405: ("method_not_allowed", "Method not allowed."),
    409: ("conflict", "Request conflicts with the current state."),
    413: ("request_too_large", "Request body exceeds 16 KiB."),
    415: ("unsupported_media_type", "Use application/json."),
    422: ("validation_error", "Request does not match the required schema."),
    431: ("request_headers_too_large", "Request headers exceed the allowed size."),
    500: ("internal_error", "Request could not be completed."),
}


class OperationError(Exception):
    def __init__(self, status: int, code: str, message: str, *, retryable=False):
        self.status, self.code, self.message, self.retryable = (
            status,
            code,
            message,
            retryable,
        )


async def operation_error_handler(request: Request, exception: OperationError):
    return error_response(
        exception.status,
        exception.code,
        exception.message,
        retryable=exception.retryable,
    )


def error_response(
    status: int,
    code: str | None = None,
    message: str | None = None,
    *,
    retryable: bool = False,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    default_code, default_message = HTTP_ERRORS.get(
        status, ("http_error", "Request failed.")
    )
    error = ErrorResponse(
        error=ErrorInfo(
            code=code or default_code,
            message=message or default_message,
            retryable=retryable,
        )
    )
    return JSONResponse(
        error.model_dump(mode="json"), status_code=status, headers=headers
    )


async def http_error_handler(
    request: Request, exception: HTTPException
) -> JSONResponse:
    headers = {"WWW-Authenticate": "Basic"} if exception.status_code == 401 else None
    return error_response(exception.status_code, headers=headers)


async def validation_error_handler(
    request: Request,
    exception: RequestValidationError,
) -> JSONResponse:
    return error_response(422)
