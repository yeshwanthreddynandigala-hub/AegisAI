"""
Tool Parameter Schemas and Strict Validation Layer.
Provides typed, validated Pydantic schemas for all registered agent tools.
Enforces strict type checking, parameter whitelist (extra='forbid'),
range constraints, and url/path sanitization to fail closed on malformed requests.
"""

from pydantic import BaseModel, Field, ConfigDict, field_validator, ValidationError
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse


class StrictToolParams(BaseModel):
    """Base class forbidding unexpected kwargs and stripped strings."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DocumentReaderParams(StrictToolParams):
    path: str = Field(..., min_length=1, max_length=1000, description="Relative path in synthetic sandbox")
    offset: int = Field(default=0, ge=0, description="Byte offset")
    limit: int = Field(default=4000, gt=0, le=50000, description="Max bytes to read")


class FilesystemReadParams(StrictToolParams):
    path: str = Field(..., min_length=1, max_length=1000, description="Relative path in synthetic sandbox")


class FilesystemWriteParams(StrictToolParams):
    path: str = Field(..., min_length=1, max_length=1000, description="Target path in synthetic sandbox")
    content: str = Field(..., max_length=500000, description="File text content")


class CalculatorParams(StrictToolParams):
    expression: str = Field(..., min_length=1, max_length=500, description="Safe arithmetic math expression")


class BrowserSearchParams(StrictToolParams):
    query: str = Field(..., min_length=1, max_length=500, description="Search query string")


class BrowserOpenParams(StrictToolParams):
    url: str = Field(..., min_length=1, max_length=2000, description="Destination URL")

    @field_validator("url")
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ["http", "https"]:
            raise ValueError(f"Disallowed URL scheme '{parsed.scheme}'. Must be http or https.")
        if not parsed.netloc:
            raise ValueError("URL must specify a valid network host.")
        return v


class DatabaseQueryParams(StrictToolParams):
    query: str = Field(..., min_length=1, max_length=10000, description="SQL query string")


class MockApiRequestParams(StrictToolParams):
    url: str = Field(..., min_length=1, max_length=2000, description="Target API endpoint")
    method: str = Field(default="GET", description="HTTP request method")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Optional HTTP request headers")
    body: Optional[Dict[str, Any]] = Field(default=None, description="Optional JSON request body")

    @field_validator("method")
    def validate_method(cls, v: str) -> str:
        allowed = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        upper_v = v.upper()
        if upper_v not in allowed:
            raise ValueError(f"Disallowed HTTP method '{v}'. Must be one of {allowed}.")
        return upper_v

    @field_validator("url")
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ["http", "https"]:
            raise ValueError(f"Disallowed URL scheme '{parsed.scheme}'. Must be http or https.")
        if not parsed.netloc:
            raise ValueError("URL must specify a valid network host.")
        return v


SUPPORTED_TOOL_SCHEMAS: Dict[str, type] = {
    "document_reader": DocumentReaderParams,
    "filesystem_read": FilesystemReadParams,
    "filesystem_write": FilesystemWriteParams,
    "calculator": CalculatorParams,
    "browser_search": BrowserSearchParams,
    "browser_open": BrowserOpenParams,
    "database_query": DatabaseQueryParams,
    "mock_api_request": MockApiRequestParams,
}


def validate_tool_parameters(
    tool_name: str,
    parameters: Dict[str, Any]
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Validates proposed tool parameters against strict tool Pydantic schema.
    Returns (is_valid, error_message, validated_dict).
    Fails closed if the tool is not registered.
    """
    schema_cls = SUPPORTED_TOOL_SCHEMAS.get(tool_name)
    if not schema_cls:
        return False, f"Tool '{tool_name}' has no registered validation schema. Fail-closed.", None

    if not isinstance(parameters, dict):
        return False, f"Parameters for '{tool_name}' must be a dictionary/object, got {type(parameters).__name__}.", None

    try:
        validated_obj = schema_cls.model_validate(parameters)
        return True, None, validated_obj.model_dump(exclude_unset=False)
    except ValidationError as err:
        errors = [f"{e['loc'][0]}: {e['msg']}" if e['loc'] else e['msg'] for e in err.errors()]
        return False, f"Parameter validation error for '{tool_name}': {'; '.join(errors)}", None
    except Exception as ex:
        return False, f"Unexpected parameter validation error for '{tool_name}': {str(ex)}", None
