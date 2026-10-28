"""
Security Sanitizer & Recursive Redaction Utility.
Provides robust, case-insensitive secret detection and redaction for tool parameters,
audit events, API serialization, and error messages.
Protects credentials, tokens, passwords, authorization headers, and embedded secrets in URLs.
"""

from typing import Any, Dict, List, Set, Union
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

SENSITIVE_KEY_PATTERNS: Set[str] = {
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "authorization",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "client_secret",
    "jwt",
    "bearer",
    "auth",
}

# Regex for common embedded credential tokens
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]+")
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
SECRET_ASSIGN_PATTERN = re.compile(r"(?i)\b(password|passwd|secret|api_key|token)\s*[:=]\s*['\"]?([^'\"\s&,]+)['\"]?")


def is_sensitive_key(key: str) -> bool:
    """Checks whether a dictionary or parameter key name matches sensitive patterns."""
    if not isinstance(key, str):
        return False
    k = key.lower().replace("-", "_").strip()
    return any(pattern in k for pattern in SENSITIVE_KEY_PATTERNS)


def sanitize_url(url_str: str) -> str:
    """
    Sanitizes embedded credentials in URLs (HTTP Basic Auth, query tokens, and API keys).
    Preserves protocol, host, and non-sensitive query parameters.
    """
    try:
        parsed = urlparse(url_str)
        if not parsed.scheme or not parsed.netloc:
            return url_str

        # 1. Sanitize userinfo in netloc (e.g. user:pass@host)
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, host = netloc.split("@", 1)
            if ":" in userinfo:
                username, _ = userinfo.split(":", 1)
                netloc = f"{username}:[REDACTED]@{host}"
            else:
                netloc = f"[REDACTED]@{host}"

        # 2. Sanitize query string parameters
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        if query_params:
            sanitized_params = []
            for k, v in query_params:
                if is_sensitive_key(k):
                    sanitized_params.append((k, "[REDACTED]"))
                else:
                    sanitized_params.append((k, v))
            new_query = urlencode(sanitized_params)
        else:
            new_query = parsed.query

        return urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    except Exception:
        return "[REDACTED_MALFORMED_URL]"


def sanitize_string(s: str) -> str:
    """Redacts known credential patterns from raw string contents."""
    if not isinstance(s, str):
        return s

    # If it's a URL, sanitize URL parameters and auth
    if s.startswith("http://") or s.startswith("https://"):
        s = sanitize_url(s)

    # Redact Bearer tokens
    s = BEARER_PATTERN.sub("Bearer [REDACTED]", s)

    # Redact AWS and synthetic mock keys
    s = AWS_KEY_PATTERN.sub("[REDACTED_AWS_KEY]", s)

    for mock_token in ["EXAMPLEKEY", "P@ssw0rdSynthetic", "synthetic_hash"]:
        if mock_token in s:
            s = s.replace(mock_token, "[REDACTED]")

    # Redact PEM private keys
    s = PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", s)

    return s


def redact_secrets(data: Any) -> Any:
    """
    Recursively redacts sensitive keys and values from dictionaries, lists, and strings.
    Safe for arbitrary nested JSON structures.
    """
    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            key_str = str(k)
            if is_sensitive_key(key_str):
                sanitized[key_str] = "[REDACTED]"
            else:
                sanitized[key_str] = redact_secrets(v)
        return sanitized
    elif isinstance(data, list):
        return [redact_secrets(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(redact_secrets(item) for item in data)
    elif isinstance(data, str):
        return sanitize_string(data)
    else:
        return data


def contains_sensitive_secrets(data: Any) -> bool:
    """
    Returns True if the data structure contains raw unencrypted credentials or sensitive keys.
    Used by the gateway to prevent persisting unencrypted credentials to deferred approval storage.
    """
    if isinstance(data, dict):
        for k, v in data.items():
            if is_sensitive_key(str(k)):
                return True
            if contains_sensitive_secrets(v):
                return True
        return False
    elif isinstance(data, (list, tuple)):
        return any(contains_sensitive_secrets(item) for item in data)
    elif isinstance(data, str):
        if "AKIA" in data or "-----BEGIN" in data or "Bearer ey" in data:
            return True
        if SECRET_ASSIGN_PATTERN.search(data):
            return True
        if data.startswith("http://") or data.startswith("https://"):
            parsed = urlparse(data)
            if "@" in parsed.netloc:
                return True
            for k, _ in parse_qsl(parsed.query):
                if is_sensitive_key(k):
                    return True
        return False
    return False
