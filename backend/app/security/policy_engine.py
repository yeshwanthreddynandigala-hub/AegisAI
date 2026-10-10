"""
Authorization Policy Engine.
Implements least-privilege zero-trust access control for AI agent tool invocations.
Evaluates proposed actions BEFORE execution and returns ALLOW, DENY, or REQUIRE_APPROVAL.
"""

from typing import Dict, Any, List, Optional
from fnmatch import fnmatch
from urllib.parse import urlparse
import re
from app.models.agent import PolicyManifestModel

class PolicyDecisionResult:
    def __init__(
        self,
        decision: str,  # ALLOW, DENY, REQUIRE_APPROVAL
        reason_code: str,
        message: str,
        risk_indicators: Optional[List[str]] = None
    ):
        self.decision = decision
        self.reason_code = reason_code
        self.message = message
        self.risk_indicators = risk_indicators or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "message": self.message,
            "risk_indicators": self.risk_indicators
        }

class PolicyEngine:
    """Evaluates agent tool requests against formal security manifests."""

    @staticmethod
    def evaluate(
        policy: PolicyManifestModel,
        tool_name: str,
        parameters: Dict[str, Any],
        session_denial_count: int = 0
    ) -> PolicyDecisionResult:
        """
        Pure evaluation logic. Returns ALLOW, DENY, or REQUIRE_APPROVAL.
        Guarantees that dangerous calls are intercepted prior to any execution.
        """
        # 0. Check Session Denial Threshold (Anti-Brute Force / Quarantine)
        max_allowed_denials = getattr(policy, "max_denial_threshold", 3)
        if session_denial_count >= max_allowed_denials:
            return PolicyDecisionResult(
                decision="DENY",
                reason_code="SESSION_QUARANTINED",
                message=f"Session exceeded threshold of {max_allowed_denials} policy denials. Automatically quarantined.",
                risk_indicators=["REPEATED_POLICY_VIOLATIONS", "SESSION_LOCKED"]
            )

        # 1. Whitelist Tool Check
        allowed_tools = getattr(policy, "allowed_tools", []) or []
        if tool_name not in allowed_tools:
            return PolicyDecisionResult(
                decision="DENY",
                reason_code="TOOL_NOT_PERMITTED",
                message=f"Tool '{tool_name}' is not in authorized tool whitelist for this agent.",
                risk_indicators=["UNAUTHORIZED_TOOL_INVOCATION"]
            )

        # 2. Filesystem & Document Resource Evaluation
        if tool_name in ["document_reader", "filesystem_read", "filesystem_write"]:
            path = str(parameters.get("path", "")).strip()

            # A. Directory Traversal Check
            if ".." in path or "/.." in path or "\\.." in path or path.startswith("/") or (len(path) > 1 and path[1] == ":"):
                return PolicyDecisionResult(
                    decision="DENY",
                    reason_code="DIRECTORY_TRAVERSAL_ATTEMPT",
                    message=f"Potential directory traversal or absolute path detected: '{path}'.",
                    risk_indicators=["DIRECTORY_TRAVERSAL", "SANDBOX_ESCAPE_ATTEMPT"]
                )

            # B. Explicit Denied Paths Check (Blacklist / Honeytokens)
            denied_paths = getattr(policy, "denied_paths", []) or []
            for pattern in denied_paths:
                if fnmatch(path, pattern) or fnmatch(path, f"*/{pattern}"):
                    is_credential = "credential" in path.lower() or ".env" in path.lower() or "secret" in path.lower()
                    return PolicyDecisionResult(
                        decision="DENY",
                        reason_code="RESTRICTED_RESOURCE_ACCESS",
                        message=f"Access to restricted path '{path}' denied by policy rule pattern '{pattern}'.",
                        risk_indicators=["SENSITIVE_CREDENTIAL_ACCESS" if is_credential else "RESTRICTED_FILE_ACCESS"]
                    )

            # C. Whitelisted Paths Check (Least Privilege)
            allowed_paths = getattr(policy, "allowed_paths", []) or []
            if allowed_paths:
                matched = any(fnmatch(path, pattern) for pattern in allowed_paths)
                if not matched:
                    return PolicyDecisionResult(
                        decision="DENY",
                        reason_code="PATH_NOT_IN_PERMITTED_SCOPE",
                        message=f"Path '{path}' is outside authorized scope {allowed_paths}.",
                        risk_indicators=["SCOPE_VIOLATION"]
                    )

            # D. Write Operations and Approvals
            if tool_name == "filesystem_write":
                require_approval = getattr(policy, "require_approval_operations", []) or []
                if "WRITE" in require_approval or "filesystem_write" in require_approval:
                    return PolicyDecisionResult(
                        decision="REQUIRE_APPROVAL",
                        reason_code="HUMAN_APPROVAL_REQUIRED",
                        message=f"Writing to '{path}' requires explicit security analyst approval.",
                        risk_indicators=["HIGH_PRIVILEGE_MODIFICATION"]
                    )

        # 3. Network and External Destination Evaluation
        if tool_name in ["browser_open", "mock_api_request"]:
            url = str(parameters.get("url", "")).strip()
            parsed = urlparse(url)
            domain = parsed.netloc.lower() or parsed.path.split("/")[0].lower()

            allowed_domains = getattr(policy, "allowed_network_domains", []) or []
            if not allowed_domains or domain not in [d.lower() for d in allowed_domains]:
                return PolicyDecisionResult(
                    decision="DENY",
                    reason_code="UNAPPROVED_NETWORK_DESTINATION",
                    message=f"Communication to unapproved destination '{domain}' is blocked. Allowed domains: {allowed_domains}.",
                    risk_indicators=["DATA_EXFILTRATION_RISK", "UNAPPROVED_DESTINATION"]
                )

        # 4. Database Query Evaluation
        if tool_name == "database_query":
            query = str(parameters.get("query", "")).strip().upper()
            
            # Check for restricted / sensitive tables
            restricted_tables = ["ADMIN_TOKENS", "PAYROLL", "SECRETS", "USERS_PASSWORD"]
            for table in restricted_tables:
                if re.search(r'\b' + table + r'\b', query):
                    return PolicyDecisionResult(
                        decision="DENY",
                        reason_code="RESTRICTED_TABLE_ACCESS",
                        message=f"Query references protected sensitive table '{table}'.",
                        risk_indicators=["SENSITIVE_DATA_QUERY", "DATABASE_HONEYTOKEN_HIT"]
                    )

            # Check destructive queries
            destructive_ops = ["DROP", "DELETE", "TRUNCATE", "ALTER"]
            if any(op in query.split() for op in destructive_ops):
                require_approval = getattr(policy, "require_approval_operations", []) or []
                if "WRITE" in require_approval or "DELETE" in require_approval:
                    return PolicyDecisionResult(
                        decision="REQUIRE_APPROVAL",
                        reason_code="HUMAN_APPROVAL_REQUIRED",
                        message="Destructive database modifications require analyst approval.",
                        risk_indicators=["DESTRUCTIVE_DATABASE_OPERATION"]
                    )

        # All validation checks succeeded
        return PolicyDecisionResult(
            decision="ALLOW",
            reason_code="POLICY_SATISFIED",
            message=f"Tool '{tool_name}' satisfied all active security constraints."
        )

policy_engine = PolicyEngine()
