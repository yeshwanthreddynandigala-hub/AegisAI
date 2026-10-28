"""
API Router: Human-in-the-Loop (HITL) Security Approvals.
Provides authenticated endpoints for SecOps analysts and administrators
to inspect, approve, and reject sensitive agent tool invocations before execution.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.approval import ApprovalRequestModel, ApprovalStatus
from app.models.user import UserModel
from app.schemas.approval import ApprovalRequestResponse, ApprovalDecisionRequest
from app.security.gateway import gateway
from app.api.deps import get_current_user

router = APIRouter(prefix="/approvals", tags=["Approvals"])


@router.get("", response_model=List[ApprovalRequestResponse])
def list_approvals(
    status: Optional[str] = Query(None, description="Filter by status (PENDING, APPROVED, REJECTED, EXPIRED, EXECUTED, FAILED)"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Lists approval requests with optional status and agent filtering.
    Accessible to authenticated SecOps Analysts and Administrators.
    Automatically recovers stale abandoned IN_PROGRESS requests to FAILED,
    and flags overdue PENDING requests as EXPIRED.
    """
    now_utc = datetime.now(timezone.utc)

    # Lazily recover any stale abandoned IN_PROGRESS requests (fail-closed, no auto-retry)
    gateway.recover_stale_approvals(db)

    # Lazily update any expired pending requests
    pending_overdue = db.query(ApprovalRequestModel).filter(
        ApprovalRequestModel.status == ApprovalStatus.PENDING.value,
        ApprovalRequestModel.expires_at < now_utc
    ).all()
    for item in pending_overdue:
        item.status = ApprovalStatus.EXPIRED.value
        item.failure_reason = "Request expired before human review."
    if pending_overdue:
        db.commit()

    q = db.query(ApprovalRequestModel)
    if status:
        q = q.filter(ApprovalRequestModel.status == status.upper())
    if agent_id:
        q = q.filter(ApprovalRequestModel.agent_id == agent_id)

    items = q.order_by(ApprovalRequestModel.created_at.desc()).offset(offset).limit(limit).all()
    return [ApprovalRequestResponse.model_validate(item) for item in items]


@router.get("/{approval_id}", response_model=ApprovalRequestResponse)
def get_approval(
    approval_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Retrieves full details and parameters for a specific approval request."""
    # First, lazily recover any stale abandoned in-progress approvals
    gateway.recover_stale_approvals(db)

    item = db.query(ApprovalRequestModel).filter(
        ApprovalRequestModel.approval_id == approval_id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")

    # Check expiration lazily
    now_utc = datetime.now(timezone.utc)
    expires_at = item.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if item.status == ApprovalStatus.PENDING.value and now_utc > expires_at:
        item.status = ApprovalStatus.EXPIRED.value
        item.failure_reason = "Request expired before human review."
        db.commit()
        db.refresh(item)

    return ApprovalRequestResponse.model_validate(item)


@router.post("/recover-stale", response_model=Dict[str, Any])
def trigger_stale_recovery(
    timeout_seconds: Optional[int] = Query(None, ge=1, le=86400, description="Override lease timeout in seconds"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Explicit endpoint for SecOps Analysts and Admins to trigger recovery of abandoned IN_PROGRESS requests.
    Idempotent and safe: transitions abandoned requests to FAILED without re-executing.
    """
    recovered_ids = gateway.recover_stale_approvals(db, timeout_seconds=timeout_seconds)
    return {
        "status": "success",
        "recovered_count": len(recovered_ids),
        "recovered_approval_ids": recovered_ids
    }


@router.post("/{approval_id}/approve", response_model=ApprovalRequestResponse)
def approve_request(
    approval_id: str,
    body: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Authorizes a pending tool invocation.
    Performs zero-trust policy revalidation, executes the sandboxed tool,
    and updates the audit trail with reviewer identity.
    """
    updated_approval = gateway.approve_tool_call(
        db=db,
        approval_id=approval_id,
        reviewer=current_user,
        justification=body.justification
    )
    return ApprovalRequestResponse.model_validate(updated_approval)


@router.post("/{approval_id}/reject", response_model=ApprovalRequestResponse)
def reject_request(
    approval_id: str,
    body: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Rejects a pending tool invocation.
    Guarantees the tool will never be executed and logs the rejection in the audit trail.
    """
    updated_approval = gateway.reject_tool_call(
        db=db,
        approval_id=approval_id,
        reviewer=current_user,
        justification=body.justification
    )
    return ApprovalRequestResponse.model_validate(updated_approval)
