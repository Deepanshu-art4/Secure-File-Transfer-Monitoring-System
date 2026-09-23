from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models import User, UserRole, FileTransfer, TransferStatus, IntegrityStatus, RiskLevel, AuditLog
from backend.schemas.transfer import (
    TransferOut,
    TransferDetailOut,
    TransferListOut,
    IntegrityVerificationRequest,
    IntegrityVerificationResponse,
)
from backend.services.transfer_service import TransferService
from backend.api.dependencies import get_current_user, get_client_ip

router = APIRouter(prefix="/transfers", tags=["File Transfers"])


@router.post("/upload", response_model=TransferOut, status_code=status.HTTP_201_CREATED)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    destination_ip: str = Form("127.0.0.1"),
    destination_label: str = Form("Internal Host"),
    protocol: str = Form("HTTPS"),
    expected_hash: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Secure File Ingestion Endpoint.
    Enforces path-traversal sanitization, extension/MIME filtering,
    streaming chunked SHA-256 calculation, and quarantine isolation for integrity mismatches.
    """
    client_ip = get_client_ip(request)

    transfer = await TransferService.process_upload(
        file=file,
        user=current_user,
        source_ip=client_ip,
        destination_ip=destination_ip,
        destination_label=destination_label,
        protocol=protocol,
        expected_hash=expected_hash,
        db=db
    )

    return transfer


@router.get("", response_model=TransferListOut)
def list_transfers(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    user_id: Optional[int] = None,
    status: Optional[TransferStatus] = None,
    protocol: Optional[str] = None,
    risk_level: Optional[RiskLevel] = None,
    integrity_status: Optional[IntegrityStatus] = None,
    search: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves filterable transfer history.
    - Standard Users are restricted to viewing only their own transfers.
    - Analysts and Administrators have global visibility across all users and filters.
    """
    query = db.query(FileTransfer)

    # Enforce RBAC boundary for standard users
    if current_user.role == UserRole.USER:
        query = query.filter(FileTransfer.user_id == current_user.id)
    elif user_id is not None:
        query = query.filter(FileTransfer.user_id == user_id)

    if status:
        query = query.filter(FileTransfer.status == status)

    if protocol:
        query = query.filter(FileTransfer.protocol.ilike(f"%{protocol.strip()}%"))

    if risk_level:
        query = query.filter(FileTransfer.risk_level == risk_level)

    if integrity_status:
        query = query.filter(FileTransfer.integrity_status == integrity_status)

    if start_date:
        query = query.filter(FileTransfer.created_at >= start_date)

    if end_date:
        query = query.filter(FileTransfer.created_at <= end_date)

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                FileTransfer.filename.ilike(term),
                FileTransfer.transfer_uuid.ilike(term),
                FileTransfer.source_ip.ilike(term),
                FileTransfer.destination_ip.ilike(term),
                FileTransfer.destination_label.ilike(term)
            )
        )

    total = query.count()
    transfers = query.order_by(FileTransfer.created_at.desc()).offset(skip).limit(limit).all()

    return TransferListOut(total=total, items=transfers)


@router.post("/verify-integrity", response_model=IntegrityVerificationResponse)
def verify_transfer_integrity(
    payload: IntegrityVerificationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Standalone cryptographic checksum comparator.
    Validates client-supplied SHA-256 against either a recorded transfer or another explicit hash.
    """
    if payload.transfer_id is not None:
        transfer = db.query(FileTransfer).filter(FileTransfer.id == payload.transfer_id).first()
        if not transfer:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File transfer record not found"
            )
        # Verify access rights
        if current_user.role == UserRole.USER and transfer.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to verify integrity for this transfer"
            )

    return TransferService.verify_integrity(
        expected_hash=payload.expected_hash,
        actual_hash=payload.actual_hash,
        transfer_id=payload.transfer_id,
        db=db
    )


@router.get("/{transfer_id}", response_model=TransferDetailOut)
def get_transfer_by_id(
    transfer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves detailed transfer report with SHA-256 verification and risk status.
    Users may only view their own transfer records; Analysts/Admins may view any record.
    """
    transfer = db.query(FileTransfer).filter(FileTransfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File transfer record not found"
        )

    if current_user.role == UserRole.USER and transfer.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view this transfer report"
        )

    return transfer


@router.get("/{transfer_id}/download")
def download_transfer_file(
    transfer_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Authorized File Download.
    - Standard Users can only download their own verified files.
    - Quarantined files are blocked from standard users (HTTP 403) and restricted to Analysts/Admins.
    - Emits immutable FILE_DOWNLOAD audit log entry upon successful download.
    """
    transfer = db.query(FileTransfer).filter(FileTransfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File transfer record not found"
        )

    # Check ownership
    if current_user.role == UserRole.USER and transfer.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to download this file"
        )

    # Restrict quarantined payload download to Security Analysts and Admins
    if transfer.is_quarantined and current_user.role == UserRole.USER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: File is quarantined due to security integrity violation. Contact SOC administrator."
        )

    file_path = TransferService.resolve_file_path(transfer)

    # Record download audit entry
    client_ip = get_client_ip(request)
    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="FILE_DOWNLOAD",
        resource_type="FILE_TRANSFER",
        resource_id=transfer.transfer_uuid,
        ip_address=client_ip,
        status="SUCCESS",
        details_json={
            "transfer_id": transfer.id,
            "filename": transfer.filename,
            "file_size_bytes": transfer.file_size_bytes,
            "sha256_hash": transfer.sha256_hash,
            "is_quarantined": transfer.is_quarantined
        }
    )
    db.add(audit)
    db.commit()

    return FileResponse(
        path=file_path,
        filename=transfer.filename,
        media_type=transfer.mime_type
    )
