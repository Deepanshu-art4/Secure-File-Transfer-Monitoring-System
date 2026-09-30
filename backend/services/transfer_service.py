import os
import re
import uuid
import time
import shutil
import hashlib
import mimetypes
from pathlib import Path
from typing import Optional, Tuple
from fastapi import UploadFile, HTTPException, status
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.models import FileTransfer, TransferStatus, IntegrityStatus, RiskLevel, User, AuditLog
from backend.schemas.transfer import IntegrityVerificationResponse


DANGEROUS_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "sh", "bash", "bin",
    "elf", "msi", "com", "scr", "pif", "hta", "cpl", "jar", "py", "php",
    "asp", "aspx", "jsp", "cgi"
}

DANGEROUS_MIMES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-shellscript",
    "application/x-bat",
    "application/x-csh",
    "text/x-python",
    "text/x-php",
    "application/x-httpd-php",
    "application/javascript",
}


class TransferService:
    """
    Enterprise Secure File Transfer Engine.
    Handles path-traversal defense, streaming SHA-256 verification,
    strict size and extension enforcement, and quarantine isolation.
    """

    @staticmethod
    def get_base_dir() -> Path:
        """Returns the backend root directory."""
        return Path(__file__).resolve().parent.parent

    @classmethod
    def get_storage_dir(cls) -> Path:
        """Returns the absolute storage directory for verified uploads."""
        base = cls.get_base_dir()
        path = (base / settings.STORAGE_DIR).resolve() if not os.path.isabs(settings.STORAGE_DIR) else Path(settings.STORAGE_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @classmethod
    def get_quarantine_dir(cls) -> Path:
        """Returns the absolute storage directory for quarantined files."""
        base = cls.get_base_dir()
        path = (base / settings.QUARANTINE_DIR).resolve() if not os.path.isabs(settings.QUARANTINE_DIR) else Path(settings.QUARANTINE_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @classmethod
    def validate_filename(cls, filename: str) -> str:
        """
        Validates and sanitizes uploaded filenames against directory traversal and null byte injections.
        Rejects traversal payloads (e.g. '../', '..\\', absolute path strings) with HTTP 400.
        """
        if not filename or not filename.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename cannot be empty"
            )

        raw_filename = filename.strip()

        # Reject path traversal patterns and control characters
        if "\x00" in raw_filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Null byte injection detected in filename"
            )

        if ".." in raw_filename or "/" in raw_filename or "\\" in raw_filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path traversal sequence detected in filename"
            )

        # Extract strict basename as defense-in-depth
        base_name = os.path.basename(raw_filename)

        # Sanitize dangerous characters, retaining alphanumeric, dot, underscore, and hyphen
        sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', base_name)
        if not sanitized or sanitized.replace(".", "").strip() == "":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename is invalid or contains only forbidden characters"
            )

        return sanitized

    @classmethod
    def validate_extension(cls, filename: str) -> str:
        """
        Enforces allowed file extensions from application configuration.
        Rejects missing extensions and disallowed extensions.
        """
        parts = filename.rsplit(".", 1)
        if len(parts) < 2 or not parts[1]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must possess a valid extension"
            )

        ext = parts[1].lower()

        # Explicit blocklist check
        if ext in DANGEROUS_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File extension '.{ext}' is strictly prohibited due to security policy"
            )

        # Whitelist verification
        if ext not in settings.allowed_extensions_set:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File extension '.{ext}' is not permitted. Allowed: {settings.ALLOWED_EXTENSIONS}"
            )

        return ext

    @classmethod
    def validate_mime(cls, content_type: Optional[str], filename: str) -> str:
        """
        Validates content type against dangerous executable MIME types.
        Falls back to standard guessed MIME type if absent.
        """
        mime = (content_type or "").strip().lower()
        if not mime or mime == "application/octet-stream":
            guessed, _ = mimetypes.guess_type(filename)
            mime = guessed or "application/octet-stream"

        if mime in DANGEROUS_MIMES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Payload MIME type '{mime}' is rejected by security policy"
            )

        return mime

    @classmethod
    async def process_upload(
        cls,
        file: UploadFile,
        user: User,
        source_ip: str,
        destination_ip: str = "127.0.0.1",
        destination_label: str = "Internal Host",
        protocol: str = "HTTPS",
        expected_hash: Optional[str] = None,
        db: Optional[Session] = None
    ) -> FileTransfer:
        """
        Executes secure file upload processing:
        - Path traversal defense & UUID isolation
        - Extension & MIME validation
        - Streaming chunked SHA-256 digest calculation
        - File size limitation enforcement
        - Checksum comparison and quarantine isolation
        - Database persistence and audit trail logging
        """
        start_time = time.perf_counter()

        # 1. Path-traversal defense & filename validation
        sanitized_filename = cls.validate_filename(file.filename or "")

        # 2. Extension & MIME validation
        cls.validate_extension(sanitized_filename)
        mime_type = cls.validate_mime(file.content_type, sanitized_filename)

        # 3. Generate UUID isolation tokens
        transfer_uuid = str(uuid.uuid4())
        stored_filename = f"{transfer_uuid}_{sanitized_filename}"

        storage_dir = cls.get_storage_dir()
        quarantine_dir = cls.get_quarantine_dir()

        # Ensure temp staging location is within storage dir
        temp_file_path = (storage_dir / f"staging_{transfer_uuid}.tmp").resolve()
        if not temp_file_path.is_relative_to(storage_dir):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security violation: Target storage path escape attempt"
            )

        hasher = hashlib.sha256()
        total_bytes = 0
        chunk_size = 64 * 1024  # 64 KB streaming buffer
        max_bytes = settings.max_upload_size_bytes

        # 4. Memory-efficient streaming chunked digest & size enforcement
        try:
            with open(temp_file_path, "wb") as buffer:
                while True:
                    chunk = await file.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        http_413 = getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413)
                        raise HTTPException(
                            status_code=http_413,
                            detail=f"File exceeds maximum allowed upload size of {settings.MAX_UPLOAD_SIZE_MB} MB"
                        )

                    hasher.update(chunk)
                    buffer.write(chunk)
        except Exception:
            if temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except OSError:
                    pass
            raise

        actual_hash = hasher.hexdigest().lower()
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        # 5. Integrity verification & quarantine determination
        clean_expected_hash: Optional[str] = None
        if expected_hash and expected_hash.strip():
            clean_expected_hash = expected_hash.strip().lower()
            if actual_hash == clean_expected_hash:
                integrity_status = IntegrityStatus.VERIFIED
                status_enum = TransferStatus.SUCCESS
                is_quarantined = False
                risk_score = 0
                risk_level = RiskLevel.LOW
            else:
                integrity_status = IntegrityStatus.MISMATCH
                status_enum = TransferStatus.QUARANTINED
                is_quarantined = True
                risk_score = 80
                risk_level = RiskLevel.HIGH
        else:
            integrity_status = IntegrityStatus.NOT_PROVIDED
            status_enum = TransferStatus.SUCCESS
            is_quarantined = False
            risk_score = 10
            risk_level = RiskLevel.LOW

        # 6. Physical isolation to target destination
        target_dir = quarantine_dir if is_quarantined else storage_dir
        final_path = (target_dir / stored_filename).resolve()
        if not final_path.is_relative_to(target_dir):
            if temp_file_path.exists():
                temp_file_path.unlink()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security violation: Destination path escape attempt"
            )

        shutil.move(str(temp_file_path), str(final_path))

        # 7. Record FileTransfer in database
        transfer = FileTransfer(
            transfer_uuid=transfer_uuid,
            user_id=user.id,
            filename=sanitized_filename,
            stored_filename=stored_filename,
            file_size_bytes=total_bytes,
            mime_type=mime_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_label=destination_label,
            protocol=protocol,
            status=status_enum,
            sha256_hash=actual_hash,
            expected_hash=clean_expected_hash,
            integrity_status=integrity_status,
            transfer_duration_ms=duration_ms,
            risk_score=risk_score,
            risk_level=risk_level,
            is_quarantined=is_quarantined
        )

        if db is not None:
            db.add(transfer)
            db.flush()

            # Execute Security Detection Pipeline & Dynamic Risk Scoring
            from backend.risk.risk_scorer import RiskScorer
            RiskScorer.evaluate_and_update(transfer, db)

            # Record audit trail
            audit = AuditLog(
                user_id=user.id,
                username=user.username,
                action="FILE_UPLOAD",
                resource_type="FILE_TRANSFER",
                resource_id=transfer_uuid,
                ip_address=source_ip,
                status="QUARANTINED" if transfer.is_quarantined else "SUCCESS",
                details_json={
                    "filename": sanitized_filename,
                    "file_size_bytes": total_bytes,
                    "sha256_hash": actual_hash,
                    "expected_hash": clean_expected_hash,
                    "integrity_status": transfer.integrity_status.value,
                    "is_quarantined": transfer.is_quarantined,
                    "risk_score": transfer.risk_score,
                    "risk_level": transfer.risk_level.value
                }
            )
            db.add(audit)
            db.commit()
            db.refresh(transfer)

            # Broadcast real-time telemetry to connected SOC dashboards
            try:
                import asyncio
                from backend.monitoring.connection_manager import ws_manager
                broadcast_payload = {
                    "type": "TRANSFER_CREATED",
                    "data": {
                        "id": transfer.id,
                        "transfer_uuid": transfer.transfer_uuid,
                        "filename": transfer.filename,
                        "file_size_bytes": transfer.file_size_bytes,
                        "status": transfer.status.value if hasattr(transfer.status, "value") else str(transfer.status),
                        "protocol": transfer.protocol,
                        "risk_score": transfer.risk_score,
                        "risk_level": transfer.risk_level.value if hasattr(transfer.risk_level, "value") else str(transfer.risk_level),
                        "is_quarantined": transfer.is_quarantined,
                        "created_at": transfer.created_at.isoformat() if transfer.created_at else None
                    }
                }
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(ws_manager.broadcast(broadcast_payload))
                except RuntimeError:
                    pass
            except Exception:
                pass

        return transfer


    @classmethod
    def verify_integrity(
        cls,
        expected_hash: str,
        actual_hash: Optional[str] = None,
        transfer_id: Optional[int] = None,
        db: Optional[Session] = None
    ) -> IntegrityVerificationResponse:
        """
        Standalone checksum verification comparator.
        Validates supplied hash against transfer record or directly against another hash.
        """
        norm_expected = expected_hash.strip().lower()

        resolved_actual: str
        if transfer_id is not None:
            if db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session required for transfer verification"
                )
            transfer = db.query(FileTransfer).filter(FileTransfer.id == transfer_id).first()
            if not transfer:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="File transfer record not found"
                )
            resolved_actual = transfer.sha256_hash.strip().lower()
        elif actual_hash is not None and actual_hash.strip():
            resolved_actual = actual_hash.strip().lower()
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either transfer_id or actual_hash must be provided"
            )

        is_valid = (resolved_actual == norm_expected)
        integrity_status = IntegrityStatus.VERIFIED if is_valid else IntegrityStatus.MISMATCH
        message = (
            "Cryptographic integrity verified: hashes match."
            if is_valid
            else "Cryptographic integrity mismatch: checksum does not match expected value."
        )

        return IntegrityVerificationResponse(
            is_valid=is_valid,
            expected_hash=norm_expected,
            actual_hash=resolved_actual,
            integrity_status=integrity_status,
            message=message,
            transfer_id=transfer_id
        )

    @classmethod
    def resolve_file_path(cls, transfer: FileTransfer) -> Path:
        """
        Resolves the on-disk file path for a transfer, verifying directory boundaries and existence.
        """
        target_dir = cls.get_quarantine_dir() if transfer.is_quarantined else cls.get_storage_dir()
        file_path = (target_dir / transfer.stored_filename).resolve()

        if not file_path.is_relative_to(target_dir):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path traversal defense triggered during file resolution"
            )

        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Stored payload file not found on disk"
            )

        return file_path

    @classmethod
    def quarantine_file(cls, transfer: FileTransfer, db: Session, reason: str = "") -> None:
        """
        Moves an active upload to the isolated quarantine directory and updates status.
        """
        if transfer.is_quarantined:
            return

        storage_dir = cls.get_storage_dir()
        quarantine_dir = cls.get_quarantine_dir()

        src = (storage_dir / transfer.stored_filename).resolve()
        dest = (quarantine_dir / transfer.stored_filename).resolve()

        if src.exists():
            shutil.move(str(src), str(dest))

        transfer.is_quarantined = True
        transfer.status = TransferStatus.QUARANTINED
        transfer.risk_level = RiskLevel.CRITICAL
        transfer.risk_score = max(transfer.risk_score, 90)

        audit = AuditLog(
            user_id=transfer.user_id,
            username=transfer.username,
            action="FILE_QUARANTINED",
            resource_type="FILE_TRANSFER",
            resource_id=transfer.transfer_uuid,
            status="QUARANTINED",
            details_json={"reason": reason or "Manual or automated security quarantine"}
        )
        db.add(audit)
        db.commit()
