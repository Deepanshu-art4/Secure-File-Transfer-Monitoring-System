import io
import csv
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.models import FileTransfer, Alert, AuditLog, SeverityLevel, TransferStatus


class ReportService:
    """
    Compliance & Security Incident Report Generation Engine.
    Produces high-fidelity PDF documents and CSV audits for SOC compliance.
    """

    @classmethod
    def generate_transfers_csv(cls, db: Session, limit: int = 1000) -> str:
        """Generates RFC 4180 compliant CSV export of file transfer audit history."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Transfer UUID",
            "Filename",
            "File Size (Bytes)",
            "Status",
            "Integrity Status",
            "Source IP",
            "Destination IP",
            "Destination Label",
            "Protocol",
            "Risk Score",
            "Risk Level",
            "Quarantined",
            "SHA-256 Hash",
            "Expected Hash",
            "Created At (UTC)"
        ])

        transfers = db.query(FileTransfer).order_by(FileTransfer.created_at.desc()).limit(limit).all()
        for t in transfers:
            writer.writerow([
                t.transfer_uuid,
                t.filename,
                t.file_size_bytes,
                t.status.value if hasattr(t.status, "value") else str(t.status),
                t.integrity_status.value if hasattr(t.integrity_status, "value") else str(t.integrity_status),
                t.source_ip,
                t.destination_ip,
                t.destination_label or "N/A",
                t.protocol,
                t.risk_score,
                t.risk_level.value if hasattr(t.risk_level, "value") else str(t.risk_level),
                "YES" if t.is_quarantined else "NO",
                t.sha256_hash,
                t.expected_hash or "N/A",
                t.created_at.isoformat() if t.created_at else ""
            ])

        return output.getvalue()

    @classmethod
    def generate_audit_logs_csv(cls, db: Session, limit: int = 2000) -> str:
        """Generates RFC 4180 compliant CSV export of tamper-evident audit logs."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Log ID",
            "Timestamp (UTC)",
            "Username",
            "Action",
            "Resource Type",
            "Resource ID",
            "IP Address",
            "Status",
            "Details"
        ])

        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
        for log in logs:
            writer.writerow([
                log.id,
                log.created_at.isoformat() if log.created_at else "",
                log.username or "SYSTEM",
                log.action,
                log.resource_type,
                log.resource_id or "N/A",
                log.ip_address,
                log.status,
                str(log.details_json)
            ])

        return output.getvalue()

    @classmethod
    def generate_transfers_pdf(cls, db: Session, limit: int = 50) -> bytes:
        """Generates formal SOC File Transfer Audit Report in PDF format."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'SOCTitle',
            parent=styles['Heading1'],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'SOCSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=15
        )
        heading2_style = ParagraphStyle(
            'SOCHeading2',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=8
        )
        cell_style = ParagraphStyle(
            'SOCCell',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#1e293b')
        )
        cell_bold = ParagraphStyle(
            'SOCCellBold',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold'
        )

        elements = []

        # Header
        elements.append(Paragraph("SOC File Transfer Security Audit Report", title_style))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Generated: {now_str} | Classification: CONFIDENTIAL / SOC INTERNAL", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=15))

        # Executive Metrics Summary
        total_tx = db.query(FileTransfer).count()
        quarantined = db.query(FileTransfer).filter(FileTransfer.is_quarantined == True).count()
        high_risk = db.query(FileTransfer).filter(FileTransfer.risk_score >= 50).count()

        summary_data = [
            [
                Paragraph("<b>Total Transfers Logged</b>", cell_style),
                Paragraph(str(total_tx), cell_bold),
                Paragraph("<b>Quarantined Files</b>", cell_style),
                Paragraph(str(quarantined), cell_bold),
                Paragraph("<b>High/Crit Risk Count</b>", cell_style),
                Paragraph(str(high_risk), cell_bold),
            ]
        ]
        summary_table = Table(summary_data, colWidths=[110, 60, 110, 60, 120, 60])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Transfer Table
        elements.append(Paragraph("Recent Monitored File Transfers", heading2_style))

        transfers = db.query(FileTransfer).order_by(FileTransfer.created_at.desc()).limit(limit).all()

        table_data = [
            [
                Paragraph("<b>Filename</b>", cell_bold),
                Paragraph("<b>Size</b>", cell_bold),
                Paragraph("<b>Dest IP</b>", cell_bold),
                Paragraph("<b>Protocol</b>", cell_bold),
                Paragraph("<b>Risk</b>", cell_bold),
                Paragraph("<b>Status</b>", cell_bold),
                Paragraph("<b>Integrity</b>", cell_bold),
            ]
        ]

        for t in transfers:
            size_kb = f"{round(t.file_size_bytes / 1024, 1)} KB" if t.file_size_bytes < 1048576 else f"{round(t.file_size_bytes / 1048576, 2)} MB"
            risk_badge = f"{t.risk_score} ({t.risk_level.value})"
            table_data.append([
                Paragraph(t.filename[:22] + "..." if len(t.filename) > 25 else t.filename, cell_style),
                Paragraph(size_kb, cell_style),
                Paragraph(t.destination_ip, cell_style),
                Paragraph(t.protocol, cell_style),
                Paragraph(risk_badge, cell_style),
                Paragraph(t.status.value, cell_style),
                Paragraph(t.integrity_status.value, cell_style),
            ])

        tx_table = Table(table_data, colWidths=[120, 60, 90, 55, 80, 75, 60])
        tx_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        elements.append(tx_table)

        doc.build(elements)
        return buffer.getvalue()

    @classmethod
    def generate_alerts_pdf(cls, db: Session, limit: int = 50) -> bytes:
        """Generates formal Incident & Threat Triage Report in PDF format."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'AlertTitle',
            parent=styles['Heading1'],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#991b1b'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'AlertSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=15
        )
        cell_style = ParagraphStyle(
            'AlertCell',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#1e293b')
        )
        cell_bold = ParagraphStyle(
            'AlertCellBold',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold'
        )

        elements = []

        # Header
        elements.append(Paragraph("SOC Security Incident & Threat Triage Report", title_style))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Generated: {now_str} | Target: SOC Security Analysts & Auditing Authorities", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#dc2626'), spaceAfter=15))

        # Alerts List
        alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()

        table_data = [
            [
                Paragraph("<b>Alert Title / Violations</b>", cell_bold),
                Paragraph("<b>Severity</b>", cell_bold),
                Paragraph("<b>Risk Score</b>", cell_bold),
                Paragraph("<b>Status</b>", cell_bold),
                Paragraph("<b>Logged Time (UTC)</b>", cell_bold),
            ]
        ]

        for a in alerts:
            table_data.append([
                Paragraph(a.title[:45] + "..." if len(a.title) > 48 else a.title, cell_style),
                Paragraph(a.severity.value, cell_bold),
                Paragraph(str(a.risk_score), cell_style),
                Paragraph(a.status.value, cell_style),
                Paragraph(a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "", cell_style),
            ])

        alert_table = Table(table_data, colWidths=[230, 70, 65, 80, 95])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')])
        ]))
        elements.append(alert_table)

        doc.build(elements)
        return buffer.getvalue()
