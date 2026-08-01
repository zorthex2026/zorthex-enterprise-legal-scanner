#!/usr/bin/env python3
"""
ZTR — Verification Receipt PDF Generator
Produces a professional, one-page PDF receipt that a professional
can download and attach to their case file.

Includes: all receipt fields, QR code for independent verification,
legal disclaimer, and TSA token reference.
"""

import os
import io
import qrcode
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics import renderPDF


# === COLORS ===
GOLD = HexColor('#b8962e')
DARK = HexColor('#1a1a2e')
LIGHT_GOLD = HexColor('#f5f0e0')
MEDIUM_GREY = HexColor('#666666')
LIGHT_GREY = HexColor('#eeeeee')
VERIFIED_GREEN = HexColor('#1a7a3a')
UNVERIFIED_RED = HexColor('#a83232')


def generate_qr_code(url: str, size: int = 120) -> io.BytesIO:
    """Generate QR code as in-memory image."""
    qr = qrcode.QRCode(
        version=1, error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8, border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#1a1a2e", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf


def create_receipt_pdf(
    output_path: str,
    receipt_id: str,
    document_sha256: str,
    review_timestamp: str,
    review_note: str,
    context: str,
    user_id: str,
    tsa_status: str,
    integrity_hmac: str,
    tsa_endpoint: str = "servizi.arubapec.it",
    org_id: str = "",
    server_version: str = "0.1",
    capsule_lineage: str = "v1.2",
):
    """Generate a professional one-page PDF receipt."""

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=15*mm, bottomMargin=15*mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle('ReceiptTitle', parent=styles['Normal'],
        fontSize=18, leading=22, fontName='Helvetica-Bold',
        textColor=DARK, alignment=TA_LEFT))

    styles.add(ParagraphStyle('ReceiptSubtitle', parent=styles['Normal'],
        fontSize=9, leading=12, textColor=MEDIUM_GREY, alignment=TA_LEFT))

    styles.add(ParagraphStyle('SectionLabel', parent=styles['Normal'],
        fontSize=8, leading=10, fontName='Helvetica-Bold',
        textColor=GOLD, spaceBefore=3*mm, spaceAfter=1*mm))

    styles.add(ParagraphStyle('FieldLabel', parent=styles['Normal'],
        fontSize=7.5, leading=9, fontName='Helvetica-Bold',
        textColor=MEDIUM_GREY))

    styles.add(ParagraphStyle('FieldValue', parent=styles['Normal'],
        fontSize=9, leading=12, fontName='Courier',
        textColor=DARK))

    styles.add(ParagraphStyle('HashValue', parent=styles['Normal'],
        fontSize=7, leading=10, fontName='Courier',
        textColor=DARK, wordWrap='CJK', splitLongWords=False))

    styles.add(ParagraphStyle('FieldValueNormal', parent=styles['Normal'],
        fontSize=9, leading=12, textColor=DARK))

    styles.add(ParagraphStyle('StatusVerified', parent=styles['Normal'],
        fontSize=10, leading=13, fontName='Helvetica-Bold',
        textColor=VERIFIED_GREEN))

    styles.add(ParagraphStyle('StatusUnverified', parent=styles['Normal'],
        fontSize=10, leading=13, fontName='Helvetica-Bold',
        textColor=UNVERIFIED_RED))

    styles.add(ParagraphStyle('Disclaimer', parent=styles['Normal'],
        fontSize=7, leading=9, textColor=MEDIUM_GREY,
        alignment=TA_JUSTIFY))

    styles.add(ParagraphStyle('Footer', parent=styles['Normal'],
        fontSize=6.5, leading=8, textColor=HexColor('#999999'),
        alignment=TA_CENTER))

    styles.add(ParagraphStyle('QRLabel', parent=styles['Normal'],
        fontSize=7, leading=9, textColor=DARK,
        alignment=TA_CENTER))

    # === BUILD STORY ===
    story = []

    # --- HEADER ---
    verify_url = f"https://temporalregistry.com/verify/{receipt_id}"
    qr_buf = generate_qr_code(verify_url)
    qr_img = Image(qr_buf, width=28*mm, height=28*mm)

    # Parse timestamp for display
    try:
        dt = datetime.fromisoformat(review_timestamp.replace('Z', '+00:00'))
        date_display = dt.strftime('%d %B %Y')
        time_display = dt.strftime('%H:%M:%S UTC')
    except:
        date_display = review_timestamp[:10]
        time_display = review_timestamp[11:19] + " UTC"

    # Header table: title left, QR right
    header_left = [
        [Paragraph("VERIFICATION RECEIPT", styles['ReceiptTitle'])],
        [Paragraph("ZTR — Temporal Registry", styles['ReceiptSubtitle'])],
        [Paragraph(f"Contemporaneous record of human verification", styles['ReceiptSubtitle'])],
    ]

    header_right = [
        [qr_img],
        [Paragraph("Scan to verify", styles['QRLabel'])],
    ]

    header_table = Table(
        [[Table(header_left), Table(header_right)]],
        colWidths=[120*mm, 40*mm],
    )
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 2*mm))

    # Gold line
    story.append(HRFlowable(width="100%", thickness=1.5, color=GOLD, spaceAfter=4*mm))

    # --- TSA STATUS BANNER ---
    if tsa_status == "VERIFIED":
        status_text = "eIDAS QUALIFIED — TIMESTAMP VERIFIED"
        status_style = 'StatusVerified'
        status_bg = HexColor('#e8f5e9')
        status_border = VERIFIED_GREEN
    else:
        status_text = f"TIMESTAMP STATUS: {tsa_status}"
        status_style = 'StatusUnverified'
        status_bg = HexColor('#fce4ec')
        status_border = UNVERIFIED_RED

    status_table = Table(
        [[Paragraph(status_text, styles[status_style])]],
        colWidths=[160*mm],
    )
    status_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_bg),
        ('BORDER_COLOR', (0, 0), (-1, -1), status_border),
        ('BOX', (0, 0), (-1, -1), 1, status_border),
        ('TOPPADDING', (0, 0), (-1, -1), 3*mm),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3*mm),
        ('LEFTPADDING', (0, 0), (-1, -1), 4*mm),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(status_table)
    story.append(Spacer(1, 4*mm))

    # --- RECEIPT DETAILS ---
    story.append(Paragraph("RECEIPT IDENTIFICATION", styles['SectionLabel']))

    details_data = [
        [Paragraph("Receipt ID", styles['FieldLabel']),
         Paragraph(receipt_id, styles['FieldValue'])],
        [Paragraph("Date", styles['FieldLabel']),
         Paragraph(date_display, styles['FieldValueNormal'])],
        [Paragraph("Time", styles['FieldLabel']),
         Paragraph(time_display, styles['FieldValueNormal'])],
        [Paragraph("Context", styles['FieldLabel']),
         Paragraph(context.replace('_', ' ').title(), styles['FieldValueNormal'])],
    ]
    if org_id:
        details_data.append(
            [Paragraph("Organisation", styles['FieldLabel']),
             Paragraph(org_id, styles['FieldValueNormal'])]
        )

    details_table = Table(details_data, colWidths=[35*mm, 125*mm])
    details_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 1.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5),
        ('LINEBELOW', (0, 0), (-1, -2), 0.3, LIGHT_GREY),
    ]))
    story.append(details_table)
    story.append(Spacer(1, 3*mm))

    # --- DOCUMENT HASH ---
    story.append(Paragraph("DOCUMENT FINGERPRINT", styles['SectionLabel']))

    hash_data = [
        [Paragraph("SHA-256 Hash", styles['FieldLabel']),
         Paragraph(document_sha256, styles['HashValue'])],
    ]
    hash_table = Table(hash_data, colWidths=[35*mm, 125*mm])
    hash_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BACKGROUND', (1, 0), (1, 0), HexColor('#f8f8f8')),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING', (1, 0), (1, 0), 3),
    ]))
    story.append(hash_table)
    story.append(Paragraph(
        "The original document was hashed and immediately discarded. "
        "It was never stored, transmitted, or retained by the system. "
        "Only this 64-character fingerprint was recorded.",
        styles['Disclaimer']
    ))
    story.append(Paragraph(
        "Hash computed on verified text content — same content produces "
        "same hash regardless of file format (PDF, DOCX, email).",
        styles['Disclaimer']
    ))
    story.append(Spacer(1, 3*mm))

    # --- REVIEWER DECLARATION ---
    story.append(Paragraph("REVIEWER DECLARATION", styles['SectionLabel']))

    note_text = review_note if review_note else "(No reviewer note recorded)"
    note_data = [
        [Paragraph("Reviewer", styles['FieldLabel']),
         Paragraph(user_id, styles['FieldValueNormal'])],
        [Paragraph("Declaration", styles['FieldLabel']),
         Paragraph(f'"{note_text}"', styles['FieldValueNormal'])],
    ]
    note_table = Table(note_data, colWidths=[35*mm, 125*mm])
    note_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 1.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5),
        ('LINEBELOW', (0, 0), (-1, -2), 0.3, LIGHT_GREY),
    ]))
    story.append(note_table)
    story.append(Spacer(1, 3*mm))

    # --- TIMESTAMP AUTHORITY ---
    story.append(Paragraph("TIMESTAMP AUTHORITY", styles['SectionLabel']))

    tsa_data = [
        [Paragraph("Provider", styles['FieldLabel']),
         Paragraph("Aruba PEC S.p.A. — Qualified Trust Service Provider (eIDAS)", styles['FieldValueNormal'])],
        [Paragraph("Standard", styles['FieldLabel']),
         Paragraph("RFC 3161 — Internet X.509 PKI Time-Stamp Protocol", styles['FieldValueNormal'])],
        [Paragraph("Endpoint", styles['FieldLabel']),
         Paragraph(tsa_endpoint, styles['FieldValue'])],
        [Paragraph("Status", styles['FieldLabel']),
         Paragraph(tsa_status, styles[status_style])],
    ]
    tsa_table = Table(tsa_data, colWidths=[35*mm, 125*mm])
    tsa_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 1.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5),
        ('LINEBELOW', (0, 0), (-1, -2), 0.3, LIGHT_GREY),
    ]))
    story.append(tsa_table)
    story.append(Spacer(1, 3*mm))

    # --- INTEGRITY ---
    story.append(Paragraph("INTEGRITY SEAL", styles['SectionLabel']))

    seal_data = [
        [Paragraph("HMAC-SHA256", styles['FieldLabel']),
         Paragraph(integrity_hmac, styles['FieldValue'])],
    ]
    seal_table = Table(seal_data, colWidths=[35*mm, 125*mm])
    seal_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BACKGROUND', (1, 0), (1, 0), HexColor('#f8f8f8')),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING', (1, 0), (1, 0), 3),
    ]))
    story.append(seal_table)
    story.append(Spacer(1, 3*mm))

    # --- INDEPENDENT VERIFICATION ---
    story.append(HRFlowable(width="100%", thickness=0.5, color=GOLD, spaceAfter=3*mm))

    story.append(Paragraph("INDEPENDENT VERIFICATION", styles['SectionLabel']))
    story.append(Paragraph(
        f"This receipt can be independently verified — without requiring access to ZTR — "
        f"at the following URL:",
        styles['Disclaimer']
    ))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph(
        f'<font color="#1a1a2e"><b>{verify_url}</b></font>',
        styles['FieldValueNormal']
    ))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph(
        "To verify: upload the original document at the URL above. The system will "
        "recalculate the SHA-256 hash, compare it with the hash in this receipt, and "
        "validate the RFC 3161 timestamp token against the Aruba PEC TSA certificate. "
        "No account or login is required.",
        styles['Disclaimer']
    ))
    story.append(Spacer(1, 3*mm))

    # --- LEGAL DISCLAIMER ---
    story.append(HRFlowable(width="100%", thickness=0.3, color=LIGHT_GREY, spaceAfter=2*mm))

    story.append(Paragraph(
        "<b>Disclaimer.</b> This receipt is a contemporaneous record that a human verification "
        "step was declared at the timestamp shown. It does not attest that the verification "
        "was performed correctly, that the document is free of errors, or that any professional "
        "duty has been fulfilled. The reviewer's declaration reflects what the reviewer stated "
        "at the time of verification — ZTR does not and cannot independently confirm its accuracy. "
        "The eIDAS-qualified timestamp provides legally presumed accuracy of the time of recording "
        "under Regulation (EU) 910/2014, recognised in 27 EU member states and the United Kingdom.",
        styles['Disclaimer']
    ))

    story.append(Spacer(1, 3*mm))

    # --- FOOTER ---
    story.append(Paragraph(
        f"ZTR — Temporal Registry | temporalregistry.com | "
        f"Server v{server_version} | Capsule lineage {capsule_lineage}<br/>"
        f"ZORTHEX\u2122 (UIBM N.302026000090628) | "
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        styles['Footer']
    ))

    # Build
    doc.build(story)
    return output_path


# === DEMO ===
if __name__ == "__main__":
    output = create_receipt_pdf(
        output_path="/mnt/user-data/outputs/ZTR_Receipt_DEMO.pdf",
        receipt_id="ZTR-20260724145329-425899ef",
        document_sha256="5ab4b6251fd5783b9e0f8c3a2d7e6b4f1a9c8d0e3f2b5a7c4d6e8f0a1b3c5d7e",
        review_timestamp="2026-07-24T14:53:29.107741+00:00",
        review_note="Citations verified against Westlaw and cross-referenced with court records. No AI-generated content was left unreviewed.",
        context="legal_filing",
        user_id="admin@temporalregistry.com",
        tsa_status="VERIFIED",
        integrity_hmac="dbfbd47a2494c890a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
        tsa_endpoint="servizi.arubapec.it/tsa/ngrequest.php",
    )
    print(f"Receipt PDF created: {output}")
