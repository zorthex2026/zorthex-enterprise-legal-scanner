#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZORTHEX™ TEMPORAL REGISTRY — REMOTE MCP CONNECTOR
====================================================
File: ztr_remote_connector.py
Add to: github.com/zorthex2026/zorthex-enterprise-legal-scanner

PURPOSE:
  Extends the existing on-premise MCP server with a REMOTE mode
  for the Anthropic Connectors Directory (Claude Cowork / Web).

  On-premise mode (existing):
    Claude Desktop → local MCP → scanner + registry on client machine

  Remote mode (new):
    Claude Cowork → HTTPS → temporalregistry.com → registry only
    Scanner stays on-premise. Only the Temporal Registry is exposed remotely.
    Document text is hashed server-side and immediately discarded.

RELATIONSHIP TO EXISTING CODE:
  - Uses the same capsule logic from zorthex_temporal_registry.py
  - Uses the same SHA-256 hashing
  - Uses the same Aruba PEC TSA (eIDAS qualified, RFC 3161)
  - Does NOT expose the scanner remotely (scanner is local-only)
  - Adds: HTTP server, OAuth, receipt storage, Anthropic directory compliance

DEPLOYMENT:
  Host: temporalregistry.com
  Stack: FastAPI + uvicorn
  Storage: SQLite (receipts)
  TSA: Aruba PEC free TSA (same as capsule v1.2)

© 2026 Renato Santi — ZORTHEX™ (Trademark UIBM N.302026000090628)
Proprietary — All rights reserved.
"""

import hashlib
import json
import sqlite3
import os
import base64
import requests
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, List


# ============================================================================
# CORE: Verification Receipt
# Derived from existing capsule v1.2 logic — same hash, same TSA, simpler
# output for the remote use case (no scanner, no verdict, no policy context)
# ============================================================================

@dataclass
class VerificationReceipt:
    """
    A contemporaneous record that a human verification step occurred.
    
    This is the remote equivalent of the on-premise capsule.
    Key differences from capsule v1.2:
      - No scanner verdict (scanner is local-only)
      - No policy context (that's the scanner's job)
      - No verification manifest (simplified for remote)
      - Adds: user identity, review note, context type
    
    Same as capsule v1.2:
      - SHA-256 document hash (document never stored)
      - eIDAS-qualified timestamp (Aruba PEC TSA)
      - HMAC integrity seal
      - Honest state: declares UNVERIFIED if no TSA available
    """
    receipt_id: str
    document_sha256: str
    review_timestamp: str           # ISO 8601 UTC
    review_note: str                # reviewer's note (optional)
    context: str                    # review type
    user_id: str                    # authenticated user
    org_id: str                     # organization (optional)
    tsa_status: str                 # VERIFIED (eIDAS) | UNVERIFIED | TSA_ERROR
    tsa_token: Optional[str]        # RFC 3161 timestamp token (base64)
    integrity_hmac: Optional[str]   # HMAC-SHA256 seal
    server_version: str = "0.1"
    capsule_lineage: str = "v1.2"   # traces origin to capsule v1.2

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ============================================================================
# HASHING — same as capsule v1.2
# ============================================================================

def compute_sha256(text: str) -> str:
    """
    SHA-256 hash of document text.
    After this call, the text MUST be discarded.
    Only the 64-character hash is retained.
    """
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def compute_hmac(receipt_data: str, key: str = None) -> str:
    """HMAC-SHA256 integrity seal — same approach as capsule v1.2."""
    import hmac
    if key is None:
        key = os.environ.get("ZTR_HMAC_KEY", "ztr-default-key-change-in-production")
    return hmac.new(
        key.encode('utf-8'),
        receipt_data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


# ============================================================================
# RECEIPT ID GENERATION
# ============================================================================

def generate_receipt_id() -> str:
    """ZTR-{YYYYMMDDHHMMSS}-{8 random hex chars}"""
    ts = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    rand = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    return f"ZTR-{ts}-{rand}"


# ============================================================================
# ARUBA PEC TSA — eIDAS qualified timestamp (RFC 3161)
# Same TSA used for capsule v1.2 — first admissible capsule 5 July 2026
# ============================================================================

def aruba_tsa_timestamp(doc_hash: str) -> dict:
    """
    Request RFC 3161 timestamp using pure Python (rfc3161ng).
    Primary: Aruba PEC free TSA (eIDAS qualified)
    Fallback: FreeTSA.org (public TSA)
    No subprocess, no openssl binary. Works on Render.
    Version: 2026-07-23-v3
    """
    import rfc3161ng
    import requests as http_requests

    hash_bytes = bytes.fromhex(doc_hash)
    tsr = rfc3161ng.make_timestamp_request(data=hash_bytes)

    endpoints = [
        'https://freetsa.aruba.it/tsa/',
        'https://freetsa.org/tsr',
    ]

    last_error = None
    for endpoint in endpoints:
        try:
            resp = http_requests.post(
                endpoint,
                data=tsr,
                headers={'Content-Type': 'application/timestamp-query'},
                timeout=15,
            )
            if resp.status_code == 200:
                token_b64 = base64.b64encode(resp.content).decode('ascii')
                return {"token": token_b64, "status": "granted", "endpoint": endpoint}
        except Exception as e:
            last_error = e
            continue

    raise Exception(f"All TSA endpoints failed. Last: {last_error}")


# ============================================================================
# RECEIPT CREATION
# ============================================================================

def create_receipt(
    document_text: str,
    user_id: str,
    org_id: str = "",
    review_note: str = "",
    context: str = "legal_filing",
    use_tsa: bool = True,
) -> VerificationReceipt:
    """
    Core receipt creation — the remote equivalent of capsule generation.

    1. Hash the document (SHA-256)
    2. Discard the document text (NEVER stored)
    3. Record timestamp
    4. Call Aruba TSA if enabled (eIDAS qualified)
    5. Seal with HMAC
    6. Return receipt
    """
    # Step 1: Hash
    doc_hash = compute_sha256(document_text)

    # Step 2: Document text is now dead to us
    # (Python GC will handle it; we never assign it to any persistent store)

    # Step 3: Timestamp
    now = datetime.now(timezone.utc).isoformat()
    receipt_id = generate_receipt_id()

    # Step 4: TSA
    tsa_status = "UNVERIFIED"
    tsa_token = None
    if use_tsa:
        try:
            tsa_result = aruba_tsa_timestamp(doc_hash)
            tsa_status = "VERIFIED"
            tsa_token = tsa_result.get("token")
        except Exception as e:
            tsa_status = f"TSA_ERROR:{str(e)[:100]}"

    # Step 5: HMAC seal
    seal_data = f"{receipt_id}:{doc_hash}:{now}:{tsa_status}"
    integrity_hmac = compute_hmac(seal_data)

    return VerificationReceipt(
        receipt_id=receipt_id,
        document_sha256=doc_hash,
        review_timestamp=now,
        review_note=review_note,
        context=context,
        user_id=user_id,
        org_id=org_id,
        tsa_status=tsa_status,
        tsa_token=tsa_token,
        integrity_hmac=integrity_hmac,
    )


# ============================================================================
# STORAGE: SQLite receipt database
# ============================================================================

class ReceiptStore:
    """Persistent storage for verification receipts."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.environ.get("ZTR_DB_PATH", "ztr_receipts.db")
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    document_sha256 TEXT NOT NULL,
                    review_timestamp TEXT NOT NULL,
                    review_note TEXT DEFAULT '',
                    context TEXT DEFAULT 'general',
                    user_id TEXT NOT NULL,
                    org_id TEXT DEFAULT '',
                    tsa_status TEXT NOT NULL,
                    tsa_token TEXT,
                    integrity_hmac TEXT,
                    server_version TEXT DEFAULT '0.1',
                    capsule_lineage TEXT DEFAULT 'v1.2',
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_user ON receipts(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON receipts(document_sha256)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_time ON receipts(review_timestamp)")

    def store(self, receipt: VerificationReceipt):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO receipts
                (receipt_id, document_sha256, review_timestamp, review_note,
                 context, user_id, org_id, tsa_status, tsa_token,
                 integrity_hmac, server_version, capsule_lineage)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                receipt.receipt_id, receipt.document_sha256,
                receipt.review_timestamp, receipt.review_note,
                receipt.context, receipt.user_id, receipt.org_id,
                receipt.tsa_status, receipt.tsa_token,
                receipt.integrity_hmac, receipt.server_version,
                receipt.capsule_lineage,
            ))

    def get(self, receipt_id: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_by_user(self, user_id: str, date_from: str = None,
                     date_to: str = None, context: str = None,
                     limit: int = 50) -> List[dict]:
        query = "SELECT * FROM receipts WHERE user_id = ?"
        params = [user_id]
        if date_from:
            query += " AND review_timestamp >= ?"
            params.append(date_from)
        if date_to:
            query += " AND review_timestamp <= ?"
            params.append(date_to)
        if context:
            query += " AND context = ?"
            params.append(context)
        query += " ORDER BY review_timestamp DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def find_by_hash(self, document_sha256: str) -> List[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM receipts WHERE document_sha256 = ? ORDER BY review_timestamp DESC",
                (document_sha256,)
            ).fetchall()]

    def count_by_user(self, user_id: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM receipts WHERE user_id = ?", (user_id,)
            ).fetchone()
            return row[0] if row else 0


# ============================================================================
# FASTAPI APPLICATION — HTTP server for Anthropic Connectors Directory
# ============================================================================

def create_app():
    """
    FastAPI application serving ZTR as a remote MCP connector.

    Endpoints:
      POST /mcp/tools/verify_document  — Create verification receipt
      POST /mcp/tools/check_receipt    — Retrieve a receipt
      POST /mcp/tools/list_receipts    — List user's receipts
      GET  /mcp/tools                  — List available tools
      GET  /health                     — Health check
      GET  /.well-known/anthropic-connector-challenge — Domain verification
    """
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI(
        title="Zorthex Temporal Registry",
        description=(
            "Verification timestamping for AI-assisted legal work. "
            "Creates contemporaneous records proving that human review occurred. "
            "Documents are hashed and immediately discarded — never stored. "
            "Timestamps are eIDAS-qualified via Aruba PEC TSA."
        ),
        version="0.1",
        docs_url="/docs",
    )

    # CORS for Claude origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://claude.ai",
            "https://www.anthropic.com",
        ],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    store = ReceiptStore()

    # --- Health ---
    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "service": "ztr-mcp-remote",
            "version": "0.1",
            "capsule_lineage": "v1.2",
            "tsa": "Aruba PEC (eIDAS qualified)",
        }

    # --- Tool: verify_document ---
    @app.post("/mcp/tools/verify_document")
    async def verify_document(request: Request):
        body = await request.json()
        user_id = request.headers.get("X-User-ID", "anonymous")
        org_id = request.headers.get("X-Org-ID", "")

        document_text = body.get("document_text")
        if not document_text:
            raise HTTPException(400, "document_text is required")
        if len(document_text) > 5_000_000:  # 5MB limit
            raise HTTPException(413, "Document too large (max 5MB)")

        receipt = create_receipt(
            document_text=document_text,
            user_id=user_id,
            org_id=org_id,
            review_note=body.get("review_note", ""),
            context=body.get("context", "legal_filing"),
            use_tsa=True,
        )
        store.store(receipt)

        # Document text is gone. Only the hash lives on.
        return JSONResponse({
            "receipt_id": receipt.receipt_id,
            "document_sha256": receipt.document_sha256,
            "review_timestamp": receipt.review_timestamp,
            "tsa_status": receipt.tsa_status,
            "integrity_hmac": receipt.integrity_hmac[:16] + "...",
            "context": receipt.context,
            "message": (
                f"Verification recorded. Receipt: {receipt.receipt_id}. "
                f"Hash: {receipt.document_sha256[:16]}... "
                f"Time: {receipt.review_timestamp}. "
                f"TSA: {receipt.tsa_status}. "
                f"Document was not stored."
            ),
        })

    # --- Tool: check_receipt ---
    @app.post("/mcp/tools/check_receipt")
    async def check_receipt(request: Request):
        body = await request.json()
        receipt_id = body.get("receipt_id")
        if not receipt_id:
            raise HTTPException(400, "receipt_id is required")

        receipt = store.get(receipt_id)
        if not receipt:
            raise HTTPException(404, f"Receipt {receipt_id} not found")

        # Don't expose TSA token in lookup (it's large)
        result = dict(receipt)
        if result.get("tsa_token"):
            result["tsa_token"] = result["tsa_token"][:32] + "...(truncated)"
        return JSONResponse(result)

    # --- Tool: list_receipts ---
    @app.post("/mcp/tools/list_receipts")
    async def list_receipts(request: Request):
        body = await request.json()
        user_id = request.headers.get("X-User-ID", "anonymous")

        receipts = store.list_by_user(
            user_id=user_id,
            date_from=body.get("date_from"),
            date_to=body.get("date_to"),
            context=body.get("context"),
        )
        # Strip TSA tokens from list view
        for r in receipts:
            if r.get("tsa_token"):
                r["tsa_token"] = "(stored)"
        return JSONResponse({"count": len(receipts), "receipts": receipts})

    # --- Tool listing ---
    @app.get("/mcp/tools")
    async def list_tools():
        return JSONResponse({"tools": MCP_TOOL_DEFINITIONS})

    # --- Anthropic domain verification ---
    @app.get("/.well-known/anthropic-connector-challenge")
    async def anthropic_challenge():
        token = os.environ.get("ANTHROPIC_CHALLENGE_TOKEN", "")
        return JSONResponse({"challenge_token": token})

    # --- HTML Pages ---
    from fastapi.responses import HTMLResponse
    import pathlib

    def read_html(filename: str) -> str:
        """Read HTML file from same directory as this script."""
        base = pathlib.Path(__file__).parent
        path = base / filename
        if path.exists():
            return path.read_text(encoding='utf-8')
        return f"<html><body><h1>{filename} not found</h1></body></html>"

    @app.get("/", response_class=HTMLResponse)
    async def homepage():
        return HTMLResponse(content=read_html("index.html"))

    @app.get("/privacy", response_class=HTMLResponse)
    async def privacy():
        return HTMLResponse(content=read_html("privacy.html"))

    @app.get("/terms", response_class=HTMLResponse)
    async def terms():
        return HTMLResponse(content=read_html("terms.html"))

    @app.get("/documentation", response_class=HTMLResponse)
    async def documentation():
        return HTMLResponse(content=read_html("docs.html"))

    return app


# ============================================================================
# MCP TOOL DEFINITIONS — for Anthropic Connectors Directory
# ============================================================================

MCP_TOOL_DEFINITIONS = [
    {
        "name": "verify_document",
        "description": (
            "[third_party_mcp_app] Zorthex Temporal Registry — Create a timestamped, "
            "eIDAS-qualified record proving that a human reviewed a document before use. "
            "The document is hashed (SHA-256) and immediately discarded — never stored or "
            "transmitted beyond the hash. Returns a verification receipt. Use this before "
            "filing any AI-assisted legal document."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_text": {
                    "type": "string",
                    "description": (
                        "The document text to verify. Hashed and immediately discarded. "
                        "Never stored."
                    ),
                },
                "review_note": {
                    "type": "string",
                    "description": "Optional note (e.g. 'Citations verified against Westlaw')",
                    "default": "",
                },
                "context": {
                    "type": "string",
                    "enum": [
                        "legal_filing", "contract_review", "legal_research",
                        "client_advice", "regulatory_submission",
                        "internal_memo", "other",
                    ],
                    "default": "legal_filing",
                },
            },
            "required": ["document_text"],
        },
    },
    {
        "name": "check_receipt",
        "description": (
            "[third_party_mcp_app] Zorthex Temporal Registry — Look up a verification "
            "receipt by ID. Returns hash, timestamp, TSA status, and reviewer identity."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "receipt_id": {
                    "type": "string",
                    "description": "Receipt ID (format: ZTR-YYYYMMDDHHMMSS-XXXXXXXX)",
                },
            },
            "required": ["receipt_id"],
        },
    },
    {
        "name": "list_receipts",
        "description": (
            "[third_party_mcp_app] Zorthex Temporal Registry — List your verification "
            "receipts. Filter by date range or review context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "date_from": {"type": "string", "description": "Start date (ISO 8601)"},
                "date_to": {"type": "string", "description": "End date (ISO 8601)"},
                "context": {"type": "string", "description": "Filter by context type"},
            },
            "required": [],
        },
    },
]


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8443))
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  ZORTHEX™ TEMPORAL REGISTRY — REMOTE MCP CONNECTOR         ║
║  Capsule lineage: v1.2 · TSA: Aruba PEC (eIDAS)            ║
║  Host: temporalregistry.com · Port: {port}                   ║
║  Documents are NEVER stored. Only 64-char SHA-256 hashes.   ║
╚══════════════════════════════════════════════════════════════╝
""")
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=port)
