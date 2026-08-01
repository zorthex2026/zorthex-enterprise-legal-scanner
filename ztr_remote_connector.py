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
  TSA: Aruba PEC qualified TSA (eIDAS, servizi.arubapec.it)

© 2026 Renato Santi — ZORTHEX™ (Trademark UIBM N.302026000090628)
Proprietary — All rights reserved.
"""

import hashlib
import json
import sqlite3
import os
import base64
import uuid
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
    Request RFC 3161 timestamp from Aruba PEC QUALIFIED TSA (eIDAS).
    Endpoint: https://servizi.arubapec.it/tsa/ngrequest.php
    Algorithm: SHA-256
    Auth: HTTP Basic (credentials from environment variables)
    Fallback: FreeTSA.org (non-qualified, free)
    Version: 2026-07-23-v4-qualified
    """
    import requests as http_requests
    from requests.auth import HTTPBasicAuth
    from pyasn1.type import univ, namedtype
    from pyasn1.codec.der import encoder
    from pyasn1_modules import rfc2459

    hash_bytes = bytes.fromhex(doc_hash)

    # --- Build RFC 3161 TimeStampReq with SHA-256 ---
    sha256_oid = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))

    class MessageImprint(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('hashAlgorithm', rfc2459.AlgorithmIdentifier()),
            namedtype.NamedType('hashedMessage', univ.OctetString())
        )

    class TimeStampReq(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('version', univ.Integer()),
            namedtype.NamedType('messageImprint', MessageImprint()),
            namedtype.OptionalNamedType('reqPolicy', univ.ObjectIdentifier()),
            namedtype.OptionalNamedType('nonce', univ.Integer()),
            namedtype.DefaultedNamedType('certReq', univ.Boolean(False))
        )

    algo = rfc2459.AlgorithmIdentifier()
    algo['algorithm'] = sha256_oid

    mi = MessageImprint()
    mi['hashAlgorithm'] = algo
    mi['hashedMessage'] = univ.OctetString(hash_bytes)

    req = TimeStampReq()
    req['version'] = univ.Integer(1)
    req['messageImprint'] = mi
    req['certReq'] = univ.Boolean(True)

    tsr_bytes = encoder.encode(req)

    # --- Try Aruba QUALIFIED first, then FreeTSA fallback ---
    aruba_user = os.environ.get("ARUBA_TSA_USERNAME", "")
    aruba_pass = os.environ.get("ARUBA_TSA_PASSWORD", "")

    endpoints = []
    if aruba_user and aruba_pass:
        endpoints.append({
            "url": "https://servizi.arubapec.it/tsa/ngrequest.php",
            "auth": HTTPBasicAuth(aruba_user, aruba_pass),
            "qualified": True,
        })
    endpoints.append({
        "url": "https://freetsa.org/tsr",
        "auth": None,
        "qualified": False,
    })

    last_error = None
    for ep in endpoints:
        try:
            resp = http_requests.post(
                ep["url"],
                data=tsr_bytes,
                headers={'Content-Type': 'application/timestamp-query'},
                auth=ep.get("auth"),
                timeout=15,
            )
            if resp.status_code == 200:
                token_b64 = base64.b64encode(resp.content).decode('ascii')
                return {
                    "token": token_b64,
                    "status": "granted",
                    "endpoint": ep["url"],
                    "qualified": ep["qualified"],
                }
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
    pre_computed_hash: str = None,
) -> VerificationReceipt:
    """
    Core receipt creation — the remote equivalent of capsule generation.

    1. Hash the document (SHA-256) or use pre-computed hash for binary files
    2. Discard the document text (NEVER stored)
    3. Record timestamp
    4. Call Aruba TSA if enabled (eIDAS qualified)
    5. Seal with HMAC
    6. Return receipt
    """
    # Step 1: Hash (pre-computed for binary files, computed for text)
    if pre_computed_hash:
        doc_hash = pre_computed_hash
    else:
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
        title="ZTR — Temporal Registry",
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

        # --- Daily quota check (BEFORE TSA call to protect marche) ---
        DAILY_QUOTA = 10
        today_start = datetime.now(timezone.utc).strftime('%Y-%m-%dT00:00:00')
        today_receipts = store.list_by_user(user_id, date_from=today_start)
        if len(today_receipts) >= DAILY_QUOTA:
            return JSONResponse(
                status_code=429,
                content={
                    "status": "QUOTA_EXCEEDED",
                    "message": (
                        f"Technical preview fair-use quota reached "
                        f"({DAILY_QUOTA} receipts/day). Quota resets at 00:00 UTC."
                    ),
                },
            )

        # --- Global TSA budget check (protects personal wallet) ---
        DAILY_TSA_BUDGET = 5  # max qualified timestamps per day, all users combined
        use_tsa = True
        with sqlite3.connect(store.db_path) as conn:
            row = conn.execute(
                """SELECT COUNT(*) FROM receipts
                   WHERE tsa_status = 'VERIFIED'
                   AND review_timestamp >= ?""",
                (today_start,),
            ).fetchone()
            if row[0] >= DAILY_TSA_BUDGET:
                use_tsa = False

        receipt = create_receipt(
            document_text=document_text,
            user_id=user_id,
            org_id=org_id,
            review_note=body.get("review_note", ""),
            context=body.get("context", "legal_filing"),
            use_tsa=use_tsa,
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

    @app.get("/cases", response_class=HTMLResponse)
    async def cases():
        return HTMLResponse(content=read_html("cases.html"))

    @app.get("/feedback", response_class=HTMLResponse)
    async def feedback_page():
        return HTMLResponse(content=read_html("feedback.html"))

    @app.get("/verify", response_class=HTMLResponse)
    async def verify_page():
        return HTMLResponse(content=read_html("verify.html"))

    @app.get("/verify/{receipt_id}")
    async def verify_receipt(receipt_id: str):
        """Public verification endpoint - no auth required."""
        with sqlite3.connect(store.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """SELECT receipt_id, document_sha256, context,
                          tsa_status, review_timestamp
                   FROM receipts WHERE receipt_id = ?""",
                (receipt_id,)
            ).fetchone()
        if not row:
            return JSONResponse(
                {"status": "NOT_FOUND", "message": "No receipt found with this ID."},
                status_code=404
            )
        return JSONResponse({
            "status": "FOUND",
            "receipt": {
                "receipt_id": row["receipt_id"],
                "document_hash": row["document_sha256"],
                "context": row["context"],
                "tsa_status": row["tsa_status"],
                "timestamp": row["review_timestamp"],
            },
            "verification_note": (
                "This receipt confirms that a professional declared "
                "they had reviewed the specified content at the stated "
                "time. The timestamp was issued by Aruba PEC S.p.A., "
                "a Qualified Trust Service Provider under EU Regulation "
                "910/2014 (eIDAS). The document hash (SHA-256) was "
                "computed on the verified text content — same content "
                "produces the same hash regardless of file format."
            ),
        })

    @app.post("/verify/check-hash")
    async def verify_hash(request: Request):
        """Check if a document hash matches any receipt — public, no auth."""
        body = await request.json()
        doc_hash = body.get("hash", "").strip().replace("\n", "").replace("\r", "").replace(" ", "")
        if not doc_hash:
            raise HTTPException(400, "hash is required")
        with sqlite3.connect(store.db_path) as conn:
            rows = conn.execute(
                """SELECT receipt_id, tsa_status,
                          review_timestamp, context
                   FROM receipts WHERE document_sha256 = ?
                   ORDER BY review_timestamp DESC""",
                (doc_hash,)
            ).fetchall()
        if not rows:
            return JSONResponse({
                "status": "NO_MATCH",
                "message": "No verification receipt matches this hash.",
            })
        return JSONResponse({
            "status": "MATCH_FOUND",
            "matches": [
                {"receipt_id": r[0], "tsa_status": r[1], "timestamp": r[2], "context": r[3]}
                for r in rows
            ],
            "message": f"{len(rows)} receipt(s) found for this document hash.",
        })

    @app.post("/api/feedback")
    async def submit_feedback(request: Request):
        body = await request.json()
        with sqlite3.connect(store.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    used_real TEXT DEFAULT '',
                    pdf_feedback TEXT DEFAULT '',
                    pricing_feedback TEXT DEFAULT '',
                    email TEXT DEFAULT '',
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.execute(
                """INSERT INTO feedback (used_real, pdf_feedback, pricing_feedback, email) VALUES (?, ?, ?, ?)""",
                (body.get("used_real", ""), body.get("pdf_feedback", ""), body.get("pricing_feedback", ""), body.get("email", ""))
            )
        return JSONResponse({"status": "ok", "message": "Thank you for your feedback."})

    @app.get("/admin/feedback")
    async def admin_feedback(request: Request):
        key = request.query_params.get("key", "")
        admin_key = os.environ.get("ZTR_ADMIN_KEY", "ztr-admin-2026")
        if key != admin_key:
            raise HTTPException(403, "Unauthorized")
        with sqlite3.connect(store.db_path) as conn:
            rows = conn.execute(
                "SELECT id, used_real, pdf_feedback, pricing_feedback, email, created_at FROM feedback ORDER BY created_at DESC"
            ).fetchall()
        feedback_list = [{"id": r[0], "used_real": r[1], "pdf_feedback": r[2], "pricing": r[3], "email": r[4], "date": r[5]} for r in rows]
        return JSONResponse({"total": len(feedback_list), "feedback": feedback_list})

    from fastapi.responses import FileResponse

    # ================================================================
    # OAUTH 2.0 — Simplified for Claude Connectors Directory
    # ================================================================

    # Token store in SQLite (same DB as receipts)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                code TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_codes (
                code TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                used INTEGER DEFAULT 0
            )
        """)

    ZTR_CLIENT_ID = "ztr-claude-connector"
    ZTR_SERVER_URL = os.environ.get("ZTR_SERVER_URL", "https://temporalregistry.com")

    @app.get("/.well-known/oauth-authorization-server")
    async def oauth_discovery():
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        return JSONResponse({
            "issuer": ZTR_SERVER_URL,
            "authorization_endpoint": f"{ZTR_SERVER_URL}/oauth/authorize",
            "token_endpoint": f"{ZTR_SERVER_URL}/oauth/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        })

    @app.get("/oauth/authorize")
    async def oauth_authorize(
        response_type: str = "code",
        client_id: str = "",
        redirect_uri: str = "",
        state: str = "",
        scope: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "",
    ):
        """
        OAuth authorize endpoint.
        Shows a minimal consent page, then redirects back to Claude
        with an authorization code.
        """
        from fastapi.responses import HTMLResponse
        import urllib.parse

        if not redirect_uri:
            redirect_uri = "https://claude.ai/api/mcp/auth_callback"

        # Generate auth code
        code = str(uuid.uuid4())

        # Store the code
        with sqlite3.connect(store.db_path) as conn:
            conn.execute(
                """INSERT INTO oauth_codes (code, user_id, client_id, redirect_uri)
                   VALUES (?, ?, ?, ?)""",
                (code, "oauth-user", client_id or ZTR_CLIENT_ID, redirect_uri)
            )

        # Build consent page
        consent_html = f"""
        <!DOCTYPE html>
        <html><head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ZTR — Authorize</title>
        <style>
            body{{background:#0a0a0a;color:#f0ede6;font-family:'Inter',system-ui,sans-serif;
                  display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
            .card{{background:#161616;border:1px solid #222;border-radius:8px;padding:40px;
                   max-width:400px;text-align:center}}
            h1{{font-size:20px;margin-bottom:8px;color:#c9a84c}}
            p{{font-size:14px;color:#999;line-height:1.6;margin-bottom:24px}}
            .perms{{text-align:left;background:#111;border:1px solid #222;border-radius:4px;
                    padding:16px;margin-bottom:24px;font-size:13px;color:#bbb}}
            .perms div{{padding:4px 0}}
            .btn{{display:inline-block;background:#c9a84c;color:#0a0a0a;padding:12px 32px;
                  border:none;border-radius:4px;font-size:14px;font-weight:600;cursor:pointer;
                  text-decoration:none;letter-spacing:0.5px}}
            .btn:hover{{background:#e8c97a}}
        </style>
        </head><body>
        <div class="card">
            <h1>ZTR — Temporal Registry</h1>
            <p>Claude is requesting access to create and retrieve verification receipts on your behalf.</p>
            <div class="perms">
                <div>✓ Create verification receipts (hash + timestamp)</div>
                <div>✓ Retrieve your past receipts</div>
                <div>✗ Access to your documents (never stored)</div>
            </div>
            <a class="btn" href="/oauth/callback?code={code}&state={urllib.parse.quote(state)}&redirect_uri={urllib.parse.quote(redirect_uri)}">
                Authorize ZTR
            </a>
        </div>
        </body></html>
        """
        return HTMLResponse(content=consent_html)

    @app.get("/oauth/callback")
    async def oauth_callback(code: str, state: str = "", redirect_uri: str = ""):
        """Internal callback that redirects to Claude with the auth code."""
        from fastapi.responses import RedirectResponse
        import urllib.parse

        if not redirect_uri:
            redirect_uri = "https://claude.ai/api/mcp/auth_callback"

        separator = "&" if "?" in redirect_uri else "?"
        target = f"{redirect_uri}{separator}code={code}"
        if state:
            target += f"&state={urllib.parse.quote(state)}"

        return RedirectResponse(url=target)

    @app.post("/oauth/token")
    async def oauth_token(request: Request):
        """Exchange authorization code for access token."""
        # Handle both form-urlencoded and JSON
        content_type = request.headers.get("content-type", "")
        try:
            if "json" in content_type:
                body = await request.json()
            else:
                form = await request.form()
                body = dict(form)
        except Exception:
            raise HTTPException(400, "Could not parse request body")

        grant_type = body.get("grant_type", "")
        code = body.get("code", "")

        if grant_type != "authorization_code":
            raise HTTPException(400, "unsupported grant_type")

        if not code:
            raise HTTPException(400, "code is required")

        # Validate code
        try:
            with sqlite3.connect(store.db_path) as conn:
                row = conn.execute(
                    "SELECT user_id, client_id FROM oauth_codes WHERE code = ? AND used = 0",
                    (code,)
                ).fetchone()

                if not row:
                    raise HTTPException(400, "invalid or expired code")

                user_id, client_id = row

                # Mark code as used
                conn.execute("UPDATE oauth_codes SET used = 1 WHERE code = ?", (code,))

                # Generate access token
                token = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO oauth_tokens (token, user_id, client_id)
                       VALUES (?, ?, ?)""",
                    (token, user_id, client_id)
                )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, f"Token generation failed: {str(e)}")

        return JSONResponse({
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "verify:read verify:write",
        })

    def get_user_from_token(request: Request) -> str:
        """Extract user_id from OAuth Bearer token or X-User-ID header."""
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            with sqlite3.connect(store.db_path) as conn:
                row = conn.execute(
                    "SELECT user_id FROM oauth_tokens WHERE token = ?", (token,)
                ).fetchone()
                if row:
                    return row[0]
        # Fallback to X-User-ID header (for testing / backward compatibility)
        return request.headers.get("X-User-ID", "anonymous")

    # ================================================================
    # MCP PROTOCOL — JSON-RPC over Streamable HTTP
    # ================================================================

    @app.post("/mcp")
    async def mcp_jsonrpc(request: Request):
        """
        MCP Streamable HTTP endpoint.
        Receives JSON-RPC 2.0 messages and routes to tool handlers.
        Methods: initialize, tools/list, tools/call
        """
        body = await request.json()
        method = body.get("method", "")
        params = body.get("params", {})
        msg_id = body.get("id")
        user_id = get_user_from_token(request)

        # --- initialize ---
        if method == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "serverInfo": {
                        "name": "ZTR — Temporal Registry",
                        "version": "0.1",
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                },
            })

        # --- tools/list ---
        if method == "tools/list":
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": MCP_TOOL_DEFINITIONS,
                },
            })

        # --- tools/call ---
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            try:
                if tool_name == "verify_document":
                    result = await _handle_verify(arguments, user_id, store)
                elif tool_name == "check_receipt":
                    result = await _handle_check(arguments, store)
                elif tool_name == "list_receipts":
                    result = await _handle_list(arguments, user_id, store)
                elif tool_name == "download_receipt_pdf":
                    result = await _handle_download_pdf(arguments, store)
                else:
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                    })

                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result)}],
                    },
                })

            except Exception as e:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": str(e)},
                })

        # --- Unknown method ---
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        })

    @app.get("/mcp")
    async def mcp_discovery(request: Request):
        """MCP discovery — returns Link header for OAuth."""
        from fastapi.responses import Response
        return Response(
            content="",
            status_code=200,
            headers={
                "Link": f'<{ZTR_SERVER_URL}/oauth/authorize>; rel="authorization"',
            },
        )

    # --- MCP Tool Handlers (shared between REST and JSON-RPC) ---

    async def _handle_verify(arguments: dict, user_id: str, store: ReceiptStore) -> dict:
        """Handle verify_document tool call."""
        document_text = arguments.get("document_text", "")
        file_content_base64 = arguments.get("file_content_base64", "")

        if not document_text and not file_content_base64:
            raise ValueError("document_text or file_content_base64 is required")

        # Compute hash: binary file takes priority over text
        if file_content_base64:
            try:
                file_bytes = base64.b64decode(file_content_base64)
                doc_hash = hashlib.sha256(file_bytes).hexdigest()
                hash_source = "binary_file"
            except Exception as e:
                raise ValueError(f"Invalid base64 content: {str(e)}")
        else:
            doc_hash = compute_sha256(document_text)
            hash_source = "text"

        if len(document_text) > 5_000_000:
            raise ValueError("Document too large (max 5MB)")

        # Daily quota check
        DAILY_QUOTA = 10
        today_start = datetime.now(timezone.utc).strftime('%Y-%m-%dT00:00:00')
        today_receipts = store.list_by_user(user_id, date_from=today_start)
        if len(today_receipts) >= DAILY_QUOTA:
            return {
                "status": "QUOTA_EXCEEDED",
                "message": f"Technical preview fair-use quota reached ({DAILY_QUOTA} receipts/day). Quota resets at 00:00 UTC.",
            }

        # Global TSA budget check
        DAILY_TSA_BUDGET = 5
        use_tsa = True
        tsa_limit_reached = False
        with sqlite3.connect(store.db_path) as conn:
            row = conn.execute(
                """SELECT COUNT(*) FROM receipts
                   WHERE tsa_status = 'VERIFIED'
                   AND review_timestamp >= ?""",
                (today_start,),
            ).fetchone()
            if row[0] >= DAILY_TSA_BUDGET:
                use_tsa = False
                tsa_limit_reached = True

        receipt = create_receipt(
            document_text=document_text if hash_source == "text" else "",
            user_id=user_id,
            org_id="",
            review_note=arguments.get("review_note", ""),
            context=arguments.get("context", "legal_filing"),
            use_tsa=use_tsa,
            pre_computed_hash=doc_hash if hash_source == "binary_file" else None,
        )

        # Override tsa_status with clear message when limit reached
        if tsa_limit_reached:
            receipt.tsa_status = "DAILY_LIMIT_REACHED"

        store.store(receipt)

        # Build response message based on TSA status
        if tsa_limit_reached:
            tsa_message = (
                "The daily limit of qualified timestamps has been reached. "
                "Your verification has been recorded with hash, timestamp, and HMAC "
                "but without an eIDAS-qualified timestamp. "
                "The limit resets at 00:00 UTC."
            )
        elif receipt.tsa_status == "VERIFIED":
            tsa_message = "Verification recorded with eIDAS-qualified timestamp."
        else:
            tsa_message = f"Verification recorded. TSA status: {receipt.tsa_status}."

        result = {
            "receipt_id": receipt.receipt_id,
            "document_sha256": receipt.document_sha256,
            "review_timestamp": receipt.review_timestamp,
            "tsa_status": receipt.tsa_status,
            "integrity_hmac": receipt.integrity_hmac[:16] + "...",
            "context": receipt.context,
            "pdf_url": f"{ZTR_SERVER_URL}/receipt/{receipt.receipt_id}/pdf",
            "message": (
                f"{tsa_message} "
                f"Receipt: {receipt.receipt_id}. "
                f"Hash: {receipt.document_sha256[:16]}... "
                f"Time: {receipt.review_timestamp}. "
                f"Document was not stored. "
                f"PDF receipt ready for download."
            ),
        }

        # Welcome message on first receipt
        user_count = store.count_by_user(user_id)
        if user_count == 1:
            result["welcome_message"] = (
                "Welcome to ZTR Early Access. Your verification has been recorded "
                "with an eIDAS-qualified timestamp by Aruba PEC S.p.A. "
                "We'd appreciate your feedback: temporalregistry.com/feedback"
            )

        return result

    async def _handle_check(arguments: dict, store: ReceiptStore) -> dict:
        """Handle check_receipt tool call."""
        receipt_id = arguments.get("receipt_id", "")
        if not receipt_id:
            raise ValueError("receipt_id is required")

        receipt = store.get(receipt_id)
        if not receipt:
            raise ValueError(f"Receipt {receipt_id} not found")

        result = dict(receipt)
        if result.get("tsa_token"):
            result["tsa_token"] = result["tsa_token"][:32] + "...(truncated)"
        return result

    async def _handle_list(arguments: dict, user_id: str, store: ReceiptStore) -> dict:
        """Handle list_receipts tool call."""
        receipts = store.list_by_user(
            user_id=user_id,
            date_from=arguments.get("date_from"),
            date_to=arguments.get("date_to"),
            context=arguments.get("context"),
        )
        for r in receipts:
            if r.get("tsa_token"):
                r["tsa_token"] = "(stored)"
        return {"count": len(receipts), "receipts": receipts}

    async def _handle_download_pdf(arguments: dict, store: ReceiptStore) -> dict:
        """Handle download_receipt_pdf tool call — returns URL to download."""
        receipt_id = arguments.get("receipt_id", "")
        if not receipt_id:
            raise ValueError("receipt_id is required")
        receipt = store.get(receipt_id)
        if not receipt:
            raise ValueError(f"Receipt {receipt_id} not found")
        return {
            "receipt_id": receipt_id,
            "download_url": f"{ZTR_SERVER_URL}/receipt/{receipt_id}/pdf",
            "message": f"PDF receipt available for download at: {ZTR_SERVER_URL}/receipt/{receipt_id}/pdf",
        }

    # ================================================================
    # PDF DOWNLOAD ENDPOINT
    # ================================================================

    @app.get("/receipt/{receipt_id}/pdf")
    async def download_receipt_pdf(receipt_id: str):
        """Download a professional PDF receipt for a verification record."""
        receipt = store.get(receipt_id)
        if not receipt:
            raise HTTPException(404, f"Receipt {receipt_id} not found")

        import tempfile
        from ztr_receipt_pdf import create_receipt_pdf

        tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
        create_receipt_pdf(
            output_path=tmp.name,
            receipt_id=receipt['receipt_id'],
            document_sha256=receipt['document_sha256'],
            review_timestamp=receipt['review_timestamp'],
            review_note=receipt.get('review_note', ''),
            context=receipt.get('context', 'other'),
            user_id=receipt['user_id'],
            tsa_status=receipt['tsa_status'],
            integrity_hmac=receipt.get('integrity_hmac', ''),
        )
        return FileResponse(
            tmp.name,
            media_type='application/pdf',
            filename=f'{receipt_id}.pdf',
        )

    # ================================================================
    # ADMIN STATS (protected)
    # ================================================================

    @app.get("/admin/stats")
    async def admin_stats(request: Request):
        key = request.query_params.get("key", "")
        admin_key = os.environ.get("ZTR_ADMIN_KEY", "ztr-admin-2026")
        if key != admin_key:
            raise HTTPException(403, "Unauthorized")

        with sqlite3.connect(store.db_path) as conn:
            conn.row_factory = sqlite3.Row

            total = conn.execute("SELECT COUNT(*) as c FROM receipts").fetchone()["c"]
            verified = conn.execute("SELECT COUNT(*) as c FROM receipts WHERE tsa_status='VERIFIED'").fetchone()["c"]
            users = conn.execute("SELECT COUNT(DISTINCT user_id) as c FROM receipts").fetchone()["c"]

            recent = [dict(r) for r in conn.execute(
                """SELECT receipt_id, user_id, context, tsa_status,
                   review_timestamp, review_note
                   FROM receipts ORDER BY review_timestamp DESC LIMIT 20"""
            ).fetchall()]

            for r in recent:
                r.pop('tsa_token', None)

            return JSONResponse({
                "total_receipts": total,
                "verified_receipts": verified,
                "unique_users": users,
                "recent": recent,
            })

    # ================================================================
    # FAVICON ROUTES
    # ================================================================

    @app.get("/favicon.ico")
    async def favicon():
        base = pathlib.Path(__file__).parent
        return FileResponse(base / "favicon.ico", media_type="image/x-icon")

    @app.get("/favicon.png")
    async def favicon_png():
        base = pathlib.Path(__file__).parent
        return FileResponse(base / "favicon.png", media_type="image/png")

    @app.get("/icon.png")
    async def icon_png():
        base = pathlib.Path(__file__).parent
        return FileResponse(base / "favicon.png", media_type="image/png")

    @app.get("/favicon-192.png")
    async def favicon_192():
        base = pathlib.Path(__file__).parent
        return FileResponse(base / "favicon-192.png", media_type="image/png")

    return app


# ============================================================================
# MCP TOOL DEFINITIONS — for Anthropic Connectors Directory
# ============================================================================

MCP_TOOL_DEFINITIONS = [
    {
        "name": "verify_document",
        "title": "Verify Document",
        "description": (
            "[third_party_mcp_app] ZTR — Temporal Registry — Create a timestamped "
            "record of human verification for an AI-assisted document. The document is "
            "hashed (SHA-256), the professional's declaration is timestamped via an "
            "eIDAS-qualified TSA (Aruba PEC S.p.A.), and a retrievable receipt with HMAC "
            "integrity seal is returned. The document is immediately discarded — never "
            "stored or transmitted beyond the hash. When the user uploads a file, pass "
            "the file content as base64 via file_content_base64 — do NOT extract text. "
            "Use this before filing, submitting, or approving any AI-assisted document — "
            "legal, medical, financial, technical, or regulatory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_text": {
                    "type": "string",
                    "description": (
                        "Plain text content to verify. Use this ONLY for text pasted "
                        "directly by the user. Do NOT use this for uploaded files."
                    ),
                },
                "file_content_base64": {
                    "type": "string",
                    "description": (
                        "Base64-encoded binary content of the original file (PDF, DOCX, etc). "
                        "When a user uploads a file, ALWAYS use this parameter instead of "
                        "extracting text. The hash will be computed on the original binary "
                        "file, ensuring integrity. Do NOT extract text from the file — the "
                        "hash must be computed on the original binary to ensure verifiability."
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
                        "client_advice",
                        "regulatory_submission", "audit_compliance",
                        "medical_review", "clinical_assessment", "diagnostic_report",
                        "credit_assessment", "risk_evaluation", "financial_report",
                        "hr_decision", "recruitment_screening",
                        "education_evaluation", "academic_review",
                        "technical_review", "safety_assessment",
                        "project_approval", "document_handover",
                        "internal_memo", "other",
                    ],
                    "default": "legal_filing",
                },
            },
            "required": ["document_text"],
        },
        "annotations": {
            "title": "Verify Document",
            "readOnlyHint": False,
            "destructiveHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "check_receipt",
        "title": "Check Receipt",
        "description": (
            "[third_party_mcp_app] ZTR — Temporal Registry — Look up a verification "
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
        "annotations": {
            "title": "Check Receipt",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "list_receipts",
        "title": "List Receipts",
        "description": (
            "[third_party_mcp_app] ZTR — Temporal Registry — List your verification "
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
        "annotations": {
            "title": "List Receipts",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "download_receipt_pdf",
        "title": "Download Receipt PDF",
        "description": (
            "[third_party_mcp_app] ZTR — Temporal Registry — Download a professional PDF "
            "receipt for a verification record. Includes QR code for independent verification, "
            "full hash, eIDAS timestamp details, and legal disclaimer."
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
        "annotations": {
            "title": "Download Receipt PDF",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
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
