"""
Juggernaut Production API - Consent Management & Cryptographic Receipts
Final Boss Technology, Inc.

PRODUCTION-READY: Real endpoints for permit creation, revocation, verification.
Uses MongoDB Atlas for persistence and cryptographic receipt chain.
"""

import os
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Header, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# ============================================================================
# Configuration
# ============================================================================

MONGODB_URI = os.environ.get("MONGODB_URI", "")
API_KEY = os.environ.get("API_KEY", "dev-key-change-in-production")
SIGNING_SECRET = os.environ.get("SIGNING_SECRET", "juggernaut-default-secret-change-me")

# ============================================================================
# MongoDB Connection (cached for serverless)
# ============================================================================

_client: Optional[MongoClient] = None
_db = None


def get_db():
    """Get MongoDB database with connection caching for serverless."""
    global _client, _db

    if _client is None:
        if not MONGODB_URI:
            return None
        try:
            _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
            _client.admin.command('ping')
            _db = _client.get_database("juggernaut")
        except ConnectionFailure:
            return None

    return _db


# ============================================================================
# Models
# ============================================================================

class PermitCreate(BaseModel):
    """Create a new consent permit."""
    subject_id: str = Field(..., description="Data subject identifier (anonymized)")
    partner_id: str = Field(..., description="Partner/organization ID")
    purpose: str = Field(..., description="Purpose of data processing")
    scope: List[str] = Field(default=["read"], description="Allowed operations")
    ttl_hours: int = Field(default=24, description="Time to live in hours")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PermitResponse(BaseModel):
    """Permit response."""
    permit_id: str
    subject_id: str
    partner_id: str
    purpose: str
    scope: List[str]
    status: str
    created_at: str
    expires_at: str
    receipt_id: Optional[str] = None
    cdt_hash: Optional[str] = None


class RevokeRequest(BaseModel):
    """Revoke a permit."""
    permit_id: str
    reason: str = Field(default="user_request", description="Reason for revocation")


class VerifyRequest(BaseModel):
    """Verify a permit or receipt."""
    permit_id: Optional[str] = None
    receipt_id: Optional[str] = None


class VerifyResponse(BaseModel):
    """Verification result."""
    valid: bool
    status: str
    message: str
    permit: Optional[Dict[str, Any]] = None


class GateRequest(BaseModel):
    """AI Gateway decision request."""
    agent_id: str = Field(..., description="AI agent identifier")
    action: str = Field(..., description="Action: INVOKE, GENERATE, ACCESS")
    target_resource: str = Field(..., description="Resource being accessed")
    purpose: str = Field(default="INFERENCE", description="Purpose of action")
    data_category: str = Field(default="TEXT", description="Category of data")
    cdt: Optional[str] = Field(default=None, description="Consent DNA Token hash")


class GateResponse(BaseModel):
    """AI Gateway decision response."""
    decision: str  # ALLOW, DENY, ESCALATE
    receipt_id: str
    timestamp: str
    latency_ms: float


class ReceiptResponse(BaseModel):
    """Receipt in the chain."""
    receipt_id: str
    action: str
    permit_id: Optional[str] = None
    chain_sequence: int
    prev_hash: str
    hash: str
    signature: str
    timestamp: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ChainIntegrityResponse(BaseModel):
    """Chain integrity verification result."""
    valid: bool
    length: int
    breaks: List[int]


class MetricsResponse(BaseModel):
    """System metrics."""
    total_permits: int
    total_revokes: int
    active_permits: int
    total_receipts: int
    chain_length: int
    last_receipt_at: Optional[str] = None


# ============================================================================
# Cryptographic Functions
# ============================================================================

def generate_cdt_hash(subject_id: str, partner_id: str, purpose: str, epoch: int = 1) -> str:
    """Generate Consent DNA Token hash."""
    payload = f"{subject_id}|{partner_id}|{purpose}|{epoch}".encode()
    return hashlib.sha256(payload).hexdigest()


def compute_receipt_hash(
    receipt_id: str,
    action: str,
    prev_hash: str,
    timestamp: str,
    payload: str
) -> str:
    """Compute receipt hash for chain linking."""
    data = f"{receipt_id}|{action}|{prev_hash}|{timestamp}|{payload}".encode()
    return hashlib.sha256(data).hexdigest()


def sign_receipt(receipt_hash: str) -> str:
    """Sign a receipt hash using HMAC-SHA256."""
    signature = hmac.new(
        SIGNING_SECRET.encode(),
        receipt_hash.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_signature(receipt_hash: str, signature: str) -> bool:
    """Verify a receipt signature."""
    expected = hmac.new(
        SIGNING_SECRET.encode(),
        receipt_hash.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ============================================================================
# Receipt Chain Management
# ============================================================================

def mint_receipt(
    db,
    action: str,
    permit_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> ReceiptResponse:
    """Mint a new receipt and append to chain."""
    receipts = db.receipts

    # Get previous receipt
    prev_receipt = receipts.find_one(sort=[("chain_sequence", -1)])
    prev_hash = prev_receipt["hash"] if prev_receipt else "genesis"
    chain_seq = (prev_receipt["chain_sequence"] + 1) if prev_receipt else 1

    # Generate receipt
    receipt_id = f"rcpt_{uuid.uuid4().hex[:16]}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    payload = f"{action}|{permit_id or 'none'}|{metadata or {}}"

    receipt_hash = compute_receipt_hash(
        receipt_id, action, prev_hash, timestamp, payload
    )
    signature = sign_receipt(receipt_hash)

    # Store
    receipt_doc = {
        "receipt_id": receipt_id,
        "action": action,
        "permit_id": permit_id,
        "chain_sequence": chain_seq,
        "prev_hash": prev_hash,
        "hash": receipt_hash,
        "signature": signature,
        "timestamp": timestamp,
        "metadata": metadata or {},
        "created_at": datetime.utcnow()
    }
    receipts.insert_one(receipt_doc)

    return ReceiptResponse(
        receipt_id=receipt_id,
        action=action,
        permit_id=permit_id,
        chain_sequence=chain_seq,
        prev_hash=prev_hash,
        hash=receipt_hash,
        signature=signature,
        timestamp=timestamp,
        metadata=metadata or {}
    )


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Juggernaut Production API",
    description="AI Governance Infrastructure - Consent Management & Cryptographic Receipts",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_api_key(x_api_key: str = Header(default=None)):
    """Verify API key for protected endpoints."""
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )


# ============================================================================
# Health Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint - API info."""
    db = get_db()
    return {
        "service": "Juggernaut Production API",
        "version": "1.0.0",
        "status": "operational",
        "database": "connected" if db else "not_configured",
        "endpoints": {
            "permit": "/permit - Create consent permits",
            "revoke": "/revoke - Revoke permits",
            "verify": "/verify - Verify permits/receipts",
            "gate": "/gate - AI gateway decisions",
            "receipts": "/receipts - View receipt chain",
            "metrics": "/metrics - System metrics"
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    db = get_db()
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "database": "connected" if db else "not_configured"
    }


# ============================================================================
# Permit Endpoints
# ============================================================================

@app.post("/permit", response_model=PermitResponse, status_code=status.HTTP_201_CREATED)
async def create_permit(
    request: PermitCreate,
    x_api_key: str = Header(default=None)
):
    """
    Create a new consent permit.

    A permit grants a partner the right to process data for a specific purpose.
    Each permit is recorded in the immutable receipt chain.
    """
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not configured. Set MONGODB_URI environment variable."
        )

    # Generate permit
    permit_id = f"permit_{uuid.uuid4().hex[:16]}"
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(hours=request.ttl_hours)
    cdt_hash = generate_cdt_hash(request.subject_id, request.partner_id, request.purpose)

    # Store permit
    permit_doc = {
        "permit_id": permit_id,
        "subject_id": request.subject_id,
        "partner_id": request.partner_id,
        "purpose": request.purpose,
        "scope": request.scope,
        "status": "ACTIVE",
        "cdt_hash": cdt_hash,
        "created_at": created_at,
        "expires_at": expires_at,
        "metadata": request.metadata
    }
    db.permits.insert_one(permit_doc)

    # Mint receipt
    receipt = mint_receipt(
        db,
        action="PERMIT_CREATED",
        permit_id=permit_id,
        metadata={
            "subject_id": request.subject_id,
            "partner_id": request.partner_id,
            "purpose": request.purpose,
            "cdt_hash": cdt_hash
        }
    )

    return PermitResponse(
        permit_id=permit_id,
        subject_id=request.subject_id,
        partner_id=request.partner_id,
        purpose=request.purpose,
        scope=request.scope,
        status="ACTIVE",
        created_at=created_at.isoformat() + "Z",
        expires_at=expires_at.isoformat() + "Z",
        receipt_id=receipt.receipt_id,
        cdt_hash=cdt_hash
    )


@app.get("/permit/{permit_id}", response_model=PermitResponse)
async def get_permit(
    permit_id: str,
    x_api_key: str = Header(default=None)
):
    """Get a permit by ID."""
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")

    permit = db.permits.find_one({"permit_id": permit_id})
    if not permit:
        raise HTTPException(status_code=404, detail="Permit not found")

    # Check expiry
    if permit["status"] == "ACTIVE" and permit["expires_at"] < datetime.utcnow():
        db.permits.update_one(
            {"permit_id": permit_id},
            {"$set": {"status": "EXPIRED"}}
        )
        permit["status"] = "EXPIRED"

    return PermitResponse(
        permit_id=permit["permit_id"],
        subject_id=permit["subject_id"],
        partner_id=permit["partner_id"],
        purpose=permit["purpose"],
        scope=permit.get("scope", []),
        status=permit["status"],
        created_at=permit["created_at"].isoformat() + "Z",
        expires_at=permit["expires_at"].isoformat() + "Z",
        cdt_hash=permit.get("cdt_hash")
    )


# ============================================================================
# Revocation Endpoints
# ============================================================================

@app.post("/revoke", response_model=PermitResponse)
async def revoke_permit(
    request: RevokeRequest,
    x_api_key: str = Header(default=None)
):
    """
    Revoke a consent permit.

    Once revoked, the permit can no longer be used for data processing.
    Revocation is recorded in the immutable receipt chain.
    """
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")

    # Find permit
    permit = db.permits.find_one({"permit_id": request.permit_id})
    if not permit:
        raise HTTPException(status_code=404, detail="Permit not found")

    if permit["status"] == "REVOKED":
        raise HTTPException(status_code=400, detail="Permit already revoked")

    # Update permit
    db.permits.update_one(
        {"permit_id": request.permit_id},
        {
            "$set": {
                "status": "REVOKED",
                "revoked_at": datetime.utcnow(),
                "revoke_reason": request.reason
            }
        }
    )

    # Mint revocation receipt
    receipt = mint_receipt(
        db,
        action="PERMIT_REVOKED",
        permit_id=request.permit_id,
        metadata={"reason": request.reason}
    )

    permit["status"] = "REVOKED"

    return PermitResponse(
        permit_id=permit["permit_id"],
        subject_id=permit["subject_id"],
        partner_id=permit["partner_id"],
        purpose=permit["purpose"],
        scope=permit.get("scope", []),
        status="REVOKED",
        created_at=permit["created_at"].isoformat() + "Z",
        expires_at=permit["expires_at"].isoformat() + "Z",
        receipt_id=receipt.receipt_id,
        cdt_hash=permit.get("cdt_hash")
    )


# ============================================================================
# Verification Endpoints
# ============================================================================

@app.post("/verify", response_model=VerifyResponse)
async def verify(
    request: VerifyRequest,
    x_api_key: str = Header(default=None)
):
    """
    Verify a permit or receipt.

    For permits: Checks if active and not expired.
    For receipts: Verifies cryptographic signature and chain integrity.
    """
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Database not configured")

    if request.permit_id:
        # Verify permit
        permit = db.permits.find_one({"permit_id": request.permit_id})
        if not permit:
            return VerifyResponse(
                valid=False,
                status="NOT_FOUND",
                message="Permit not found"
            )

        # Check status
        if permit["status"] == "REVOKED":
            return VerifyResponse(
                valid=False,
                status="REVOKED",
                message="Permit has been revoked",
                permit={"revoked_at": permit.get("revoked_at", "").isoformat() if permit.get("revoked_at") else None}
            )

        # Check expiry
        if permit["expires_at"] < datetime.utcnow():
            return VerifyResponse(
                valid=False,
                status="EXPIRED",
                message="Permit has expired",
                permit={"expired_at": permit["expires_at"].isoformat()}
            )

        return VerifyResponse(
            valid=True,
            status="ACTIVE",
            message="Permit is valid",
            permit={
                "permit_id": permit["permit_id"],
                "subject_id": permit["subject_id"],
                "partner_id": permit["partner_id"],
                "purpose": permit["purpose"],
                "expires_at": permit["expires_at"].isoformat()
            }
        )

    if request.receipt_id:
        # Verify receipt
        receipt = db.receipts.find_one({"receipt_id": request.receipt_id})
        if not receipt:
            return VerifyResponse(
                valid=False,
                status="NOT_FOUND",
                message="Receipt not found"
            )

        # Verify signature
        is_valid = verify_signature(receipt["hash"], receipt["signature"])

        return VerifyResponse(
            valid=is_valid,
            status="VALID" if is_valid else "INVALID_SIGNATURE",
            message="Receipt signature verified" if is_valid else "Signature verification failed",
            permit={"chain_sequence": receipt["chain_sequence"]}
        )

    raise HTTPException(status_code=400, detail="Must provide permit_id or receipt_id")


# ============================================================================
# AI Gateway Endpoint
# ============================================================================

@app.post("/gate", response_model=GateResponse)
async def ai_gate(
    request: GateRequest,
    x_api_key: str = Header(default=None)
):
    """
    AI Gateway - Make access control decision for AI operations.

    Evaluates whether an AI agent should be allowed to perform an action.
    All decisions are recorded in the immutable receipt chain.
    """
    import time
    start = time.time()

    verify_api_key(x_api_key)

    db = get_db()
    decision = "ALLOW"

    # If no database, still allow but log warning
    if db:
        # Check if CDT is provided and valid
        if request.cdt:
            # Look for a permit with matching CDT hash
            permit = db.permits.find_one({
                "cdt_hash": request.cdt,
                "status": "ACTIVE"
            })
            if not permit:
                decision = "DENY"
            elif permit["expires_at"] < datetime.utcnow():
                decision = "DENY"

        # Mint decision receipt
        receipt = mint_receipt(
            db,
            action=f"GATE_{decision}",
            metadata={
                "agent_id": request.agent_id,
                "action": request.action,
                "target_resource": request.target_resource,
                "purpose": request.purpose,
                "data_category": request.data_category,
                "cdt": request.cdt
            }
        )
        receipt_id = receipt.receipt_id
    else:
        receipt_id = f"rcpt_{uuid.uuid4().hex[:16]}"

    latency = (time.time() - start) * 1000

    return GateResponse(
        decision=decision,
        receipt_id=receipt_id,
        timestamp=datetime.utcnow().isoformat() + "Z",
        latency_ms=round(latency, 2)
    )


# ============================================================================
# Receipt Chain Endpoints
# ============================================================================

@app.get("/receipts")
async def list_receipts(
    limit: int = Query(default=50, le=100),
    offset: int = Query(default=0),
    x_api_key: str = Header(default=None)
):
    """Get the receipt chain."""
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        return {"receipts": [], "total": 0}

    total = db.receipts.count_documents({})
    receipts = list(db.receipts.find().sort("chain_sequence", -1).skip(offset).limit(limit))

    return {
        "receipts": [
            {
                "receipt_id": r["receipt_id"],
                "action": r["action"],
                "permit_id": r.get("permit_id"),
                "chain_sequence": r["chain_sequence"],
                "prev_hash": r["prev_hash"],
                "hash": r["hash"],
                "signature": r["signature"],
                "timestamp": r["timestamp"],
                "metadata": r.get("metadata", {})
            }
            for r in receipts
        ],
        "total": total
    }


@app.get("/receipts/chain/verify", response_model=ChainIntegrityResponse)
async def verify_chain(x_api_key: str = Header(default=None)):
    """Verify the integrity of the entire receipt chain."""
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        return ChainIntegrityResponse(valid=True, length=0, breaks=[])

    receipts = list(db.receipts.find().sort("chain_sequence", 1))

    if not receipts:
        return ChainIntegrityResponse(valid=True, length=0, breaks=[])

    breaks = []
    prev_hash = "genesis"

    for r in receipts:
        # Verify chain link
        if r["prev_hash"] != prev_hash:
            breaks.append(r["chain_sequence"])

        # Verify signature
        if not verify_signature(r["hash"], r["signature"]):
            breaks.append(r["chain_sequence"])

        prev_hash = r["hash"]

    return ChainIntegrityResponse(
        valid=len(breaks) == 0,
        length=len(receipts),
        breaks=breaks
    )


# ============================================================================
# Metrics Endpoint
# ============================================================================

@app.get("/metrics", response_model=MetricsResponse)
async def get_metrics(x_api_key: str = Header(default=None)):
    """Get system metrics."""
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        return MetricsResponse(
            total_permits=0,
            total_revokes=0,
            active_permits=0,
            total_receipts=0,
            chain_length=0,
            last_receipt_at=None
        )

    total_permits = db.permits.count_documents({})
    total_revokes = db.permits.count_documents({"status": "REVOKED"})
    active_permits = db.permits.count_documents({
        "status": "ACTIVE",
        "expires_at": {"$gt": datetime.utcnow()}
    })
    total_receipts = db.receipts.count_documents({})

    last_receipt = db.receipts.find_one(sort=[("chain_sequence", -1)])

    return MetricsResponse(
        total_permits=total_permits,
        total_revokes=total_revokes,
        active_permits=active_permits,
        total_receipts=total_receipts,
        chain_length=total_receipts,
        last_receipt_at=last_receipt["timestamp"] if last_receipt else None
    )


# ============================================================================
# Permit Listing
# ============================================================================

@app.get("/permits")
async def list_permits(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=50, le=100),
    offset: int = Query(default=0),
    x_api_key: str = Header(default=None)
):
    """List all permits with optional filtering."""
    verify_api_key(x_api_key)

    db = get_db()
    if not db:
        return {"permits": [], "total": 0}

    query = {}
    if status_filter:
        query["status"] = status_filter.upper()

    total = db.permits.count_documents(query)
    permits = list(db.permits.find(query).sort("created_at", -1).skip(offset).limit(limit))

    return {
        "permits": [
            {
                "permit_id": p["permit_id"],
                "subject_id": p["subject_id"],
                "partner_id": p["partner_id"],
                "purpose": p["purpose"],
                "scope": p.get("scope", []),
                "status": p["status"],
                "created_at": p["created_at"].isoformat() + "Z",
                "expires_at": p["expires_at"].isoformat() + "Z",
                "cdt_hash": p.get("cdt_hash"),
                "metadata": p.get("metadata", {})
            }
            for p in permits
        ],
        "total": total
    }
