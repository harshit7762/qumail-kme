# kme_server.py
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from uuid import uuid4
import base64
from Crypto.Random import get_random_bytes

app = FastAPI(title="Minimal KME Server (demo)")

# Simple in-memory key store: key_id -> {key: bytes, key_type: str}
KEY_STORE = {}

MAX_KEY_REQUEST = 10 * 1024 * 1024  # 10 MB upper limit for safety in demo


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


class KeyInfo(BaseModel):
    key_id: str
    key: str  # base64


class KeysResponse(BaseModel):
    keys: List[KeyInfo]


@app.get("/GET_KEY", response_model=KeysResponse)
def get_key(count: Optional[int] = Query(None, ge=0), key_type: str = Query(...), key_id: Optional[str] = None):
    """
    GET_KEY endpoint:

    - If key_id is provided -> return the stored key for that key_id (ignores count).
      (Useful for decryption to fetch previously created key material.)
    - Else: generate `count` bytes (must be provided and <= MAX_KEY_REQUEST), store with a new key_id, and return it.
    """
    if key_id:
        # Fetch existing key
        entry = KEY_STORE.get(key_id)
        if not entry:
            raise HTTPException(status_code=404, detail="key_id not found")
        return {"keys": [{"key_id": key_id, "key": b64(entry["key"])}]}

    if count is None:
        raise HTTPException(status_code=400, detail="count must be provided when key_id is not supplied")

    if count > MAX_KEY_REQUEST:
        raise HTTPException(status_code=400, detail=f"count too large (max {MAX_KEY_REQUEST})")

    # For demo: generate random bytes of exactly `count`
    key_bytes = get_random_bytes(count if count > 0 else 1) if count > 0 else b""
    # create key_id
    kid = str(uuid4())
    KEY_STORE[kid] = {"key": key_bytes, "key_type": key_type}
    return {"keys": [{"key_id": kid, "key": b64(key_bytes)}]}


@app.get("/LIST_KEYS")
def list_keys():
    """Return list of currently stored key ids (demo)."""
    return {"count": len(KEY_STORE), "key_ids": list(KEY_STORE.keys())}
