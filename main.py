# app/main.py

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Import your crypto utilities
from .crypto_utils import (
    load_private_key,
    decrypt_seed,
    save_seed_to_file,
    load_seed_from_file,
    generate_totp_code,
    verify_totp_code,
    SEED_FILE,
)

app = FastAPI()

PRIVATE_KEY_PATH = "student_private.pem"  # will be mounted into container


class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class Verify2FARequest(BaseModel):
    code: str | None = None


# Load private key at startup
@app.on_event("startup")
def startup_event():
    global student_private_key
    student_private_key = load_private_key(PRIVATE_KEY_PATH)


# ---------- Endpoint 1: POST /decrypt-seed ----------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: DecryptSeedRequest):
    encrypted_seed_b64 = body.encrypted_seed

    try:
        hex_seed = decrypt_seed(encrypted_seed_b64, student_private_key)
        save_seed_to_file(hex_seed, SEED_FILE)
    except Exception as e:
        # Do not expose detailed errors to client
        raise HTTPException(status_code=500, detail="Decryption failed")

    return {"status": "ok"}


# ---------- Endpoint 2: GET /generate-2fa ----------

@app.get("/generate-2fa")
def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        hex_seed = load_seed_from_file(SEED_FILE)
        code = generate_totp_code(hex_seed)
    except Exception:
        raise HTTPException(status_code=500, detail="Error generating code")

    # Compute remaining seconds in current 30-second period
    import time
    period = 30
    now = int(time.time())
    remaining = period - (now % period)

    return {"code": code, "valid_for": remaining}


# ---------- Endpoint 3: POST /verify-2fa ----------

@app.post("/verify-2fa")
def verify_2fa(body: Verify2FARequest):
    if body.code is None:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        hex_seed = load_seed_from_file(SEED_FILE)
        is_valid = verify_totp_code(hex_seed, body.code, valid_window=1)
    except Exception:
        raise HTTPException(status_code=500, detail="Verification error")

    return {"valid": is_valid}