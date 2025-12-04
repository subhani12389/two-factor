# app/main.py
import base64
import time
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

ROOT = Path.cwd()
DATA_DIR = ROOT / "data"
SEED_PATH = DATA_DIR / "seed.txt"

app = FastAPI(title="PKI + TOTP Microservice")

# Load student private key
def load_private_key(path: Path = Path("student_private.pem")):
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")
    raw = path.read_bytes()
    return serialization.load_pem_private_key(raw, password=None)

student_priv = load_private_key()

# Utilities
def is_valid_hex_seed(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)

def hex_to_base32(hex_seed: str) -> str:
    raw = bytes.fromhex(hex_seed)
    return base64.b32encode(raw).decode().strip("=")

def generate_totp(hex_seed: str) -> Dict[str, object]:
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30, digest="sha1")
    code = totp.now()
    valid_for = 30 - (int(time.time()) % 30)
    return {"code": code, "valid_for": valid_for}

def verify_totp(hex_seed: str, code: str, window: int = 1) -> bool:
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30, digest="sha1")
    return totp.verify(code, valid_window=window)

# Request models
class EncryptedSeed(BaseModel):
    encrypted_seed: str  # base64 string

class VerifyPayload(BaseModel):
    code: str

@app.post("/decrypt-seed")
def decrypt_seed(payload: EncryptedSeed):
    try:
        data = base64.b64decode(payload.encrypted_seed)
        plain = student_priv.decrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        seed_hex = plain.decode().strip()
        if not is_valid_hex_seed(seed_hex):
            raise ValueError("Decrypted seed invalid")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        SEED_PATH.write_text(seed_hex)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@app.get("/generate-2fa")
def get_2fa():
    if not SEED_PATH.exists():
        raise HTTPException(status_code=400, detail="Seed not set. Call /decrypt-seed first.")
    seed_hex = SEED_PATH.read_text().strip()
    try:
        return generate_totp(seed_hex)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TOTP generation failed: {str(e)}")

@app.post("/verify-2fa")
def verify_2fa(payload: VerifyPayload):
    if not SEED_PATH.exists():
        raise HTTPException(status_code=400, detail="Seed not set. Call /decrypt-seed first.")
    seed_hex = SEED_PATH.read_text().strip()
    valid = verify_totp(seed_hex, payload.code, window=1)
    return {"valid": bool(valid)}