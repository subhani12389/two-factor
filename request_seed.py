# app/crypto_utils.py
import base64
from pathlib import Path
from typing import Tuple

import pyotp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


SEED_FILE = Path("/data/seed.txt")  # will be used inside container


# -------- Key Loading --------

def load_private_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        key_data = f.read()
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
    )
    return private_key


def load_public_key(path: str):
    with open(path, "rb") as f:
        key_data = f.read()
    public_key = serialization.load_pem_public_key(key_data)
    return public_key


# -------- Step 5: Decrypt Seed --------

def decrypt_seed(encrypted_seed_b64: str, private_key: rsa.RSAPrivateKey) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP-SHA256
    Returns 64-character hex seed string
    """
    # 1. Base64 decode
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 ciphertext: {e}")

    # 2. RSA/OAEP decrypt
    try:
        seed_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")

    # 3. Decode to UTF-8 string
    seed_str = seed_bytes.decode("utf-8").strip()

    # 4. Validate 64-char hex
    if len(seed_str) != 64:
        raise ValueError("Seed is not 64 characters long")
    allowed = set("0123456789abcdef")
    if any(c not in allowed for c in seed_str):
        raise ValueError("Seed contains non-hex characters")

    return seed_str


def save_seed_to_file(hex_seed: str, path: Path = SEED_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(hex_seed)


def load_seed_from_file(path: Path = SEED_FILE) -> str:
    if not path.exists():
        raise FileNotFoundError("Seed file not found")
    return path.read_text().strip()


# -------- Step 6: TOTP Generation / Verification --------

def hex_seed_to_base32(hex_seed: str) -> str:
    # Convert hex string -> bytes -> base32
    seed_bytes = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(seed_bytes).decode("utf-8").strip("=")
    return b32


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code from hex seed
    """
    b32_seed = hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(b32_seed)  # default: SHA1, 30s, 6 digits
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with ±valid_window periods tolerance
    """
    b32_seed = hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(b32_seed)
    # valid_window=N means current ± N periods
    return totp.verify(code, valid_window=valid_window)