# app/crypto_utils.py

import base64
import json
from pathlib import Path
from typing import Optional

import pyotp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


SEED_FILE = Path("seed.txt")


# ---------------------------- LOAD PRIVATE KEY ---------------------------- #

def load_private_key(private_key_path: str):
    """Load student's RSA private key from PEM file."""
    with open(private_key_path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


# ---------------------------- DECRYPT SEED ---------------------------- #

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """Decrypt base64 encrypted seed using student's private RSA key."""
    encrypted_bytes = base64.b64decode(encrypted_seed_b64)

    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # decrypted output is raw seed in hex format
    return decrypted_bytes.decode()


# ---------------------------- SAVE / LOAD SEED ---------------------------- #

def save_seed_to_file(seed_hex: str, filepath: Path = SEED_FILE):
    filepath.write_text(seed_hex)


def load_seed_from_file(filepath: Path = SEED_FILE) -> str:
    return filepath.read_text().strip()


# ---------------------------- TOTP GENERATION ---------------------------- #

def generate_totp_code(seed_hex: str) -> str:
    """Generate 6-digit TOTP using the decrypted hex seed."""
    key_bytes = bytes.fromhex(seed_hex)
    b32_secret = base64.b32encode(key_bytes).decode()

    totp = pyotp.TOTP(b32_secret, digits=6, interval=30)
    return totp.now()


# ---------------------------- TOTP VERIFICATION ---------------------------- #

def verify_totp_code(seed_hex: str, code: str, valid_window: int = 1) -> bool:
    key_bytes = bytes.fromhex(seed_hex)
    b32_secret = base64.b32encode(key_bytes).decode()

    totp = pyotp.TOTP(b32_secret, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)
