#!/usr/bin/env python3
import datetime
from app.crypto_utils import load_seed_from_file, generate_totp_code, SEED_FILE

def main():
    try:
        hex_seed = load_seed_from_file(SEED_FILE)
    except FileNotFoundError:
        # Seed not decrypted yet, just log message
        print("Seed not available yet")
        return

    try:
        code = generate_totp_code(hex_seed)
    except Exception as e:
        print(f"Error generating code: {e}")
        return

    # Current UTC timestamp
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    ts = now_utc.strftime("%Y-%m-%d %H:%M:%S")

    print(f"{ts} - 2FA Code: {code}")


if _name_ == "_main_":
    main()