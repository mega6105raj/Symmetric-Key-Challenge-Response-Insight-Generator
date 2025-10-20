import time
from typing import Dict, Optional
from config import NONCE_SIZE
from core.crypto_utils import generate_nonce, encrypt_message, decrypt_message


def alice_initiate() -> Dict[str, str]:
    """Alice creates an initial nonce RA for two-way protocol."""
    ra = generate_nonce(NONCE_SIZE)
    return {
        "ra_bytes": ra,
        "ra_hex": ra.hex(),
        "timestamp": time.time()
    }


def bob_respond(ra_bytes: bytes, key: bytes) -> Dict[str, str]:
    """Bob receives RA and responds by creating RB and C1 = E_K(RA || RB)."""
    rb = generate_nonce(NONCE_SIZE)
    plaintext = ra_bytes + rb
    c1 = encrypt_message(key, plaintext)
    return {
        "c1": c1,
        "c1_hex": c1.hex(),
        "rb_bytes": rb,
        "rb_hex": rb.hex(),
        "timestamp": time.time()
    }


def alice_finalize(c1_bytes: bytes, ra_expected: bytes, key: bytes) -> Dict[str, Optional[str]]:
    """Alice decrypts C1, verifies RA, and returns C2 = E_K(RB) on success."""
    try:
        plaintext = decrypt_message(key, c1_bytes)
        ra_len = len(ra_expected)
        ra_recv = plaintext[:ra_len]
        rb = plaintext[ra_len:]
        if ra_recv != ra_expected:
            return {
                "c2": None,
                "c2_hex": None,
                "success": False,
                "error": "ra_mismatch",
                "timestamp": time.time()
            }
        c2 = encrypt_message(key, rb)
        return {
            "c2": c2,
            "c2_hex": c2.hex(),
            "success": True,
            "error": None,
            "timestamp": time.time()
        }
    except Exception as e:
        return {
            "c2": None,
            "c2_hex": None,
            "success": False,
            "error": f"decryption_failed: {e}",
            "timestamp": time.time()
        }


def bob_verify_final(rb_expected: bytes, c2_bytes: bytes, key: bytes) -> Dict[str, Optional[str]]:
    """Bob decrypts C2 and checks it matches the expected RB."""
    try:
        plaintext = decrypt_message(key, c2_bytes)
        ok = plaintext == rb_expected
        return {
            "rb_decrypted_hex": plaintext.hex() if plaintext is not None else None,
            "success": bool(ok),
            "error": None,
            "timestamp": time.time()
        }
    except Exception as e:
        return {
            "rb_decrypted_hex": None,
            "success": False,
            "error": f"decryption_failed: {e}",
            "timestamp": time.time()
        }