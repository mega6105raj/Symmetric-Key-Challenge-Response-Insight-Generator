import time
from typing import Dict, Optional
from config import NONCE_SIZE
from core.crypto_utils import generate_nonce, encrypt_message, decrypt_message

def bob_initiate() -> Dict[str, str]:
    rb = generate_nonce(NONCE_SIZE)
    return {
        "rb_bytes": rb,
        "rb_hex": rb.hex(),
        "timestamp": time.time()
    }

def alice_respond(rb_bytes: bytes, key: bytes) -> Dict[str, str]:
    ra = generate_nonce(NONCE_SIZE)
    plaintext = rb_bytes + ra
    c1 = encrypt_message(key, plaintext)
    return {
        "ra_bytes": ra,
        "ra_hex": ra.hex(),
        "c1":c1,
        'c1_hex':c1.hex(),
        "timestamp":time.time()
    }

def bob_finalize(c1_bytes: bytes, rb_expected: bytes, key:bytes) -> Dict[str, Optional[str]]:
    try:
        plaintext = decrypt_message(key, c1_bytes)
        rb_len = len(rb_expected)
        rb_recv = plaintext[:rb_len]
        ra = plaintext[rb_len:]
        if rb_recv != rb_expected:
            return {
                "ra_hex": None,
                "c2": None,
                "c2_hex": None,
                "success": False,
                "error": "rb_mismatch",
                "timestamp": time.time()
            }
        c2 = encrypt_message(key, ra)
        return {
            "ra_hex": ra.hex(),
            "c2": c2,
            "c2_hex": c2.hex(),
            "success": True,
            "error": None,
            "timestamp": time.time()
        }
    except Exception as e:
        return {
            "ra_hex": None,
            "c2": None,
            "c2_hex": None,
            "success": False,
            "error": f"decryption_failed: {e}",
            "timestamp": time.time()
        }
    
    def alice_verify_final(ra_expected: bytes, c2_bytes: bytes, key: bytes) -> Dict[str, Optional[str]]:
        try:
            plaintext = decrypt_message(key, c2_bytes)
            ok = plaintext == ra_expected
            return {
                "ra_decrypted_hex": plaintext.hex(),
                "success": bool(ok),
                "error": None,
                "timestamp": time.time()
            }
        except Exception as e:
            return {
                "ra_decrypted_hex": None,
                "success": False,
                "error": f"decryption_failed: {e}",
                "timestamp": time.time()
            }