import time
from typing import Dict, Optional
from config import NONCE_SIZE
from core.crypto_utils import generate_nonce, encrypt_message, decrypt_message

def bob_create_challenge() -> Dict[str, str]:
    rb = generate_nonce(NONCE_SIZE)
    return {
        "rb_bytes": rb,
        "rb_hex": rb.hex(),
        "timestamp": time.time()
    }

def alice_create_response_encrypt(rb_bytes: bytes, key: bytes) -> Dict[str, str]:
    ct = encrypt_message(key, rb_bytes)
    return {
        "alice_cipher": ct,
        "alice_cipher_hex": ct.hex(),
        "timestamp": time.time()
    }

def bob_verify_response(rb_bytes: bytes, alice_cipher: bytes, key: bytes) -> Dict[str, Optional[str]]:
    try:
        plaintext = decrypt_message(key, alice_cipher)
        ok = plaintext == rb_bytes
        return {
            "decrypted_plain_hex": plaintext.hex(),
            "success": bool(ok),
            "error": None,
            "timestamp": time.time()
        }
    except Exception as e:
        return {
            "decrypted_plain_hex": None,
            "success": False,
            "error": f"decryption_failed: {e}",
            "timestamp": time.time()
        }