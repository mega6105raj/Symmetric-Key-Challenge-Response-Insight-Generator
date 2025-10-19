import json
import struct
import socket
from typing import Optional, Any, Dict

# keys that we expect to be hex-encoded when transporting over JSON
_HEX_FIELDS = ("ra", "rb", "c1", "c2", "alice_cipher", "alice_resp", "bob_resp", "resp", "iv",
               "alice_response", "bob_response", "alice_cipher", "bob_cipher", "payload_bytes",
               "raw")

def bytes_to_hex(b: Optional[bytes]) -> Optional[str]:
    return None if b is None else b.hex()

def hex_to_bytes(h: Optional[str]) -> Optional[bytes]:
    return None if h is None else bytes.fromhex(h)

def _prepare_for_send(obj: Dict[str, Any]) -> bytes:
    safe = {}
    for k, v in obj.items():
        if isinstance(v, (bytes, bytearray)):
            safe[k] = v.hex()
        else:
            safe[k] = v
    return json.dumps(safe, separators=(",", ":"), sort_keys=False).encode("utf-8")

def _post_recv(obj: Dict[str, Any]) -> Dict[str, Any]:
    for k in list(obj.keys()):
        if isinstance(obj[k], str) and all(c in "0123456789abcdef" for c in obj[k]):
            try:
                obj[k] = bytes.fromhex(obj[k])
            except Exception:
                pass
    return obj

def send_msg(sock: socket.socket, obj: Dict[str, Any]) -> None:
    raw = _prepare_for_send(obj)
    header = struct.pack("!I", len(raw))
    sock.sendall(header + raw)

def recv_msg(sock: socket.socket, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
    sock.settimeout(timeout)
    try:
        hdr = sock.recv(4)
        if not hdr or len(hdr) < 4:
            return None
        (n,) = struct.unpack("!I", hdr)
        data = bytearray()
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data.extend(chunk)
        obj = json.loads(data.decode("utf-8"))
        return _post_recv(obj)
    except socket.timeout:
        return None
    except Exception:
        return None
