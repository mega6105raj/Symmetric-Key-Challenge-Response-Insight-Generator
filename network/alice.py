"""
network/alice.py

Alice client class that connects to Router and handles incoming payloads.
It exposes callbacks that your orchestrator/simulation can register or override.

Typical payloads received by Alice:
 - {"type": "challenge_rb", "from":"Bob", "rb": <bytes>}
 - {"type": "bob_ra_rb", "from":"Bob", "ra": <bytes>, "rb": <bytes>, "bob_resp": <bytes>}
"""

import socket
import threading
import time
import logging
from typing import Callable, Optional
from .communication import send_msg, recv_msg
import ssl

log = logging.getLogger("network.alice")

class AliceClient(threading.Thread):
    def __init__(self, router_host: str, router_port: int, name: str = "Alice"):
        super().__init__(daemon=True)
        self.router_host = router_host
        self.router_port = router_port
        self.name = name
        self.sock: Optional[socket.socket] = None
        self.running = threading.Event()
        self.running.set()

        # callbacks (set by orchestrator). signature: fn(payload_dict)
        self.on_challenge_rb: Optional[Callable[[dict], None]] = None
        self.on_bob_ra_rb: Optional[Callable[[dict], None]] = None

    def connect_and_register(self, timeout: float = 5.0):
        print(f"[Alice] Starting TLS connection to {self.router_host}:{self.router_port}")
        attempts = 0
        while True:
            try:
                # TLS context setup
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((self.router_host, self.router_port))
                tls_sock = context.wrap_socket(s, server_hostname=self.router_host)
                print("[Alice] TLS handshake successful. Registering...")
                send_msg(tls_sock, {"type": "register", "name": self.name})
                self.sock = tls_sock
                tls_sock.settimeout(None)
                print("[Alice] Registered and ready.")
                return
            except Exception as e:
                print(f"[Alice] Connection attempt {attempts+1} failed: {e}")
                attempts += 1
                if attempts >= 10:
                    print("[Alice] Failed to connect after 10 attempts.")
                    raise
                time.sleep(0.1)

    def send(self, to: str, payload: dict):
        if not self.sock:
            raise RuntimeError("not connected")
        send_msg(self.sock, {"type": "send", "to": to, "payload": payload})

    def run(self):
        print("[Alice] Thread started.")
        if not self.sock:
            self.connect_and_register()
        print("[Alice] Connected & registered. Listening for messages...")
        while self.running.is_set():
            msg = recv_msg(self.sock, timeout=1.0)
            if msg is None:
                continue
            t = msg.get("type")
            try:
                print(f"[Alice] Received message of type: {t}")
                if t == "challenge_rb":
                    if self.on_challenge_rb:
                        self.on_challenge_rb(msg)
                elif t == "bob_ra_rb":
                    if self.on_bob_ra_rb:
                        self.on_bob_ra_rb(msg)
                else:
                    print(f"[Alice] Unknown message type: {t}")
            except Exception as e:
                print(f"[Alice] Handler exception: {e}")

    def stop(self):
        self.running.clear()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
