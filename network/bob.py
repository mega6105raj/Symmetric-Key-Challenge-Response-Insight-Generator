"""
network/bob.py

Bob client that connects to Router and handles incoming payloads.
Bob will typically receive RA (init) and needs to reply with encrypted C1 (E_K(RA||RB))
or receive response_rb messages as result of one-way protocol.

Callbacks:
 - on_init_ra(payload)       -> called when RA received (init for two-way)
 - on_response_rb(payload)   -> called when Alice responded to RB (one-way)
"""

import socket
import threading
import logging
import time
from typing import Callable, Optional
from .communication import send_msg, recv_msg
import ssl

log = logging.getLogger("network.bob")

class BobClient(threading.Thread):
    def __init__(self, router_host: str, router_port: int, name: str = "Bob"):
        super().__init__(daemon=True)
        self.router_host = router_host
        self.router_port = router_port
        self.name = name
        self.sock: Optional[socket.socket] = None
        self.running = threading.Event()
        self.running.set()

        self.on_init_ra: Optional[Callable[[dict], None]] = None
        self.on_response_rb: Optional[Callable[[dict], None]] = None

    def connect_and_register(self, timeout: float = 5.0):
        print(f"[Bob] Starting TLS connection to {self.router_host}:{self.router_port}")
        attempts = 0
        while True:
            try:
                # TLS context setup
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.load_cert_chain(certfile="certs/bob.crt", keyfile="certs/bob.pem")

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((self.router_host, self.router_port))
                tls_sock = context.wrap_socket(s, server_side=False, do_handshake_on_connect=True)
                print("[Bob] TLS handshake successful. Registering...")
                send_msg(tls_sock, {"type": "register", "name": self.name})
                self.sock = tls_sock
                tls_sock.settimeout(None)
                print("[Bob] Registered and ready.")
                return
            except Exception as e:
                print(f"[Bob] Connection attempt {attempts+1} failed: {e}")
                attempts += 1
                if attempts >= 10:
                    print("[Bob] Failed to connect after 10 attempts.")
                    raise
                time.sleep(0.1)

    def send(self, to: str, payload: dict):
        if not self.sock:
            raise RuntimeError("not connected")
        send_msg(self.sock, {"type": "send", "to": to, "payload": payload})

    def run(self):
        print("[Bob] Thread started.")
        if not self.sock:
            self.connect_and_register()
        print("[Bob] Connected & registered. Listening for messages...")
        while self.running.is_set():
            msg = recv_msg(self.sock, timeout=1.0)
            if msg is None:
                continue
            t = msg.get("type")
            try:
                print(f"[Bob] Received message of type: {t}")
                if t == "init_ra":
                    if self.on_init_ra:
                        self.on_init_ra(msg)
                elif t == "response_rb":
                    if self.on_response_rb:
                        self.on_response_rb(msg)
                else:
                    print(f"[Bob] Unknown message type: {t}")
            except Exception as e:
                print(f"[Bob] Handler exception: {e}")

    def stop(self):
        self.running.clear()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
