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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((self.router_host, self.router_port))
        send_msg(s, {"type": "register", "name": self.name})
        self.sock = s
        # set blocking mode for normal recv
        s.settimeout(None)

    def send(self, to: str, payload: dict):
        if not self.sock:
            raise RuntimeError("not connected")
        send_msg(self.sock, {"type": "send", "to": to, "payload": payload})

    def run(self):
        if not self.sock:
            self.connect_and_register()
        log.info("Alice connected & registered")
        while self.running.is_set():
            msg = recv_msg(self.sock, timeout=1.0)
            if msg is None:
                continue
            t = msg.get("type")
            try:
                if t == "challenge_rb":
                    if self.on_challenge_rb:
                        self.on_challenge_rb(msg)
                elif t == "bob_ra_rb":
                    if self.on_bob_ra_rb:
                        self.on_bob_ra_rb(msg)
                else:
                    # unknown or unused type
                    pass
            except Exception as e:
                log.exception("Alice handler raised: %s", e)

    def stop(self):
        self.running.clear()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
