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
from typing import Callable, Optional
from .communication import send_msg, recv_msg

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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((self.router_host, self.router_port))
        send_msg(s, {"type": "register", "name": self.name})
        self.sock = s
        s.settimeout(None)

    def send(self, to: str, payload: dict):
        if not self.sock:
            raise RuntimeError("not connected")
        send_msg(self.sock, {"type": "send", "to": to, "payload": payload})

    def run(self):
        if not self.sock:
            self.connect_and_register()
        log.info("Bob connected & registered")
        while self.running.is_set():
            msg = recv_msg(self.sock, timeout=1.0)
            if msg is None:
                continue
            t = msg.get("type")
            try:
                if t == "init_ra":
                    if self.on_init_ra:
                        self.on_init_ra(msg)
                elif t == "response_rb":
                    if self.on_response_rb:
                        self.on_response_rb(msg)
                else:
                    pass
            except Exception as e:
                log.exception("Bob handler raised: %s", e)

    def stop(self):
        self.running.clear()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
