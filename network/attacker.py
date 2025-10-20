"""
network/attacker.py

An attacker client that can operate in two modes:
 - passive_recorder: records every payload observed (hooked into Router via attacker_recorder)
 - active_replayer: replays previously captured messages by sending them back into the network via Router

This module provides Attacker class usable by orchestrator for more controlled attacks.
"""

import threading
import time
import random
import logging
from typing import List, Dict, Optional, Callable
from .communication import send_msg, recv_msg
import socket

log = logging.getLogger("network.attacker")

class AttackerRecorder:
    """
    Simple in-memory recording store.
    The Router can call `.record(sender, dest, payload)` for every forwarded message.
    """

    def __init__(self):
        self.records: List[Dict] = []
        self.lock = threading.Lock()

    def record(self, sender: str, dest: str, payload: dict):
        # store a JSON-serializable snapshot (convert bytes->hex)
        with self.lock:
            safe = {}
            for k, v in payload.items():
                if isinstance(v, (bytes, bytearray)):
                    safe[k] = v.hex()
                else:
                    safe[k] = v
            self.records.append({
                "time": time.time(),
                "from": sender,
                "to": dest,
                "payload": safe
            })

    def sample(self, n: int = 1):
        with self.lock:
            if not self.records:
                return []
            return random.sample(self.records, min(n, len(self.records)))

class AttackerClient(threading.Thread):
    """
    Attacker client that connects to Router and can inject messages (replays).
    The orchestrator may call `inject_replay(payload_dict, dest_name)` to make it forward a
    previously-captured payload.
    """

    def __init__(self, router_host: str, router_port: int, name: str = "Attacker"):
        super().__init__(daemon=True)
        self.router_host = router_host
        self.router_port = router_port
        self.name = name
        self.sock: Optional[socket.socket] = None
        self.running = threading.Event()
        self.running.set()

    def connect_and_register(self, timeout: float = 5.0):
        attempts = 0
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((self.router_host, self.router_port))
                send_msg(s, {"type": "register", "name": self.name})
                self.sock = s
                s.settimeout(None)
                return
            except Exception:
                attempts += 1
                if attempts >= 10:
                    raise
                time.sleep(0.1)

    def inject_replay(self, payload: dict, dest: str):
        """
        This sends a message on behalf of the attacker to dest, with the given payload.
        payload should be a dict; bytes values will be hex-encoded by send_msg.
        """
        if not self.sock:
            raise RuntimeError("attacker not connected")
        send_msg(self.sock, {"type": "send", "to": dest, "payload": payload})

    def run(self):
        if not self.sock:
            self.connect_and_register()
        log.info("Attacker connected & registered")
        while self.running.is_set():
            # Attacker can optionally listen for messages forwarded to it (e.g., to implement advanced MITM)
            msg = recv_msg(self.sock, timeout=1.0)
            if msg is not None:
                # simple passive behavior: log it; orchestrator can make decisions based on Attacker's local copy
                log.debug("Attacker got message: %s", msg)
            time.sleep(0.1)

    def stop(self):
        self.running.clear()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
