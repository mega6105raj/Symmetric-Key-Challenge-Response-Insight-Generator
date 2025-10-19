"""
network/router.py

A Router/Dispatcher that accepts TCP client connections and forwards messages between named clients.

Clients must register with:
    {"type": "register", "name": "<ClientName>"}

To send a message, clients send:
    {"type": "send", "to": "<DestName>", "payload": { ... arbitrary payload ... }}

Router forwards `payload` as-is to the destination client (if connected).
Router optionally supports:
 - an `interceptor` callable(sender_name, dest_name, payload) -> payload | None
   - returning None drops the message
   - returning modified payload changes what the destination receives
 - an `attacker_recorder` callable(sender, dest, payload) for passive logging
"""

import threading
import socket
from typing import Optional, Callable, Dict
from .communication import recv_msg, send_msg

class Router(threading.Thread):
    def __init__(self, host: str, port: int,
                 interceptor: Optional[Callable[[str, str, dict], Optional[dict]]] = None,
                 attacker_recorder: Optional[Callable[[str, str, dict], None]] = None,
                 backlog: int = 50):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.interceptor = interceptor
        self.attacker_recorder = attacker_recorder
        self.backlog = backlog

        self.server_socket = None
        self.name_to_conn: Dict[str, socket.socket] = {}
        self.lock = threading.RLock()
        self.running = threading.Event()
        self.running.set()

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(self.backlog)
        self.server_socket = s
        try:
            while self.running.is_set():
                conn, addr = s.accept()
                t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
                t.start()
        finally:
            self.shutdown()

    def shutdown(self):
        self.running.clear()
        with self.lock:
            for conn in list(self.name_to_conn.values()):
                try:
                    conn.close()
                except Exception:
                    pass
            self.name_to_conn.clear()
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _handle_conn(self, conn: socket.socket):
        # Expect register message first
        msg = recv_msg(conn, timeout=5.0)
        if not msg or msg.get("type") != "register" or "name" not in msg:
            try:
                conn.close()
            except Exception:
                pass
            return
        name = msg["name"]
        with self.lock:
            self.name_to_conn[name] = conn

        try:
            while self.running.is_set():
                msg = recv_msg(conn, timeout=1.0)
                if msg is None:
                    continue
                if msg.get("type") == "send":
                    dest = msg.get("to")
                    payload = msg.get("payload", {})
                    # interceptor hook
                    if self.interceptor:
                        try:
                            payload = self.interceptor(name, dest, payload)
                            if payload is None:
                                # dropped
                                continue
                        except Exception:
                            # on exception, don't block forwarding
                            pass
                    # passive recording hook (attacker)
                    if self.attacker_recorder:
                        try:
                            self.attacker_recorder(name, dest, payload)
                        except Exception:
                            pass

                    # forward
                    with self.lock:
                        dest_conn = self.name_to_conn.get(dest)
                    if dest_conn:
                        try:
                            send_msg(dest_conn, payload)
                        except Exception:
                            # remove dead connections
                            with self.lock:
                                self.name_to_conn.pop(dest, None)
                    else:
                        # destination not available; drop silently (or could queue)
                        pass
                else:
                    # ignore unknown message types
                    pass
        finally:
            with self.lock:
                self.name_to_conn.pop(name, None)
            try:
                conn.close()
            except Exception:
                pass
