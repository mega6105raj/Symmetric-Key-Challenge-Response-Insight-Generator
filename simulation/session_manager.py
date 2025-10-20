"""
simulation/session_manager.py

Orchestrator that wires Router + Alice + Bob + optional Attacker and runs many sessions,
logging dataset rows with the columns specified in the project plan.

Assumptions:
 - network.router.Router, network.alice.AliceClient, network.bob.BobClient,
   network.attacker.AttackerRecorder/AttackerClient and network.communication exist.
 - core.protocol_oneway and core.protocol_twoway exist and use encryption helpers
   from core.crypto_utils.

Usage:
    from simulation.session_manager import SessionManager
    sm = SessionManager()
    sm.run()
"""

import os
import time
import threading
import secrets
import pandas as pd
from typing import Optional, Dict, Any

from config import (
    NUM_SESSIONS, ATTACK_RATE, REPLAY_PROB, RANDOM_GUESS_PROB,
    BOB_HOST, BOB_PORT, DATA_DIR, LOG_DIR, DATASET_FILENAME, SAVE_INTERVAL, ENABLE_ATTACKER_THREAD
)
# network components
from network.router import Router
from network.alice import AliceClient
from network.bob import BobClient
from network.attacker import AttackerRecorder, AttackerClient

# protocol cores
from core import protocol_oneway, protocol_twoway
from core.crypto_utils import generate_key
from utils.entropy import combined_entropy

# ensure data directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class SessionManager:
    def __init__(self,
                 num_sessions: int = NUM_SESSIONS,
                 attack_rate: float = ATTACK_RATE,
                 replay_prob: float = REPLAY_PROB,
                 random_guess_prob: float = RANDOM_GUESS_PROB,
                 router_host: str = BOB_HOST,
                 router_port: int = BOB_PORT,
                 enable_attacker: bool = ENABLE_ATTACKER_THREAD):
        self.num_sessions = num_sessions
        self.attack_rate = attack_rate
        self.replay_prob = replay_prob
        self.random_guess_prob = random_guess_prob
        self.router_host = router_host
        self.router_port = router_port
        self.enable_attacker = enable_attacker

        # shared secret key between Alice and Bob
        self.shared_key = generate_key()

        # Router & attacker recorder
        self.attacker_recorder = AttackerRecorder() if enable_attacker else None
        self.router = Router(host=self.router_host, port=self.router_port,
                             interceptor=None,
                             attacker_recorder=(self.attacker_recorder.record if self.attacker_recorder else None))

        # clients
        self.alice = AliceClient(self.router_host, self.router_port, name="Alice")
        self.bob = BobClient(self.router_host, self.router_port, name="Bob")
        self.attacker_client: Optional[AttackerClient] = None

        # storage
        self.records = []
        self._lock = threading.Lock()
        # map session_id -> expected values (for verification when brokered by callbacks)
        self.session_state: Dict[int, Dict[str, Any]] = {}

        # sequence control
        self._stop_event = threading.Event()

    # -------------------
    # Handlers registered on Alice/Bob
    # -------------------
    def _alice_on_challenge_rb(self, payload: dict):
        """
        Called when Alice receives a one-way challenge {"type":"challenge_rb","from":"Bob","rb": bytes}
        She should encrypt RB under shared key and send to Bob as {"type":"response_rb","resp": ciphertext}
        """
        rb = payload.get("rb")  # bytes
        # find session id associated with this RB (best-effort)
        # We'll check session_state for an entry with matching rb hex if available.
        rb_hex = rb.hex() if rb else None
        sid = None
        with self._lock:
            for s_id, s in self.session_state.items():
                if s.get("protocol_type") == "one-way" and s.get("rb") == rb_hex and not s.get("alice_responded"):
                    sid = s_id
                    break

        # Create encrypted response
        alice_resp_struct = protocol_oneway.alice_create_response_encrypt(rb, self.shared_key)
        # send ciphertext bytes to Bob
        cipher_bytes = alice_resp_struct["alice_cipher"]
        self.alice.send("Bob", {"type": "response_rb", "from": "Alice", "resp": cipher_bytes})

        # update session_state
        if sid is not None:
            with self._lock:
                self.session_state[sid]["alice_response"] = alice_resp_struct["alice_cipher_hex"]
                self.session_state[sid]["alice_responded"] = True
                # compute nonce entropy and add timestamp if missing
                # for one-way, nonce list is just RB
                self.session_state[sid]["nonce_entropy"] = combined_entropy(rb)
                # response_time etc are filled on Bob's end when he receives the response

    def _bob_on_init_ra(self, payload: dict):
        """
        Called when Bob receives init RA (two-way start).
        Bob should create RB and C1 = E_K(RA||RB) and send C1 to Alice.
        We will also store RB in session_state for later verification when Alice returns C2.
        """
        ra = payload.get("ra")
        ra_hex = ra.hex() if ra else None
        # find session id (where we created RA originally)
        sid = None
        with self._lock:
            for s_id, s in self.session_state.items():
                if s.get("protocol_type") == "two-way" and s.get("ra") == ra_hex and not s.get("bob_responded"):
                    sid = s_id
                    break

        # Bob computes response
        bob_resp_struct = protocol_twoway.bob_respond(ra, self.shared_key)
        c1 = bob_resp_struct["c1"]            # raw bytes
        rb = bob_resp_struct["rb_bytes"]
        rb_hex = bob_resp_struct["rb_hex"]

        # send C1 to Alice
        self.bob.send("Alice", {"type": "bob_ra_rb", "from": "Bob", "ra": ra, "rb": rb, "bob_resp": bob_resp_struct["c1"]})

        # store rb for this session id
        if sid is not None:
            with self._lock:
                self.session_state[sid]["rb"] = rb_hex
                self.session_state[sid]["bob_response"] = bob_resp_struct["c1_hex"]
                self.session_state[sid]["bob_responded"] = True
                self.session_state[sid]["rb_bytes"] = rb  # for later verification

    def _alice_on_bob_ra_rb(self, payload: dict):
        """
        Called when Alice receives C1 (bob_ra_rb). She should decrypt, verify RA, and send back C2 (alice_final).
        We'll capture the resulting C2 and update session_state so orchestrator can mark success later.
        """
        # payload contains 'ra', 'rb' and 'bob_resp' (but bob_resp here might actually be c1 bytes depending on sender)
        c1 = payload.get("bob_resp") or payload.get("c1")
        ra_received = payload.get("ra")
        # find session id by ra
        ra_hex = ra_received.hex() if ra_received else None
        sid = None
        with self._lock:
            for s_id, s in self.session_state.items():
                if s.get("protocol_type") == "two-way" and s.get("ra") == ra_hex and not s.get("alice_final_sent"):
                    sid = s_id
                    break

        # Alice decrypts and finalizes
        alice_finalize_struct = protocol_twoway.alice_finalize(c1, ra_received, self.shared_key)
        if alice_finalize_struct["success"]:
            c2 = alice_finalize_struct["c2"]
            # send C2 to Bob
            self.alice.send("Bob", {"type": "alice_final", "from": "Alice", "alice_resp": c2})
            if sid is not None:
                with self._lock:
                    self.session_state[sid]["alice_response"] = alice_finalize_struct["c2_hex"]
                    self.session_state[sid]["alice_final_sent"] = True
                    self.session_state[sid]["nonce_entropy"] = combined_entropy(bytes.fromhex(self.session_state[sid]["ra"]), bytes.fromhex(self.session_state[sid]["rb"]))
        else:
            # failed: record error in session_state if known
            if sid is not None:
                with self._lock:
                    self.session_state[sid]["alice_response"] = None
                    self.session_state[sid]["alice_final_error"] = alice_finalize_struct.get("error")
                    self.session_state[sid]["alice_final_sent"] = False

    def _on_incoming_response_rb_at_bob(self, payload: dict):
        """
        Called when Bob receives a one-way response_rb from Alice.
        Bob should decrypt/verify and we will build a full session record.
        """
        resp = payload.get("resp")
        # Try to match to session_id by searching session_state for identical rb->alice_response mapping
        # Find the session where bob previously created rb
        sid = None
        with self._lock:
            for s_id, s in self.session_state.items():
                if s.get("protocol_type") == "one-way" and not s.get("logged") and "rb" in s:
                    # expected alice_response hex will be computed after Alice responds, but we can match by RB
                    # we need the original RB bytes to compute expected ciphertext for verification
                    expected_rb_hex = s.get("rb")
                    if expected_rb_hex:
                        if bytes.fromhex(expected_rb_hex) and True:
                            # check if this session's RB equals one in record: we'll simply accept first unmatched one-way
                            sid = s_id
                            break

        # For one-way, Bob verifies by decrypting resp and comparing to RB
        # But we don't have decrypt_message here; use protocol_oneway.bob_verify_response
        # Need original RB bytes
        if sid is not None:
            rb_hex = self.session_state[sid].get("rb")
            rb_bytes = bytes.fromhex(rb_hex) if rb_hex else None
            verify = protocol_oneway.bob_verify_response(rb_bytes, resp, self.shared_key)
            # collect session-level record
            rec = {
                "protocol_type": "one-way",
                "session_id": sid,
                "ra": None,
                "rb": rb_hex,
                "alice_response": self.session_state[sid].get("alice_response"),
                "bob_response": None,
                "success": bool(verify.get("success")),
                "timestamp": self.session_state[sid].get("timestamp"),
                "response_time": None,  # could calculate using timestamps if desired
                "attack_flag": bool(self.session_state[sid].get("attack_flag")),
                "nonce_entropy": self.session_state[sid].get("nonce_entropy"),
                "is_replay": bool(self.session_state[sid].get("is_replay")),
                "is_random_guess": bool(self.session_state[sid].get("is_random_guess"))
            }
            with self._lock:
                self.records.append(rec)
                self.session_state[sid]["logged"] = True

    def _on_incoming_alice_final_at_bob(self, payload: dict):
        """
        Called when Bob receives Alice's final message in two-way (alice_final).
        We need to find matching session and verify C2 by decrypting it and comparing to stored RB.
        """
        c2 = payload.get("alice_resp") or payload.get("resp") or payload.get("alice_response")
        # find session that has bob_rb_bytes stored and not yet logged
        sid = None
        with self._lock:
            for s_id, s in self.session_state.items():
                if s.get("protocol_type") == "two-way" and s.get("rb_bytes") and not s.get("logged"):
                    sid = s_id
                    break
        if sid is not None:
            rb_bytes = self.session_state[sid].get("rb_bytes")
            verify = protocol_twoway.bob_verify_final(rb_bytes, c2, self.shared_key)
            rec = {
                "protocol_type": "two-way",
                "session_id": sid,
                "ra": self.session_state[sid].get("ra"),
                "rb": self.session_state[sid].get("rb"),
                "alice_response": self.session_state[sid].get("alice_response"),
                "bob_response": self.session_state[sid].get("bob_response"),
                "success": bool(verify.get("success")),
                "timestamp": self.session_state[sid].get("timestamp"),
                "response_time": None,
                "attack_flag": bool(self.session_state[sid].get("attack_flag")),
                "nonce_entropy": self.session_state[sid].get("nonce_entropy"),
                "is_replay": bool(self.session_state[sid].get("is_replay")),
                "is_random_guess": bool(self.session_state[sid].get("is_random_guess"))
            }
            with self._lock:
                self.records.append(rec)
                self.session_state[sid]["logged"] = True

    # -------------------
    # Session orchestration
    # -------------------
    def start_components(self):
        # start router
        self.router.start()
        time.sleep(0.5)  # allow server to start

        # start Alice and Bob clients and register callbacks
        # If they are not connected yet, AliceClient/BobClient will call connect on run()
        self.alice.on_challenge_rb = self._alice_on_challenge_rb
        self.alice.on_bob_ra_rb = self._alice_on_bob_ra_rb

        # Bob will handle init_ra and response_rb (we remap alice_final handling to orchestrator)
        self.bob.on_init_ra = self._bob_on_init_ra
        # hook response_rb to orchestrator verification for one-way
        self.bob.on_response_rb = self._on_incoming_response_rb_at_bob

        self.alice.start()
        self.bob.start()

        # wait for clients to establish connections to the router (avoid race)
        wait_start = time.time()
        while time.time() - wait_start < 5.0:
            if getattr(self.alice, "sock", None) is not None and getattr(self.bob, "sock", None) is not None:
                break
            time.sleep(0.05)

        # start attacker client if enabled (for active injection)
        if self.enable_attacker:
            self.attacker_client = AttackerClient(self.router_host, self.router_port, name="Attacker")
            self.attacker_client.start()

    def stop_components(self):
        if self.attacker_client:
            self.attacker_client.stop()
        self.alice.stop()
        self.bob.stop()
        self.router.shutdown()

    def run(self):
        self.start_components()
        session_id = 0

        try:
            for sid in range(self.num_sessions):
                if self._stop_event.is_set():
                    break
                session_id = sid
                # decide protocol and attack
                protocol_type = "one-way" if secrets.randbelow(2) == 0 else "two-way"
                attack_flag = (secrets.randbelow(100) < int(self.attack_rate * 100))
                attack_type = None
                if attack_flag:
                    attack_type = "replay" if secrets.randbelow(100) < int(self.replay_prob * 100) else "random_guess"

                ts = time.time()
                # prepare session state skeleton
                with self._lock:
                    self.session_state[sid] = {
                        "protocol_type": protocol_type,
                        "session_id": sid,
                        "ra": None,
                        "rb": None,
                        "rb_bytes": None,
                        "alice_response": None,
                        "bob_response": None,
                        "success": None,
                        "timestamp": ts,
                        "response_time": None,
                        "attack_flag": attack_flag,
                        "is_replay": (attack_type == "replay"),
                        "is_random_guess": (attack_type == "random_guess"),
                        "alice_responded": False,
                        "bob_responded": False,
                        "alice_final_sent": False,
                        "logged": False
                    }

                # One-way orchestration: Bob -> Alice (RB), Alice -> Bob (E_K(RB))
                if protocol_type == "one-way":
                    # Bob creates RB locally (we'll use protocol_oneway.bob_create_challenge)
                    bob_ch = protocol_oneway.bob_create_challenge()
                    rb_bytes = bob_ch["rb_bytes"]
                    rb_hex = bob_ch["rb_hex"]
                    # possibly simulate a replay attack by replacing rb_bytes with a reused nonce (old_nonce)
                    if attack_flag and attack_type == "replay":
                        rb_bytes_to_send = b"old_nonce"
                    else:
                        rb_bytes_to_send = rb_bytes

                    # update session state
                    with self._lock:
                        self.session_state[sid]["rb"] = rb_hex
                        self.session_state[sid]["timestamp"] = ts

                    # Bob sends challenge to Alice via Router (Bob -> Alice)
                    self.bob.send("Alice", {"type": "challenge_rb", "from": "Bob", "rb": rb_bytes_to_send})

                    # we expect Alice to respond and our bob.on_response_rb handler will be invoked which will log the session
                    # wait small time for flow to complete
                    time.sleep(0.02)

                else:
                    # Two-way orchestration: Alice initiates with RA -> Bob
                    alice_init = protocol_twoway.alice_initiate()
                    ra_bytes = alice_init["ra_bytes"]
                    ra_hex = alice_init["ra_hex"]

                    # simulate replay by replacing RA with old_nonce if chosen
                    if attack_flag and attack_type == "replay":
                        ra_bytes_to_send = b"old_nonce"
                    else:
                        ra_bytes_to_send = ra_bytes

                    with self._lock:
                        self.session_state[sid]["ra"] = ra_hex
                        self.session_state[sid]["timestamp"] = ts

                    # Alice sends RA to Bob (Alice -> Bob)
                    self.alice.send("Bob", {"type": "init_ra", "from": "Alice", "ra": ra_bytes_to_send})

                    # Bob's on_init_ra will create rb and send c1 to Alice; then Alice's on_bob_ra_rb will send c2; orchestrator will verify when Bob receives c2
                    time.sleep(0.04)

                # occasionally let the system settle, and periodically save partial dataset
                if sid % SAVE_INTERVAL == 0 and sid > 0:
                    self._flush_records_to_csv(partial=True)

                # small pacing
                time.sleep(0.005)

            # After loop, wait a short while to let final messages be processed
            time.sleep(0.5)

            # collect any unlogged sessions — for sessions that didn't get logged via callbacks, attempt best-effort logging
            with self._lock:
                for s_id, s in list(self.session_state.items()):
                    if not s.get("logged") and s.get("protocol_type") == "one-way":
                        # try to verify using protocol_oneway if alice_response was set
                        if s.get("alice_response") and s.get("rb"):
                            # verify
                            try:
                                rb_bytes = bytes.fromhex(s["rb"])
                                alice_cipher_bytes = bytes.fromhex(s["alice_response"])
                                verify = protocol_oneway.bob_verify_response(rb_bytes, alice_cipher_bytes, self.shared_key)
                                rec = {
                                    "protocol_type": "one-way",
                                    "session_id": s_id,
                                    "ra": None,
                                    "rb": s["rb"],
                                    "alice_response": s.get("alice_response"),
                                    "bob_response": None,
                                    "success": bool(verify.get("success")),
                                    "timestamp": s.get("timestamp"),
                                    "response_time": None,
                                    "attack_flag": bool(s.get("attack_flag")),
                                    "nonce_entropy": s.get("nonce_entropy"),
                                    "is_replay": bool(s.get("is_replay")),
                                    "is_random_guess": bool(s.get("is_random_guess"))
                                }
                                self.records.append(rec)
                                self.session_state[s_id]["logged"] = True
                            except Exception:
                                pass
                    if not s.get("logged") and s.get("protocol_type") == "two-way":
                        # try to verify if we have both alice_response and bob_response
                        if s.get("alice_response") and s.get("bob_response") and s.get("rb_bytes"):
                            try:
                                c2_bytes = bytes.fromhex(s["alice_response"])
                                rb_bytes = s.get("rb_bytes")
                                verify = protocol_twoway.bob_verify_final(rb_bytes, c2_bytes, self.shared_key)
                                rec = {
                                    "protocol_type": "two-way",
                                    "session_id": s_id,
                                    "ra": s.get("ra"),
                                    "rb": s.get("rb"),
                                    "alice_response": s.get("alice_response"),
                                    "bob_response": s.get("bob_response"),
                                    "success": bool(verify.get("success")),
                                    "timestamp": s.get("timestamp"),
                                    "response_time": None,
                                    "attack_flag": bool(s.get("attack_flag")),
                                    "nonce_entropy": s.get("nonce_entropy"),
                                    "is_replay": bool(s.get("is_replay")),
                                    "is_random_guess": bool(s.get("is_random_guess"))
                                }
                                self.records.append(rec)
                                self.session_state[s_id]["logged"] = True
                            except Exception:
                                pass

            # final save
            self._flush_records_to_csv(partial=False)
        finally:
            self.stop_components()

    def _flush_records_to_csv(self, partial: bool = True):
        """
        Write collected records to a CSV file. If partial, append to existing file; otherwise overwrite final file.
        """
        if not self.records:
            return
        df = pd.DataFrame(self.records)
        out_path = os.path.join(DATA_DIR, DATASET_FILENAME)
        if partial and os.path.exists(out_path):
            # append
            df.to_csv(out_path, mode="a", header=False, index=False)
        else:
            df.to_csv(out_path, index=False)
        print(f"[SessionManager] Wrote {len(self.records)} records to {out_path} (partial={partial})")

# If executed as a script, run a small demo
if __name__ == "__main__":
    sm = SessionManager(num_sessions=200, attack_rate=0.2, replay_prob=0.6, enable_attacker=True)
    sm.run()
