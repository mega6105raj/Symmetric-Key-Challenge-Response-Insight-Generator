"""Generate a large dataset by running the SessionManager multiple sessions.

Usage:
    python generate_dataset.py --sessions 1000 --attack-rate 0.2 --replay-prob 0.6

This script will run the simulator (SessionManager) with the requested parameters,
then read the CSV and print summary statistics (total records, attack counts, replay counts).
"""
import argparse
import time
import os
import pandas as pd
from simulation.session_manager import SessionManager


def run_and_save(sessions: int, attack_rate: float, replay_prob: float, enable_attacker: bool):
    sm = SessionManager(num_sessions=sessions, attack_rate=attack_rate, replay_prob=replay_prob, enable_attacker=enable_attacker)
    start = time.time()
    sm.run()
    elapsed = time.time() - start
    # After run, read CSV and summarize
    from config import DATA_DIR, DATASET_FILENAME
    out_path = os.path.join(DATA_DIR, DATASET_FILENAME)
    if os.path.exists(out_path):
        df = pd.read_csv(out_path)
        total = len(df)
        attacks = df[df['attack_flag'] == True]
        num_attacks = len(attacks)
        replays = df[df['is_replay'] == True]
        num_replays = len(replays)
        randoms = df[df['is_random_guess'] == True]
        num_randoms = len(randoms)
        print(f"Wrote/loaded {total} records from {out_path}")
        print(f"Elapsed: {elapsed:.1f}s  Attacks: {num_attacks}  Replays: {num_replays}  Random guesses: {num_randoms}")
    else:
        print("No output CSV found at expected path:", out_path)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--sessions', type=int, default=1000)
    p.add_argument('--attack-rate', type=float, default=0.2)
    p.add_argument('--replay-prob', type=float, default=0.6)
    p.add_argument('--dataset-filename', type=str, default=None, help='Optional dataset filename to write to in data/results')
    p.add_argument('--no-attacker', dest='enable_attacker', action='store_false')
    p.set_defaults(enable_attacker=True)
    args = p.parse_args()

    # If dataset-filename is provided, pass it through to SessionManager by temporarily overriding DATASET_FILENAME
    if args.dataset_filename:
        sm = SessionManager(num_sessions=args.sessions, attack_rate=args.attack_rate, replay_prob=args.replay_prob, enable_attacker=args.enable_attacker, dataset_filename=args.dataset_filename)
        start = time.time()
        sm.run()
        elapsed = time.time() - start
        from config import DATA_DIR
        out_path = os.path.join(DATA_DIR, args.dataset_filename)
    else:
        run_and_save(args.sessions, args.attack_rate, args.replay_prob, args.enable_attacker)
        from config import DATA_DIR, DATASET_FILENAME
        out_path = os.path.join(DATA_DIR, DATASET_FILENAME)

    # summarize results
    if os.path.exists(out_path):
        df = pd.read_csv(out_path)
        total = len(df)
        attacks = df[df['attack_flag'] == True]
        num_attacks = len(attacks)
        replays = df[df['is_replay'] == True]
        num_replays = len(replays)
        randoms = df[df['is_random_guess'] == True]
        num_randoms = len(randoms)
        print(f"Wrote/loaded {total} records from {out_path}")
        print(f"Elapsed: {elapsed:.1f}s  Attacks: {num_attacks}  Replays: {num_replays}  Random guesses: {num_randoms}")
    else:
        print("No output CSV found at expected path:", out_path)
