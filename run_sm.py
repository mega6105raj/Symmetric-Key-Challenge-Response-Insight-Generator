"""Small runner for SessionManager to allow quick local runs.
Usage:
  C:/.../python.exe run_sm.py --sessions 500 [--enable-attacker]
"""
import sys
import argparse
from simulation.session_manager import SessionManager


def main():
    p = argparse.ArgumentParser(description='Run SessionManager (quick runner).')
    p.add_argument('--sessions', type=int, default=500, help='Number of sessions to run')
    p.add_argument('--enable-attacker', dest='enable_attacker', action='store_true',
                   help='Enable attacker thread (default: disabled)')
    args = p.parse_args()

    # create and run the session manager with requested options
    sm = SessionManager(num_sessions=args.sessions, enable_attacker=args.enable_attacker)
    try:
        sm.run()
    finally:
        # ensure components are stopped and sockets/threads cleaned up
        try:
            sm.stop_components()
        except Exception:
            pass
    print('RUN_COMPLETE, recorded:', len(sm.records))


if __name__ == '__main__':
    main()
