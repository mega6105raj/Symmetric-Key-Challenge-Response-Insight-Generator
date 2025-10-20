"""Small runner for SessionManager to allow quick local runs.
Usage:
  C:/.../python.exe run_sm.py
"""
import sys
from simulation.session_manager import SessionManager

if __name__ == '__main__':
  # run: sessions, attacker disabled (requested)
  sm = SessionManager(num_sessions=500, enable_attacker=False)
  try:
    sm.run()
  finally:
    # ensure components are stopped and sockets/threads cleaned up
    try:
      sm.stop_components()
    except Exception:
      pass
  print('RUN_COMPLETE, recorded:', len(sm.records))
