#!/usr/bin/env python3
############################################################
#  [*] AnyPool — Entry Point
#
#  The only file the Dockerfile runs (python -u main.py).
#  Deliberately thin: validates the configuration, resolves
#  which coin FAMILY the selected coin belongs to (bitcoin
#  or cryptonote — they speak different stratum dialects and
#  build work differently), and hands control to that
#  family's runner. Everything else lives in the anypool/
#  package — see anypool/__init__.py for the module map.
#
#  Used by:
#    - Dockerfile — CMD ["python", "-u", "main.py"]
############################################################


import asyncio

from anypool import config, families








############################################################
# main
############################################################
#
# Fail-fast config check, then block on the active family's
# run() until the process is stopped.
#
# Used by:
#   - the __main__ guard below
############################################################

def main():
    config.validate()
    runner = families.active()
    asyncio.run(runner.run())








if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
