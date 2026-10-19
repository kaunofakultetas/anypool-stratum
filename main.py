#!/usr/bin/env python3
############################################################
#  [*] AnyPool — Entry Point
#
#  The only file the Dockerfile runs, with Python's output
#  unbuffered so every panel reaches the container log the
#  moment it is printed.
#
#  Deliberately thin: validates the configuration, resolves
#  which coin FAMILY the selected coin belongs to (bitcoin
#  or cryptonote — they speak different stratum dialects and
#  build work differently), and hands control to that
#  family's runner. Everything else lives in the anypool/
#  package — see anypool/__init__.py for the module map.
#
#  Used by:
#    - Dockerfile — its CMD starts the pool with this file
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








# Ctrl+C in an interactive run ends the pool with one line
# instead of a traceback
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
