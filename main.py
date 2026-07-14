#!/usr/bin/env python3
# -----------------------------------------------------------
#  [*] AnyPool — Entry Point
#
#  The only file the Dockerfile runs (python -u main.py).
#  Deliberately thin: validates the configuration, creates
#  the one StratumServer instance, and runs its two loops
#  side by side until Ctrl+C:
#
#    - the TCP listener accepting miner connections on
#      STRATUM_PORT (handled by connection.handle_client)
#    - the job refresh loop polling getblocktemplate every
#      5 seconds so new blocks reach miners quickly
#
#  All actual pool logic lives in the anypool/ package — see
#  anypool/__init__.py for the module map.
#
#  Used by:
#    - Dockerfile — CMD ["python", "-u", "main.py"]
# -----------------------------------------------------------

import asyncio

from anypool import config
from anypool.stratum.connection import handle_client
from anypool.stratum.server import StratumServer


# Seconds between getblocktemplate polls
JOB_REFRESH_INTERVAL = 5




# -----------------------------------------------------------
# job_refresh_loop
# -----------------------------------------------------------
#
# Polls the node forever. create_job() itself decides whether
# the template contains new work, so calling it every few
# seconds is cheap — no new job is cut (and no broadcast is
# sent) unless the chain tip actually moved.
#
# Used by:
#   - main.py — main()
# -----------------------------------------------------------
async def job_refresh_loop(server: StratumServer):
    while True:
        await asyncio.sleep(JOB_REFRESH_INTERVAL)
        await server.create_job()










# -----------------------------------------------------------
# main
# -----------------------------------------------------------
#
# Boot sequence: validate config -> create the server (prints
# the startup banner) -> cut the initial job -> open the
# stratum port -> run listener + refresh loop concurrently.
#
# Used by:
#   - main.py — __main__ guard below
# -----------------------------------------------------------
async def main():
    config.validate()

    server = StratumServer()

    # Cut the initial job so the first miner to connect
    # receives work immediately
    initial_job = await server.create_job()
    if initial_job:
        await server.broadcast_new_job()

    # Open the stratum port for miners
    stratum_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, server),
        "0.0.0.0",
        config.STRATUM_PORT
    )

    print(f"[SERVER] Ready for connections on port {config.STRATUM_PORT}")

    try:
        await asyncio.gather(
            stratum_server.serve_forever(),
            job_refresh_loop(server)
        )
    finally:
        await server.rpc.close()










if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
