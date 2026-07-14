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
#      5 seconds (safety net)
#    - the longpoll loop, which keeps a getblocktemplate
#      request hanging at the node so a new chain tip
#      triggers a job cut IMMEDIATELY instead of after up
#      to 5 seconds of hashing stale work
#
#  All actual pool logic lives in the anypool/ package — see
#  anypool/__init__.py for the module map.
#
#  Used by:
#    - Dockerfile — CMD ["python", "-u", "main.py"]
# -----------------------------------------------------------

import asyncio

from anypool import coins, config
from anypool.stratum.connection import handle_client
from anypool.stratum.server import StratumServer


# Seconds between getblocktemplate polls
JOB_REFRESH_INTERVAL = 5

# Max seconds one longpoll request may hang at the node before
# we re-issue it. The node answers much sooner when the chain
# tip actually moves — this is only the recycle interval.
LONGPOLL_TIMEOUT = 600




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
# longpoll_loop
# -----------------------------------------------------------
#
# Instant new-block detection. Every block template carries a
# "longpollid"; sending it back in another getblocktemplate
# call makes the node HOLD that request open and only answer
# once the chain tip moves (or the timeout recycles it). The
# moment it answers we cut a new job, so miners stop hashing
# stale work within milliseconds of a new block instead of
# waiting for the next 5-second poll.
#
# Any error (node restart, timeout, no job yet) just waits a
# poll interval and retries — the job_refresh_loop keeps the
# pool alive regardless.
#
# Used by:
#   - main.py — main()
# -----------------------------------------------------------
async def longpoll_loop(server: StratumServer):
    while True:

        job = server.job_manager.current_job
        longpollid = job["template"].get("longpollid") if job else None

        if not longpollid:
            await asyncio.sleep(JOB_REFRESH_INTERVAL)
            continue

        try:
            await server.rpc.call(
                "getblocktemplate",
                [{"rules": coins.active().gbt_rules, "longpollid": longpollid}],
                timeout=LONGPOLL_TIMEOUT,
            )
        except Exception:
            # Timeout recycle or node hiccup — just re-arm
            await asyncio.sleep(JOB_REFRESH_INTERVAL)
            continue

        # The node answered: the tip (probably) moved.
        # create_job() re-checks and dedupes false alarms.
        await server.create_job()










# -----------------------------------------------------------
# main
# -----------------------------------------------------------
#
# Boot sequence: validate config -> create the server (prints
# the startup banner) -> cut the initial job -> open the
# stratum port -> run listener, refresh loop and longpoll
# loop concurrently.
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
            job_refresh_loop(server),
            longpoll_loop(server)
        )
    finally:
        await server.rpc.close()










if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
