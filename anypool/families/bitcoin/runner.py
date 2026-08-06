############################################################
#  [*] Bitcoin Family — Runner
#
#  The event loops of a Bitcoin-family pool:
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
#  Used by:
#    - main.py — via families.active().run()
############################################################


import asyncio

from anypool import coins, config
from anypool.families.bitcoin.connection import handle_client
from anypool.families.bitcoin.server import StratumServer


# Seconds between getblocktemplate polls
JOB_REFRESH_INTERVAL = 5








############################################################
# job_refresh_loop
############################################################
#
# Polls the node forever. create_job() itself decides whether
# the template contains new work, so calling it every few
# seconds is cheap — no new job is cut (and no broadcast is
# sent) unless the chain tip actually moved.
#
# Used by:
#   - runner.py — run()
############################################################

async def job_refresh_loop(server: StratumServer):
    while True:
        await asyncio.sleep(JOB_REFRESH_INTERVAL)
        await server.create_job()








############################################################
# longpoll_loop
############################################################
#
# Instant new-block detection. Every block template carries a
# "longpollid"; sending it back in another getblocktemplate
# call makes the node HOLD that request open and only answer
# once the chain tip moves. The moment it answers we cut a
# new job, so miners stop hashing stale work within
# milliseconds of a new block instead of waiting for the
# next 5-second poll.
#
# IMPORTANT: the longpoll call uses timeout=None on purpose.
# Bitcoin Core-style nodes never notice a client that gives
# up on a longpoll — the abandoned request keeps occupying
# one of the node's few RPC worker threads forever. A client
# -side timeout therefore leaks one node thread per recycle
# until the whole RPC work queue is saturated ("work queue
# depth exceeded"). Letting the request hang indefinitely
# means exactly ONE node thread is ever held by longpoll.
#
# Any error (node restart, dropped connection, no job yet)
# just waits a poll interval and retries — the
# job_refresh_loop keeps the pool alive regardless.
#
# Used by:
#   - runner.py — run()
############################################################

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
                coins.active().gbt_request(longpollid=longpollid),
                timeout=None,
            )
        except Exception:
            # Node hiccup or dropped connection — just re-arm
            await asyncio.sleep(JOB_REFRESH_INTERVAL)
            continue

        # The node answered: the tip (probably) moved.
        # create_job() re-checks and dedupes false alarms.
        await server.create_job()








############################################################
# run
############################################################
#
# Boot sequence: create the server (prints the startup
# banner) -> cut the initial job -> open the stratum port ->
# run listener, refresh loop and longpoll loop concurrently.
#
# Used by:
#   - main.py — via families.active().run()
############################################################

async def run():
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
