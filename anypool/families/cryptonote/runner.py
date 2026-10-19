############################################################
#  [*] CryptoNote Family — Runner
#
#  The event loops of a CryptoNote pool:
#
#    - the TCP listener accepting miner connections on
#      STRATUM_PORT (handled by connection.handle_client)
#    - the tip poll loop hitting the daemon's cheap
#      /getheight endpoint every couple of seconds — 0.11-era
#      CryptoNote daemons have NO longpoll, so this is how a
#      new chain tip is noticed (a found block also triggers
#      an immediate refresh from the submission path)
#    - the template refresh loop re-fetching the template
#      periodically even without a tip change, so newly
#      arrived mempool transactions get mined
#
#  Used by:
#    - main.py — main() runs this module's run() once
#      families.active() has picked the CryptoNote family
############################################################


import asyncio

from anypool import config
from anypool.families.cryptonote.connection import handle_client
from anypool.families.cryptonote.server import CnStratumServer


# Seconds between /getheight tip polls. The call costs the
# daemon nearly nothing, so polling this often is free and
# keeps the window in which miners hash on a stale tip down
# to a couple of seconds.
TIP_POLL_INTERVAL = 2

# Seconds between forced template refreshes (picks up new
# mempool transactions when the tip has not moved).
TEMPLATE_REFRESH_INTERVAL = 120








############################################################
# tip_poll_loop
############################################################
#
# Notices chain tip movement: when /getheight disagrees with
# the height the current template mines at, cut a fresh job.
# Errors just wait an interval and retry — the pool stays up
# through node restarts. A reorg that swaps the tip block
# without changing the height is invisible to this check;
# template_refresh_loop() picks it up on its next round.
#
# Used by:
#   - runner.py — run()
############################################################

async def tip_poll_loop(server: CnStratumServer):
    while True:
        await asyncio.sleep(TIP_POLL_INTERVAL)
        try:
            info = await server.rpc.plain("/getheight")
            node_height = info.get("height")
            template = server.job_manager.template
            # Both are "the height of the NEXT block": /getheight
            # returns the block count and the template's height is
            # the index being mined, which equals it — so any
            # disagreement means the tip moved under us.
            if node_height and (template is None or node_height != template["height"]):
                await server.create_job()
        except Exception as e:
            print(f"[POLL] Tip poll failed: {e}")








############################################################
# template_refresh_loop
############################################################
#
# Slow safety net: even on an unchanged tip, re-fetch the
# template and push fresh personalized jobs so waiting
# mempool transactions (and a current timestamp) make it
# into mined blocks.
#
# Used by:
#   - runner.py — run()
############################################################

async def template_refresh_loop(server: CnStratumServer):
    while True:
        await asyncio.sleep(TEMPLATE_REFRESH_INTERVAL)
        await server.create_job(force_broadcast=True)








############################################################
# run
############################################################
#
# Boot sequence: create the server (which prints the
# startup banner), fetch the initial template, open the
# stratum port, then run the listener and both poll loops
# concurrently until the process stops — closing the
# daemon session on the way out. A failed first fetch is
# not fatal: the poll loops and the first login retry it.
#
# Used by:
#   - main.py — main(), once families.active() has picked
#     this family
############################################################

async def run():
    server = CnStratumServer()

    # Fetch the initial template so the first miner to connect
    # receives work immediately
    await server.create_job()

    stratum_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, server),
        "0.0.0.0",
        config.STRATUM_PORT
    )

    print(f"[SERVER] Ready for connections on port {config.STRATUM_PORT}")

    try:
        await asyncio.gather(
            stratum_server.serve_forever(),
            tip_poll_loop(server),
            template_refresh_loop(server),
        )
    finally:
        await server.rpc.close()
