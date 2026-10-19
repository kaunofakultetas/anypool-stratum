#!/usr/bin/env python3
############################################################
#  [*] Integration — MWEB Activation on a Regtest Node
#
#  Proves the pool's MWEB handling end to end against a LIVE
#  Litecoin-family node on regtest. The pool's own
#  StratumServer mines a block before MWEB, runs into the
#  first MWEB block's stall (the node refuses every template
#  until a peg-in waits in its mempool), lets its MWEB watch
#  peg in from the node's wallet, and mines the first MWEB
#  blocks — each one built from a share the pool validated,
#  submitted the way the pool submits blocks, and accepted by
#  the node. The activation height is read from the node,
#  never assumed, so the same run proves whatever height the
#  node activates MWEB at: regtest's default, or one moved
#  with the node's -vbparams option.
#
#  It needs a fresh regtest chain (MWEB not active yet) on a
#  node with wallet support, reached through the RPC_*
#  settings, and refuses any chain but regtest — it mines.
#  Run it inside the stratum image, from the repo root (the
#  image's working directory), as a module of the tests
#  package: importing the package first runs
#  tests/__init__.py, which pins the KNF pool settings the
#  unit tests use.
#
#  The exit code is 0 once the stall was recognized, the
#  peg-in sent and the first MWEB blocks accepted, 2 when the
#  chain is not a fresh regtest chain, and anything else on
#  a failure.
#
#  Used by:
#    - manual integration runs against a regtest node;
#      unittest discovery never picks it up (its name does
#      not start with test)
############################################################


import asyncio
import dataclasses
import os
import sys

from anypool import coins, config
from anypool.coins.base import MwebPegin
from anypool.families.bitcoin.mweb import deployment_state
from anypool.families.bitcoin.server import StratumServer
from anypool.families.bitcoin.shares import build_header


# The wallet the run creates on the node to fund the peg-in
WALLET = "anypool-mweb-integration"

# The share every block is solved with — printable extranonce2
# bytes, as on the live chain, which the MWEB section must
# survive
EXTRANONCE1 = "00000001"
EXTRANONCE2 = "6c390000"

# Blocks the node's own miner pays the wallet before the pool
# mines: one more than coinbase maturity, so the peg-in has
# coins to spend
FUNDING_BLOCKS = 101








############################################################
# drain
############################################################
#
# Awaits every background task the server has in flight —
# the block submission a winning share launches, and the
# follow-up job and deployment read it starts in turn.
# Bounded, so a node that never answers fails the run
# instead of hanging it.
#
# Used by:
#   - mine_with_pool() (below)
############################################################

async def drain(server):
    async def _all():
        while server.background_tasks:
            await asyncio.gather(*list(server.background_tasks))
    await asyncio.wait_for(_all(), timeout=60.0)








############################################################
# mine_with_pool
############################################################
#
# One block through the pool's own paths: create_job() cuts
# (or keeps) the job, a nonce is ground until the header
# meets the job's network target, process_share() judges the
# share and submits the block in the background. Returns the
# job and the node's answer for its new tip — or no job when
# create_job() handed out none (the stall).
#
# Used by:
#   - main() (below)
############################################################

async def mine_with_pool(server):
    job = await server.create_job()
    if job is None:
        return None, None

    for value in range(1 << 32):
        nonce = f"{value:08x}"
        pow_hash, _, _ = build_header(job, EXTRANONCE1, EXTRANONCE2, job["ntime"], nonce)
        if int(pow_hash, 16) <= job["network_target"]:
            break

    accepted, error = await server.process_share("integration.worker", job["job_id"], EXTRANONCE1,
                                                 EXTRANONCE2, job["ntime"], nonce)
    if not accepted:
        raise AssertionError(f"the pool rejected its own share: {error}")
    await drain(server)

    tip = await server.rpc.call("getblock", [await server.rpc.call("getbestblockhash"), 1])
    return job, tip








############################################################
# use_pegin
############################################################
#
# Gives the active coin's definition the MWEB peg-in settings
# a step needs — the run's stand-in for an operator setting
# MWEB_PEGIN_* before starting the pool.
#
# Used by:
#   - main() (below)
############################################################

def use_pegin(settings):
    coins.REGISTRY[config.COIN] = dataclasses.replace(coins.active(), mweb_pegin=settings)








############################################################
# node_info
############################################################
#
# The node's getblockchaininfo, waiting up to a minute for a
# node that is still starting — refusing connections, or
# answering that it is warming up — so the run can begin
# right after the node container.
#
# Used by:
#   - main() (below)
############################################################

async def node_info(rpc):
    for _ in range(60):
        try:
            return await rpc.call("getblockchaininfo")
        except Exception:
            await asyncio.sleep(1)
    return await rpc.call("getblockchaininfo")








############################################################
# expect
############################################################
#
# One check of the run: prints it as passed, or raises with
# what went wrong.
#
# Used by:
#   - main() (below)
############################################################

def expect(condition, what):
    if not condition:
        raise AssertionError(what)
    print(f"[MWEB-IT] ✅ {what}")








############################################################
# main
############################################################
#
# The whole scenario in one pass — see the file header.
# Returns the process exit code.
#
# Used by:
#   - the __main__ guard below
############################################################

async def main():
    server = StratumServer()
    rpc = server.rpc
    try:
        # STEP 1: a fresh regtest chain that knows MWEB, not active yet
        # =============================================================
        chain = await node_info(rpc)
        state = deployment_state(chain)
        if chain.get("chain") != "regtest" or state is None or state["active"]:
            print(f"[MWEB-IT] needs a fresh regtest chain with MWEB not yet active "
                  f"(chain {chain.get('chain')}, mweb {state})")
            return 2
        print(f"[MWEB-IT] regtest at height {chain['blocks']}, MWEB {state['status']}")


        # STEP 2: a wallet with mature coins for the peg-in
        # =================================================
        await rpc.call("createwallet", [WALLET])
        funding = await rpc.call("getnewaddress", [], wallet=WALLET)
        await rpc.call("generatetoaddress", [FUNDING_BLOCKS, funding])


        # STEP 3: a block before MWEB, mined through the pool
        # ===================================================
        job, tip = await mine_with_pool(server)
        expect(tip["height"] == job["height"], f"block {job['height']} before MWEB accepted")
        expect("mweb" not in tip, f"block {job['height']} carries no MWEB section")


        # STEP 4: the node's own miner up to the block before
        # the first MWEB block, wherever this node puts it
        # ===================================================
        while not deployment_state(await rpc.call("getblockchaininfo"))["active"]:
            await rpc.call("generatetoaddress", [1, funding])
        chain = await rpc.call("getblockchaininfo")
        first_mweb_height = chain["blocks"] + 1
        print(f"[MWEB-IT] MWEB applies from height {first_mweb_height}")


        # STEP 5: without a peg-in configured the pool hands out
        # no work, and the node's tip stays where it is
        # ======================================================
        use_pegin(MwebPegin())
        job, _ = await mine_with_pool(server)
        expect(job is None, f"no job while block {first_mweb_height} waits for a peg-in")
        expect((await rpc.call("getblockchaininfo"))["blocks"] == first_mweb_height - 1,
               "the chain is stuck in front of the first MWEB block")


        # STEP 6: with a peg-in amount in the coin's settings the
        # pool pegs in itself and mines the first MWEB block
        # =======================================================
        use_pegin(MwebPegin("1", WALLET, os.getenv("MWEB_PEGIN_FEE_RATE", "10")))
        job, tip = await mine_with_pool(server)
        expect(job is not None and job["height"] == first_mweb_height,
               f"the pool pegged in and cut the job for block {first_mweb_height}")
        expect(tip["height"] == first_mweb_height and "mweb" in tip,
               f"first MWEB block {first_mweb_height} accepted, with its MWEB section")
        expect(len(tip["tx"]) == 3, "it carries coinbase, peg-in and HogEx")


        # STEP 7: the next MWEB blocks need no peg-in — each
        # HogEx spends the previous one
        # ==================================================
        for _ in range(2):
            job, tip = await mine_with_pool(server)
            expect(tip["height"] == job["height"] and "mweb" in tip and len(tip["tx"]) == 2,
                   f"MWEB block {job['height']} accepted (coinbase + HogEx)")

        expect(server.blocks_found == 4, "every block the pool solved was accepted")
        print(f"[MWEB-IT] integration test PASSED (MWEB activated at height {first_mweb_height})")
        return 0

    except Exception as failure:
        print(f"[MWEB-IT] ❌ FAIL: {failure}")
        return 1

    finally:
        await rpc.close()








if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
