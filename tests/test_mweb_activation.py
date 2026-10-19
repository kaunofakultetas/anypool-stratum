############################################################
#  [*] Tests — MWEB Activation through the Stratum Server
#
#  The server's side of a chain's first MWEB block, replayed
#  with the real node answers in tests/mweb_vectors.py:
#
#    - while the node refuses the template in front of the
#      first MWEB block, create_job() hands out nothing and
#      the log explains the stall once — no error line on
#      every poll
#    - with MWEB_PEGIN_AMOUNT set the server pegs in through
#      its MWEB watch and cuts the job from the template the
#      node serves next: peg-in, HogEx and MWEB data
#    - the share that solved the real first MWEB block is
#      submitted as exactly the block the node accepted
#    - any other template failure is still reported as an
#      error, and a coin without MWEB never consults a watch
#    - a new tip has the watch read the deployment state,
#      announced only when it changed
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import contextlib
import io
import unittest
from unittest import mock

from anypool.families.bitcoin.server import StratumServer
from anypool.node.rpc import NodeRPCError
from tests import mweb_vectors as mv
from tests.test_mweb import MWEB_ADDRESS, STALL_TITLE, chain_info, pegin_settings
from tests.test_server import FakeNodeRPC, drain


# The share that solved the real first MWEB block
FIRST_SHARE = {key: mv.FIRST_MWEB_BLOCK[key] for key in ("extranonce1", "extranonce2", "ntime", "nonce")}








############################################################
# stalled_server
############################################################
#
# A StratumServer (its startup output swallowed) on a
# FakeNodeRPC standing where the regtest node stood in front
# of its first MWEB block: every template refused with the
# node's real refusal, MWEB bound from the next block, the
# tip without an MWEB section. A peg-in is answered with the
# real peg-in's txid and — as on the real node — turns the
# template the node serves into the first MWEB block's.
#
# Used by:
#   - every test case below, in TestFirstMwebBlockStall and
#     TestDeploymentAnnouncements
############################################################

def stalled_server():
    with contextlib.redirect_stdout(io.StringIO()):
        server = StratumServer()
    node = FakeNodeRPC()
    tip = mv.TIP_BEFORE_FIRST_MWEB_BLOCK

    node.template = NodeRPCError(mv.STALL_ERROR)
    node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_ACTIVE_FIRST_BLOCK_PENDING, tip["height"], tip["hash"])
    node.answers["getblock"] = dict(tip)
    node.answers["getnewaddress"] = MWEB_ADDRESS

    def pegin(params):
        node.template = mv.FIRST_MWEB_BLOCK["template"]
        return mv.PEGIN_TXID

    node.answers["sendtoaddress"] = pegin
    server.rpc = node
    return server, node








############################################################
# create_job_printing
############################################################
#
# One create_job() call (plus the background work it starts)
# with stdout captured; hands back the job and what it
# printed.
#
# Used by:
#   - TestFirstMwebBlockStall (below) — all but the block
#     submission test, which drives create_job() itself to
#     slip a share in before the drain
#   - TestDeploymentAnnouncements (below)
############################################################

async def create_job_printing(server):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        job = await server.create_job()
        await drain(server)
    return job, out.getvalue()








############################################################
# TestFirstMwebBlockStall
############################################################
#
# The server at the chain's first MWEB block, on a fake node
# that refuses every template the way the real one did:
# quiet while the stall lasts, unstuck by the configured
# peg-in, the first MWEB block then submitted exactly as the
# node accepted it — while any other template failure stays
# a plain error.
############################################################

class TestFirstMwebBlockStall(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_stall_hands_out_nothing_and_explains_once
    ############################################################
    #
    # No peg-in configured: every poll comes back empty, the
    # stall is explained once, and no "Failed to create job"
    # error repeats on each poll.
    ############################################################

    async def test_stall_hands_out_nothing_and_explains_once(self):
        server, node = stalled_server()

        output = ""
        with pegin_settings(amount="", wallet=None, fee_rate=""):
            for _ in range(3):
                job, printed = await create_job_printing(server)
                self.assertIsNone(job)
                output += printed

        self.assertIsNone(server.job_manager.current_job)
        self.assertEqual(output.count(STALL_TITLE), 1)
        self.assertNotIn("Failed to create job", output)
        self.assertEqual(node.calls_to("sendtoaddress"), [])






    ############################################################
    # test_peg_in_cuts_the_first_mweb_job
    ############################################################
    #
    # With MWEB_PEGIN_AMOUNT set the first poll pegs in and the
    # job comes from the template the node serves then: block
    # 432 with the peg-in and the HogEx — the peg-in's txid
    # the first step of the coinbase's merkle branch, the
    # three transactions making it two steps long. The calls
    # run in the recovery's order: the refused template, the
    # watch's two reads, the two wallet calls of the peg-in,
    # then the template again.
    ############################################################

    async def test_peg_in_cuts_the_first_mweb_job(self):
        server, node = stalled_server()

        with pegin_settings():
            job, output = await create_job_printing(server)

        template = mv.FIRST_MWEB_BLOCK["template"]
        self.assertIs(job["template"], template)
        self.assertEqual(job["height"], 432)
        self.assertEqual(job["merkle_branch"][0], bytes.fromhex(mv.PEGIN_TXID)[::-1].hex())
        self.assertEqual(len(job["merkle_branch"]), 2)
        self.assertEqual([method for method, _ in node.calls][:6], [
            "getblocktemplate", "getblockchaininfo", "getblock",
            "getnewaddress", "sendtoaddress", "getblocktemplate",
        ])
        self.assertIn("MWEB peg-in sent", output)






    ############################################################
    # test_first_mweb_share_submits_the_accepted_block
    ############################################################
    #
    # The share that solved the real first MWEB block becomes,
    # in the background, exactly the block the node accepted —
    # peg-in, HogEx and MWEB section included.
    ############################################################

    async def test_first_mweb_share_submits_the_accepted_block(self):
        server, node = stalled_server()

        with pegin_settings(), contextlib.redirect_stdout(io.StringIO()):
            job = await server.create_job()
            accepted, error = await server.process_share(
                "tester.worker1", job["job_id"], FIRST_SHARE["extranonce1"],
                FIRST_SHARE["extranonce2"], FIRST_SHARE["ntime"], FIRST_SHARE["nonce"],
            )
            await drain(server)

        self.assertTrue(accepted)
        self.assertIsNone(error)
        self.assertEqual(node.calls_to("submitblock"), [[mv.FIRST_MWEB_BLOCK["block_hex"]]])
        self.assertEqual(server.blocks_found, 1)






    ############################################################
    # test_other_template_failures_stay_errors
    ############################################################
    #
    # A template failure that is not the stall — here a node
    # still in its initial sync, with MWEB only locked in — is
    # still an error line, and no peg-in is tried.
    ############################################################

    async def test_other_template_failures_stay_errors(self):
        server, node = stalled_server()
        node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_LOCKED_IN, 301)
        node.template = NodeRPCError({"code": -10, "message": "KnfCoin is in initial sync and waiting for blocks..."})

        with pegin_settings():
            job, output = await create_job_printing(server)

        self.assertIsNone(job)
        self.assertIn("Failed to create job", output)
        self.assertNotIn(STALL_TITLE, output)
        self.assertEqual(node.calls_to("sendtoaddress"), [])






    ############################################################
    # test_coin_without_mweb_has_no_watch
    ############################################################
    #
    # A coin without MWEB has no watch: a refused template is
    # an error straight away, without asking the node about
    # deployments.
    ############################################################

    async def test_coin_without_mweb_has_no_watch(self):
        with mock.patch("anypool.config.COIN", "BTC"):
            server, node = stalled_server()
            job, output = await create_job_printing(server)

        self.assertIsNone(server.mweb)
        self.assertIsNone(job)
        self.assertIn("Failed to create job", output)
        self.assertEqual([method for method, _ in node.calls], ["getblocktemplate"])








############################################################
# TestDeploymentAnnouncements
############################################################
#
# The deployment report riding along with new tips: the
# server has its MWEB watch read the state after each one,
# in the background, and the log hears only of changes.
############################################################

class TestDeploymentAnnouncements(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_new_tips_announce_changes_only
    ############################################################
    #
    # Each new tip has the watch read the deployment state in
    # the background; it is announced on the first tip and
    # again only when it changes.
    ############################################################

    async def test_new_tips_announce_changes_only(self):
        server, node = stalled_server()
        node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_STARTED, 200)
        node.template = mv.PRE_MWEB_BLOCK["template"]

        job, first = await create_job_printing(server)

        moved = dict(mv.PRE_MWEB_BLOCK["template"], previousblockhash="5c" * 32, height=202)
        node.template = moved
        _, second = await create_job_printing(server)

        node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_LOCKED_IN, 301)
        node.template = dict(moved, previousblockhash="5d" * 32, height=302)
        _, third = await create_job_printing(server)

        self.assertEqual(job["height"], 201)
        self.assertIn("MWEB deployment: started", first)
        self.assertNotIn("MWEB deployment", second)
        self.assertIn("MWEB deployment: locked_in", third)
        self.assertEqual(len(node.calls_to("getblockchaininfo")), 3)








if __name__ == "__main__":
    unittest.main()
