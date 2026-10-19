############################################################
#  [*] Tests — Share-to-Block Submission Flow
#
#  Covers families/bitcoin/server.py around a found block —
#  the guarantees that keep ASICs fed when blocks fall
#  quickly:
#
#    - process_share() must answer the miner WITHOUT waiting
#      for the node's submitblock round-trip
#    - a sibling block (same job solved twice before the
#      clean-jobs notify reached the miner) must NOT be
#      submitted — it can only come back "inconclusive"
#    - a failed submission must free the parent for a retry
#    - an accepted block must cut the follow-up job
#      immediately instead of waiting for the longpoll
#
#  The winning share is the real KNF block 1777 vector, so
#  the block handed to the fake node is asserted against the
#  byte-exact serialization the network accepted (less the
#  lone MWEB marker byte the pool used to append to it).
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
#    - tests/test_job_freshness.py, test_mweb.py,
#      test_mweb_activation.py — import FakeNodeRPC and the
#      helpers below
############################################################


import asyncio
import unittest

from anypool.families.bitcoin.jobs import build_job, stratum_prevhash
from anypool.families.bitcoin.server import MAX_SUBMITTED_PARENTS, StratumServer
from tests import vectors








############################################################
# FakeNodeRPC
############################################################
#
# Stands in for node/rpc.py's NodeRPC. Records every call
# (and the wallet it was routed to), answers getblocktemplate
# from `template`, submitblock from the `submit_results` queue
# (empty queue means None — block accepted) and any other
# method from its entry in `answers`. Setting `gate` makes
# submitblock hang until the event fires, simulating a node
# that is busy connecting the previous block.
#
# Used by:
#   - make_server() (below), and through it every test case
#     here and in tests/test_job_freshness.py
#   - tests/test_mweb.py — stalled_node() and the MwebWatch
#     test cases; SlowWallet subclasses it
#   - tests/test_mweb_activation.py — stalled_server()
############################################################

class FakeNodeRPC:






    ############################################################
    # __init__
    ############################################################
    #
    # Starts with no template, no queued verdicts, no gate and
    # no answers for any other call.
    #
    # Used by:
    #   - make_server() (below)
    #   - tests/test_mweb.py — stalled_node(), the MwebWatch
    #     test cases, and SlowWallet.__init__() through super()
    #   - tests/test_mweb_activation.py — stalled_server()
    ############################################################

    def __init__(self):
        self.calls = []
        self.wallets = []
        self.template = None
        self.submit_results = []
        self.gate = None
        self.answers = {}






    ############################################################
    # call
    ############################################################
    #
    # The NodeRPC.call() signature, answered from the fields:
    # submitblock waits on `gate` (when set) then pops a
    # queued verdict; getblocktemplate answers `template`, any
    # other method its entry in `answers`. An answer that is
    # an exception is raised; one that is callable is called
    # with the call's parameters first — how a test lets a
    # peg-in change the template the node serves next.
    #
    # Used by:
    #   - the code under test, wherever it holds this fake as
    #     its node: StratumServer._fetch_template() and
    #     _submit_block() (families/bitcoin/server.py),
    #     MwebWatch.observe(), MwebWatch.diagnose() and
    #     send_pegin() (families/bitcoin/mweb.py)
    #   - tests/test_mweb.py — SlowWallet.call() hands every
    #     call on to it
    ############################################################

    async def call(self, method, params=None, timeout=10.0, wallet=None):
        self.calls.append((method, params))
        self.wallets.append((method, wallet))
        if method == "submitblock":
            if self.gate is not None:
                await self.gate.wait()
            return self.submit_results.pop(0) if self.submit_results else None

        answer = self.template if method == "getblocktemplate" else self.answers.get(method)
        if callable(answer):
            answer = answer(params)
        if isinstance(answer, BaseException):
            raise answer
        return answer






    ############################################################
    # calls_to
    ############################################################
    #
    # The parameters of every call to one method, in order.
    #
    # Used by:
    #   - tests/test_mweb.py, test_mweb_activation.py — their
    #     assertions on the node traffic a stall, a peg-in or a
    #     submission caused (nothing in this file calls it)
    ############################################################

    def calls_to(self, method):
        return [params for (name, params) in self.calls if name == method]






    ############################################################
    # submitted_blocks
    ############################################################
    #
    # Every block hex handed to submitblock, in call order.
    #
    # Used by:
    #   - TestBackgroundBlockSubmission, TestSiblingBlockGuard
    #     (below)
    #   - tests/test_job_freshness.py — TestBlockBelowShareTarget
    ############################################################

    def submitted_blocks(self):
        return [params[0] for (method, params) in self.calls if method == "submitblock"]








############################################################
# make_server
############################################################
#
# A StratumServer with its node RPC swapped for a FakeNodeRPC
# and the block 1777 job stored — difficulty state snapshotted
# into the job exactly the way create_job() does it.
#
# Used by:
#   - every test case below
#   - tests/test_job_freshness.py — make_freshness_server()
#     and TestBlockBelowShareTarget
############################################################

def make_server():
    server = StratumServer()
    server.rpc = FakeNodeRPC()

    job = build_job(vectors.TEMPLATE, server.job_manager.next_job_id())
    job["pool_difficulty"] = vectors.POOL_DIFFICULTY
    job["pool_target"] = vectors.POOL_TARGET
    job["network_difficulty"] = server.calculate_mining_difficulty(vectors.NETWORK_TARGET)
    job["network_target"] = vectors.NETWORK_TARGET
    server.job_manager.store(job)

    return server, job








############################################################
# submit_share
############################################################
#
# One process_share() call for the stored job. Defaults to
# the real winning nonce of block 1777; pass another nonce to
# submit a different (sibling) solve of the same job.
#
# Used by:
#   - every test case below but
#     test_submitted_parents_are_pruned, which starts its
#     submissions directly
#   - tests/test_job_freshness.py — TestBlockBelowShareTarget
############################################################

async def submit_share(server, job, nonce=vectors.SHARE_NONCE):
    return await server.process_share(
        "tester.worker1", job["job_id"], vectors.EXTRANONCE1,
        vectors.EXTRANONCE2, vectors.SHARE_NTIME, nonce
    )








############################################################
# drain
############################################################
#
# Awaits every background task the server has in flight (a
# task may spawn follow-up tasks, hence the loop). Bounded so
# a regression can fail the test instead of hanging the run.
#
# Used by:
#   - every test case below that starts a submission
#   - tests/test_job_freshness.py — the two broadcast test
#     cases and TestBlockBelowShareTarget
#   - tests/test_mweb_activation.py — create_job_printing()
#     and test_first_mweb_share_submits_the_accepted_block
############################################################

async def drain(server):
    async def _all():
        while server.background_tasks:
            await asyncio.gather(*list(server.background_tasks))
    await asyncio.wait_for(_all(), timeout=5.0)








############################################################
# moved_tip_template
############################################################
#
# The template the node would report AFTER our block 1777 got
# accepted: one height up, previous hash pointing at some new
# tip. What create_job() should turn into the follow-up job.
#
# Used by:
#   - test_accepted_block_cuts_new_job_immediately,
#     test_sibling_block_is_not_submitted and
#     test_failed_submission_allows_retry_on_parent (below)
#   - tests/test_job_freshness.py —
#     test_new_tip_broadcast_cleans_jobs and
#     TestBlockBelowShareTarget
############################################################

def moved_tip_template(new_tip_hash):
    template = dict(vectors.TEMPLATE)
    template["previousblockhash"] = new_tip_hash
    template["height"] = vectors.TEMPLATE["height"] + 1
    return template








############################################################
# TestBackgroundBlockSubmission
############################################################
#
# Block submission run beside the miner's conversation, not
# inside it: what the miner hears back while the node is
# still busy, what the node finally receives, and what the
# pool does once the node has accepted the block.
############################################################

class TestBackgroundBlockSubmission(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_share_response_does_not_wait_for_node
    ############################################################
    #
    # The ASIC-stall guarantee: the mining.submit verdict must
    # come back even while the node has not yet answered
    # submitblock. The fake node hangs on `gate`, so any
    # implementation that awaits the submission inline times
    # this test out.
    ############################################################

    async def test_share_response_does_not_wait_for_node(self):
        server, job = make_server()
        server.rpc.gate = asyncio.Event()      # node "busy": submitblock hangs

        accepted, error = await asyncio.wait_for(
            submit_share(server, job), timeout=2.0
        )

        self.assertTrue(accepted)
        self.assertIsNone(error)
        self.assertEqual(server.blocks_found, 0)             # submission still in flight
        self.assertEqual(len(server.background_tasks), 1)

        server.rpc.gate.set()                  # node finally answers: accepted
        await drain(server)

        self.assertEqual(server.blocks_found, 1)






    ############################################################
    # test_submitted_block_is_byte_exact
    ############################################################
    #
    # The background submission must hand the node block 1777
    # as the network accepted it: header, transaction count
    # and full coinbase — without the lone MWEB marker byte
    # the pool used to append, which a pre-MWEB block never
    # carries.
    ############################################################

    async def test_submitted_block_is_byte_exact(self):
        server, job = make_server()

        accepted, _ = await submit_share(server, job)
        await drain(server)

        expected_coinbase = (job["coinb1_full"] + vectors.EXTRANONCE1 +
                             vectors.EXTRANONCE2 + job["coinb2_full"])
        expected_block = vectors.HEADER_HEX + "01" + expected_coinbase

        self.assertTrue(accepted)
        self.assertEqual(server.rpc.submitted_blocks(), [expected_block])
        self.assertEqual(server.blocks_found, 1)






    ############################################################
    # test_plain_share_is_not_submitted
    ############################################################
    #
    # A hash that meets the pool target but not the network
    # target is just a share — no submission task, no node
    # traffic.
    ############################################################

    async def test_plain_share_is_not_submitted(self):
        server, job = make_server()
        job["pool_target"] = 2 ** 256 - 1      # anything is a share...
        job["network_target"] = 0              # ...nothing is a block

        accepted, error = await submit_share(server, job, nonce="00000001")

        self.assertTrue(accepted)
        self.assertIsNone(error)
        self.assertEqual(server.rpc.calls, [])
        self.assertEqual(len(server.background_tasks), 0)
        self.assertEqual(server.submitted_parents, {})






    ############################################################
    # test_accepted_block_cuts_new_job_immediately
    ############################################################
    #
    # After the node accepts our block, the follow-up job must
    # be cut right away (submitblock returns only once the tip
    # moved) — not seconds later when a poll comes around. The
    # new tip then has the MWEB watch read the deployment
    # state, in the background and after the job is cut.
    ############################################################

    async def test_accepted_block_cuts_new_job_immediately(self):
        server, job = make_server()
        new_tip = "5c" * 32
        server.rpc.template = moved_tip_template(new_tip)

        await submit_share(server, job)
        await drain(server)

        self.assertEqual([method for method, _ in server.rpc.calls],
                         ["submitblock", "getblocktemplate", "getblockchaininfo"])

        new_job = server.job_manager.current_job
        self.assertNotEqual(new_job["job_id"], job["job_id"])
        self.assertEqual(new_job["prevhash"], stratum_prevhash(new_tip))
        self.assertEqual(new_job["height"], job["height"] + 1)








############################################################
# TestSiblingBlockGuard
############################################################
#
# The one-submission-per-parent guard in
# _start_block_submission(), which keeps a second solve of
# an already submitted parent away from a node still busy
# with the first — when it holds, when it lets go again,
# and how much it remembers.
############################################################

class TestSiblingBlockGuard(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_sibling_block_is_not_submitted
    ############################################################
    #
    # The "inconclusive" scenario: the miner solves the SAME job
    # twice before the clean-jobs notify reaches it. The first
    # solve is submitted; the sibling must be accepted as a
    # share but never reach the node — even while the first
    # submission is still in flight.
    ############################################################

    async def test_sibling_block_is_not_submitted(self):
        server, job = make_server()
        job["pool_target"] = 2 ** 256 - 1      # every share solves a block
        job["network_target"] = 2 ** 256 - 1
        server.rpc.gate = asyncio.Event()      # hold the first submission open
        server.rpc.template = moved_tip_template("5c" * 32)

        accepted_1, error_1 = await submit_share(server, job, nonce="00000001")
        accepted_2, error_2 = await submit_share(server, job, nonce="00000002")

        self.assertTrue(accepted_1)
        self.assertTrue(accepted_2)            # sibling still counts for the miner
        self.assertIsNone(error_1)
        self.assertIsNone(error_2)
        self.assertEqual(len(server.background_tasks), 1)    # only ONE submission launched
        self.assertIn(job["prevhash"], server.submitted_parents)

        server.rpc.gate.set()
        await drain(server)

        self.assertEqual(len(server.rpc.submitted_blocks()), 1)
        self.assertEqual(server.blocks_found, 1)
        self.assertEqual(server.shares_accepted, 2)






    ############################################################
    # test_failed_submission_allows_retry_on_parent
    ############################################################
    #
    # A submission the node rejects must unmark the parent, so
    # a later solve on that parent gets its own attempt.
    ############################################################

    async def test_failed_submission_allows_retry_on_parent(self):
        server, job = make_server()
        job["pool_target"] = 2 ** 256 - 1
        job["network_target"] = 2 ** 256 - 1
        server.rpc.template = moved_tip_template("5c" * 32)
        server.rpc.submit_results = ["inconclusive"]     # first attempt bounces

        await submit_share(server, job, nonce="00000001")
        await drain(server)

        self.assertEqual(len(server.rpc.submitted_blocks()), 1)
        self.assertEqual(server.blocks_found, 0)
        self.assertNotIn(job["prevhash"], server.submitted_parents)  # freed for retry

        await submit_share(server, job, nonce="00000002")            # queue empty: accepted
        await drain(server)

        self.assertEqual(len(server.rpc.submitted_blocks()), 2)
        self.assertEqual(server.blocks_found, 1)






    ############################################################
    # test_submitted_parents_are_pruned
    ############################################################
    #
    # The guard's memory must stay bounded and forget the
    # OLDEST parents first — same pruning contract as the
    # JobManager's job store.
    ############################################################

    async def test_submitted_parents_are_pruned(self):
        server, job = make_server()
        server.rpc.gate = asyncio.Event()      # hold every submission in flight
        total = MAX_SUBMITTED_PARENTS + 10

        for i in range(total):
            fork_job = dict(job)
            fork_job["prevhash"] = f"{i:064x}"
            self.assertTrue(server._start_block_submission(
                fork_job, vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.HEADER_HEX
            ))

        self.assertEqual(len(server.submitted_parents), MAX_SUBMITTED_PARENTS)
        self.assertNotIn(f"{0:064x}", server.submitted_parents)          # oldest: pruned
        self.assertIn(f"{total - 1:064x}", server.submitted_parents)     # newest: kept

        # Let the held submissions finish so no task outlives the test
        server.rpc.submit_results = ["inconclusive"] * total
        server.rpc.gate.set()
        await drain(server)








if __name__ == "__main__":
    unittest.main()
