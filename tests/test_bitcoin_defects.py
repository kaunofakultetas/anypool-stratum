############################################################
#  [*] Pinned Defects — Bitcoin Family
#
#  Known bugs of the Bitcoin-family pool, each pinned as a
#  regression test that states the WANTED behaviour and fails
#  today. Every test is marked @unittest.expectedFailure, so
#  the suite stays green while the bug is on record. Once a
#  fix lands, unittest reports an "unexpected success", which
#  fails the run — the cue to drop the decorator and move the
#  test into its home file.
#
#    - the duplicate-share guard misses the same share in
#      another letter case, and the same share submitted
#      again under a re-issue of the same work
#    - a target easier than difficulty 1 (a regtest chain)
#      reads as difficulty 0, and with POLL_DIFF_DROPPER on
#      the job cannot even be cut
#    - a new target on the SAME tip is announced as a new
#      block
#    - heights 1 to 16 are pushed as a data byte where
#      Bitcoin Core's BIP34 check wants OP_1 to OP_16
#    - nothing refuses a coinbase over the 100-byte scriptSig
#      limit, so every block of such a pool is invalid
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import contextlib
import io
import unittest
from unittest import mock

from anypool import coins
from anypool.families.bitcoin.coinbase import bip34_height_push, build_coinbase_parts
from anypool.families.bitcoin.errors import ERROR_DUPLICATE_SHARE
from anypool.families.bitcoin.server import JOB_NTIME_REFRESH_SECONDS, StratumServer
from tests import mweb_vectors, vectors
from tests.test_job_freshness import make_freshness_server, same_tip_template
from tests.test_server import FakeNodeRPC, drain


# The winning share of KNF block 1777, as its miner sent it
SHARE = (vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.SHARE_NTIME, vectors.SHARE_NONCE)








############################################################
# quietly
############################################################
#
# Runs one coroutine with stdout captured, and hands back its
# result together with everything it printed.
#
# Used by:
#   - the test cases below
############################################################

async def quietly(coro):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = await coro
    return result, out.getvalue()








############################################################
# quietly_made
############################################################
#
# Builds a test server with the startup banner it prints
# captured, and hands back whatever the builder returns.
#
# Used by:
#   - the test cases below
############################################################

def quietly_made(builder):
    with contextlib.redirect_stdout(io.StringIO()):
        return builder()








############################################################
# share_only
############################################################
#
# Makes a stored job judge shares only: a network target of
# zero means no hash is a block, so no submission task runs
# alongside the duplicate checks.
#
# Used by:
#   - TestDuplicateShares (below)
############################################################

def share_only(job):
    job["network_target"] = 0
    return job








############################################################
# TestDuplicateShares
############################################################
#
# The duplicate-share guard must count one share once,
# however it is resubmitted.
############################################################

class TestDuplicateShares(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_a_share_resubmitted_in_another_letter_case_is_refused
    ############################################################
    #
    # Hex digits are case-blind: the same share in upper case
    # builds the same header and hash, and is a replay — the
    # guard keys on the strings as submitted and counts it
    # again.
    ############################################################

    @unittest.expectedFailure
    async def test_a_share_resubmitted_in_another_letter_case_is_refused(self):
        server, job = quietly_made(make_freshness_server)
        share_only(job)

        first, _ = await quietly(server.process_share("tester.worker1", job["job_id"], *SHARE))
        again, _ = await quietly(server.process_share("tester.worker1", job["job_id"],
                                                      *(part.upper() for part in SHARE)))

        self.assertEqual(first, (True, None))
        self.assertEqual(again, (False, ERROR_DUPLICATE_SHARE))






    ############################################################
    # test_one_share_counts_once_across_a_reissue_of_the_same_work
    ############################################################
    #
    # When the tip stays put, create_job() re-issues the same
    # work under a new job id with a fresh ntime. The share
    # hashes identically under both ids, so the second
    # submission is a replay — the guard's record is per job
    # and counts it again.
    ############################################################

    @unittest.expectedFailure
    async def test_one_share_counts_once_across_a_reissue_of_the_same_work(self):
        server, job = quietly_made(make_freshness_server)
        server.rpc.template = same_tip_template(JOB_NTIME_REFRESH_SECONDS)
        reissue, _ = await quietly(server.create_job())
        await drain(server)
        share_only(job)
        share_only(reissue)

        first, _ = await quietly(server.process_share("tester.worker1", job["job_id"], *SHARE))
        again, _ = await quietly(server.process_share("tester.worker1", reissue["job_id"], *SHARE))

        self.assertNotEqual(reissue["job_id"], job["job_id"])
        self.assertEqual(first, (True, None))
        self.assertEqual(again, (False, ERROR_DUPLICATE_SHARE))








############################################################
# TestDifficultyBelowOne
############################################################
#
# A chain whose target is easier than difficulty 1 — any
# regtest chain — must still give the pool a usable
# difficulty.
############################################################

class TestDifficultyBelowOne(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_a_target_easier_than_difficulty_one_reads_as_one
    ############################################################
    #
    # The real regtest target is easier than difficulty 1;
    # integer division makes it difficulty 0, a value no miner
    # can be given.
    ############################################################

    @unittest.expectedFailure
    async def test_a_target_easier_than_difficulty_one_reads_as_one(self):
        server = quietly_made(StratumServer)
        regtest_target = int(mweb_vectors.PRE_MWEB_BLOCK["template"]["target"], 16)

        self.assertGreater(regtest_target, coins.active().difficulty_1_target)
        self.assertGreaterEqual(server.calculate_mining_difficulty(regtest_target), 1)






    ############################################################
    # test_the_dropper_cuts_a_usable_job_on_a_regtest_chain
    ############################################################
    #
    # With POLL_DIFF_DROPPER on, that difficulty 0 becomes the
    # pool difficulty — and the job panel divides by it, so
    # create_job() fails and no job is cut at all.
    ############################################################

    @unittest.expectedFailure
    async def test_the_dropper_cuts_a_usable_job_on_a_regtest_chain(self):
        server = quietly_made(StratumServer)
        server.rpc = FakeNodeRPC()
        server.rpc.template = mweb_vectors.PRE_MWEB_BLOCK["template"]

        with mock.patch("anypool.config.POLL_DIFF_DROPPER", True):
            job, _ = await quietly(server.create_job())
            await drain(server)

        self.assertIsNotNone(job)
        self.assertGreaterEqual(job["pool_difficulty"], 1)








############################################################
# TestSameTipAnnouncements
############################################################
#
# The "New Block Detected" panel must mean a new block.
############################################################

class TestSameTipAnnouncements(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_a_new_target_on_the_same_tip_is_no_new_block
    ############################################################
    #
    # A target change on an unchanged tip (a testnet difficulty
    # flip) is new work, rightly cut as a new job — but no new
    # block, and the log must not announce one.
    ############################################################

    @unittest.expectedFailure
    async def test_a_new_target_on_the_same_tip_is_no_new_block(self):
        server, job = quietly_made(make_freshness_server)
        server.rpc.template = dict(vectors.TEMPLATE, target=f"{vectors.NETWORK_TARGET // 2:064x}")

        new_job, output = await quietly(server.create_job())
        await drain(server)

        self.assertEqual(new_job["prevhash"], job["prevhash"])
        self.assertNotEqual(new_job["job_id"], job["job_id"])
        self.assertNotIn("New Block Detected", output)








############################################################
# TestCoinbaseConsensusRules
############################################################
#
# The coinbase the pool builds must be one every node of the
# coin accepts, at every height and with every message.
############################################################

class TestCoinbaseConsensusRules(unittest.TestCase):






    ############################################################
    # test_heights_1_to_16_are_pushed_as_small_number_opcodes
    ############################################################
    #
    # Bitcoin Core's BIP34 check rebuilds the height the way
    # its scripts write small numbers: OP_1 to OP_16 for
    # heights 1 to 16. A one-byte data push of the same number
    # is refused there (bad-cb-height) on any chain enforcing
    # BIP34 from its first blocks. (KnfCoin's node accepts
    # both forms, which is why its block 1 carries the data
    # push; the fix changes the height-1 corner case in
    # tests/test_coinbase.py along with this pin.)
    ############################################################

    @unittest.expectedFailure
    def test_heights_1_to_16_are_pushed_as_small_number_opcodes(self):
        for height in range(1, 17):
            with self.subTest(height=height):
                self.assertEqual(bip34_height_push(height), bytes([0x50 + height]))






    ############################################################
    # test_a_coinbase_over_the_scriptsig_limit_is_refused
    ############################################################
    #
    # Consensus caps the coinbase scriptSig at 100 bytes. A
    # COINBASE_MESSAGE that pushes it past the cap makes every
    # block the pool submits invalid (bad-cb-length) while
    # shares keep being accepted — the coinbase must be
    # refused when it is built instead.
    ############################################################

    @unittest.expectedFailure
    def test_a_coinbase_over_the_scriptsig_limit_is_refused(self):
        with mock.patch("anypool.config.COINBASE_MESSAGE", "/" + "x" * 98 + "/"):
            with self.assertRaises(ValueError):
                build_coinbase_parts(vectors.TEMPLATE)








if __name__ == "__main__":
    unittest.main()
