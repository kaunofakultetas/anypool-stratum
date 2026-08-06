############################################################
#  [*] Tests — CryptoNote Server Core
#
#  The CryptoNote counterpart of test_server.py: share
#  judgment paths (unknown/foreign job, stale height,
#  malformed nonce, duplicate, lying result, accept), the
#  one-submission-per-parent sibling guard, per-connection
#  difficulty parsing and the effective-difficulty clamps.
#
#  CryptoNight itself is mocked here (a controlled hash lets
#  every verdict path be steered precisely); the REAL PoW is
#  covered by test_cn_pow.py and the integration miner.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest
from unittest.mock import patch

from anypool.families.cryptonote import errors
from anypool.families.cryptonote.connection import parse_client_difficulty
from anypool.families.cryptonote.server import CnStratumServer
from tests import cn_vectors








############################################################
# template_result
############################################################
#
# The daemon's getblocktemplate answer for the captured
# TEMPLATE_BLOB vector, shaped the way create_job() /
# set_template() consume it.
#
# Used by:
#   - make_server(), TestProcessShare — fresh and stale
#     templates
############################################################

def template_result():
    return {
        "blocktemplate_blob": cn_vectors.TEMPLATE_BLOB,
        "height": cn_vectors.TEMPLATE_HEIGHT,
        "difficulty": cn_vectors.TEMPLATE_DIFFICULTY,
        "prev_hash": cn_vectors.TEMPLATE_PREV_HASH,
        "reserved_offset": cn_vectors.TEMPLATE_RESERVED_OFFSET,
    }








############################################################
# Stands in for a CnConnection: process_share() only reads
# identity fields off the client, so plain class attributes
# are enough. Each instance is a distinct "connection" for
# the foreign-job test.
############################################################

class FakeClient:
    client_ip = "203.0.113.7"
    worker_name = "test-worker"
    miner_software = "test/1.0"


# A PoW hash value that meets pool difficulty 50 but NOT the
# template's network difficulty (~830k): 2^240 as little-endian.
MID_HASH = (1 << 240).to_bytes(32, "little")

# A hash value meeting ANY difficulty (value 1).
TINY_HASH = (1).to_bytes(32, "little")








############################################################
# make_server
############################################################
#
# A CnStratumServer with the vector template already stored
# and the network difficulty set — no RPC client is touched,
# no sockets are opened.
#
# Used by:
#   - the test cases below
############################################################

def make_server():
    server = CnStratumServer()
    server.job_manager.set_template(template_result(), 16)
    server.network_difficulty = cn_vectors.TEMPLATE_DIFFICULTY
    return server


# The CN server resolves the active coin at share time
# (coins.active().cn_variant), so these tests pin COIN=LTL for
# their whole module instead of trusting the process env or
# whatever a previously run test module selected.
_COIN_PATCH = patch("anypool.config.COIN", "LTL")








############################################################
# unittest's module-wide fixture hook: the COIN pin starts
# before the first test in this file runs.
############################################################

def setUpModule():
    _COIN_PATCH.start()








############################################################
# The matching teardown: unpin COIN after this file's last
# test, so later test modules see the process default again.
############################################################

def tearDownModule():
    _COIN_PATCH.stop()








class TestProcessShare(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # Every test starts from one issued job: pool difficulty
    # 50, extranonce b"EXTRANON", owned by self.client.
    ############################################################

    def setUp(self):
        self.server = make_server()
        self.client = FakeClient()
        self.job = self.server.job_manager.make_job(self.client, b"EXTRANON", 50)






    ############################################################
    # One process_share() call with CryptoNight mocked to
    # return hash_value — every keyword strays from a valid
    # submission in exactly one way, so each test names only
    # its own deviation.
    ############################################################

    async def submit(self, job_id=None, nonce="00000001", result=None,
                     client=None, hash_value=MID_HASH):
        with patch("anypool.families.cryptonote.server.cn_slow_hash",
                   return_value=hash_value):
            return await self.server.process_share(
                client or self.client,
                job_id or self.job["job_id"],
                nonce,
                result if result is not None else hash_value.hex(),
            )






    ############################################################
    # First reject gate: a job id the manager never issued
    # answers "Invalid job id".
    ############################################################

    async def test_unknown_job_rejected(self):
        accepted, error = await self.submit(job_id="ffffffff")
        self.assertFalse(accepted)
        self.assertEqual(error, errors.ERROR_INVALID_JOB)






    ############################################################
    # A share for a job issued to ANOTHER connection must not
    # count — job ids are per client in this family, and a
    # foreign job id looks exactly like an unknown one.
    ############################################################

    async def test_foreign_job_rejected(self):
        accepted, error = await self.submit(client=FakeClient())
        self.assertFalse(accepted)
        self.assertEqual(error, errors.ERROR_INVALID_JOB)






    ############################################################
    # Once the template moved to a new tip, shares for jobs
    # cut from the old one answer "Block expired".
    ############################################################

    async def test_stale_height_rejected(self):
        stale = dict(template_result(), height=cn_vectors.TEMPLATE_HEIGHT + 1,
                     prev_hash="ab" * 32)
        self.server.job_manager.set_template(stale, 16)
        accepted, error = await self.submit()
        self.assertFalse(accepted)
        self.assertEqual(error, errors.ERROR_BLOCK_EXPIRED)






    ############################################################
    # A non-hex nonce is rejected by the server's own shape
    # gate (the connection has one too, but the server must
    # not rely on it).
    ############################################################

    async def test_malformed_nonce_rejected(self):
        accepted, error = await self.submit(nonce="zz000001")
        self.assertFalse(accepted)
        self.assertEqual(error, errors.ERROR_MALFORMED_NONCE)






    ############################################################
    # The same nonce twice on one job: first accepted, the
    # replay rejected — one winning share must not be
    # resubmittable to inflate the accepted count.
    ############################################################

    async def test_duplicate_nonce_rejected(self):
        accepted, _ = await self.submit(nonce="00000001")
        self.assertTrue(accepted)
        accepted, error = await self.submit(nonce="00000001")
        self.assertFalse(accepted)
        self.assertEqual(error, errors.ERROR_DUPLICATE_SHARE)






    ############################################################
    # The claimed result must equal the recomputed hash — a
    # mismatch means broken or cheating mining software, and
    # the share is invalid even though the hash itself would
    # have met the difficulty.
    ############################################################

    async def test_lying_result_rejected(self):
        accepted, error = await self.submit(result="11" * 32)
        self.assertFalse(accepted)
        self.assertEqual(error, errors.ERROR_INVALID_SHARE)






    ############################################################
    # A hash NOT meeting pool difficulty 50 (value just above
    # the pool target: 2^256/10 > 2^256/50) answers with the
    # conventional "Low difficulty share".
    ############################################################

    async def test_low_difficulty_rejected(self):
        high = ((1 << 256) // 10).to_bytes(32, "little")
        accepted, error = await self.submit(hash_value=high)
        self.assertFalse(accepted)
        self.assertEqual(error, errors.ERROR_LOW_DIFFICULTY)






    ############################################################
    # The accept path: meets pool difficulty but not network
    # grade — counted as a share, no submission task, no
    # parent marked.
    ############################################################

    async def test_share_accepted(self):
        accepted, error = await self.submit()
        self.assertTrue(accepted)
        self.assertIsNone(error)
        self.assertEqual(self.server.shares_accepted, 1)
        self.assertEqual(self.server.blocks_found, 0)
        self.assertEqual(self.server.submitted_parents, {})






    ############################################################
    # The block path: a network-grade hash launches exactly
    # ONE submission per parent — the second solve stays an
    # accepted share but the sibling guard swallows its
    # submission.
    ############################################################

    async def test_block_share_launches_single_submission(self):
        launched = []
        with patch.object(self.server, "_spawn", side_effect=lambda coro: (launched.append(coro), coro.close())):
            accepted, _ = await self.submit(nonce="00000002", hash_value=TINY_HASH)
            self.assertTrue(accepted)
            self.assertEqual(len(launched), 1)

            # A second solve on the same parent is swallowed by the guard
            accepted, _ = await self.submit(nonce="00000003", hash_value=TINY_HASH)
            self.assertTrue(accepted)   # the share still counts
            self.assertEqual(len(launched), 1)








class TestEffectiveDifficulty(unittest.TestCase):






    ############################################################
    # A pool default of 5000 for every clamp test below.
    ############################################################

    def setUp(self):
        self.server = make_server()
        self.server.pool_difficulty = 5000






    ############################################################
    # No per-connection request -> the pool default.
    ############################################################

    def test_default_when_no_request(self):
        self.assertEqual(self.server.effective_difficulty(None), 5000)






    ############################################################
    # A requested difficulty overrides the default (in either
    # direction).
    ############################################################

    def test_requested_difficulty_wins(self):
        self.assertEqual(self.server.effective_difficulty(250000), 250000)






    ############################################################
    # Requests beyond 2^32-1 are clamped — the job's 4-byte
    # compact target cannot encode more (see compact_target).
    ############################################################

    def test_clamped_to_target_encoding(self):
        self.assertEqual(self.server.effective_difficulty(1 << 40), 0xFFFFFFFF)






    ############################################################
    # Zero is falsy, so it degrades to the default rather
    # than clamping up to 1.
    ############################################################

    def test_clamped_to_at_least_one(self):
        self.assertEqual(self.server.effective_difficulty(0), 5000)






    ############################################################
    # With POLL_DIFF_DROPPER on, no connection mines above
    # the network difficulty — same dropper semantics as the
    # Bitcoin family, applied per client.
    ############################################################

    def test_dropper_caps_at_network_difficulty(self):
        with patch("anypool.families.cryptonote.server.config.POLL_DIFF_DROPPER", True):
            self.server.network_difficulty = 1000
            self.assertEqual(self.server.effective_difficulty(250000), 1000)








class TestParseClientDifficulty(unittest.TestCase):






    ############################################################
    # "worker+DIFF" in the login: suffix stripped from the
    # worker name, difficulty extracted.
    ############################################################

    def test_login_suffix(self):
        self.assertEqual(parse_client_difficulty("rig1+25000", ""), ("rig1", 25000))






    ############################################################
    # "d=DIFF" in the password field.
    ############################################################

    def test_password_d(self):
        self.assertEqual(parse_client_difficulty("rig1", "d=25000"), ("rig1", 25000))






    ############################################################
    # The long "diff=DIFF" keyword works too.
    ############################################################

    def test_password_diff_keyword(self):
        self.assertEqual(parse_client_difficulty("rig1", "diff=300"), ("rig1", 300))






    ############################################################
    # When both forms appear, the login suffix wins.
    ############################################################

    def test_login_suffix_wins_over_password(self):
        self.assertEqual(parse_client_difficulty("rig1+100", "d=200"), ("rig1", 100))






    ############################################################
    # A non-numeric "+suffix" is part of the worker name, not
    # a difficulty request — it must survive untouched.
    ############################################################

    def test_non_numeric_suffix_kept_in_name(self):
        self.assertEqual(parse_client_difficulty("team+alpha", "x"), ("team+alpha", None))






    ############################################################
    # Plain login + meaningless password: no request.
    ############################################################

    def test_no_request(self):
        self.assertEqual(parse_client_difficulty("worker", "x"), ("worker", None))






    ############################################################
    # "+0" is not a usable difficulty; treated as part of the
    # name rather than granting difficulty 0.
    ############################################################

    def test_zero_rejected(self):
        self.assertEqual(parse_client_difficulty("worker+0", ""), ("worker+0", None))
