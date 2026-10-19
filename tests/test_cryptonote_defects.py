############################################################
#  [*] Pinned Defects — CryptoNote Family
#
#  Known bugs of the CryptoNote pool, each pinned as a
#  regression test that states the WANTED behaviour and fails
#  today, marked @unittest.expectedFailure — once a fix lands
#  the unexpected success fails the run, the cue to drop the
#  decorator and move the test into its home file:
#
#    - a hash that meets the network difficulty but not a
#      higher pool difficulty solves a block that is never
#      submitted
#    - a login whose requested difficulty is written in
#      non-ASCII digits gets no answer at all
#    - the job tells the miner cn/0 whatever CryptoNight
#      variant the coin uses
#    - the new-block panel calls the keccak block id SHA256
#
#  CryptoNight itself is mocked where a test needs a
#  particular hash, as in test_cn_server.py.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import contextlib
import dataclasses
import io
import unittest
from unittest.mock import patch

from anypool import coins
from anypool.families.cryptonote.connection import CnConnection, parse_client_difficulty
from tests import cn_vectors
from tests.test_cn_server import FakeClient, make_server, template_result


# The CN server resolves the active coin at share and job
# time, so this module pins COIN to LTL for its whole run, as
# test_cn_server.py does for its own
_COIN_PATCH = patch("anypool.config.COIN", "LTL")








############################################################
# setUpModule
############################################################
#
# unittest's module-wide fixture hook: the COIN pin starts
# before the first test in this file runs.
############################################################

def setUpModule():
    _COIN_PATCH.start()








############################################################
# tearDownModule
############################################################
#
# The matching teardown: unpin COIN after this file's last
# test.
############################################################

def tearDownModule():
    _COIN_PATCH.stop()








############################################################
# FakeWriter
############################################################
#
# The one thing a CnConnection asks of its socket writer
# when it is built: the peer's address.
#
# Used by:
#   - TestJobPayload (below)
############################################################

class FakeWriter:






    ############################################################
    # get_extra_info
    ############################################################
    #
    # Answers the peer address a connection logs its miner by.
    ############################################################

    def get_extra_info(self, name):
        return ("203.0.113.7", 40000)








############################################################
# FakeDaemon
############################################################
#
# A CryptoNote daemon that serves the captured template of
# tests/cn_vectors.py and nothing else.
#
# Used by:
#   - TestNewBlockPanel (below)
############################################################

class FakeDaemon:






    ############################################################
    # call
    ############################################################
    #
    # The MoneroRPC.call() signature: getblocktemplate answers
    # the captured template, anything else nothing.
    ############################################################

    async def call(self, method, params=None):
        return template_result() if method == "getblocktemplate" else None








############################################################
# TestBlockBelowPoolDifficulty
############################################################
#
# A block found by a share that misses the pool difficulty
# must still reach the daemon.
############################################################

class TestBlockBelowPoolDifficulty(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_a_block_below_the_pool_difficulty_is_still_submitted
    ############################################################
    #
    # With POLL_DIFF_DROPPER off the pool difficulty can sit
    # above the network's. A hash meeting the network
    # difficulty but not the pool's solves a block: it must be
    # submitted and the share accepted, as the Bitcoin family
    # does — today the block is only looked for among accepted
    # shares, so it is refused as low difficulty and dropped.
    ############################################################

    @unittest.expectedFailure
    async def test_a_block_below_the_pool_difficulty_is_still_submitted(self):
        server, client = make_server(), FakeClient()
        job = server.job_manager.make_job(client, b"EXTRANON", cn_vectors.TEMPLATE_DIFFICULTY * 10)
        network_grade = ((1 << 256) // (cn_vectors.TEMPLATE_DIFFICULTY * 2)).to_bytes(32, "little")

        launched = []
        with patch.object(server, "_spawn", side_effect=lambda coro: (launched.append(coro), coro.close())), \
             patch("anypool.families.cryptonote.server.cn_slow_hash", return_value=network_grade), \
             contextlib.redirect_stdout(io.StringIO()):
            accepted, error = await server.process_share(client, job["job_id"], "00000001", network_grade.hex())

        self.assertEqual(len(launched), 1)
        self.assertTrue(accepted)
        self.assertIsNone(error)








############################################################
# TestLoginDifficulty
############################################################
#
# A login's requested difficulty that cannot be read must
# count as no request — never break the login.
############################################################

class TestLoginDifficulty(unittest.TestCase):






    ############################################################
    # test_non_ascii_digits_are_no_request
    ############################################################
    #
    # Superscript digits pass str.isdigit() but int() refuses
    # them: in the login suffix or the password, they raise
    # instead of reading as no request, and the miner's login
    # goes unanswered.
    ############################################################

    @unittest.expectedFailure
    def test_non_ascii_digits_are_no_request(self):
        self.assertEqual(parse_client_difficulty("worker+²", "x"), ("worker+²", None))
        self.assertEqual(parse_client_difficulty("worker", "d=²"), ("worker", None))








############################################################
# TestJobPayload
############################################################
#
# The job a miner receives must name the algorithm the pool
# checks its shares with.
############################################################

class TestJobPayload(unittest.TestCase):






    ############################################################
    # test_the_job_names_the_coins_cryptonight_variant
    ############################################################
    #
    # process_share() hashes with the coin's cn_variant, but
    # the job always tells XMRig cn/0: on a coin using another
    # variant the miner runs the wrong algorithm and every
    # share fails the result check.
    ############################################################

    @unittest.expectedFailure
    def test_the_job_names_the_coins_cryptonight_variant(self):
        variant_one = dataclasses.replace(coins.REGISTRY["LTL"], cn_variant=1)
        with patch.dict(coins.REGISTRY, {"LTL": variant_one}), contextlib.redirect_stdout(io.StringIO()):
            connection = CnConnection(None, FakeWriter(), make_server())
            payload = connection.job_payload()

        self.assertEqual(payload["algo"], "cn/1")








############################################################
# TestNewBlockPanel
############################################################
#
# The new-block panel must name the block id for what it is.
############################################################

class TestNewBlockPanel(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_a_cryptonote_block_id_is_not_called_sha256
    ############################################################
    #
    # A CryptoNote block id is a keccak hash, yet the panel the
    # CryptoNote server prints for a new tip labels it SHA256,
    # the Bitcoin family's hash.
    ############################################################

    @unittest.expectedFailure
    async def test_a_cryptonote_block_id_is_not_called_sha256(self):
        with contextlib.redirect_stdout(io.StringIO()):
            server = make_server()
        server.job_manager.template = None
        server.rpc = FakeDaemon()

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            template = await server.create_job()

        self.assertIsNotNone(template)
        self.assertIn("New Block Detected", output.getvalue())
        self.assertNotIn("SHA256", output.getvalue())








if __name__ == "__main__":
    unittest.main()
