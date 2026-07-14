# -----------------------------------------------------------
#  [*] Tests — BTC Testnet3 Block 5062063
#
#  The SHA256d counterpart of the block 1777 suite: the pool
#  mined testnet3 block 5062063 on 2026-07-14 and the network
#  accepted it. These tests replay that block from the
#  captured template/job/share values and require the code to
#  reproduce every intermediate value — including the 4-level
#  merkle branch, which the coinbase-only block 1777 cannot
#  exercise.
#
#  The suite-wide environment (tests/__init__.py) pins the
#  KNF coin, so each test temporarily switches the config to
#  the BTC pool that mined this block and restores it after.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool import config
from anypool.mining.jobs import build_job
from anypool.mining.shares import build_header
from tests import vectors




class TestBtcBlock5062063(unittest.TestCase):


    # -----------------------------------------------------------
    # Switch the pool config to the BTC testnet3 setup that
    # mined the block; restore the suite-wide KNF config after.
    # -----------------------------------------------------------
    def setUp(self):
        self._saved = (config.COIN, config.COIN_NETWORK,
                       config.REWARD_ADDR, config.COINBASE_MESSAGE)
        config.COIN = "BTC"
        config.COIN_NETWORK = "testnet3"
        config.REWARD_ADDR = "tb1qzlz8wv7qu40xx66sqc3r98qkgsys6vwtp3k0nj"
        config.COINBASE_MESSAGE = "/AnyPool Miner from VU KNF/"


    def tearDown(self):
        (config.COIN, config.COIN_NETWORK,
         config.REWARD_ADDR, config.COINBASE_MESSAGE) = self._saved




    # -----------------------------------------------------------
    # build_job() fed with the block's template must reproduce
    # the exact job the pool broadcast — including the merkle
    # branch over the 8 template transactions.
    # -----------------------------------------------------------
    def test_job_fields(self):
        job = build_job(vectors.BTC_TEMPLATE, "00000002")

        self.assertEqual(job["prevhash"], vectors.BTC_JOB_PREVHASH_WIRE)
        self.assertEqual(job["coinb1"], vectors.BTC_COINB1)
        self.assertEqual(job["coinb2"], vectors.BTC_COINB2)
        self.assertEqual(job["merkle_branch"], vectors.BTC_MERKLE_BRANCH)
        self.assertEqual(job["version"], vectors.BTC_JOB_VERSION)
        self.assertEqual(job["nbits"], vectors.BTC_JOB_NBITS)
        self.assertEqual(job["ntime"], vectors.BTC_JOB_NTIME)
        self.assertEqual(job["height"], vectors.BTC_HEIGHT)




    # -----------------------------------------------------------
    # The winning share must rebuild the accepted block's
    # 80-byte header and its hash (for SHA256d the PoW hash IS
    # the block hash), and pass both targets.
    # -----------------------------------------------------------
    def test_winning_share_round_trip(self):
        job = build_job(vectors.BTC_TEMPLATE, "00000002")

        pow_hash, header_hex, header_bytes = build_header(
            job,
            vectors.BTC_EXTRANONCE1, vectors.BTC_EXTRANONCE2,
            vectors.BTC_SHARE_NTIME, vectors.BTC_SHARE_NONCE,
        )

        self.assertEqual(header_hex, vectors.BTC_HEADER_HEX)
        self.assertEqual(len(header_bytes), 80)
        self.assertEqual(pow_hash, vectors.BTC_BLOCK_HASH)

        hash_int = int(pow_hash, 16)
        self.assertLessEqual(hash_int, vectors.BTC_POOL_TARGET)
        self.assertLessEqual(hash_int, vectors.BTC_NETWORK_TARGET)




    # -----------------------------------------------------------
    # Any other nonce must change the header and fail the
    # min-difficulty target.
    # -----------------------------------------------------------
    def test_wrong_nonce_fails_targets(self):
        job = build_job(vectors.BTC_TEMPLATE, "00000002")

        pow_hash, header_hex, _ = build_header(
            job,
            vectors.BTC_EXTRANONCE1, vectors.BTC_EXTRANONCE2,
            vectors.BTC_SHARE_NTIME, "00000000",
        )

        self.assertNotEqual(header_hex, vectors.BTC_HEADER_HEX)
        self.assertGreater(int(pow_hash, 16), vectors.BTC_NETWORK_TARGET)




if __name__ == "__main__":
    unittest.main()
