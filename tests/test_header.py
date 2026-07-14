# -----------------------------------------------------------
#  [*] Tests — Block Header Round-Trip
#
#  Covers anypool/shares.py. The end-to-end assertion of the
#  whole suite: given the job fields and the exact nonces the
#  ASIC submitted for KNF block 1777, build_header() must
#  reproduce the accepted block's 80-byte header, its Scrypt
#  PoW hash, and that hash must sit below both targets — the
#  full share-validation path in one test.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.mining.shares import build_header, validate_share_params
from tests import vectors




# -----------------------------------------------------------
# block_1777_job
# -----------------------------------------------------------
#
# The job dict for block 1777, reassembled from the captured
# log values (only the fields build_header() reads).
#
# Used by:
#   - tests/test_header.py — the test cases below
# -----------------------------------------------------------
def block_1777_job():
    return {
        "prevhash": vectors.JOB_PREVHASH_WIRE,
        "coinb1": vectors.COINB1,
        "coinb2": vectors.COINB2,
        "merkle_branch": [],
        "version": vectors.JOB_VERSION,
        "nbits": vectors.JOB_NBITS,
        "ntime": vectors.JOB_NTIME,
    }










class TestBuildHeader(unittest.TestCase):


    # -----------------------------------------------------------
    # The winning share must rebuild the exact header and PoW
    # hash the network accepted.
    # -----------------------------------------------------------
    def test_block_1777_round_trip(self):
        scrypt_hash, header_hex, header_bytes = build_header(
            block_1777_job(),
            vectors.EXTRANONCE1, vectors.EXTRANONCE2,
            vectors.SHARE_NTIME, vectors.SHARE_NONCE,
        )

        self.assertEqual(header_hex, vectors.HEADER_HEX)
        self.assertEqual(len(header_bytes), 80)
        self.assertEqual(scrypt_hash, vectors.SCRYPT_HASH)






    # -----------------------------------------------------------
    # The same PoW hash must pass both the pool and network
    # target comparisons — this share WAS a block.
    # -----------------------------------------------------------
    def test_block_1777_meets_targets(self):
        scrypt_hash, _, _ = build_header(
            block_1777_job(),
            vectors.EXTRANONCE1, vectors.EXTRANONCE2,
            vectors.SHARE_NTIME, vectors.SHARE_NONCE,
        )

        hash_int = int(scrypt_hash, 16)
        self.assertLessEqual(hash_int, vectors.POOL_TARGET)
        self.assertLessEqual(hash_int, vectors.NETWORK_TARGET)






    # -----------------------------------------------------------
    # Any different nonce must produce a different header and
    # (astronomically certain) fail the targets.
    # -----------------------------------------------------------
    def test_wrong_nonce_fails_targets(self):
        scrypt_hash, header_hex, _ = build_header(
            block_1777_job(),
            vectors.EXTRANONCE1, vectors.EXTRANONCE2,
            vectors.SHARE_NTIME, "00000000",
        )

        self.assertNotEqual(header_hex, vectors.HEADER_HEX)
        self.assertGreater(int(scrypt_hash, 16), vectors.NETWORK_TARGET)










class TestValidateShareParams(unittest.TestCase):


    # -----------------------------------------------------------
    # The exact parameter list cgminer submitted for the block.
    # -----------------------------------------------------------
    def test_real_submission_accepted(self):
        params = ["tomosiuks12.364053", "00000001",
                  vectors.EXTRANONCE2, vectors.SHARE_NTIME, vectors.SHARE_NONCE]
        self.assertTrue(validate_share_params(params))






    # -----------------------------------------------------------
    # Wrong arity, non-hex values and wrong field widths must
    # all be rejected before any hashing happens.
    # -----------------------------------------------------------
    def test_malformed_submissions_rejected(self):
        self.assertFalse(validate_share_params([]))
        self.assertFalse(validate_share_params(["w", "job"]))
        self.assertFalse(validate_share_params(["w", "job", "xyz", "6a5639fc", "3a337292"]))       # non-hex
        self.assertFalse(validate_share_params(["w", "job", "090000", "6a5639fc", "3a337292"]))    # too short
        self.assertFalse(validate_share_params(["w", "job", "09000000", "6a5639fc", "3a3372921"])) # too long
        self.assertFalse(validate_share_params(["w", "job", "09000000", "6a5639fc", None]))        # wrong type




if __name__ == "__main__":
    unittest.main()
