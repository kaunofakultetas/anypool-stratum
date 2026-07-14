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

from anypool.mining.shares import (
    NTIME_BACKWARD_SLACK,
    NTIME_FORWARD_SLACK,
    build_header,
    ntime_within_range,
    validate_share_params,
)
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




    # -----------------------------------------------------------
    # Some ASIC firmwares (e.g. NexusL1/BM1491) append a 6th
    # parameter: the BIP310 version-rolling bits. The pool
    # declines version-rolling in mining.configure, so the only
    # legal value is zero — the exact submission a rented L1
    # sent on Dogecoin testnet, which an earlier version of this
    # pool rejected purely for its arity.
    # -----------------------------------------------------------
    def test_six_param_submission_with_zero_version_bits_accepted(self):
        params = ["x", "00000001", "000aace1", "6a5667d4", "5a5b7e3d", "00000000"]
        self.assertTrue(validate_share_params(params))


    def test_six_param_submission_with_nonzero_version_bits_rejected(self):
        # Non-zero bits mean the miner rolled the header version,
        # which we never negotiated — the rebuilt header would not
        # match what was hashed.
        params = ["x", "00000001", "000aace1", "6a5667d4", "5a5b7e3d", "1fffe000"]
        self.assertFalse(validate_share_params(params))
        # Garbage in the 6th slot must also be rejected
        self.assertFalse(validate_share_params(["x", "00000001", "000aace1", "6a5667d4", "5a5b7e3d", "xyz"]))
        self.assertFalse(validate_share_params(["x", "00000001", "000aace1", "6a5667d4", "5a5b7e3d", None]))


    def test_seven_param_submission_rejected(self):
        params = ["x", "00000001", "000aace1", "6a5667d4", "5a5b7e3d", "00000000", "extra"]
        self.assertFalse(validate_share_params(params))










class TestNtimeWithinRange(unittest.TestCase):


    # -----------------------------------------------------------
    # The real share submitted ntime identical to the job ntime,
    # and small legitimate rolls must also pass.
    # -----------------------------------------------------------
    def test_legitimate_ntime_accepted(self):
        self.assertTrue(ntime_within_range(vectors.JOB_NTIME, vectors.SHARE_NTIME))

        job_ntime = int(vectors.JOB_NTIME, 16)
        self.assertTrue(ntime_within_range(vectors.JOB_NTIME, f"{job_ntime + 60:08x}"))
        self.assertTrue(ntime_within_range(vectors.JOB_NTIME, f"{job_ntime - 60:08x}"))






    # -----------------------------------------------------------
    # Exactly at the window edges is still allowed; one second
    # beyond either edge is rejected.
    # -----------------------------------------------------------
    def test_window_edges(self):
        job_ntime = int(vectors.JOB_NTIME, 16)

        self.assertTrue(ntime_within_range(vectors.JOB_NTIME, f"{job_ntime + NTIME_FORWARD_SLACK:08x}"))
        self.assertTrue(ntime_within_range(vectors.JOB_NTIME, f"{job_ntime - NTIME_BACKWARD_SLACK:08x}"))

        self.assertFalse(ntime_within_range(vectors.JOB_NTIME, f"{job_ntime + NTIME_FORWARD_SLACK + 1:08x}"))
        self.assertFalse(ntime_within_range(vectors.JOB_NTIME, f"{job_ntime - NTIME_BACKWARD_SLACK - 1:08x}"))






    # -----------------------------------------------------------
    # Absurd timestamps (zero, far future) must be rejected.
    # -----------------------------------------------------------
    def test_absurd_ntime_rejected(self):
        self.assertFalse(ntime_within_range(vectors.JOB_NTIME, "00000000"))
        self.assertFalse(ntime_within_range(vectors.JOB_NTIME, "ffffffff"))




if __name__ == "__main__":
    unittest.main()
