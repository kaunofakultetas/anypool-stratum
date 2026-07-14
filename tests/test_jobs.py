# -----------------------------------------------------------
#  [*] Tests — Job Construction & JobManager
#
#  Covers anypool/jobs.py: build_job() must turn the block
#  1777 template into exactly the job the pool broadcast that
#  day, and the JobManager must store, look up, prune and
#  recognize unchanged work correctly.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.mining.jobs import MAX_STORED_JOBS, JobManager, build_job, stratum_prevhash
from tests import vectors




class TestBuildJob(unittest.TestCase):


    # -----------------------------------------------------------
    # The block 1777 template must produce the exact job fields
    # the pool logged when it cut job 00000001.
    # -----------------------------------------------------------
    def test_block_1777_job_fields(self):
        job = build_job(vectors.TEMPLATE, "00000001")

        self.assertEqual(job["job_id"], "00000001")
        self.assertEqual(job["prevhash"], vectors.JOB_PREVHASH_WIRE)
        self.assertEqual(job["coinb1"], vectors.COINB1)
        self.assertEqual(job["coinb2"], vectors.COINB2)
        self.assertEqual(job["merkle_branch"], [])
        self.assertEqual(job["version"], vectors.JOB_VERSION)
        self.assertEqual(job["nbits"], vectors.JOB_NBITS)
        self.assertEqual(job["ntime"], vectors.JOB_NTIME)
        self.assertEqual(job["height"], 1777)






    # -----------------------------------------------------------
    # Old daemons (pre-Bitcoin-Core-0.13 forks) provide only a
    # "hash" field per transaction, no "txid" — build_job must
    # fall back to it transparently.
    # -----------------------------------------------------------
    def test_txid_fallback_for_old_daemons(self):
        tx_hash_be = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        template = dict(vectors.TEMPLATE)
        template["transactions"] = [{"hash": tx_hash_be, "data": "00"}]  # no "txid" key

        job = build_job(template, "00000009")

        expected_le = bytes.fromhex(tx_hash_be)[::-1].hex()
        self.assertEqual(job["merkle_branch"], [expected_le])






    # -----------------------------------------------------------
    # The prevhash conversion in isolation: template (BE) form
    # to the word-swapped stratum wire form from the logs.
    # -----------------------------------------------------------
    def test_stratum_prevhash(self):
        self.assertEqual(
            stratum_prevhash(vectors.TEMPLATE["previousblockhash"]),
            vectors.JOB_PREVHASH_WIRE
        )










class TestJobManager(unittest.TestCase):


    # -----------------------------------------------------------
    # store() must set the current job and get() must find it;
    # unknown ids must return None (stale-share rejection path).
    # -----------------------------------------------------------
    def test_store_and_get(self):
        manager = JobManager()
        job = build_job(vectors.TEMPLATE, manager.next_job_id())
        manager.store(job)

        self.assertIs(manager.current_job, job)
        self.assertIs(manager.get(job["job_id"]), job)
        self.assertIsNone(manager.get("ffffffff"))






    # -----------------------------------------------------------
    # Job ids must increment as zero-padded hex.
    # -----------------------------------------------------------
    def test_job_id_sequence(self):
        manager = JobManager()
        self.assertEqual(manager.next_job_id(), "00000001")
        self.assertEqual(manager.next_job_id(), "00000002")






    # -----------------------------------------------------------
    # An identical template (same tip, mweb, target) must be
    # recognized as the same work — no needless job restarts.
    # -----------------------------------------------------------
    def test_is_same_work(self):
        manager = JobManager()
        manager.store(build_job(vectors.TEMPLATE, manager.next_job_id()))

        network_target = int(vectors.TEMPLATE["target"], 16)
        self.assertTrue(manager.is_same_work(vectors.TEMPLATE, network_target))

        # A new chain tip must NOT count as the same work
        moved_tip = dict(vectors.TEMPLATE)
        moved_tip["previousblockhash"] = "00" * 32
        self.assertFalse(manager.is_same_work(moved_tip, network_target))

        # A changed network target must NOT count as the same work
        self.assertFalse(manager.is_same_work(vectors.TEMPLATE, network_target - 1))






    # -----------------------------------------------------------
    # Duplicate-share guard: the first submission of a nonce
    # combination registers, every replay is refused. A fresh
    # job starts with a clean slate.
    # -----------------------------------------------------------
    def test_register_share_rejects_duplicates(self):
        manager = JobManager()
        job = build_job(vectors.TEMPLATE, manager.next_job_id())
        manager.store(job)

        share = (vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.SHARE_NTIME, vectors.SHARE_NONCE)

        self.assertTrue(manager.register_share(job, *share))    # first time: accepted
        self.assertFalse(manager.register_share(job, *share))   # replay: refused
        self.assertFalse(manager.register_share(job, *share))   # still refused

        # A different nonce is a different share
        self.assertTrue(manager.register_share(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.SHARE_NTIME, "00000000"))

        # A new job does not remember old shares
        new_job = build_job(vectors.TEMPLATE, manager.next_job_id())
        manager.store(new_job)
        self.assertTrue(manager.register_share(new_job, *share))






    # -----------------------------------------------------------
    # The store must never grow beyond MAX_STORED_JOBS, and it
    # is the OLDEST jobs that get pruned.
    # -----------------------------------------------------------
    def test_pruning(self):
        manager = JobManager()

        for _ in range(MAX_STORED_JOBS + 5):
            manager.store(build_job(vectors.TEMPLATE, manager.next_job_id()))

        self.assertEqual(len(manager.jobs), MAX_STORED_JOBS)
        self.assertIsNone(manager.get("00000001"))                   # oldest: pruned
        self.assertIsNotNone(manager.get(manager.current_job["job_id"]))  # newest: kept




if __name__ == "__main__":
    unittest.main()
