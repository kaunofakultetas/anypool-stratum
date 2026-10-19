############################################################
#  [*] Tests — CryptoNote Job Manager
#
#  Covers families/cryptonote/jobs.py: per-client job cutting
#  (every miner must get DIFFERENT work from the same
#  template), tip-change detection, duplicate-nonce guarding
#  and job pruning.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest

from anypool.families.cryptonote.jobs import MAX_STORED_JOBS, CnJobManager
from tests import cn_vectors








############################################################
# template_result
############################################################
#
# The daemon's getblocktemplate answer for the captured
# TEMPLATE_BLOB vector; a prev_hash or height override
# simulates tip movement. Only the prev_hash one is used at
# the moment — no test moves the height.
#
# Used by:
#   - TestTemplateTracking and TestPruning (below) — every
#     test case
#   - TestJobCutting.setUp and TestNonceGuard.setUp (below)
############################################################

def template_result(prev_hash=None, height=None):
    return {
        "blocktemplate_blob": cn_vectors.TEMPLATE_BLOB,
        "height": height if height is not None else cn_vectors.TEMPLATE_HEIGHT,
        "difficulty": cn_vectors.TEMPLATE_DIFFICULTY,
        "prev_hash": prev_hash or cn_vectors.TEMPLATE_PREV_HASH,
        "reserved_offset": cn_vectors.TEMPLATE_RESERVED_OFFSET,
    }








############################################################
# TestTemplateTracking
############################################################
#
# set_template(): telling new work — a template on a
# different parent — from a mere re-fetch of the same one,
# which decides whether miners get a broadcast.
############################################################

class TestTemplateTracking(unittest.TestCase):






    ############################################################
    # test_first_template_is_new_work
    ############################################################
    #
    # The very first template is always new work.
    ############################################################

    def test_first_template_is_new_work(self):
        manager = CnJobManager()
        self.assertTrue(manager.set_template(template_result(), 16))






    ############################################################
    # test_same_parent_is_not_new_work
    ############################################################
    #
    # A re-fetched template on the same parent is NOT new work
    # — the refresh loop must not trigger broadcasts for it.
    ############################################################

    def test_same_parent_is_not_new_work(self):
        manager = CnJobManager()
        manager.set_template(template_result(), 16)
        self.assertFalse(manager.set_template(template_result(), 16))






    ############################################################
    # test_new_parent_is_new_work
    ############################################################
    #
    # A template on a different parent means the tip moved:
    # new work.
    ############################################################

    def test_new_parent_is_new_work(self):
        manager = CnJobManager()
        manager.set_template(template_result(), 16)
        self.assertTrue(manager.set_template(template_result(prev_hash="ab" * 32), 16))








############################################################
# TestJobCutting
############################################################
#
# make_job(): one personalized job per client from the
# stored template — unique work, everything share
# validation needs, and the difficulty snapshot the share
# is later judged by.
############################################################

class TestJobCutting(unittest.TestCase):






    ############################################################
    # setUp
    ############################################################
    #
    # Every test cuts jobs from one freshly stored template.
    ############################################################

    def setUp(self):
        self.manager = CnJobManager()
        self.manager.set_template(template_result(), 16)






    ############################################################
    # test_clients_get_distinct_blobs
    ############################################################
    #
    # The core property of the family: two clients mining the
    # same template must receive DIFFERENT blobs, or they
    # would duplicate each other's work.
    ############################################################

    def test_clients_get_distinct_blobs(self):
        job_a = self.manager.make_job("client-a", b"AAAAAAAA", 5000)
        job_b = self.manager.make_job("client-b", b"BBBBBBBB", 5000)

        self.assertNotEqual(job_a["hashing_blob"], job_b["hashing_blob"])
        self.assertNotEqual(job_a["job_id"], job_b["job_id"])






    ############################################################
    # test_job_fields
    ############################################################
    #
    # One cut job carries everything share validation and the
    # wire payload need, straight from the template.
    ############################################################

    def test_job_fields(self):
        job = self.manager.make_job("client", b"EXTRANON", 5000)

        self.assertEqual(len(job["hashing_blob"]), 76)
        self.assertEqual(job["nonce_offset"], 39)
        self.assertEqual(job["height"], cn_vectors.TEMPLATE_HEIGHT)
        self.assertEqual(job["network_difficulty"], cn_vectors.TEMPLATE_DIFFICULTY)
        self.assertEqual(job["pool_difficulty"], 5000)
        self.assertEqual(job["target"], "711b0d00")   # compact target of diff 5000






    ############################################################
    # test_difficulty_snapshot
    ############################################################
    #
    # Difficulty is SNAPSHOTTED per job: a share arriving after
    # the pool difficulty changed is judged by what the miner
    # was actually given.
    ############################################################

    def test_difficulty_snapshot(self):
        old = self.manager.make_job("client", b"EXTRANON", 1000)
        new = self.manager.make_job("client", b"EXTRANON", 9000)

        self.assertEqual(old["pool_difficulty"], 1000)
        self.assertEqual(new["pool_difficulty"], 9000)






    ############################################################
    # test_make_job_without_template_raises
    ############################################################
    #
    # Cutting a job before any template exists is a bug in the
    # caller (login handles it) and must raise, not mint an
    # empty job.
    ############################################################

    def test_make_job_without_template_raises(self):
        with self.assertRaises(RuntimeError):
            CnJobManager().make_job("client", b"EXTRANON", 1000)








############################################################
# TestNonceGuard
############################################################
#
# register_nonce(), the duplicate-share guard: a nonce
# counts once per job, whatever its hex case.
############################################################

class TestNonceGuard(unittest.TestCase):






    ############################################################
    # setUp
    ############################################################
    #
    # Every test guards nonces on one issued job.
    ############################################################

    def setUp(self):
        self.manager = CnJobManager()
        self.manager.set_template(template_result(), 16)
        self.job = self.manager.make_job("client", b"EXTRANON", 5000)






    ############################################################
    # test_first_nonce_accepted_replay_rejected
    ############################################################
    #
    # First submission of a nonce registers; the replay is
    # refused.
    ############################################################

    def test_first_nonce_accepted_replay_rejected(self):
        self.assertTrue(self.manager.register_nonce(self.job, "deadbeef"))
        self.assertFalse(self.manager.register_nonce(self.job, "deadbeef"))






    ############################################################
    # test_case_insensitive
    ############################################################
    #
    # A nonce sent again in the other hex case is the same
    # nonce — hex case must not open a replay hole.
    ############################################################

    def test_case_insensitive(self):
        self.assertTrue(self.manager.register_nonce(self.job, "ABCD1234"))
        self.assertFalse(self.manager.register_nonce(self.job, "abcd1234"))






    ############################################################
    # test_different_nonces_both_accepted
    ############################################################
    #
    # Distinct nonces on the same job are distinct shares.
    ############################################################

    def test_different_nonces_both_accepted(self):
        self.assertTrue(self.manager.register_nonce(self.job, "00000001"))
        self.assertTrue(self.manager.register_nonce(self.job, "00000002"))








############################################################
# TestPruning
############################################################
#
# The bound on stored jobs: as new jobs are cut the oldest
# are dropped, so memory stays flat while the job a miner
# holds stays resolvable.
############################################################

class TestPruning(unittest.TestCase):






    ############################################################
    # test_jobs_are_pruned
    ############################################################
    #
    # Job storage is bounded: a long-running pool with many
    # clients must not grow forever.
    ############################################################

    def test_jobs_are_pruned(self):
        manager = CnJobManager()
        manager.set_template(template_result(), 16)

        for i in range(MAX_STORED_JOBS + 25):
            manager.make_job("client", i.to_bytes(8, "big"), 5000)

        self.assertEqual(len(manager.jobs), MAX_STORED_JOBS)






    ############################################################
    # test_recent_job_survives_pruning
    ############################################################
    #
    # Pruning drops the OLDEST jobs — the one just issued must
    # still be resolvable when its share comes back.
    ############################################################

    def test_recent_job_survives_pruning(self):
        manager = CnJobManager()
        manager.set_template(template_result(), 16)

        for i in range(MAX_STORED_JOBS):
            manager.make_job("client", i.to_bytes(8, "big"), 5000)
        newest = manager.make_job("client", b"NEWESTXX", 5000)

        self.assertIsNotNone(manager.get(newest["job_id"]))
