############################################################
#  [*] Tests — Job Freshness on a Quiet Chain
#
#  Covers the regression that made rented ASICs refuse to
#  mine: the pool only cut a new job when the chain tip
#  moved, so on a chain where nobody mines (fresh lab
#  network, chicken-and-egg) the single job's ntime drifted
#  minutes into the past. Miners and rental proxies judge a
#  pool by the freshness of its work — old-ntime work reads
#  as a dead pool and they disconnect without hashing.
#
#  The guarantees pinned down here:
#
#    - a template with the SAME tip keeps the current job
#      while its ntime is younger than
#      JOB_NTIME_REFRESH_SECONDS
#    - once the ntime is that old, the same-tip template must
#      cut a REFRESHED job: new job id, fresh ntime, same
#      prevhash/height
#    - the refresh broadcast carries clean_jobs=False so
#      miners keep their in-flight work; a moved-tip job
#      still broadcasts clean_jobs=True
#    - a hash that solves a BLOCK while missing the share
#      target (possible whenever pool difficulty > network
#      difficulty, e.g. rental-recommended fixed difficulty
#      on a low-difficulty chain) must be accepted and
#      submitted, never rejected as "low difficulty"
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest

from anypool.families.bitcoin.server import JOB_NTIME_REFRESH_SECONDS
from tests import vectors
from tests.test_server import drain, make_server, moved_tip_template, submit_share




############################################################
# same_tip_template
############################################################
#
# The template the node reports while the tip has NOT moved:
# identical to the job's template except for curtime, which
# keeps ticking on the node regardless of blocks.
#
# Used by:
#   - tests/test_job_freshness.py — the test cases below
############################################################

def same_tip_template(seconds_later):
    template = dict(vectors.TEMPLATE)
    template["curtime"] = vectors.TEMPLATE["curtime"] + seconds_later
    return template




############################################################
# FakeClient
############################################################
#
# Stands in for a connected StratumConnection: records every
# notification broadcast_new_job() sends so a test can assert
# on the exact mining.notify parameters (clean_jobs flag).
#
# Used by:
#   - tests/test_job_freshness.py — the broadcast test cases
############################################################

class FakeClient:

    def __init__(self):
        self.notifications = []

        # The connection attributes display.broadcast_panel reads
        self.client_ip = "203.0.113.1"
        self.worker_name = "tester.worker1"
        self.miner_software = "FakeClient/1.0"
        self.extra_nonce1 = vectors.EXTRANONCE1

    async def send_notification(self, method, params):
        self.notifications.append((method, params))

    def notify_params(self):
        return [params for (method, params) in self.notifications
                if method == "mining.notify"]




############################################################
# make_freshness_server
############################################################
#
# make_server() plus the network state create_job() snapshots
# on a real run — is_same_work() compares the template target
# against it, so without this every template would look like
# new work and the keep-the-job path could never be exercised.
#
# Used by:
#   - tests/test_job_freshness.py — the test cases below
############################################################

def make_freshness_server():
    server, job = make_server()
    server.network_target = vectors.NETWORK_TARGET
    server.network_difficulty = server.calculate_mining_difficulty(vectors.NETWORK_TARGET)
    return server, job




class TestJobNtimeRefresh(unittest.IsolatedAsyncioTestCase):




    ############################################################
    # Same tip, ntime still young: the job the miners are
    # hashing must be kept — a pointless re-issue would churn
    # job ids for nothing.
    ############################################################

    async def test_fresh_job_is_kept_on_same_tip(self):
        server, job = make_freshness_server()
        server.rpc.template = same_tip_template(JOB_NTIME_REFRESH_SECONDS - 1)

        result = await server.create_job()

        self.assertIs(result, job)
        self.assertEqual(list(server.job_manager.jobs.keys()), [job["job_id"]])




    ############################################################
    # Same tip, ntime one refresh interval old: a REFRESHED job
    # must be cut — fresh ntime from the new template, new job
    # id, but the same parent and height (no block happened).
    # This is the ASIC-refuses-stale-work regression.
    ############################################################

    async def test_stale_ntime_cuts_refreshed_job(self):
        server, job = make_freshness_server()
        template = same_tip_template(JOB_NTIME_REFRESH_SECONDS)
        server.rpc.template = template

        refreshed = await server.create_job()

        self.assertIsNotNone(refreshed)
        self.assertNotEqual(refreshed["job_id"], job["job_id"])
        self.assertEqual(refreshed["ntime"], f"{template['curtime']:08x}")
        self.assertEqual(refreshed["prevhash"], job["prevhash"])
        self.assertEqual(refreshed["height"], job["height"])
        self.assertIs(server.job_manager.current_job, refreshed)




    ############################################################
    # The job must never be allowed to grow stale: as long as
    # the node keeps reporting later curtimes, every refresh
    # interval must produce a fresh job again.
    ############################################################

    async def test_refresh_repeats_every_interval(self):
        server, job = make_freshness_server()

        seen_ids = {job["job_id"]}
        for interval in range(1, 4):
            template = same_tip_template(interval * JOB_NTIME_REFRESH_SECONDS)
            server.rpc.template = template

            refreshed = await server.create_job()

            self.assertEqual(refreshed["ntime"], f"{template['curtime']:08x}")
            self.assertNotIn(refreshed["job_id"], seen_ids)
            seen_ids.add(refreshed["job_id"])




    ############################################################
    # A refresh is the SAME work with a newer timestamp, so its
    # broadcast must say clean_jobs=False — miners keep their
    # in-flight shares instead of restarting every interval.
    ############################################################

    async def test_refresh_broadcast_keeps_inflight_work(self):
        server, job = make_freshness_server()
        client = FakeClient()
        server.add_client(client)
        server.rpc.template = same_tip_template(JOB_NTIME_REFRESH_SECONDS)

        await server.create_job()
        await drain(server)

        notifies = client.notify_params()
        self.assertEqual(len(notifies), 1)
        self.assertIs(notifies[0][8], False)                 # clean_jobs




    ############################################################
    # A moved tip is genuinely NEW work: its broadcast must
    # keep saying clean_jobs=True so miners abandon work on
    # the orphaned parent immediately.
    ############################################################

    async def test_new_tip_broadcast_cleans_jobs(self):
        server, job = make_freshness_server()
        client = FakeClient()
        server.add_client(client)
        server.rpc.template = moved_tip_template("5c" * 32)

        await server.create_job()
        await drain(server)

        notifies = client.notify_params()
        self.assertEqual(len(notifies), 1)
        self.assertIs(notifies[0][8], True)                  # clean_jobs




class TestBlockBelowShareTarget(unittest.IsolatedAsyncioTestCase):




    ############################################################
    # Pool difficulty above network difficulty (rental services
    # demand a high fixed difficulty; a young chain sits far
    # below it): a hash can solve a block while missing the
    # share target. That block must be accepted and submitted —
    # the old "is a share first, then maybe a block" gating
    # silently threw such blocks away.
    ############################################################

    async def test_block_missing_share_target_is_still_submitted(self):
        server, job = make_server()
        job["pool_target"] = 0                 # nothing passes the share target...
        job["network_target"] = 2 ** 256 - 1   # ...everything is block-grade
        server.rpc.template = moved_tip_template("5c" * 32)

        accepted, error = await submit_share(server, job)
        await drain(server)

        self.assertTrue(accepted)
        self.assertIsNone(error)
        self.assertEqual(len(server.rpc.submitted_blocks()), 1)
        self.assertEqual(server.blocks_found, 1)
        self.assertEqual(server.shares_accepted, 1)




if __name__ == "__main__":
    unittest.main()
