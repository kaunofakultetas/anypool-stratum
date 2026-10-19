############################################################
#  [*] Pinned Defects — Test Tooling
#
#  Known bugs of the test suite's own tooling, each pinned as
#  a regression test that states the WANTED behaviour and
#  fails today, marked @unittest.expectedFailure — once a fix
#  lands the unexpected success fails the run, the cue to
#  drop the decorator and move the test where it belongs:
#
#    - one test module run alone (discovery narrowed to its
#      file) reads the container's real settings, because
#      the pins of tests/__init__.py land after config.py
#      was first imported, or never
#    - the CryptoNote integration miner, after a share is
#      refused, mines the same job from nonce zero again and
#      resubmits the very same share
#    - its negative check takes any error as the refusal of
#      its deliberately wrong share, not the invalid-share
#      refusal it is there to prove
#
#  The miner is driven against a scripted fake pool on the
#  loopback, so every answer it gets is the one the test
#  needs; the real CryptoNight hash runs (py-cryptonight).
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import contextlib
import gc
import io
import json
import os
import socket
import subprocess
import sys
import threading
import unittest
import warnings
from unittest import mock

try:
    import pycryptonight  # noqa: F401
    HAVE_CRYPTONIGHT = True
except ImportError:
    HAVE_CRYPTONIGHT = False


# The repository root, where discovery runs from
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The settings tests/__init__.py pins for the whole suite
PINNED_SETTINGS = ("COIN", "COIN_NETWORK", "REWARD_ADDR", "COINBASE_MESSAGE",
                   "POOL_DIFFICULTY", "DEBUG", "POLL_DIFF_DROPPER")

# The one job the fake pool hands out: an all-zero hashing
# blob at the easiest target, so the first nonce is a share
FAKE_JOB = {"blob": "00" * 76, "job_id": "job-1", "target": "ffffffff",
            "height": 1, "algo": "cn/0", "id": "session-1"}

# The fake pool's answers to a submit
ACCEPT = {"result": {"status": "OK"}, "error": None}
INVALID_SHARE = {"result": None, "error": {"code": -1, "message": "Invalid share"}}
LOW_DIFFICULTY = {"result": None, "error": {"code": -1, "message": "Low difficulty share"}}
UNAUTHENTICATED = {"result": None, "error": {"code": -1, "message": "Unauthenticated"}}








############################################################
# FakeCnPool
############################################################
#
# A CryptoNote pool on the loopback that takes one miner's
# connection, answers its login with FAKE_JOB, records every
# submit and answers the submits with the given replies in
# order. Runs on its own thread, as the miner talks through
# blocking sockets.
#
# Used by:
#   - TestCnIntegrationMiner (below)
############################################################

class FakeCnPool(threading.Thread):






    ############################################################
    # __init__
    ############################################################
    #
    # Opens the listening socket on a free loopback port and
    # keeps the submit replies to give.
    #
    # Used by:
    #   - TestCnIntegrationMiner.run_miner() (below)
    ############################################################

    def __init__(self, submit_replies):
        super().__init__(daemon=True)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.submit_replies = list(submit_replies)
        self.submissions = []






    ############################################################
    # run
    ############################################################
    #
    # Serves the one connection until the miner hangs up:
    # login answered with the job, each submit recorded and
    # answered with the next reply.
    #
    # Used by:
    #   - threading — start()
    ############################################################

    def run(self):
        connection, _ = self.listener.accept()
        with connection, connection.makefile("rw") as stream:
            for line in stream:
                message = json.loads(line)
                if message["method"] == "login":
                    reply = {"result": {"id": "session-1", "status": "OK", "job": FAKE_JOB}, "error": None}
                else:
                    self.submissions.append(message["params"])
                    reply = self.submit_replies.pop(0)
                stream.write(json.dumps({"id": message["id"], "jsonrpc": "2.0", **reply}) + "\n")
                stream.flush()
        self.listener.close()








############################################################
# TestPinnedSettings
############################################################
#
# The settings tests/__init__.py pins must hold however a
# test module is started.
############################################################

class TestPinnedSettings(unittest.TestCase):






    ############################################################
    # test_one_test_module_alone_runs_on_the_pinned_settings
    ############################################################
    #
    # Discovery narrowed to test_config.py, in an environment
    # carrying none of the pinned settings (as a plain
    # container has none): the module imports config.py
    # without ever importing the tests package, so config.py
    # reads the bare environment — COIN falls back to LTC,
    # REWARD_ADDR is missing — and its tests fail.
    ############################################################

    @unittest.expectedFailure
    def test_one_test_module_alone_runs_on_the_pinned_settings(self):
        environment = {key: value for key, value in os.environ.items() if key not in PINNED_SETTINGS}

        run = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_config.py"],
                             cwd=REPO_ROOT, env=environment, capture_output=True, text=True, timeout=300)

        self.assertEqual(run.returncode, 0, run.stderr[-1500:])








############################################################
# TestCnIntegrationMiner
############################################################
#
# tests/integration_cn_miner.py against the fake pool: a
# refused share must be followed by a different one, and the
# negative check must hold out for the invalid-share refusal.
############################################################

@unittest.skipUnless(HAVE_CRYPTONIGHT, "py-cryptonight not installed (run inside the container)")
class TestCnIntegrationMiner(unittest.TestCase):






    ############################################################
    # run_miner
    ############################################################
    #
    # Runs the integration miner's main() against a fake pool
    # giving the submit replies in order, its output captured,
    # on a thread with a deadline so a hung exchange fails the
    # test instead of the run. The script leaves its socket for
    # the garbage collector, so the ResourceWarning that brings
    # is silenced here. Hands back the exit code and everything
    # the pool recorded.
    #
    # Used by:
    #   - the test cases of TestCnIntegrationMiner (below)
    ############################################################

    def run_miner(self, *submit_replies):
        from tests import integration_cn_miner

        pool = FakeCnPool(submit_replies)
        pool.start()
        outcome = {}

        def mine():
            with mock.patch.object(sys, "argv", ["integration_cn_miner", "127.0.0.1", str(pool.port), "60"]), \
                 contextlib.redirect_stdout(io.StringIO()), warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                outcome["code"] = integration_cn_miner.main()
                gc.collect()

        miner = threading.Thread(target=mine, daemon=True)
        miner.start()
        miner.join(timeout=90)
        self.assertFalse(miner.is_alive(), "the miner hung")
        return outcome.get("code"), pool.submissions






    ############################################################
    # test_a_refused_share_is_followed_by_a_different_one
    ############################################################
    #
    # After the pool refuses a share, mining the same job from
    # nonce zero again finds the same nonce and submits the
    # very same share once more — a duplicate no pool accepts.
    ############################################################

    @unittest.expectedFailure
    def test_a_refused_share_is_followed_by_a_different_one(self):
        code, submissions = self.run_miner(LOW_DIFFICULTY, ACCEPT, INVALID_SHARE)

        self.assertEqual(code, 0)
        self.assertNotEqual(submissions[0]["nonce"], submissions[1]["nonce"])






    ############################################################
    # test_the_wrong_share_must_be_refused_as_invalid
    ############################################################
    #
    # The deliberately wrong share is there to prove the pool
    # catches a lying result. A refusal for any other reason —
    # here a login problem — proves nothing, so the run must
    # fail; today any error counts as the refusal and the run
    # passes.
    ############################################################

    @unittest.expectedFailure
    def test_the_wrong_share_must_be_refused_as_invalid(self):
        code, _ = self.run_miner(ACCEPT, UNAUTHENTICATED)

        self.assertEqual(code, 1)








if __name__ == "__main__":
    unittest.main()
