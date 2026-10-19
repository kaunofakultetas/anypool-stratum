############################################################
#  [*] Test Suite Setup
#
#  Pins the pool's environment for the tests, so they are
#  deterministic no matter what the surrounding container
#  or shell has configured. config.py reads os.environ once,
#  at import time, so a pin only counts when it lands before
#  config.py is first imported.
#
#  The values match the real KNF mainnet pool that mined
#  block 1777 on 2026-07-14, so the block 1777 vectors in
#  tests/vectors.py — taken from that pool's server logs and
#  accepted by the network — are known-good end to end.
#
#  The suite runs under unittest discovery started in this
#  directory, with the repository root as the working
#  directory, inside a stratum container — its image has
#  scrypt and the other dependencies installed. Discovery
#  started here imports the test modules under their bare
#  names, so this file runs only when the first of them
#  imports something from the tests package: test_bech32.py
#  in a full run, before anything has imported config.py.
#  A discovery run narrowed by file pattern to one module
#  that imports pool code ahead of its tests import (many
#  do, and test_config.py has no tests import at all) lets
#  config.py read the container's real environment first,
#  and the pins below land too late.
#
#  Used by:
#    - every test module that imports from the tests package
#      (a vectors module or another test module) — the first
#      such import of a run executes this file
############################################################


import os


os.environ["COIN"] = "KNF"
os.environ["COIN_NETWORK"] = "mainnet"
os.environ["REWARD_ADDR"] = "knf1q6v5tfdrvaunzz60c6as9fx9dttzc98j435ll4a"
os.environ["COINBASE_MESSAGE"] = "/Public Miner/"
os.environ["POOL_DIFFICULTY"] = "100000"
os.environ["DEBUG"] = "false"

# Pinned OFF so the difficulty-clamp tests see the plain math:
# on a service running with POLL_DIFF_DROPPER on, the dropper
# would cap requested difficulties at the network difficulty
# first. The one test that wants the dropper ON patches the
# config attribute for its own scope (test_cn_server.py).
os.environ["POLL_DIFF_DROPPER"] = "false"
