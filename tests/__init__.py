############################################################
#  [*] Test Suite Setup
#
#  Pins the environment BEFORE any anypool module is imported
#  (config.py reads os.environ at import time), so the tests
#  are deterministic no matter what the surrounding container
#  or shell has configured.
#
#  The values match the real KNF mainnet pool that mined
#  block 1777 on 2026-07-14 — all test vectors in this suite
#  come from that block's server logs, which the network
#  accepted, so they are known-good end to end.
#
#  Run inside the stratum container (has scrypt installed),
#  e.g. bitlitas-stratum or knfcoin-stratum:
#
#    docker exec <stratum-container> python -m unittest discover -s tests -v
#
#  Used by:
#    - unittest — imported automatically before test modules
############################################################


import os


os.environ["COIN"] = "KNF"
os.environ["COIN_NETWORK"] = "mainnet"
os.environ["REWARD_ADDR"] = "knf1q6v5tfdrvaunzz60c6as9fx9dttzc98j435ll4a"
os.environ["COINBASE_MESSAGE"] = "/Public Miner/"
os.environ["POOL_DIFFICULTY"] = "100000"
os.environ["DEBUG"] = "false"

# Pinned OFF so the difficulty-clamp tests see the plain math:
# on a service running POLL_DIFF_DROPPER=True the dropper would
# cap requested difficulties at the network difficulty first.
# The one test that wants the dropper ON patches the config
# attribute for its own scope (test_cn_server.py).
os.environ["POLL_DIFF_DROPPER"] = "false"
