# -----------------------------------------------------------
#  [*] Pool Configuration
#
#  Every knob of the pool lives here and nowhere else. All
#  values are read from environment variables once, at import
#  time, so the rest of the codebase can simply do
#  `from anypool import config` and use plain attributes.
#
#  Per-coin properties (PoW function, address prefixes, GBT
#  rules, ...) do NOT live here — see the anypool/coins/
#  package. This module only knows WHICH coin was selected.
#
#  validate() should be called once on startup: it fails fast
#  with a clear message instead of letting a missing reward
#  address crash deep inside the coinbase builder.
#
#  Used by:
#    - main.py       — validate() on startup
#    - every module  — reads config attributes
# -----------------------------------------------------------

import os




# -----------------------------------------------------------
# Coin selection
# -----------------------------------------------------------
COIN = os.getenv("COIN", "LTC")
COIN_NETWORK = os.getenv("COIN_NETWORK", "testnet")


# -----------------------------------------------------------
# Full node RPC endpoint
# -----------------------------------------------------------
RPC_HOST = os.getenv("RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.getenv("RPC_PORT", "19332"))
RPC_USER = os.getenv("RPC_USER", "admin")
RPC_PASS = os.getenv("RPC_PASS", "admin")
RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}"


# -----------------------------------------------------------
# Coinbase transaction
# -----------------------------------------------------------
REWARD_ADDR = os.getenv("REWARD_ADDR")
COINBASE_MESSAGE = os.getenv("COINBASE_MESSAGE", "/AnyPool by VU Kaunas faculty/")


# -----------------------------------------------------------
# Pool settings
# -----------------------------------------------------------
STRATUM_PORT = int(os.getenv("STRATUM_PORT", "3333"))
POOL_DIFFICULTY = int(os.getenv("POOL_DIFFICULTY", "2048"))

# If the network difficulty drops below the pool difficulty,
# temporarily lower the pool difficulty to match it.
POLL_DIFF_DROPPER = os.getenv("POLL_DIFF_DROPPER", "false").lower() == "true"


# -----------------------------------------------------------
# Debugging (prints verbose boxed panels for every share/job)
# -----------------------------------------------------------
DEBUG = os.getenv("DEBUG", "false").lower() == "true"




# -----------------------------------------------------------
# validate
# -----------------------------------------------------------
#
# Called once from main() before anything else starts. Checks
# that the selected coin/network exists in the coin registry
# and that REWARD_ADDR is set and carries the right prefix,
# so a misconfigured pool dies immediately with a readable
# error instead of failing on the first block template.
#
# (The anypool.coins import is deliberately local — coins
# imports config, so a module-level import would be a cycle.)
#
# Used by:
#   - main.py — startup
# -----------------------------------------------------------
def validate() -> None:
    from anypool import coins

    if COIN not in coins.REGISTRY:
        raise SystemExit(f"[CONFIG] Unknown COIN '{COIN}'. Supported: {list(coins.REGISTRY.keys())}")

    coin = coins.get_coin(COIN)
    if COIN_NETWORK not in coin.networks():
        raise SystemExit(f"[CONFIG] Unknown COIN_NETWORK '{COIN_NETWORK}' for {COIN}. Supported: {coin.networks()}")

    if not REWARD_ADDR:
        raise SystemExit("[CONFIG] REWARD_ADDR environment variable is required (bech32 address for block rewards)")

    expected_prefix = coin.addr_prefix(COIN_NETWORK)
    if not REWARD_ADDR.lower().startswith(expected_prefix + "1"):
        raise SystemExit(f"[CONFIG] REWARD_ADDR '{REWARD_ADDR}' does not look like a {COIN} {COIN_NETWORK} address (expected prefix: {expected_prefix}1...)")
