############################################################
#  [*] Pool Configuration
#
#  Every pool-wide knob lives here. All values are read from
#  environment variables once, at import time, so every other
#  module simply imports this one and reads plain attributes.
#
#  Per-coin properties (PoW function, address prefixes, GBT
#  rules, ...) do NOT live here — see the anypool/coins/
#  package — and neither do the knobs only some coins have:
#  the MWEB peg-in settings belong to the coins with MWEB
#  (MwebPegin in coins/base.py). This module only knows WHICH
#  coin was selected.
#
#  validate() should be called once on startup: it fails fast
#  with a clear message instead of letting a missing reward
#  address crash deep inside the coinbase builder.
#
#  Used by:
#    - main.py              — validate() on startup
#    - coins/__init__.py    — active() reads COIN
#    - display.py           — DEBUG, the startup banner
#    - families/bitcoin/    — coinbase (REWARD_ADDR,
#                             COIN_NETWORK, COINBASE_MESSAGE),
#                             server (pool difficulty and
#                             its dropper), runner (port)
#    - families/cryptonote/ — server (REWARD_ADDR, pool
#                             difficulty and its dropper),
#                             runner (port)
#    - node/rpc.py          — RPC_URL, RPC_USER, RPC_PASS
#    - node/monero_rpc.py   — RPC_URL
#    - stratum/base.py      — DEBUG, the wire logging
############################################################


import os








############################################################
# Coin selection
############################################################

COIN = os.getenv("COIN", "LTC")
COIN_NETWORK = os.getenv("COIN_NETWORK", "testnet")








############################################################
# Full node RPC endpoint
############################################################

RPC_HOST = os.getenv("RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.getenv("RPC_PORT", "19332"))
RPC_USER = os.getenv("RPC_USER", "admin")
RPC_PASS = os.getenv("RPC_PASS", "admin")
RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}"








############################################################
# Coinbase transaction
############################################################

REWARD_ADDR = os.getenv("REWARD_ADDR")
COINBASE_MESSAGE = os.getenv("COINBASE_MESSAGE", "/AnyPool by VU Kaunas faculty/")








############################################################
# Pool settings
############################################################

STRATUM_PORT = int(os.getenv("STRATUM_PORT", "3333"))
POOL_DIFFICULTY = int(os.getenv("POOL_DIFFICULTY", "2048"))

# If the network difficulty drops below the pool difficulty,
# temporarily lower the pool difficulty to match it. The
# name says POLL, not POOL, and stays that way: it is the
# spelling the README and the sample compose file document.
POLL_DIFF_DROPPER = os.getenv("POLL_DIFF_DROPPER", "false").lower() == "true"








############################################################
# Debugging (prints verbose boxed panels for every share/job)
############################################################

DEBUG = os.getenv("DEBUG", "false").lower() == "true"








############################################################
# validate
############################################################
#
# Called once from main() before anything else starts. Checks
# that the selected coin/network exists in the coin registry
# and that REWARD_ADDR is set and fully decodes, checksum
# included, as an address of that coin and network, so a
# misconfigured pool dies immediately with a readable error
# instead of failing on the first block template. The coin's
# own settings are held to the same standard: a coin with
# MWEB judges its peg-in settings itself, and peg-in
# settings given for a coin without MWEB would do nothing,
# so they stop the pool rather than leave the operator
# believing a peg-in is set up.
#
# (The anypool.coins imports are deliberately local:
# coins/__init__.py imports config as well, inside active(),
# and with both sides function-local the two modules can
# never meet half-initialized in an import cycle.)
#
# Used by:
#   - main.py — startup
############################################################

def validate() -> None:
    from anypool import coins
    from anypool.coins.base import MwebPegin

    if COIN not in coins.REGISTRY:
        raise SystemExit(f"[CONFIG] Unknown COIN '{COIN}'. Supported: {list(coins.REGISTRY.keys())}")

    coin = coins.get_coin(COIN)
    if COIN_NETWORK not in coin.networks():
        raise SystemExit(f"[CONFIG] Unknown COIN_NETWORK '{COIN_NETWORK}' for {COIN}. Supported: {coin.networks()}")

    if not REWARD_ADDR:
        raise SystemExit("[CONFIG] REWARD_ADDR environment variable is required (address for block rewards)")

    # Full decode (checksum and all) through the coin's address
    # scheme. For the Bitcoin family that is the exact code path
    # the coinbase builder takes later, so an address that
    # passes here cannot fail deeper in; a CryptoNote daemon
    # parses the address again with its own code.
    try:
        coin.address_scheme.validate_address(REWARD_ADDR, COIN_NETWORK)
    except ValueError as e:
        raise SystemExit(f"[CONFIG] REWARD_ADDR '{REWARD_ADDR}' is not a valid {COIN} {COIN_NETWORK} address: {e}")

    pegin = getattr(coin, "mweb_pegin", None)
    if pegin is None and MwebPegin.from_environment().is_set():
        raise SystemExit(f"[CONFIG] MWEB_PEGIN_* is set, but {COIN} has no MWEB")
    if pegin is not None and pegin.problem():
        raise SystemExit(f"[CONFIG] {pegin.problem()}")
