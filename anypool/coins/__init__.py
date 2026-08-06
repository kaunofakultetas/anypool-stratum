############################################################
#  [*] Coin Registry
#
#  Central lookup of every coin this pool can mine. All
#  per-coin knowledge (PoW function, targets, prefixes, GBT
#  rules, family) lives in one definition module per coin,
#  and the rest of the pool only ever asks the registry.
#
#  To support a new coin:
#
#    1. Create anypool/coins/<symbol>.py with a
#       CoinDefinition (see base.py for the fields).
#    2. Add it to REGISTRY below.
#    3. Set COIN=<SYMBOL> in the environment. Done — no
#       family or stratum code needs to change.
#
#  Used by:
#    - config.py            — validate()
#    - families/__init__.py — family pick at boot
#    - families/bitcoin/    — payout script, PoW hash,
#                             difficulty-1 target, GBT rules
#    - families/cryptonote/ — address scheme, CN variant,
#                             reserve size
############################################################


from typing import Dict

from anypool.coins.base import CoinDefinition
from anypool.coins.btc import BTC
from anypool.coins.doge import DOGE
from anypool.coins.knf import KNF
from anypool.coins.ltc import LTC
from anypool.coins.ltl import LTL


REGISTRY: Dict[str, object] = {
    "KNF": KNF,
    "LTL": LTL,
    "LTC": LTC,
    "DOGE": DOGE,
    "BTC": BTC,
}








############################################################
# get_coin
############################################################
#
# Looks a coin up by its ticker symbol. KeyError on unknown
# symbols — config.validate() turns that into a readable
# startup error before anything else runs.
#
# Used by:
#   - config.py     — validate()
#   - tests/test_coins.py, tests/test_hashing.py
############################################################

def get_coin(symbol: str) -> CoinDefinition:
    return REGISTRY[symbol]








############################################################
# active
############################################################
#
# The CoinDefinition selected by the COIN environment
# variable — the one the pool is currently mining. This is
# the accessor the family engines use everywhere.
#
# Used by:
#   - families/__init__.py — family pick at boot
#   - families/bitcoin/    — coinbase, shares, connection,
#                            server, runner
#   - families/cryptonote/ — server
############################################################

def active() -> CoinDefinition:
    from anypool import config
    return REGISTRY[config.COIN]
