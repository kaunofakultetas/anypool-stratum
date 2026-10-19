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
#    1. Create a module for it here, named after its ticker
#       symbol, holding a CoinDefinition — or a
#       CryptonoteCoinDefinition for a CryptoNote coin (see
#       base.py for the fields).
#    2. Add it to REGISTRY below.
#    3. Select it by setting the COIN environment variable
#       to that symbol. As long as the coin fits one of the
#       existing families, no family or stratum code needs
#       to change.
#
#  Used by:
#    - config.py            — validate()
#    - families/__init__.py — family pick at boot
#    - families/bitcoin/    — payout script, PoW hash,
#                             difficulty-1 target, GBT rules,
#                             version-rolling mask, MWEB
#                             flag and peg-in settings
#    - families/cryptonote/ — CN variant, reserve size
############################################################


from typing import Dict

from anypool.coins.base import CoinDefinition
from anypool.coins.btc import BTC
from anypool.coins.doge import DOGE
from anypool.coins.knf import KNF
from anypool.coins.ltc import LTC
from anypool.coins.ltl import LTL


# Every coin the pool can mine, keyed by the ticker symbol the
# COIN variable names. Typed object because the values are
# CoinDefinition or CryptonoteCoinDefinition instances.
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
# Looks a coin up by its ticker symbol; an unknown symbol
# raises KeyError. config.validate() checks the symbol
# against REGISTRY before it calls this, so at startup an
# unknown coin ends in a readable error instead. The return
# type says CoinDefinition, but a CryptoNote coin comes back
# as its CryptonoteCoinDefinition.
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
# The coin definition selected by the COIN environment
# variable — the one the pool is currently mining (for a
# CryptoNote coin a CryptonoteCoinDefinition, whatever the
# return type says). This is the accessor the family engines
# use everywhere.
#
# Used by:
#   - families/__init__.py — family pick at boot
#   - families/bitcoin/    — coinbase, shares, connection,
#                            server, runner, mweb
#   - families/cryptonote/ — server
############################################################

def active() -> CoinDefinition:
    from anypool import config
    return REGISTRY[config.COIN]
