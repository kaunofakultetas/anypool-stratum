# -----------------------------------------------------------
#  [*] Coin Registry
#
#  Central lookup of every coin this pool can mine. Replaces
#  the old flat COINS_CONFIG dict: instead of scattering
#  per-coin knowledge (PoW function, targets, prefixes, GBT
#  rules) across the codebase, each coin lives in its own
#  definition module and the rest of the pool only ever asks
#  the registry.
#
#  To support a new coin:
#
#    1. Create anypool/coins/<symbol>.py with a
#       CoinDefinition (see base.py for the fields).
#    2. Add it to REGISTRY below.
#    3. Set COIN=<SYMBOL> in the environment. Done — no
#       mining or stratum code needs to change.
#
#  Used by:
#    - config.py           — validate()
#    - mining/coinbase.py  — address prefix for payouts
#    - mining/shares.py    — PoW hash function
#    - stratum/server.py   — difficulty-1 target, GBT rules
# -----------------------------------------------------------

from typing import Dict

from anypool.coins.base import CoinDefinition
from anypool.coins.doge import DOGE
from anypool.coins.knf import KNF
from anypool.coins.ltc import LTC


REGISTRY: Dict[str, CoinDefinition] = {
    "KNF": KNF,
    "LTC": LTC,
    "DOGE": DOGE,
}




# -----------------------------------------------------------
# get_coin
# -----------------------------------------------------------
#
# Looks a coin up by its ticker symbol. KeyError on unknown
# symbols — config.validate() turns that into a readable
# startup error before anything else runs.
#
# Used by:
#   - coins/__init__.py — active()
#   - config.py         — validate()
# -----------------------------------------------------------
def get_coin(symbol: str) -> CoinDefinition:
    return REGISTRY[symbol]










# -----------------------------------------------------------
# active
# -----------------------------------------------------------
#
# The CoinDefinition selected by the COIN environment
# variable — the one the pool is currently mining. This is
# the accessor the mining/stratum layers use everywhere.
#
# Used by:
#   - mining/coinbase.py, mining/shares.py, stratum/server.py
# -----------------------------------------------------------
def active() -> CoinDefinition:
    from anypool import config
    return REGISTRY[config.COIN]
