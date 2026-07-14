# -----------------------------------------------------------
#  [*] Coin Definition Base
#
#  The contract every supported coin must fulfill. A coin is
#  fully described by one frozen CoinDefinition instance:
#  which PoW function it uses, what its difficulty-1 target
#  is, which getblocktemplate rules to request, and which
#  bech32 prefix its addresses carry on each network.
#
#  Adding a new coin never touches the mining/stratum code —
#  create anypool/coins/<symbol>.py with one CoinDefinition
#  and register it in anypool/coins/__init__.py.
#
#  Used by:
#    - coins/knf.py, coins/ltc.py — instantiate it
#    - coins/__init__.py          — registry typing
# -----------------------------------------------------------

from dataclasses import dataclass, field
from typing import Callable, Dict, List




@dataclass(frozen=True)
class CoinDefinition:

    # Ticker symbol, e.g. "KNF"
    name: str

    # Human-readable PoW algorithm name, e.g. "SCRYPT"
    algo: str

    # The function hashing an 80-byte header into the PoW
    # hash (big-endian hex, comparable against a target)
    pow_hash: Callable[[bytes], str]

    # Reference target at difficulty 1 for this algorithm:
    #   target = difficulty_1_target // difficulty
    difficulty_1_target: int

    # Rules to request from getblocktemplate
    gbt_rules: List[str]

    # network name -> bech32 address prefix (hrp)
    addr_prefixes: Dict[str, str] = field(default_factory=dict)






    # -----------------------------------------------------------
    # addr_prefix
    # -----------------------------------------------------------
    #
    # The bech32 prefix of this coin on the given network,
    # e.g. KNF mainnet -> "knf", LTC testnet -> "tltc".
    #
    # Used by:
    #   - config.py            — validate()
    #   - mining/coinbase.py   — payout script construction
    # -----------------------------------------------------------
    def addr_prefix(self, network: str) -> str:
        return self.addr_prefixes[network]






    # -----------------------------------------------------------
    # networks
    # -----------------------------------------------------------
    #
    # The network names this coin supports ("mainnet", ...).
    #
    # Used by:
    #   - config.py — validate()
    # -----------------------------------------------------------
    def networks(self) -> List[str]:
        return list(self.addr_prefixes.keys())
