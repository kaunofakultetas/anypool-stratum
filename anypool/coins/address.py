# -----------------------------------------------------------
#  [*] Address Schemes
#
#  How a coin turns the operator's REWARD_ADDR into the
#  coinbase payout scriptPubKey. Two schemes cover every
#  Bitcoin Core fork this pool targets:
#
#    Bech32P2WPKH — native segwit addresses ("ltc1...",
#                   "knf1..."), producing a P2WPKH script.
#    Base58P2PKH  — legacy addresses of older forks with no
#                   segwit (Dogecoin "D...", etc.),
#                   producing a P2PKH script.
#
#  A scheme is just a payout_script(addr, network) callable
#  plus the list of networks it knows version bytes/prefixes
#  for — CoinDefinition holds one and the rest of the pool
#  never asks which format the address is in.
#
#  Used by:
#    - coins/base.py       — CoinDefinition.address_scheme
#    - coins/knf.py, ltc.py, doge.py — pick their scheme
#    - mining/coinbase.py  — payout output construction
#    - config.py           — validate() REWARD_ADDR check
# -----------------------------------------------------------

from typing import Dict, List

from anypool.crypto.base58 import p2pkh_script_for_address
from anypool.crypto.bech32 import p2wpkh_script_for_address




class Bech32P2WPKH:


    # -----------------------------------------------------------
    # __init__
    # -----------------------------------------------------------
    #
    # Takes the bech32 human-readable prefix per network,
    # e.g. {"mainnet": "knf", "testnet": "tknf"}.
    #
    # Used by:
    #   - coins/knf.py, coins/ltc.py
    # -----------------------------------------------------------
    def __init__(self, hrp_by_network: Dict[str, str]):
        self.hrp_by_network = hrp_by_network






    # -----------------------------------------------------------
    # networks
    # -----------------------------------------------------------
    #
    # Network names this scheme has a prefix for.
    #
    # Used by:
    #   - coins/base.py — CoinDefinition.networks()
    # -----------------------------------------------------------
    def networks(self) -> List[str]:
        return list(self.hrp_by_network.keys())






    # -----------------------------------------------------------
    # payout_script
    # -----------------------------------------------------------
    #
    # Native segwit address -> P2WPKH scriptPubKey hex.
    # Raises ValueError for wrong-network or malformed input.
    #
    # Used by:
    #   - mining/coinbase.py, config.py
    # -----------------------------------------------------------
    def payout_script(self, addr: str, network: str) -> str:
        return p2wpkh_script_for_address(addr, self.hrp_by_network[network])










class Base58P2PKH:


    # -----------------------------------------------------------
    # __init__
    # -----------------------------------------------------------
    #
    # Takes the base58check version byte per network,
    # e.g. Dogecoin: {"mainnet": 0x1e, "testnet": 0x71}.
    #
    # Used by:
    #   - coins/doge.py
    # -----------------------------------------------------------
    def __init__(self, version_by_network: Dict[str, int]):
        self.version_by_network = version_by_network






    # -----------------------------------------------------------
    # networks
    # -----------------------------------------------------------
    #
    # Network names this scheme has a version byte for.
    #
    # Used by:
    #   - coins/base.py — CoinDefinition.networks()
    # -----------------------------------------------------------
    def networks(self) -> List[str]:
        return list(self.version_by_network.keys())






    # -----------------------------------------------------------
    # payout_script
    # -----------------------------------------------------------
    #
    # Legacy address -> P2PKH scriptPubKey hex.
    # Raises ValueError for wrong-network or malformed input.
    #
    # Used by:
    #   - mining/coinbase.py, config.py
    # -----------------------------------------------------------
    def payout_script(self, addr: str, network: str) -> str:
        return p2pkh_script_for_address(addr, self.version_by_network[network])
