############################################################
#  [*] Address Schemes
#
#  How a coin validates the operator's REWARD_ADDR — and,
#  for the Bitcoin family, turns it into the coinbase payout
#  scriptPubKey. Three schemes cover every coin this pool
#  targets:
#
#    Bech32P2WPKH — native segwit addresses ("ltc1...",
#                   "knf1..."), producing a P2WPKH script.
#    Base58P2PKH  — legacy addresses of older forks with no
#                   segwit (Dogecoin "D...", etc.),
#                   producing a P2PKH script.
#    CryptoNoteAddress — CryptoNote addresses ("4...");
#                   validate-only, the daemon builds the
#                   coinbase itself.
#
#  A scheme is a validate_address(addr, network) callable
#  plus the list of networks it knows version bytes/prefixes
#  for (the Bitcoin schemes add payout_script) —
#  CoinDefinition holds one and the rest of the pool never
#  asks which format the address is in.
#
#  Used by:
#    - coins/base.py       — the address_scheme field
#    - coins/btc.py, ltc.py, doge.py, knf.py, ltl.py
#    - families/bitcoin/coinbase.py  — payout output construction
#    - config.py           — validate() REWARD_ADDR check
############################################################


from typing import Dict, List

from anypool.crypto.base58 import p2pkh_script_for_address
from anypool.crypto.bech32 import p2wpkh_script_for_address








class Bech32P2WPKH:






    ############################################################
    # __init__
    ############################################################
    #
    # Takes the bech32 human-readable prefix per network,
    # e.g. {"mainnet": "knf", "testnet": "tknf"}.
    #
    # Used by:
    #   - coins/btc.py, coins/ltc.py, coins/knf.py
    ############################################################

    def __init__(self, hrp_by_network: Dict[str, str]):
        self.hrp_by_network = hrp_by_network






    ############################################################
    # networks
    ############################################################
    #
    # Network names this scheme has a prefix for.
    #
    # Used by:
    #   - coins/base.py — CoinDefinition.networks()
    ############################################################

    def networks(self) -> List[str]:
        return list(self.hrp_by_network.keys())






    ############################################################
    # payout_script
    ############################################################
    #
    # Native segwit address -> P2WPKH scriptPubKey hex.
    # Raises ValueError for wrong-network or malformed input.
    #
    # Used by:
    #   - families/bitcoin/coinbase.py, config.py
    ############################################################

    def payout_script(self, addr: str, network: str) -> str:
        return p2wpkh_script_for_address(addr, self.hrp_by_network[network])






    ############################################################
    # validate_address
    ############################################################
    #
    # Family-neutral validation entrypoint (config.validate
    # calls this on every scheme): valid when a payout script
    # can be derived.
    #
    # Used by:
    #   - config.py — validate() REWARD_ADDR check
    ############################################################

    def validate_address(self, addr: str, network: str) -> None:
        self.payout_script(addr, network)








class Base58P2PKH:






    ############################################################
    # __init__
    ############################################################
    #
    # Takes the base58check version byte per network,
    # e.g. Dogecoin: {"mainnet": 0x1e, "testnet": 0x71}.
    #
    # Used by:
    #   - coins/doge.py
    ############################################################

    def __init__(self, version_by_network: Dict[str, int]):
        self.version_by_network = version_by_network






    ############################################################
    # networks
    ############################################################
    #
    # Network names this scheme has a version byte for.
    #
    # Used by:
    #   - coins/base.py — CoinDefinition.networks()
    ############################################################

    def networks(self) -> List[str]:
        return list(self.version_by_network.keys())






    ############################################################
    # payout_script
    ############################################################
    #
    # Legacy address -> P2PKH scriptPubKey hex.
    # Raises ValueError for wrong-network or malformed input.
    #
    # Used by:
    #   - families/bitcoin/coinbase.py, config.py
    ############################################################

    def payout_script(self, addr: str, network: str) -> str:
        return p2pkh_script_for_address(addr, self.version_by_network[network])






    ############################################################
    # validate_address
    ############################################################
    #
    # Family-neutral validation entrypoint (config.validate
    # calls this on every scheme): valid when a payout script
    # can be derived.
    #
    # Used by:
    #   - config.py — validate() REWARD_ADDR check
    ############################################################

    def validate_address(self, addr: str, network: str) -> None:
        self.payout_script(addr, network)








class CryptoNoteAddress:






    ############################################################
    # __init__
    ############################################################
    #
    # Takes the address prefix varint per network, e.g.
    # {"mainnet": 18, "testnet": 53}. Unlike the Bitcoin
    # schemes there is no payout SCRIPT — the daemon builds
    # the coinbase itself from the raw address string — so
    # this scheme only knows how to VALIDATE an address.
    #
    # Used by:
    #   - coins/ltl.py
    ############################################################

    def __init__(self, prefix_by_network: Dict[str, int]):
        self.prefix_by_network = prefix_by_network






    ############################################################
    # networks
    ############################################################
    #
    # Network names this scheme has a prefix for.
    #
    # Used by:
    #   - coins/base.py — CryptonoteCoinDefinition.networks()
    ############################################################

    def networks(self) -> List[str]:
        return list(self.prefix_by_network.keys())






    ############################################################
    # validate_address
    ############################################################
    #
    # Full CryptoNote address check: base58 decode, keccak
    # checksum, network prefix, and the 64-byte spend+view
    # key payload. Raises ValueError with the reason.
    #
    # Used by:
    #   - config.py — validate() REWARD_ADDR check
    ############################################################

    def validate_address(self, addr: str, network: str) -> None:
        from anypool.crypto.cn_base58 import decode_addr

        prefix, payload = decode_addr(addr)

        expected = self.prefix_by_network[network]
        if prefix != expected:
            raise ValueError(f"address prefix {prefix} does not match {network} prefix {expected}")
        if len(payload) != 64:
            raise ValueError(f"address payload is {len(payload)} bytes, expected 64 (spend+view keys)")
