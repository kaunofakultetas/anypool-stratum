############################################################
#  [*] Address Schemes
#
#  How a coin validates the operator's REWARD_ADDR — and,
#  for the Bitcoin family, turns it into the coinbase payout
#  scriptPubKey. Three schemes cover every coin this pool
#  targets:
#
#    Bech32P2WPKH      — native segwit (bech32) addresses of
#                        BTC, LTC and KNF, paid through a
#                        P2WPKH script.
#    Base58P2PKH       — legacy base58check addresses of
#                        older forks with no segwit (DOGE),
#                        paid through a P2PKH script.
#    CryptoNoteAddress — CryptoNote addresses (LTL);
#                        validate-only, the daemon builds
#                        the coinbase itself.
#
#  Every scheme offers validate_address, which takes the
#  address and the network name, and networks, which lists
#  the networks it knows version bytes or prefixes for; the
#  Bitcoin schemes add payout_script. The coin definition
#  holds one, and the rest of the pool never asks which
#  format the address is in.
#
#  Used by:
#    - coins/btc.py, doge.py, knf.py, ltc.py, ltl.py — one
#      scheme each
#    - coins/base.py — the address_scheme field, networks()
#    - families/bitcoin/coinbase.py — the payout output
#    - config.py — validate(), the REWARD_ADDR check
############################################################


from typing import Dict, List

from anypool.crypto.base58 import p2pkh_script_for_address
from anypool.crypto.bech32 import p2wpkh_script_for_address








############################################################
# Bech32P2WPKH
############################################################
#
# The address scheme of the segwit coins: the reward address
# is a native segwit (bech32, witness version 0) address,
# and the coinbase pays it through a P2WPKH script. Networks
# differ only in the address's human-readable prefix, so the
# scheme holds nothing but that prefix per network — the
# decoding itself lives in crypto/bech32.py.
#
# Used by:
#   - coins/btc.py, coins/knf.py, coins/ltc.py — their
#     address_scheme
#   - families/bitcoin/coinbase.py — payout_script()
#   - config.py — validate(), through validate_address()
############################################################

class Bech32P2WPKH:






    ############################################################
    # __init__
    ############################################################
    #
    # Takes the bech32 human-readable prefix for each network
    # the coin runs on, keyed by the network name COIN_NETWORK
    # selects.
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
    # Turns a native segwit address into the P2WPKH
    # scriptPubKey, as hex, that the coinbase pays. Raises
    # ValueError for wrong-network or malformed input — bar
    # the two malformed shapes p2wpkh_script_for_address()
    # in crypto/bech32.py lets escape as other errors.
    #
    # Used by:
    #   - families/bitcoin/coinbase.py — build_coinbase_parts(),
    #     the payout output
    #   - validate_address() (below)
    ############################################################

    def payout_script(self, addr: str, network: str) -> str:
        return p2wpkh_script_for_address(addr, self.hrp_by_network[network])






    ############################################################
    # validate_address
    ############################################################
    #
    # The family-neutral check config.validate() runs on
    # whichever scheme the selected coin has: an address is
    # valid when a payout script can be derived from it.
    #
    # Used by:
    #   - config.py — validate(), the REWARD_ADDR check
    ############################################################

    def validate_address(self, addr: str, network: str) -> None:
        self.payout_script(addr, network)








############################################################
# Base58P2PKH
############################################################
#
# The address scheme of the older forks that never adopted
# segwit: the reward address is a legacy base58check
# address, and the coinbase pays it through a P2PKH script.
# Networks differ only in the version byte at the front of
# the address, so the scheme holds nothing but that byte per
# network — the decoding itself lives in crypto/base58.py.
#
# Used by:
#   - coins/doge.py — its address_scheme
#   - families/bitcoin/coinbase.py — payout_script()
#   - config.py — validate(), through validate_address()
############################################################

class Base58P2PKH:






    ############################################################
    # __init__
    ############################################################
    #
    # Takes the base58check version byte for each network the
    # coin runs on, keyed by the network name COIN_NETWORK
    # selects.
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
    # Turns a legacy address into the P2PKH scriptPubKey, as
    # hex, that the coinbase pays. Raises ValueError for
    # wrong-network or malformed input.
    #
    # Used by:
    #   - families/bitcoin/coinbase.py — build_coinbase_parts(),
    #     the payout output
    #   - validate_address() (below)
    ############################################################

    def payout_script(self, addr: str, network: str) -> str:
        return p2pkh_script_for_address(addr, self.version_by_network[network])






    ############################################################
    # validate_address
    ############################################################
    #
    # The family-neutral check config.validate() runs on
    # whichever scheme the selected coin has: an address is
    # valid when a payout script can be derived from it.
    #
    # Used by:
    #   - config.py — validate(), the REWARD_ADDR check
    ############################################################

    def validate_address(self, addr: str, network: str) -> None:
        self.payout_script(addr, network)








############################################################
# CryptoNoteAddress
############################################################
#
# The address scheme of the CryptoNote family. The pool
# hands the raw address string to the daemon, which builds
# the coinbase from it, so there is no payout SCRIPT to
# derive: this scheme only VALIDATES the reward address —
# checksum, network prefix and key payload — so a mistyped
# address stops the pool at startup with a readable error.
# Networks differ only in the prefix varint at the front of
# the address.
#
# Used by:
#   - coins/ltl.py — its address_scheme
#   - config.py — validate(), through validate_address()
############################################################

class CryptoNoteAddress:






    ############################################################
    # __init__
    ############################################################
    #
    # Takes the address prefix (the varint at the front of
    # every address) for each network the coin runs on, keyed
    # by the network name COIN_NETWORK selects.
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
    # Full CryptoNote address check: block-base58 decode,
    # keccak checksum, network prefix, and the 64-byte payload
    # of the public spend and view keys. Raises ValueError
    # with the reason.
    #
    # Used by:
    #   - config.py — validate(), the REWARD_ADDR check
    ############################################################

    def validate_address(self, addr: str, network: str) -> None:
        from anypool.crypto.cn_base58 import decode_addr

        prefix, payload = decode_addr(addr)

        expected = self.prefix_by_network[network]
        if prefix != expected:
            raise ValueError(f"address prefix {prefix} does not match {network} prefix {expected}")
        if len(payload) != 64:
            raise ValueError(f"address payload is {len(payload)} bytes, expected 64 (spend+view keys)")
