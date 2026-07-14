# -----------------------------------------------------------
#  [*] Coin — DOGE (Dogecoin)
#
#  An OLDER Bitcoin Core fork: Scrypt PoW like Litecoin, but
#  no segwit, no MWEB, and legacy base58check addresses
#  ("D..." on mainnet) — which makes it the reference
#  definition for pre-segwit forks in general:
#
#    - Base58P2PKH address scheme (P2PKH payout script)
#    - empty gbt_rules (old daemons predate the rules param)
#    - has_mweb=False (no extension tail in the block)
#
#  NOTE: solo mining only. Dogecoin is usually merge-mined
#  with Litecoin (AuxPoW); this pool mines standalone blocks,
#  which the network also accepts.
#
#  ⚠ Not yet validated against a live Dogecoin node — mine
#  one testnet block and freeze its values into tests/
#  vectors before trusting it on mainnet.
#
#  Used by:
#    - coins/__init__.py — registered in the coin registry
# -----------------------------------------------------------

from anypool.coins.address import Base58P2PKH
from anypool.coins.base import CoinDefinition
from anypool.crypto.hashing import scrypt_pow_hash


DOGE = CoinDefinition(
    name="DOGE",
    algo="SCRYPT",
    pow_hash=scrypt_pow_hash,
    difficulty_1_target=0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    gbt_rules=[],
    address_scheme=Base58P2PKH({
        "mainnet": 0x1e,   # addresses start with "D"
        "testnet": 0x71,   # addresses start with "n"
    }),
    has_mweb=False,
)
