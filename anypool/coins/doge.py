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
#  which the network also accepts. Version rolling must stay
#  disabled: the header version bits encode the AuxPoW chain
#  id, so they are not free for miners to flip.
#
#  Validated against a live node (testnet, dogecoind 1.14.7).
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
