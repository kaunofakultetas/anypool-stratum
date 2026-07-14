# -----------------------------------------------------------
#  [*] Coin — LTC (Litecoin)
#
#  Scrypt PoW with native segwit addresses and MWEB extension
#  block support. This is the reference definition the pool
#  was originally built and tested against (LTC testnet4).
#
#  Used by:
#    - coins/__init__.py — registered in the coin registry
# -----------------------------------------------------------

from anypool.coins.address import Bech32P2WPKH
from anypool.coins.base import CoinDefinition
from anypool.crypto.hashing import scrypt_pow_hash


LTC = CoinDefinition(
    name="LTC",
    algo="SCRYPT",
    pow_hash=scrypt_pow_hash,
    difficulty_1_target=0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    gbt_rules=["segwit", "mweb"],
    address_scheme=Bech32P2WPKH({
        "mainnet": "ltc",
        "testnet": "tltc",
    }),
    has_mweb=True,
)
