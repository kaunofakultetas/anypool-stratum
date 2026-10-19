############################################################
#  [*] Coin — LTC (Litecoin)
#
#  Scrypt PoW with native segwit addresses and MWEB extension
#  block support, the operator's MWEB peg-in settings
#  included — the fully-featured end of the Bitcoin family in
#  this registry, and the reference definition for modern
#  Litecoin-lineage forks (see knf.py for one).
#
#  Used by:
#    - coins/__init__.py — registered in the coin registry
############################################################


from anypool.coins.address import Bech32P2WPKH
from anypool.coins.base import CoinDefinition, MwebPegin
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
    mweb_pegin=MwebPegin.from_environment(),
)
