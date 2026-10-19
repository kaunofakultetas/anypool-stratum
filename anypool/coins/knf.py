############################################################
#  [*] Coin — KNF (KnfCoin)
#
#  KnfCoin is a Litecoin fork, so it inherits Scrypt PoW,
#  Litecoin's difficulty-1 target, native segwit addresses,
#  the segwit + mweb template rules and MWEB itself, with the
#  operator's MWEB peg-in settings — only the address
#  prefixes differ.
#
#  Used by:
#    - coins/__init__.py — registered in the coin registry
############################################################


from anypool.coins.address import Bech32P2WPKH
from anypool.coins.base import CoinDefinition, MwebPegin
from anypool.crypto.hashing import scrypt_pow_hash


KNF = CoinDefinition(
    name="KNF",
    algo="SCRYPT",
    pow_hash=scrypt_pow_hash,
    difficulty_1_target=0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    gbt_rules=["segwit", "mweb"],
    address_scheme=Bech32P2WPKH({
        "mainnet": "knf",
        "testnet": "tknf",
    }),
    has_mweb=True,
    mweb_pegin=MwebPegin.from_environment(),
)
