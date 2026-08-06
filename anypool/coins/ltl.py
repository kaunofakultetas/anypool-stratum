############################################################
#  [*] Coin — LTL (Bitlitas)
#
#  Bitlitas is a CryptoNote coin (a Monero v0.11 'Helium
#  Hydra' fork from 2018), so it belongs to the cryptonote
#  family: XMRig-style login/job/submit stratum, block
#  template blobs from the daemon, CryptoNight PoW.
#
#  The chain froze at block major version 1 in Feb 2018 and
#  is being revived — major version 1 means classic
#  CryptoNight (cn/0), no variants.
#
#  Address prefixes come straight from the coin's
#  cryptonote_config.h: 18 on mainnet (addresses start with
#  '4', same prefix Monero uses), 53 on testnet.
#
#  Used by:
#    - coins/__init__.py — registered in the coin registry
############################################################


from anypool.coins.address import CryptoNoteAddress
from anypool.coins.base import CryptonoteCoinDefinition


LTL = CryptonoteCoinDefinition(
    name="LTL",
    algo="CRYPTONIGHT",
    cn_variant=0,
    address_scheme=CryptoNoteAddress({
        "mainnet": 18,
        "testnet": 53,
    }),
    reserve_size=16,
)
