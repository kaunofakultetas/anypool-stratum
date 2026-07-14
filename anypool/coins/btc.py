# -----------------------------------------------------------
#  [*] Coin — BTC (Bitcoin)
#
#  The original. SHA256d PoW — the PoW hash IS the block
#  hash, unlike Scrypt coins where the two differ. Native
#  segwit (bech32 "bc1q..." addresses, P2WPKH payout script)
#  and the mandatory "segwit" GBT rule: Bitcoin Core refuses
#  getblocktemplate without it.
#
#  Three networks:
#    mainnet  — "bc1q..." addresses
#    testnet3 — "tb1q..." addresses (original testnet)
#    testnet4 — "tb1q..." addresses (BIP94 testnet; same
#               address prefixes as testnet3, only the chain
#               and the node differ)
#
#  The difficulty-1 target is Bitcoin's classic bdiff
#  reference (0x1d00ffff expanded). Note it is 2^16 times
#  HARDER than the scrypt coins' diff-1 in this registry —
#  SHA256 miners expect exactly this convention from
#  mining.set_difficulty, so pool difficulties for BTC are
#  numerically much smaller than for scrypt at an equal
#  share rate.
#
#  ⚠ Not yet validated against a live block — mine one
#  testnet3/testnet4 block and freeze its values into tests/
#  vectors before trusting it on mainnet.
#
#  Used by:
#    - coins/__init__.py — registered in the coin registry
# -----------------------------------------------------------

from anypool.coins.address import Bech32P2WPKH
from anypool.coins.base import CoinDefinition
from anypool.crypto.hashing import sha256d_pow_hash


BTC = CoinDefinition(
    name="BTC",
    algo="SHA256D",
    pow_hash=sha256d_pow_hash,
    difficulty_1_target=0x00000000FFFF0000000000000000000000000000000000000000000000000000,
    gbt_rules=["segwit"],
    address_scheme=Bech32P2WPKH({
        "mainnet": "bc",
        "testnet3": "tb",
        "testnet4": "tb",
    }),
    has_mweb=False,

    # Standard BIP320 mask: bits 13..28 are free for AsicBoost
    # version rolling — required by essentially every modern
    # SHA256 ASIC.
    version_rolling_mask=0x1FFFE000,
)
