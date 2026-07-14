# -----------------------------------------------------------
#  [*] Known-Good Test Vectors
#
#  Two accepted blocks, both captured from the pool's own logs
#  on 2026-07-14 ("[SUBMIT] Block ACCEPTED by network!"):
#
#    - KNF mainnet block 1777 (Scrypt, cgminer 4.9.0,
#      coinbase-only block, empty merkle branch)
#    - BTC testnet3 block 5062063 (SHA256d, cgminer 4.4.2,
#      8 transactions, 4-level merkle branch, mined during a
#      testnet 20-minute min-difficulty window)
#
#  That network acceptance is what makes these vectors
#  trustworthy: if the code reproduces every intermediate
#  value below, it produces byte-identical blocks to the code
#  that demonstrably worked on a live chain.
#
#  Used by:
#    - tests/test_hashing.py, test_merkle.py, test_coinbase.py,
#      test_jobs.py, test_shares.py, test_blocks.py,
#      test_btc_block.py
# -----------------------------------------------------------


# -----------------------------------------------------------
# The block template as getblocktemplate reported it
# (transactions list was empty — coinbase-only block)
# -----------------------------------------------------------
TEMPLATE = {
    "version": 0x20000000,
    "previousblockhash": "96fbd8c5a13bc5b07d791d00dbd696e28db358d3b14b9ee9715c5c9a76240bb0",
    "bits": "1c3fffc0",
    "curtime": 0x6a5639fc,
    "height": 1777,
    "coinbasevalue": 5000000000,
    "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
    "target": "000000003fffc000000000000000000000000000000000000000000000000000",
    "transactions": [],
}


# -----------------------------------------------------------
# The job as the pool cut it from that template
# -----------------------------------------------------------
JOB_PREVHASH_WIRE = "76240bb0715c5c9ab14b9ee98db358d3dbd696e27d791d00a13bc5b096fbd8c5"
JOB_VERSION = "20000000"
JOB_NBITS = "1c3fffc0"
JOB_NTIME = "6a5639fc"

COINB1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1902f106"
COINB2 = ("2f5075626c6963204d696e65722fffffffff0200f2052a01000000160014"
          "d328b4b46cef262169f8d7605498ad5ac5829e550000000000000000266a"
          "24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48b"
          "ebd836974e8cf900000000")

# Full (witness) serialization only differs in coinb1 (segwit
# marker+flag after the version) and coinb2 (witness stack
# before the locktime)
COINB1_FULL = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff1902f106"

# The payout scriptPubKey for the pool's reward address
REWARD_ADDR = "knf1q6v5tfdrvaunzz60c6as9fx9dttzc98j435ll4a"
PAYOUT_SCRIPT = "0014d328b4b46cef262169f8d7605498ad5ac5829e55"


# -----------------------------------------------------------
# The winning share exactly as the ASIC submitted it
# -----------------------------------------------------------
EXTRANONCE1 = "00000001"     # assigned by the pool to this connection
EXTRANONCE2 = "09000000"     # chosen by the miner
SHARE_NTIME = "6a5639fc"
SHARE_NONCE = "3a337292"

# Merkle root of the block (equals the coinbase txid here,
# because the merkle branch was empty)
MERKLE_ROOT_LE = "9561e72d4099beec889f0e569c53d87719b54c77ff93ee1ada12c5bc0f343275"

# The serialized 80-byte header, field by field
HEADER_HEX = (
    "00000020"                                                          # version
    "b00b24769a5c5c71e99e4bb1d358b38de296d6db001d797db0c53ba1c5d8fb96"  # prevhash
    "9561e72d4099beec889f0e569c53d87719b54c77ff93ee1ada12c5bc0f343275"  # merkle root
    "fc39566a"                                                          # ntime
    "c0ff3f1c"                                                          # nbits
    "9272333a"                                                          # nonce
)

# Proof-of-work and block hashes of the accepted block
SCRYPT_HASH = "00000000285b5d789f013d5858e55e39a0d2c2cd7350741c6e1672b58a9e03ea"
BLOCK_SHA256 = "d5c1ecebcfd630b06bf380461169d67005d300e8dc9b3d30447f7d17eb40a144"


# -----------------------------------------------------------
# Targets in effect when the share arrived
# -----------------------------------------------------------
POOL_DIFFICULTY = 100000
POOL_TARGET = 0x00000000a7c5ac471b4784230fcf80dc33721d53cddd6e04c059210385c67dfe
NETWORK_TARGET = 0x000000003fffc000000000000000000000000000000000000000000000000000








# ===========================================================
#  BTC testnet3 block 5062063 — SHA256d, 8 transactions
# ===========================================================
#
# Mined 2026-07-14 20:29:02 through this pool (job 00000002)
# during a testnet 20-minute min-difficulty window (nbits
# 1d00ffff, network difficulty 1). Unlike block 1777 this
# block carries a NON-empty merkle branch, so it also
# exercises the branch folding path end to end.
#
# The pool ran with:
#   COIN=BTC, COIN_NETWORK=testnet3
#   REWARD_ADDR=tb1qzlz8wv7qu40xx66sqc3r98qkgsys6vwtp3k0nj
#   COINBASE_MESSAGE=/AnyPool Miner from VU KNF/

# The block template as getblocktemplate reported it,
# reconstructed from the logged job + coinbase debug boxes.
# ("data" is not in the logs, so it is left empty — enough for
# build_job, which only reads the txids.)
BTC_TEMPLATE = {
    "version": 0x20000000,
    "previousblockhash": "00000000723c77aa63fb7e8d308791616d1f9350e0731cbf8a4156235d065067",
    "bits": "1d00ffff",
    "curtime": 0x6a5671dc,
    "height": 5062063,
    "coinbasevalue": 16516,
    "default_witness_commitment": "6a24aa21a9edef7bcd0d8dc834c653814fa7c50b3ba0ff22a7bf07d4e785bbc7a016b1bb3971",
    "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
    "transactions": [
        {"txid": "08819924a8f2e0a50b760054ebd43586ffcf16e8897b0c7d488016b6592c10fc", "data": ""},
        {"txid": "862016ef466534cda206938deafbb100e2ce8ac812d24548729cf777a279ae28", "data": ""},
        {"txid": "8c6eb88613bc0c244b17ba53ff3acaf6803e67886affd641451a621b2681d680", "data": ""},
        {"txid": "dea78838cc9aba6220475ea43dcc052ed83b4d1507229aa4ec832ac41124c596", "data": ""},
        {"txid": "2bf42438456cae29ab6804d8b371aeb3067f609adaf8d08b6440e113e9d2c1ac", "data": ""},
        {"txid": "e5dcadd9589bbfefdf6294b51cdabfb8cd8081b43b8ef228d2d8596b8a8a5b1f", "data": ""},
        {"txid": "3813cca4cee032fee22ec241275cdc22f2a53683a3f463eeacfca29c8ca65886", "data": ""},
        {"txid": "6a4526855c28a71956d1f58ba85c4af043391ccb268272d262fc0976907206b1", "data": ""},
    ],
}

# The job as the pool cut it (from the mining.notify / debug logs)
BTC_HEIGHT = 5062063
BTC_JOB_PREVHASH_WIRE = "5d0650678a415623e0731cbf6d1f93503087916163fb7e8d723c77aa00000000"
BTC_JOB_VERSION = "20000000"
BTC_JOB_NBITS = "1d00ffff"
BTC_JOB_NTIME = "6a5671dc"

BTC_COINB1 = ("01000000010000000000000000000000000000000000000000000000000000"
              "000000000000ffffffff2703af3d4d")
BTC_COINB2 = ("2f416e79506f6f6c204d696e65722066726f6d205655204b4e462fffffffff"
              "02844000000000000016001417c47733c0e55e636b500622329c1644090d31"
              "cb0000000000000000266a24aa21a9edef7bcd0d8dc834c653814fa7c50b3b"
              "a0ff22a7bf07d4e785bbc7a016b1bb397100000000")

# Sibling hashes proving the coinbase (raw sha256d byte order,
# exactly as sent in mining.notify)
BTC_MERKLE_BRANCH = [
    "fc102c59b61680487d0c7b89e816cfff8635d4eb5400760ba5e0f2a824998108",
    "61c71ef88f74f958936def0353f8161a378e2595aa5402414fd10ae0dab49fbc",
    "ac22a726826511c4f4ede9fdf90803a697315317658eafb56f89946c1cdf8746",
    "4e7ab096280abbb7b9399cea67939fb1a8a4e7c11239dca45e7e870ababff721",
]

# The 8 template transaction ids (LE, as build_job feeds them
# into the merkle branch calculation; coinbase not included)
BTC_TEMPLATE_TXIDS_LE = [
    "fc102c59b61680487d0c7b89e816cfff8635d4eb5400760ba5e0f2a824998108",
    "28ae79a277f79c724845d212c88acee200b1fbea8d9306a2cd346546ef162086",
    "80d681261b621a4541d6ff6a88673e80f6ca3aff53ba174b240cbc1386b86e8c",
    "96c52411c42a83eca49a2207154d3bd82e05cc3da45e472062ba9acc3888a7de",
    "acc1d2e913e140648bd0f8da9a607f06b3ae71b3d80468ab29ae6c453824f42b",
    "1f5b8a8a6b59d8d228f28e3bb48180cdb8bfda1cb59462dfefbf9b58d9addce5",
    "8658a68c9ca2fcacee63f4a38336a5f222dc5c2741c22ee2fe32e0cea4cc1338",
    "b10672907609fc62d2728226cb1c3943f04a5ca88bf5d15619a7285c8526456a",
]

# The winning share exactly as cgminer 4.4.2 submitted it:
#   {"params":["x","00000002","0a000000","6a5671dc","a6065390"]}
BTC_EXTRANONCE1 = "00000001"     # assigned by the pool to this connection
BTC_EXTRANONCE2 = "0a000000"     # chosen by the miner
BTC_SHARE_NTIME = "6a5671dc"
BTC_SHARE_NONCE = "a6065390"

# Merkle root after folding the coinbase txid through the branch
BTC_MERKLE_ROOT_LE = "13a73e6d02eeecb2245db607201389a2b59b30f0c7a9029acd24435a8e54b939"

# The serialized 80-byte header, field by field
BTC_HEADER_HEX = (
    "00000020"                                                          # version
    "6750065d2356418abf1c73e050931f6d619187308d7efb63aa773c7200000000"  # prevhash
    "13a73e6d02eeecb2245db607201389a2b59b30f0c7a9029acd24435a8e54b939"  # merkle root
    "dc71566a"                                                          # ntime
    "ffff001d"                                                          # nbits
    "905306a6"                                                          # nonce
)

# For SHA256d coins the PoW hash IS the block hash
BTC_BLOCK_HASH = "00000000b0f90acd2369909c621f4ec05aa6d7b04c7ba44986f5b444cff09d6e"

# Targets in effect when the share arrived (min-difficulty
# window: POLL_DIFF_DROPPER had lowered pool diff to 1, so
# pool target == network target == bdiff 1)
BTC_POOL_DIFFICULTY = 1
BTC_POOL_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
BTC_NETWORK_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
