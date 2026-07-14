# -----------------------------------------------------------
#  [*] Known-Good Test Vectors — KNF Mainnet Block 1777
#
#  Every value in this file was captured from the pool's own
#  logs on 2026-07-14 while it mined KNF block 1777 with a
#  Scrypt ASIC (cgminer 4.9.0) — and that block was ACCEPTED
#  by the network ("[SUBMIT] Block ACCEPTED by network!").
#
#  That acceptance is what makes these vectors trustworthy:
#  if the refactored code reproduces every intermediate value
#  below, it produces byte-identical blocks to the code that
#  demonstrably worked on mainnet.
#
#  Used by:
#    - tests/test_hashing.py, test_merkle.py, test_coinbase.py,
#      test_jobs.py, test_shares.py, test_blocks.py
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
