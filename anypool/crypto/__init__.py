############################################################
#  [*] Crypto Subpackage
#
#  The pure, dependency-light primitives of the pool — no
#  pool state, no config (except what callers pass in), no
#  networking. Everything in here is a deterministic
#  function of its inputs, which is why the test suite
#  focuses on this package first:
#
#    hashing.py     — sha256d, scrypt/sha256d PoW, hex
#                     byte-order helpers
#    merkle.py      — merkle branch / root calculation
#    bech32.py      — BIP-173 address decoding (P2WPKH)
#    base58.py      — base58check decoding (P2PKH)
#    keccak.py      — keccak-256 with CryptoNote's original
#                     padding (the CN tree hash built on it
#                     lives in families/cryptonote/blob.py)
#    cn_base58.py   — CryptoNote block-base58 addresses +
#                     varints
#    cryptonight.py — CryptoNight PoW via the py-cryptonight
#                     C extension, plus the CryptoNote
#                     difficulty math
#
#  Used by:
#    - anypool/families/ — both mining engines
#    - anypool/coins/    — PoW functions and address schemes
#    - tests/            — unit tests with known protocol
#                          vectors
############################################################
