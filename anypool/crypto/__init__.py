# -----------------------------------------------------------
#  [*] Crypto Subpackage
#
#  The pure, dependency-light primitives of the pool — no
#  pool state, no config (except what callers pass in), no
#  networking. Everything in here is a deterministic
#  function of its inputs, which is why the test suite
#  focuses on this package first:
#
#    hashing.py — sha256d, scrypt PoW, hex byte-order helpers
#    merkle.py  — merkle branch / root calculation
#    bech32.py  — BIP-173 address decoding (P2WPKH scripts)
#
#  Used by:
#    - anypool/mining/ and anypool/stratum/ modules
#    - anypool/coins/  — PoW functions for coin definitions
#    - tests/          — unit tests with known protocol vectors
# -----------------------------------------------------------
