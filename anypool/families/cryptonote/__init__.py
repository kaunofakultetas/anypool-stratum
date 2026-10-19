############################################################
#  [*] CryptoNote Family
#
#  The mining model of CryptoNote coins (LTL/Bitlitas — a
#  Monero v0.11 fork). Fundamentally different from the
#  Bitcoin family: the DAEMON builds the whole block from
#  the pool's wallet address, the pool only injects an
#  extranonce into the template's reserved space, derives
#  the (usually 76-byte) hashing blob, and miners (XMRig
#  etc.) speak the login/job/submit dialect and roll a
#  4-byte nonce.
#
#    runner.py     — boot, the tip-height poll (the 0.11
#                    daemon has no longpoll) and the
#                    periodic template refresh
#    server.py     — template pipeline, share judgment
#                    (CryptoNight), block submission
#    connection.py — the CryptoNote stratum dialect
#    jobs.py       — per-client job instances (each miner
#                    gets a personalized blob)
#    blob.py       — block blob parsing/derivation/injection
#
#  Shared plumbing (line framing, client registry, stats)
#  lives in anypool/stratum/base.py.
#
#  Used by:
#    - anypool/families/__init__.py — active()
############################################################
