############################################################
#  [*] Bitcoin Family
#
#  The mining model of Bitcoin Core forks (BTC, LTC, DOGE,
#  KNF): the pool builds the coinbase and merkle tree itself
#  and miners speak stratum v1.
#
#    runner.py     — boot + job refresh + longpoll loops
#    server.py     — job pipeline, share judgment, submission
#    connection.py — the stratum v1 dialect (mining.*)
#    jobs.py       — template -> job conversion, JobManager
#    coinbase.py   — coinbase tx construction (BIP34, segwit)
#    blocks.py     — full block serialization for submitblock
#    shares.py     — header rebuild + PoW check helpers
#    errors.py     — stratum v1 error tuples
#
#  Shared plumbing (line framing, client registry, stats)
#  lives in anypool/stratum/base.py.
#
#  Used by:
#    - anypool/families/__init__.py — active()
############################################################
