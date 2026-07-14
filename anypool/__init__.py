# -----------------------------------------------------------
#  [*] AnyPool Package
#
#  Stratum mining pool server, split by responsibility:
#
#    config.py     — environment variables + validation
#    display.py    — all console panels (boxen)
#
#    coins/        — per-coin definitions + registry
#                    (add new coins HERE, nowhere else)
#    crypto/       — pure primitives (hashing, merkle, bech32)
#    mining/       — coinbase, jobs, shares, block assembly
#    node/         — JSON-RPC client to the full node
#    stratum/      — the miner-facing network layer
#
#  Dependency direction (top depends on bottom):
#
#        main.py
#           |
#        stratum/  ->  node/
#           |
#        mining/   ->  coins/
#           |
#        crypto/       config.py, display.py
#
#  Used by:
#    - main.py — the entry point one directory up
# -----------------------------------------------------------
