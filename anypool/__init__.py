############################################################
#  [*] AnyPool Package
#
#  Stratum mining pool server, split by responsibility:
#
#    config.py     — environment variables + validation
#    display.py    — all console panels (pyboxen boxes)
#
#    coins/        — per-coin definitions + registry
#                    (add new coins HERE, nowhere else)
#    crypto/       — pure primitives (hashing, merkle,
#                    bech32, base58, keccak, cn_base58,
#                    cryptonight)
#    families/     — one subpackage per MINING MODEL:
#                    bitcoin/ (stratum v1, coinbase+merkle)
#                    cryptonote/ (login/job/submit, blobs)
#    node/         — JSON-RPC clients to the full node
#                    (rpc.py bitcoin-style, monero_rpc.py)
#    stratum/      — shared miner-facing plumbing (framing,
#                    client registry, stats)
#
#  Dependency direction (top depends on bottom):
#
#        main.py
#           |
#        families/ ->  node/, stratum/
#           |
#        coins/
#           |
#        crypto/       config.py, display.py
#
#  config.py and display.py sit at the bottom: every layer
#  may read them. The one upward reach is config.validate(),
#  which imports coins/ inside the function to check the
#  selected coin and its reward address.
#
#  Used by:
#    - main.py — the entry point one directory up
############################################################
