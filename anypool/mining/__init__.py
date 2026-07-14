# -----------------------------------------------------------
#  [*] Mining Subpackage
#
#  The protocol-independent mining logic — everything between
#  "here is a block template" and "here is a serialized block
#  ready for submitblock":
#
#    coinbase.py — coinbase tx builder (stratum halves)
#    jobs.py     — build_job() + JobManager
#    shares.py   — share validation / header rebuilding
#    blocks.py   — full block assembly
#
#  Nothing in here opens a socket or reads a stratum message;
#  the stratum/ package drives this one.
#
#  Used by:
#    - anypool/stratum/ — server + connection layers
#    - tests/           — most vectors exercise this package
# -----------------------------------------------------------
