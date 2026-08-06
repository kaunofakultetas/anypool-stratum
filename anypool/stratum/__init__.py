############################################################
#  [*] Stratum Subpackage
#
#  The protocol-NEUTRAL half of the miner-facing layer. Both
#  stratum dialects this pool speaks are newline-delimited
#  JSON-RPC over TCP, and everything below the message
#  vocabulary lives here exactly once:
#
#    base.py — BaseStratumConnection (socket lifecycle, line
#              framing, wire debug logging) and
#              BasePoolServer (client registry, statistics,
#              background-task bookkeeping)
#
#  The dialects themselves — Bitcoin stratum v1 (mining.*)
#  and CryptoNote login/job/submit — live in their family
#  packages under anypool/families/, which subclass the two
#  bases.
#
#  Used by:
#    - families/bitcoin/server.py, connection.py
#    - families/cryptonote/server.py, connection.py
############################################################
