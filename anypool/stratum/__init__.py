# -----------------------------------------------------------
#  [*] Stratum Subpackage
#
#  The network-facing layer speaking stratum v1 to miners:
#
#    server.py     — StratumServer: pool state, client
#                    registry, job/share/block orchestration
#    connection.py — StratumConnection: one per miner,
#                    JSON-RPC framing + method dispatch
#
#  This layer delegates all actual mining math to anypool/
#  mining/ and all daemon communication to anypool/node/.
#
#  Used by:
#    - main.py — creates the server and wires connections
# -----------------------------------------------------------
