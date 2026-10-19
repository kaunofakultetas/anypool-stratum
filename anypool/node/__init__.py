############################################################
#  [*] Node Subpackage
#
#  Communication with the coin daemon:
#
#    rpc.py        — NodeRPC, JSON-RPC 1.0 for Bitcoin-style
#                    daemons (litecoind / knfd): templates,
#                    block submission, and the MWEB
#                    deployment reads and peg-in
#    monero_rpc.py — MoneroRPC, JSON-RPC 2.0 at /json_rpc
#                    plus plain endpoints (/getheight) for
#                    CryptoNote daemons (bitlitasd)
#
#  Used by:
#    - anypool/families/*/server.py — each owns one client
#    - anypool/families/*/runner.py — longpoll/height polls
#      through the server's client
#    - anypool/families/bitcoin/mweb.py — NodeRPCError, to
#      explain a refused peg-in
############################################################
