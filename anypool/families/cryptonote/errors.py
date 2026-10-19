############################################################
#  [*] CryptoNote Stratum Error Messages
#
#  The CryptoNote dialect reports share rejections as a
#  JSON-RPC error object with code -1 and a message, and the
#  MESSAGE STRING is what miners parse — XMRig prints it
#  verbatim and has special handling for the conventional
#  ones below ("Block expired" and "Low difficulty share"
#  drive its own stale/invalid counters), so the exact
#  wording follows the convention every CryptoNote pool
#  uses, not our taste.
#
#  Used by:
#    - families/cryptonote/connection.py — submit replies
#    - families/cryptonote/server.py     — process_share verdicts
############################################################


ERROR_UNAUTHENTICATED = "Unauthenticated"
ERROR_INVALID_JOB = "Invalid job id"
ERROR_BLOCK_EXPIRED = "Block expired"
ERROR_MALFORMED_NONCE = "Malformed nonce"
ERROR_DUPLICATE_SHARE = "Duplicate share"
ERROR_INVALID_SHARE = "Invalid share"
ERROR_LOW_DIFFICULTY = "Low difficulty share"








############################################################
# as_rpc_error
############################################################
#
# Wraps a message in the error object the dialect expects
# on the wire: code -1, with the message beside it. The code
# is always the same — miners tell errors apart by message.
#
# Used by:
#   - families/cryptonote/connection.py — every error reply
#     (unknown method, no work yet, unauthenticated, share
#     rejections)
############################################################

def as_rpc_error(message: str) -> dict:
    return {"code": -1, "message": message}
