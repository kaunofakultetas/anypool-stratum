############################################################
#  [*] Stratum Error Codes
#
#  The standard stratum v1 share-rejection error tuples,
#  sent as the "error" field of a mining.submit response:
#  the numeric code, the human-readable message and a
#  traceback slot that is always null.
#
#  Miners (cgminer, ASIC firmwares) parse these and show the
#  message in their own logs — so a miner operator can see
#  WHY shares are rejected without access to the pool logs.
#
#  Used by:
#    - families/bitcoin/server.py     — process_share() verdicts
#    - families/bitcoin/connection.py — handle_submit() early rejects
############################################################


ERROR_OTHER = [20, "Other/Unknown", None]
ERROR_JOB_NOT_FOUND = [21, "Job not found (stale)", None]
ERROR_DUPLICATE_SHARE = [22, "Duplicate share", None]
ERROR_LOW_DIFFICULTY = [23, "Low difficulty share", None]
ERROR_UNAUTHORIZED = [24, "Unauthorized worker", None]

# Stratum v1 defines no codes for these two rejects, so they
# ride on 20 (other) and name the reason in their message
ERROR_TIME_OUT_OF_RANGE = [20, "ntime out of range", None]
ERROR_VERSION_ROLLING = [20, "Version bits outside negotiated version-rolling mask", None]
