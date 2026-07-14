# -----------------------------------------------------------
#  [*] Mining Jobs
#
#  Everything about the unit of work a miner receives:
#
#    build_job()  — turns a getblocktemplate result into the
#                   job dict that mining.notify is built from
#                   (stratum-ready prevhash, coinbase halves,
#                   merkle branch, version/nbits/ntime).
#
#    JobManager   — remembers every job by its id so a share
#                   can be validated against the EXACT job
#                   the miner worked on, tracks the current
#                   job, and decides whether a fresh template
#                   actually contains new work.
#
#  A job dict carries these keys:
#
#    job_id         — 8-hex-char sequence number
#    prevhash       — word-swapped LE, stratum wire format
#    coinb1/coinb2  — coinbase halves, txid serialization
#    coinb1_full/coinb2_full — with witness, for submission
#    merkle_branch  — sibling hashes proving the coinbase
#    version/nbits/ntime — big-endian hex, as sent to miners
#    height         — block height being mined
#    template       — the raw getblocktemplate result
#                     (needed later for block submission)
#
#  Used by:
#    - stratum/server.py — create_job(), process_share()
# -----------------------------------------------------------

from typing import Dict, Optional

from anypool import display
from anypool.crypto.hashing import reverse_hex, reverse_hex_4b_chunks, sha256d
from anypool.crypto.merkle import calculate_merkle_branch
from anypool.mining.coinbase import build_coinbase_parts


# How many historical jobs to keep around for late shares.
# Anything older is genuinely stale (the chain tip moved) and
# would be rejected anyway; without a cap the dict grows for
# the lifetime of the process.
MAX_STORED_JOBS = 10




# -----------------------------------------------------------
# stratum_prevhash
# -----------------------------------------------------------
#
# Converts the previous block hash from the big-endian form
# getblocktemplate reports into the word-swapped form the
# stratum protocol transmits: full byte reversal to LE, then
# each 4-byte word flipped back.
#
# Used by:
#   - mining/jobs.py    — build_job()
#   - stratum/server.py — create_job() "did the tip move?" check
# -----------------------------------------------------------
def stratum_prevhash(prevhash_be: str) -> str:
    prevhash_le = reverse_hex(prevhash_be)
    return reverse_hex_4b_chunks(prevhash_le)










# -----------------------------------------------------------
# build_job
# -----------------------------------------------------------
#
# Assembles one complete mining job from a template:
#
#   1. Convert prevhash/version/nbits/ntime into the formats
#      miners expect on the wire.
#   2. Build the coinbase halves (see coinbase.py).
#   3. Compute the merkle branch that proves the coinbase.
#      A placeholder extranonce is used here — the branch is
#      composed of the OTHER transactions' hashes, so it is
#      identical for every miner regardless of extranonce.
#
# Used by:
#   - stratum/server.py — create_job()
# -----------------------------------------------------------
def build_job(template: Dict, job_id: str) -> Dict:

    # Step 1: Field conversions for the stratum wire format
    prevhash_final = stratum_prevhash(template["previousblockhash"])
    version_be = f"{template['version']:08x}"
    nbits_be = f"{int(template['bits'], 16):08x}"
    ntime_be = f"{template['curtime']:08x}"


    # Step 2: All template transactions (txids as reported, flipped to LE)
    template_txs = template.get("transactions", [])
    template_txids_be = [t["txid"] for t in template_txs]
    template_txids_le = [bytes.fromhex(txid)[::-1].hex() for txid in template_txids_be]

    display.debug_box("DEBUG - jobs.build_job()", [
        "Total transactions in template: ".ljust(35) + str(len(template_txs)),
    ])


    # Step 3: Coinbase halves + merkle branch.
    # The placeholder extranonce only fills the coinbase for hashing
    # position 0 — the resulting BRANCH does not depend on it.
    coinbase_parts = build_coinbase_parts(template)
    placeholder_extranonce1 = "00000000"
    placeholder_coinbase_hex = coinbase_parts["coinb1_txid"] + placeholder_extranonce1 + ("00" * 4) + coinbase_parts["coinb2_txid"]
    coinbase_txid_le = sha256d(bytes.fromhex(placeholder_coinbase_hex)).hex()

    all_txids_le = [coinbase_txid_le] + template_txids_le
    merkle_branch_le = calculate_merkle_branch(all_txids_le, 0)

    display.debug_box("DEBUG - jobs.build_job() merkle", [
        "Coinbase txid (placeholder): ".ljust(35) + coinbase_txid_le[::-1],
        "All txids: ".ljust(35) +                   str(all_txids_le),
        "Calculated merkle branch: ".ljust(35) +    str(merkle_branch_le),
    ], color="red")


    # Step 4: The job dict itself
    return {
        "job_id": job_id,
        "prevhash": prevhash_final,
        "coinb1": coinbase_parts["coinb1_txid"],       # For stratum protocol (TXID version)
        "coinb2": coinbase_parts["coinb2_txid"],       # For stratum protocol (TXID version)
        "coinb1_full": coinbase_parts["coinb1_full"],  # For block submission (with witness)
        "coinb2_full": coinbase_parts["coinb2_full"],  # For block submission (with witness)
        "merkle_branch": merkle_branch_le,
        "version": version_be,
        "nbits": nbits_be,
        "ntime": ntime_be,
        "height": template["height"],

        # Every share submitted for this job, for duplicate
        # detection — pruned together with the job itself
        "seen_shares": set(),

        # Kept whole for block submission (tx data, mweb, ...)
        "template": template,
    }










class JobManager:


    # -----------------------------------------------------------
    # __init__
    # -----------------------------------------------------------
    #
    # Starts with an empty job store; job ids are a simple
    # incrementing counter rendered as 8 hex chars.
    #
    # Used by:
    #   - stratum/server.py — StratumServer.__init__()
    # -----------------------------------------------------------
    def __init__(self):
        self.jobs: Dict[str, Dict] = {}
        self.current_job: Optional[Dict] = None
        self.job_seq = 0






    # -----------------------------------------------------------
    # next_job_id
    # -----------------------------------------------------------
    #
    # Hands out the next unique job id ("00000001", ...).
    #
    # Used by:
    #   - stratum/server.py — create_job()
    # -----------------------------------------------------------
    def next_job_id(self) -> str:
        self.job_seq += 1
        return f"{self.job_seq:08x}"






    # -----------------------------------------------------------
    # is_same_work
    # -----------------------------------------------------------
    #
    # True when a freshly fetched template describes the work
    # we are already mining: same chain tip, same MWEB data,
    # same network target. When true the caller must NOT cut a
    # new job — miners would needlessly restart on identical
    # work.
    #
    # Used by:
    #   - stratum/server.py — create_job()
    # -----------------------------------------------------------
    def is_same_work(self, template: Dict, current_network_target: Optional[int]) -> bool:
        if self.current_job is None:
            return False

        return (
            self.current_job.get("prevhash") == stratum_prevhash(template["previousblockhash"])
            and self.current_job.get("template").get("mweb") == template.get("mweb")
            and current_network_target == int(template["target"], 16)
        )






    # -----------------------------------------------------------
    # store
    # -----------------------------------------------------------
    #
    # Registers a new job as the current one and prunes the
    # oldest entries beyond MAX_STORED_JOBS. Old jobs are kept
    # at all so that a share submitted moments after a new job
    # broadcast can still be validated against what the miner
    # actually hashed.
    #
    # Used by:
    #   - stratum/server.py — create_job()
    # -----------------------------------------------------------
    def store(self, job: Dict) -> None:
        self.jobs[job["job_id"]] = job
        self.current_job = job

        while len(self.jobs) > MAX_STORED_JOBS:
            oldest_id = next(iter(self.jobs))
            del self.jobs[oldest_id]






    # -----------------------------------------------------------
    # get
    # -----------------------------------------------------------
    #
    # Looks a job up by id; None means the job is stale or
    # never existed and the share must be rejected.
    #
    # Used by:
    #   - stratum/server.py — process_share()
    # -----------------------------------------------------------
    def get(self, job_id: str) -> Optional[Dict]:
        return self.jobs.get(job_id)






    # -----------------------------------------------------------
    # register_share
    # -----------------------------------------------------------
    #
    # Duplicate-share guard. Returns True the FIRST time this
    # exact (extranonce1, extranonce2, ntime, nonce) combination
    # is submitted for the job, False on every resubmission —
    # without this, one winning share could be replayed forever
    # to inflate a miner's accepted-share count.
    #
    # Used by:
    #   - stratum/server.py — process_share()
    # -----------------------------------------------------------
    def register_share(self, job: Dict, extra_nonce1: str, extra_nonce2: str,
                       ntime: str, nonce: str) -> bool:
        share_key = (extra_nonce1, extra_nonce2, ntime, nonce)

        if share_key in job["seen_shares"]:
            return False

        job["seen_shares"].add(share_key)
        return True
