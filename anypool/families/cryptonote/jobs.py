############################################################
#  [*] CryptoNote Mining Jobs
#
#  Job bookkeeping for the CryptoNote family. The structural
#  difference from the Bitcoin family: jobs are PER CLIENT.
#  A Bitcoin pool broadcasts one identical job and miners
#  personalize it themselves by splicing their extranonce
#  into the coinbase; a CryptoNote miner receives a finished
#  hashing blob it cannot alter (except the 4-byte nonce), so
#  the POOL must personalize the work before sending — by
#  writing a per-client extranonce into the template's
#  reserved space, which changes the miner tx hash and thus
#  the tree root of every blob it derives.
#
#  CnJobManager owns:
#
#    - the current template (one per chain tip fetch)
#    - every issued per-client job, so a submit can be
#      validated against the EXACT bytes the miner hashed
#    - per-job nonce sets for duplicate detection
#
#  A job dict carries:
#
#    job_id          — 8-hex-char sequence number
#    client          — the connection this job was issued to
#    extranonce      — the 8 bytes written into reserved space
#    template_blob   — full block blob WITH extranonce (bytes)
#    hashing_blob    — the 76-byte blob the miner hashes (bytes)
#    nonce_offset    — where the miner's nonce lands (39)
#    height / prev_hash / seed of the template it came from
#    pool_difficulty / network_difficulty — snapshotted, so a
#        late share is judged against the difficulty the
#        miner was actually given
#    seen_nonces     — duplicate-share guard
#
#  Used by:
#    - families/cryptonote/server.py, connection.py
############################################################


from typing import Dict, Optional

from anypool.crypto.cryptonight import compact_target
from anypool.families.cryptonote.blob import hashing_blob, parse_block, with_extranonce


# How many issued jobs to keep. CryptoNote miners hold ONE
# job at a time, so this only needs to cover clients * the
# couple of jobs that can be in flight during a broadcast.
MAX_STORED_JOBS = 200








class CnJobManager:






    ############################################################
    # __init__
    ############################################################
    #
    # Starts with no template; job ids are a simple
    # incrementing counter rendered as 8 hex chars.
    #
    # Used by:
    #   - families/cryptonote/server.py — CnStratumServer.__init__()
    ############################################################

    def __init__(self):
        self.template: Optional[Dict] = None
        self.jobs: Dict[str, Dict] = {}
        self.job_seq = 0






    ############################################################
    # next_job_id
    ############################################################
    #
    # Hands out the next unique job id ("00000001", ...).
    #
    # Used by:
    #   - make_job() (below)
    ############################################################

    def next_job_id(self) -> str:
        self.job_seq += 1
        return f"{self.job_seq:08x}"






    ############################################################
    # set_template
    ############################################################
    #
    # Stores a freshly fetched block template (parsed once so
    # every per-client job derives from the same offsets).
    # Returns True when it describes NEW work — a different
    # parent than the template miners are currently on.
    #
    # Used by:
    #   - families/cryptonote/server.py — create_job()
    ############################################################

    def set_template(self, result: Dict, reserve_size: int) -> bool:
        blob = bytes.fromhex(result["blocktemplate_blob"])
        parsed = parse_block(blob)

        is_new = (self.template is None
                  or self.template["prev_hash"] != result["prev_hash"])

        self.template = {
            "blob": blob,
            "height": result["height"],
            "difficulty": result["difficulty"],
            "prev_hash": result["prev_hash"],
            "reserved_offset": result["reserved_offset"],
            "reserve_size": reserve_size,
            "nonce_offset": parsed["nonce_offset"],
        }
        return is_new






    ############################################################
    # make_job
    ############################################################
    #
    # Cuts one personalized job from the current template for
    # one client: write the client's extranonce into the
    # reserved space, derive the hashing blob, snapshot the
    # difficulty state, store and return the job.
    #
    # Used by:
    #   - families/cryptonote/server.py — login pushes + broadcasts
    ############################################################

    def make_job(self, client, extranonce: bytes, pool_difficulty: int) -> Dict:
        if self.template is None:
            raise RuntimeError("no block template yet")

        t = self.template
        template_blob = with_extranonce(t["blob"], extranonce,
                                        t["reserved_offset"], t["reserve_size"])

        job = {
            "job_id": self.next_job_id(),
            "client": client,
            "extranonce": extranonce,
            "template_blob": template_blob,
            "hashing_blob": hashing_blob(template_blob),
            "nonce_offset": t["nonce_offset"],
            "height": t["height"],
            "prev_hash": t["prev_hash"],
            "pool_difficulty": pool_difficulty,
            "network_difficulty": t["difficulty"],
            "target": compact_target(pool_difficulty),
            "seen_nonces": set(),
        }

        self.jobs[job["job_id"]] = job
        while len(self.jobs) > MAX_STORED_JOBS:
            del self.jobs[next(iter(self.jobs))]

        return job






    ############################################################
    # get
    ############################################################
    #
    # Looks a job up by id; None means stale or never existed
    # and the share must be rejected.
    #
    # Used by:
    #   - families/cryptonote/server.py — process_share()
    ############################################################

    def get(self, job_id: str) -> Optional[Dict]:
        return self.jobs.get(job_id)






    ############################################################
    # register_nonce
    ############################################################
    #
    # Duplicate-share guard: True the FIRST time this nonce is
    # submitted for the job, False on every replay.
    #
    # Used by:
    #   - families/cryptonote/server.py — process_share()
    ############################################################

    def register_nonce(self, job: Dict, nonce: str) -> bool:
        key = nonce.lower()
        if key in job["seen_nonces"]:
            return False
        job["seen_nonces"].add(key)
        return True
