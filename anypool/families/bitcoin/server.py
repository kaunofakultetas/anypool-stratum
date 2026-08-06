############################################################
#  [*] Stratum Server Core
#
#  The stateful heart of the pool. StratumServer owns:
#
#    - the RPC client to the full node
#    - the JobManager (current + recent jobs)
#    - the pool/network difficulty and target state
#    - the set of connected miner clients
#    - lifetime share/block statistics
#
#  and orchestrates the three flows that make a pool a pool:
#
#    create_job()      — poll getblocktemplate, cut a fresh
#                        job when the chain tip moves, and
#                        broadcast it to every miner.
#    process_share()   — validate a submitted share against
#                        pool and network targets.
#    _start_block_submission() — launch the submission of a
#                        network-grade share as a background
#                        task, so the miner's submit response
#                        NEVER waits on a node round-trip.
#
#  Per-connection protocol handling lives in connection.py;
#  this module never parses stratum messages itself.
#
#  Used by:
#    - families/bitcoin/runner.py     — creates the single StratumServer
#    - families/bitcoin/connection.py — calls into it per miner message
############################################################


from typing import Dict

from anypool import coins, config, display
from anypool.crypto.hashing import reverse_hex, reverse_hex_4b_chunks, sha256d
from anypool.families.bitcoin.blocks import assemble_block
from anypool.families.bitcoin.jobs import JobManager, build_job
from anypool.families.bitcoin.shares import build_header, ntime_within_range
from anypool.node.rpc import NodeRPC
from anypool.stratum.base import BasePoolServer
from anypool.families.bitcoin.errors import (
    ERROR_DUPLICATE_SHARE,
    ERROR_JOB_NOT_FOUND,
    ERROR_LOW_DIFFICULTY,
    ERROR_OTHER,
    ERROR_TIME_OUT_OF_RANGE,
)


# How many recently solved parents (job prevhashes a block
# submission was launched for) the sibling-block guard in
# _start_block_submission() remembers. Jobs themselves are
# pruned at MAX_STORED_JOBS (10), so 50 parents is far more
# history than any live share can still reference.
MAX_SUBMITTED_PARENTS = 50

# Re-issue the current job with a fresh ntime once it is this
# old, even when the chain tip has not moved. Miners and rental
# proxies judge a pool by the freshness of its work: a job whose
# ntime drifts minutes into the past reads as a dead pool and
# ASICs refuse to hash it. On a quiet chain (no blocks for
# hours) the tip alone would never trigger a new job.
JOB_NTIME_REFRESH_SECONDS = 30








class StratumServer(BasePoolServer):






    ############################################################
    # __init__
    ############################################################
    #
    # Wires up the RPC client and JobManager, zeroes the stats,
    # derives the initial pool target from POOL_DIFFICULTY and
    # prints the startup banner.
    #
    # Used by:
    #   - families/bitcoin/runner.py — run(), once at startup
    ############################################################

    def __init__(self):
        super().__init__()

        self.rpc = NodeRPC()
        self.job_manager = JobManager()

        # Difficulty / target state (network side is learned
        # from the first block template)
        self.network_difficulty = None
        self.network_target = None
        self.pool_difficulty = config.POOL_DIFFICULTY
        self.pool_target = self.calculate_mining_target(config.POOL_DIFFICULTY)

        # Each miner gets a unique extranonce1
        self.extranonce1_counter = 0

        # Parents (job prevhash, wire format) a block submission was
        # already launched for — the sibling-block guard state of
        # _start_block_submission(). A dict standing in for an
        # insertion-ordered set so it can be pruned oldest-first.
        self.submitted_parents = {}

        display.startup_banner(self.pool_difficulty)






    ############################################################
    # calculate_mining_target
    ############################################################
    #
    # difficulty -> target. A share is valid when its hash,
    # read as a 256-bit integer, is at or below the target.
    # The difficulty-1 reference target comes from the active
    # coin's definition.
    #
    # Used by:
    #   - families/bitcoin/server.py — __init__() and create_job()
    ############################################################

    def calculate_mining_target(self, difficulty: int) -> int:
        return coins.active().difficulty_1_target // difficulty






    ############################################################
    # calculate_mining_difficulty
    ############################################################
    #
    # target -> difficulty. The inverse of the above, used to
    # express the network target as a human-readable number.
    #
    # Used by:
    #   - families/bitcoin/server.py — create_job()
    ############################################################

    def calculate_mining_difficulty(self, target: int) -> int:
        return coins.active().difficulty_1_target // target






    ############################################################
    # next_extranonce1
    ############################################################
    #
    # Hands out a unique 4-byte extranonce1 per connection so
    # every miner hashes a distinct coinbase (and can never
    # duplicate another miner's work).
    #
    # Used by:
    #   - families/bitcoin/connection.py — StratumConnection.__init__()
    ############################################################

    def next_extranonce1(self) -> str:
        self.extranonce1_counter += 1
        return f"{self.extranonce1_counter:08x}"






    ############################################################
    # broadcast_new_job
    ############################################################
    #
    # Pushes the current job to every connected miner: first a
    # mining.set_difficulty, then the mining.notify with
    # clean_jobs=True (miners must abandon the previous job).
    # Clients that fail to receive are treated as disconnected
    # and removed.
    #
    # Used by:
    #   - families/bitcoin/server.py — create_job()
    #   - families/bitcoin/runner.py — after the initial job
    ############################################################

    async def broadcast_new_job(self, clean_jobs: bool = True) -> None:
        job = self.job_manager.current_job
        if not job or not self.connected_clients:
            return

        # Copy: clients may get removed while we iterate
        clients_to_broadcast = list(self.connected_clients)
        disconnected_clients = set()

        notification_params = [
            job["job_id"], job["prevhash"], job["coinb1"], job["coinb2"],
            job["merkle_branch"], job["version"], job["nbits"], job["ntime"], clean_jobs
        ]

        # Send sequentially so per-client failures can be caught
        for client in clients_to_broadcast:
            try:
                await client.send_notification("mining.set_difficulty", [self.pool_difficulty])
                await client.send_notification("mining.notify", notification_params)
            except Exception as e:
                print(f"[BROADCAST] Failed to send to client: {e}")
                disconnected_clients.add(client)

        for client in disconnected_clients:
            self.remove_client(client)
        if len(disconnected_clients) > 0:
            print(f"[BROADCAST] Removed {len(disconnected_clients)} disconnected clients")

        if self.connected_clients:
            display.broadcast_panel(job["job_id"], self.connected_clients)






    ############################################################
    # create_job
    ############################################################
    #
    # The job pipeline, run at startup and then every few
    # seconds by the refresh loop in runner.py:
    #
    #   1. getblocktemplate from the node.
    #   2. If it describes the work we are already mining
    #      (same tip / mweb / target), keep the current job —
    #      miners hate pointless restarts.
    #   3. Otherwise refresh the difficulty/target state
    #      (optionally dropping pool difficulty to network
    #      difficulty, see POLL_DIFF_DROPPER).
    #   4. Build, store and broadcast the new job.
    #
    # Returns the current job, or None when the node call or
    # job construction failed (the refresh loop just retries).
    #
    # Used by:
    #   - families/bitcoin/runner.py — run() (initial job),
    #     job_refresh_loop(), longpoll_loop()
    #   - families/bitcoin/connection.py — handle_subscribe()
    #     when no job exists yet
    #   - _submit_block_task() below — cut the follow-up job
    ############################################################

    async def create_job(self) -> Dict:
        try:
            # STEP 1: fetch a fresh block template (request per
            # coin definition)
            # =================================================
            template = await self.rpc.call("getblocktemplate", coins.active().gbt_request())
            if not template or "previousblockhash" not in template:
                print(f"[ERROR] Invalid block template: {template}")
                return None


            # STEP 2: nothing changed? Keep the job miners are working on
            # — but only while its ntime is still fresh. A stagnant tip
            # must not freeze the job forever: miners treat old-ntime
            # work as a dead pool (see JOB_NTIME_REFRESH_SECONDS).
            # ===========================================================
            same_work = self.job_manager.is_same_work(template, self.network_target)
            if same_work:
                job_ntime = int(self.job_manager.current_job["ntime"], 16)
                if template["curtime"] - job_ntime < JOB_NTIME_REFRESH_SECONDS:
                    return self.job_manager.current_job


            # STEP 3: refresh difficulty and target state
            # ===========================================
            self.network_target = int(template["target"], 16)
            self.network_difficulty = self.calculate_mining_difficulty(self.network_target)
            self.pool_target = self.calculate_mining_target(config.POOL_DIFFICULTY)
            self.pool_difficulty = config.POOL_DIFFICULTY

            # If the network difficulty drops below the pool's fixed
            # difficulty, mine at network difficulty instead
            if config.POLL_DIFF_DROPPER:
                if self.network_difficulty < config.POOL_DIFFICULTY:
                    self.pool_difficulty = self.network_difficulty
                    self.pool_target = self.network_target

            if not same_work:
                display.new_block_panel(template["height"] - 1, template["previousblockhash"])


            # STEP 4: build, store and broadcast the new job.
            # The difficulty state is snapshotted INTO the job: a late
            # share must be judged against the difficulty the miner was
            # actually given for this job, not whatever is current when
            # the share arrives (testnet's 20-minute rule flips the
            # difficulty constantly, see POLL_DIFF_DROPPER).
            # =========================================================
            job = build_job(template, self.job_manager.next_job_id())
            job["pool_difficulty"] = self.pool_difficulty
            job["pool_target"] = self.pool_target
            job["network_difficulty"] = self.network_difficulty
            job["network_target"] = self.network_target
            self.job_manager.store(job)

            if self.connected_clients:
                print(f"[BROADCAST] BROADCASTING NEW JOB to {len(self.connected_clients)} clients...")
                # Same tip, fresh ntime only: clean_jobs=False so miners
                # keep their in-flight work instead of restarting.
                self._spawn(self.broadcast_new_job(clean_jobs=not same_work))

            if same_work:
                print(f"[REFRESH] Job {job['job_id']} re-issued with fresh ntime {job['ntime']} (same tip, height {job['height']})")
            else:
                display.job_created_panel(job, self.pool_difficulty, self.network_difficulty,
                                          self.pool_target, self.network_target)

                display.debug_box("DEBUG - StratumServer.create_job()", [
                    "Stored job: ".ljust(25) +          job["job_id"],
                    "Jobs in memory: ".ljust(25) +      str(len(self.job_manager.jobs)),
                    "Job keys: ".ljust(25) +            str(list(self.job_manager.jobs.keys())),
                    "Height: ".ljust(25) +              str(job["height"]),
                    "Template transactions: ".ljust(25) + str(len(template.get("transactions", []))),
                ])

            return job

        except Exception as e:
            print(f"[ERROR] Failed to create job: {e}")
            return None






    ############################################################
    # process_share
    ############################################################
    #
    # Judges one submitted share:
    #
    #   1. Look up the EXACT job the miner worked on (stale
    #      job id -> reject).
    #   2. Cheap sanity gates: ntime inside the allowed window,
    #      not a duplicate of an earlier submission.
    #   3. Rebuild the header the miner hashed and its PoW
    #      hash (shares.build_header).
    #   4. hash <= pool target?     -> share accepted.
    #      hash <= network target?  -> it is a full block:
    #      launch its submission as a background task
    #      (_start_block_submission) and answer the miner
    #      right away.
    #
    # Returns (accepted, error): accepted travels back to the
    # miner as the mining.submit result, error is a standard
    # stratum error tuple (or None) shown in the miner's log.
    # The verdict deliberately does NOT depend on the node's
    # submitblock outcome — the share met the target it was
    # issued for, and waiting on the node here would hold the
    # response (and the whole connection) hostage.
    #
    # Used by:
    #   - families/bitcoin/connection.py — handle_submit()
    ############################################################

    async def process_share(self, worker_name: str, job_id: str, extra_nonce1: str,
                            extra_nonce2: str, ntime: str, nonce: str,
                            version_bits: str = "00000000"):
        self.shares_submitted += 1

        try:
            # STEP 1: find the job this share belongs to
            # ==========================================
            job = self.job_manager.get(job_id)
            if not job:
                print("[SHARE] Stale/unknown job_id; rejecting")
                self.shares_rejected += 1
                return False, ERROR_JOB_NOT_FOUND


            # STEP 2: cheap sanity gates before any hashing work
            # ==================================================
            if not ntime_within_range(job["ntime"], ntime):
                print(f"[SHARE] ntime {ntime} outside allowed window of job ntime {job['ntime']}; rejecting")
                self.shares_rejected += 1
                return False, ERROR_TIME_OUT_OF_RANGE

            if not self.job_manager.register_share(job, extra_nonce1, extra_nonce2, ntime, nonce, version_bits):
                print(f"[SHARE] Duplicate share for job {job_id} (nonce {nonce}); rejecting")
                self.shares_rejected += 1
                return False, ERROR_DUPLICATE_SHARE

            display.debug_box("DEBUG - Job and share details comparison", [
                "Job ID: ".ljust(25) +             job_id,
                "Job prevhash: ".ljust(25) +       job.get("prevhash", "MISSING"),
                "Job nbits: ".ljust(25) +          job.get("nbits", "MISSING"),
                "Job ntime: ".ljust(25) +          job.get("ntime", "MISSING"),
                "Job merkle branch: ".ljust(25) +  str(job.get("merkle_branch", "MISSING")),
                "Miner extra nonce1: ".ljust(25) + extra_nonce1,
                "Miner extra nonce2: ".ljust(25) + extra_nonce2,
                "Miner ntime: ".ljust(25) +        ntime,
                "Miner nonce: ".ljust(25) +        nonce,
                "Miner version bits: ".ljust(25) + version_bits,
            ], color="red")


            # STEP 3: rebuild the header the miner hashed
            # ===========================================
            result_hash, header_hex, header_bytes = build_header(
                job, extra_nonce1, extra_nonce2, ntime, nonce, context="process_share",
                version_bits=version_bits
            )


            # STEP 4: compare against the targets THIS JOB was issued
            # under (snapshotted in create_job) — the current pool/network
            # state may already describe a newer job at a different
            # difficulty, which must not affect this share's verdict.
            # ============================================================
            hash_int = int(result_hash, 16)
            # A block-grade hash is judged independently of the share
            # target: when pool difficulty exceeds network difficulty a
            # hash can solve a block while missing the share target, and
            # it must still be submitted (and credited) — never dropped
            # as a "low difficulty" share.
            is_block = hash_int <= job["network_target"]
            is_accepted = hash_int <= job["pool_target"] or is_block

            if is_accepted:
                self.shares_accepted += 1
            else:
                self.shares_rejected += 1

            display.share_result_panel(
                is_accepted=is_accepted,
                is_block=is_block,
                job_id=job_id,
                height=job["height"],
                result_hash=result_hash,
                sha256_hash=sha256d(header_bytes)[::-1].hex(),
                prevhash_display=reverse_hex_4b_chunks(reverse_hex(job["prevhash"])),
                pool_difficulty=job["pool_difficulty"],
                network_difficulty=job["network_difficulty"],
                pool_target=job["pool_target"],
                network_target=job["network_target"],
            )


            # STEP 5: a network-grade share is a block — submit it in
            # the BACKGROUND. The node is at its busiest right after a
            # block (validating, relaying, answering longpolls), and a
            # response held back for that round-trip stalls the miner's
            # whole stratum conversation: the read loop in
            # connection.handle() processes one message at a time, so
            # ASICs see a silent pool, declare it lagging and pause.
            # =========================================================
            if is_block:
                self._start_block_submission(job, extra_nonce1, extra_nonce2, header_hex)

            return is_accepted, (None if is_accepted else ERROR_LOW_DIFFICULTY)

        except Exception as e:
            self.shares_rejected += 1
            print(f"[ERROR] Share processing failed: {e}")
            import traceback
            traceback.print_exc()
            return False, ERROR_OTHER

        finally:
            self._print_stats()






    ############################################################
    # _start_block_submission
    ############################################################
    #
    # Launches the submission of a solved block as a background
    # task — process_share() must never wait on the node.
    #
    # Guard: ONE submission per parent. When blocks fall quickly
    # an ASIC often solves the same job again before the clean-
    # jobs notify reaches it; that second solve is a sibling of
    # the block the node just accepted (same height, same parent)
    # and can never become the best tip — submitting it only
    # earns an "inconclusive" from a node that is busy connecting
    # the first block. The parent is marked BEFORE the task runs
    # so a sibling arriving mid-submission is caught as well; a
    # FAILED submission unmarks it, so a later solve on that
    # parent may try again. Keyed by prevhash rather than height:
    # after a reorg the same height is mined on a NEW parent, and
    # that block must still be submitted.
    #
    # Returns True when a submission task was launched, False
    # when the sibling guard swallowed the block.
    #
    # Used by:
    #   - families/bitcoin/server.py — process_share()
    ############################################################

    def _start_block_submission(self, job: Dict, extra_nonce1: str, extra_nonce2: str,
                                header_hex: str) -> bool:
        parent = job["prevhash"]

        if parent in self.submitted_parents:
            print("[SUBMIT] ⏭️  Sibling block NOT submitted: a block on this parent was already "
                  "sent to the node (a second one can only be stale). Share stays accepted.")
            return False

        self.submitted_parents[parent] = True
        while len(self.submitted_parents) > MAX_SUBMITTED_PARENTS:
            del self.submitted_parents[next(iter(self.submitted_parents))]

        self._spawn(self._submit_block_task(job, extra_nonce1, extra_nonce2, header_hex))
        return True






    ############################################################
    # _submit_block_task
    ############################################################
    #
    # The background half of a block submission. On acceptance,
    # counts the block and IMMEDIATELY cuts the next job:
    # submitblock only returns after the node connected the
    # block, so getblocktemplate already describes the new tip
    # and miners receive fresh work without waiting for the
    # longpoll to fire (the longpoll stays as the safety net —
    # create_job() recognizes the tip it already cut a job for
    # and dedupes the double trigger). On failure the parent is
    # unmarked so a later block on it may be submitted after all.
    #
    # Used by:
    #   - families/bitcoin/server.py — _start_block_submission()
    ############################################################

    async def _submit_block_task(self, job: Dict, extra_nonce1: str, extra_nonce2: str,
                                 header_hex: str) -> None:
        if await self._submit_block(job, extra_nonce1, extra_nonce2, header_hex):
            self.blocks_found += 1
            self._print_stats()
            await self.create_job()
        else:
            self.submitted_parents.pop(job["prevhash"], None)






    ############################################################
    # _submit_block
    ############################################################
    #
    # Assembles the complete block around the already-verified
    # header and hands it to the node. The header comes from
    # the same build_header() call that validated the share,
    # so header and block body cannot disagree.
    #
    # submitblock returns null on success and an error string
    # ("bad-txnmrklroot", "high-hash", ...) on rejection.
    #
    # Used by:
    #   - families/bitcoin/server.py — _submit_block_task()
    ############################################################

    async def _submit_block(self, job: Dict, extra_nonce1: str, extra_nonce2: str,
                            header_hex: str) -> bool:
        try:
            print("[SUBMIT] Building block for submission...")
            complete_block = assemble_block(job, extra_nonce1, extra_nonce2, header_hex,
                                            has_mweb=coins.active().has_mweb)

            print("[SUBMIT] Submitting to network...")
            result = await self.rpc.call("submitblock", [complete_block])

            if result is None:
                print("[SUBMIT] ✅ Block ACCEPTED by network!")
                return True
            else:
                print(f"[SUBMIT] ❌ Block REJECTED: {result}")
                return False

        except Exception as e:
            print(f"[SUBMIT] ❌ Block submission error: {e}")
            import traceback
            traceback.print_exc()
            return False
