############################################################
#  [*] Console Display
#
#  Every boxed panel the pool prints lives in this module,
#  so the business logic (jobs, shares, connections) stays
#  free of presentation code. Nothing here affects mining —
#  deleting this whole file's output would leave a working
#  but silent pool.
#
#  Two kinds of output:
#
#    - Operator panels (green/red) — always printed: startup
#      banner, new block detected, job created/broadcasted,
#      share validation results.
#    - Debug panels (blue/red)     — printed only when the
#      DEBUG env variable is true, via debug_box().
#
#  Bitcoin-family panels take stratum-v1-shaped jobs; the
#  cn_* variants below render the same operator story for the
#  CryptoNote family (per-client jobs, blob-based shares).
#
#  Used by:
#    - families/bitcoin/  — job/broadcast/share panels
#    - families/cryptonote/ — the cn_* panels
#    - both families      — startup_banner, new_block_panel,
#                           debug_box
############################################################


from datetime import datetime
from typing import Dict, List

from pyboxen import boxen

from anypool import config








############################################################
# timestamp
############################################################
#
# The "YYYY-MM-DD HH:MM:SS" prefix used in panel titles.
#
# Used by:
#   - display.py — panel titles below
############################################################

def timestamp() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')








############################################################
# debug_box
############################################################
#
# Prints a boxed debug panel, but only when DEBUG is enabled.
# Callers pass pre-formatted lines; use ljust() for aligned
# label/value columns.
#
# Used by:
#   - families/bitcoin/ — coinbase, jobs, shares, server
#   - families/cryptonote/server.py
############################################################

def debug_box(title: str, lines: List[str], color: str = "blue") -> None:
    if not config.DEBUG:
        return
    print(
        boxen(
            *lines,
            title=title,
            color=color,
            padding=(0, 3, 0, 3),
        )
    )








############################################################
# startup_banner
############################################################
#
# The green box shown once when the pool boots, summarizing
# the whole configuration at a glance.
#
# Used by:
#   - families/bitcoin/server.py    — StratumServer.__init__()
#   - families/cryptonote/server.py — CnStratumServer.__init__()
############################################################

def startup_banner(pool_difficulty: int) -> None:
    print("")
    print(
        boxen(
            "Coin: ".ljust(20) +            f"{config.COIN} ({config.COIN_NETWORK})",
            "RPC: ".ljust(20) +             config.RPC_URL,
            "Port: ".ljust(20) +            str(config.STRATUM_PORT),
            "Reward Address: ".ljust(20) +  config.REWARD_ADDR,
            "Pool Difficulty: ".ljust(20) + str(pool_difficulty),

            title="AnyPool - Stratum Server ⚙️   ⚙️   ⚙️  ",
            color="green",
            padding=1,
        )
    )








############################################################
# new_block_panel
############################################################
#
# Announces that the chain tip moved and we are about to cut
# a fresh job for the new height.
#
# Used by:
#   - families/bitcoin/server.py    — create_job() on a new template
#   - families/cryptonote/server.py — create_job() on a new template
############################################################

def new_block_panel(prev_height: int, prev_hash: str) -> None:
    print()
    print(
        boxen(
            "Height: ".ljust(10) + str(prev_height),
            "SHA256: ".ljust(10) + prev_hash,
            title=f"{timestamp()} - New Block Detected  📦  📦  📦 ",
            color="green",
            padding=1,
        )
    )








############################################################
# job_created_panel
############################################################
#
# The full report printed whenever a new mining job is cut:
# job identity, difficulties and targets side by side so an
# operator can immediately sanity-check the pool/network gap.
#
# Used by:
#   - families/bitcoin/server.py — create_job()
############################################################

def job_created_panel(job: Dict, pool_difficulty: int, network_difficulty: int,
                      pool_target: int, network_target: int) -> None:

    times_easier = int(network_difficulty / pool_difficulty)

    print()
    print(
        boxen(
            "JOB DETAILS:",
            "Job ID:".ljust(30) +                   job["job_id"],
            "Job prevhash:".ljust(30) +             job["template"]["previousblockhash"],
            "Job nbits:".ljust(30) +                job["nbits"],
            "Job ntime:".ljust(30) +                job["ntime"],
            "Job merkle branch count:".ljust(30) +  str(len(job.get("merkle_branch", []))),
            "",
            "DIFFICULTY:",
            "Pool Difficulty:".ljust(30) +          f"{pool_difficulty:,} {f'(Pool is {times_easier:,}x easier)' if times_easier > 1 else ''}",
            "Network Difficulty:".ljust(30) +       f"{network_difficulty:,}",
            "",
            "TARGETS:",
            "Pool Target:".ljust(30) +              f"{pool_target:064x}",
            "Network Target:".ljust(30) +           f"{network_target:064x}",

            title=f"{timestamp()} - New Mining Job Created and Broadcasted to Miners  ⛏️   ⛏️   ⛏️  ",
            title_alignment="left",
            text_alignment="left",
            color="green",
            padding=(0, 3, 0, 3),
        )
    )








############################################################
# broadcast_panel
############################################################
#
# Lists every connected miner a job was just pushed to, with
# its IP, mining software and assigned extranonce1.
#
# Used by:
#   - families/bitcoin/server.py — broadcast_new_job()
############################################################

def broadcast_panel(job_id: str, clients) -> None:
    to_print = [""]
    to_print.append(f"JOB ID: {job_id.ljust(20)}")
    to_print.append("")

    for client in clients:
        to_print.append("Miner:    " + f"IP Address:    {client.client_ip}".ljust(35) + f"- Soft: {client.miner_software}".ljust(25) + f"- Worker: {client.worker_name}".ljust(25))
        to_print.append("Job:      " + f"Extra Nonce 1: {client.extra_nonce1}".ljust(35))
        to_print.append("")

    print()
    print(
        boxen(
            "\n".join(to_print),
            title=f"{timestamp()} - Job broadcasted to connected clients",
            color="green",
            padding=(0, 3, 0, 3),
        )
    )








############################################################
# share_result_panel
############################################################
#
# The verdict box printed for every submitted share: whether
# it met the pool target, whether it is a full block, and all
# hashes/targets involved so a rejected share can be debugged
# straight from the logs.
#
# Used by:
#   - families/bitcoin/server.py — process_share()
############################################################

def share_result_panel(is_accepted: bool, is_block: bool, job_id: str, height: int,
                       result_hash: str, sha256_hash: str, prevhash_display: str,
                       pool_difficulty: int, network_difficulty: int,
                       pool_target: int, network_target: int) -> None:

    to_print = []

    if is_accepted and is_block:
        to_print.append(" --- YOUR MINER HAS FOUND A NEW BLOCK! 🎉🎉🎉🎉 ✅✅✅✅ ---")
        to_print.append("Share Status: 🎉 FOUND A BLOCK! 🎉")
    elif is_accepted:
        to_print.append(" --- Your miner found a share, but it's not a block. Keep mining!")
        to_print.append("Share Status: ✅ ACCEPTED (NOT A BLOCK)")
    else:
        to_print.append("Share Status: ❌ REJECTED - Hash too high")

    to_print.append("")
    to_print.append("Job ID:".ljust(25) +                f"{job_id}")
    to_print.append("Mined for Height:".ljust(25) +      f"{height}")
    to_print.append("")
    to_print.append("PoW Hash:".ljust(25) +              f"{result_hash}")
    to_print.append("Pool Target:".ljust(25) +           f"{pool_target:064x}")
    to_print.append("Network Target:".ljust(25) +        f"{network_target:064x}")
    to_print.append("")
    to_print.append("Pool Difficulty:".ljust(25) +       f"{pool_difficulty:,}")
    to_print.append("Network Difficulty:".ljust(25) +    f"{network_difficulty:,}")
    to_print.append("")
    to_print.append("SHA256 Previous Hash:".ljust(25) +  f"{prevhash_display}")
    to_print.append("SHA256 Hash:".ljust(25) +           sha256_hash)
    to_print.append("Proposed block Height:".ljust(25) + f"{height}")

    print()
    print(
        boxen(
            "\n".join(to_print),
            title=f"{timestamp()} - Mined share validation result 👷  👷  👷 ",
            color="green" if is_accepted else "red",
            padding=1,
        )
    )








############################################################
# cn_job_created_panel
############################################################
#
# The CryptoNote counterpart of job_created_panel: whenever a
# new template is cut, show its identity, both difficulties
# and both 256-bit targets side by side. Job ids are not
# shown here because CryptoNote jobs are per client — see
# cn_broadcast_panel for those.
#
# Used by:
#   - families/cryptonote/server.py — create_job()
############################################################

def cn_job_created_panel(height: int, prev_hash: str, blob_size: int, tx_count: int,
                         pool_difficulty: int, network_difficulty: int) -> None:

    pool_target = (2 ** 256 - 1) // pool_difficulty
    network_target = (2 ** 256 - 1) // network_difficulty
    times_easier = int(network_difficulty / pool_difficulty)

    print()
    print(
        boxen(
            "TEMPLATE DETAILS:",
            "Mining height:".ljust(30) +            str(height),
            "Parent block:".ljust(30) +             prev_hash,
            "Template blob size:".ljust(30) +       f"{blob_size} bytes",
            "Mempool transactions:".ljust(30) +     str(tx_count),
            "",
            "DIFFICULTY:",
            "Pool Difficulty:".ljust(30) +          f"{pool_difficulty:,} {f'(Pool is {times_easier:,}x easier)' if times_easier > 1 else ''}",
            "Network Difficulty:".ljust(30) +       f"{network_difficulty:,}",
            "",
            "TARGETS:",
            "Pool Target:".ljust(30) +              f"{pool_target:064x}",
            "Network Target:".ljust(30) +           f"{network_target:064x}",

            title=f"{timestamp()} - New Mining Job Created and Broadcasted to Miners  ⛏️   ⛏️   ⛏️  ",
            title_alignment="left",
            text_alignment="left",
            color="green",
            padding=(0, 3, 0, 3),
        )
    )








############################################################
# cn_broadcast_panel
############################################################
#
# The CryptoNote counterpart of broadcast_panel. Because every
# miner receives a PERSONALIZED job, the rows carry each
# client's own job id, difficulty and extranonce rather than
# one shared job id.
#
# Used by:
#   - families/cryptonote/server.py — broadcast_new_jobs()
############################################################

def cn_broadcast_panel(deliveries) -> None:
    to_print = [""]

    for client, job in deliveries:
        to_print.append("Miner:    " + f"IP Address: {client.client_ip}".ljust(32) + f"- Soft: {client.miner_software}".ljust(28) + f"- Worker: {client.worker_name}".ljust(25))
        to_print.append("Job:      " + f"Job ID: {job['job_id']}".ljust(32) + f"- Difficulty: {job['pool_difficulty']:,}".ljust(28) + f"- Extranonce: {job['extranonce'].hex()}".ljust(25))
        to_print.append("")

    print()
    print(
        boxen(
            "\n".join(to_print),
            title=f"{timestamp()} - Job broadcasted to connected clients",
            color="green",
            padding=(0, 3, 0, 3),
        )
    )








############################################################
# cn_share_result_panel
############################################################
#
# The CryptoNote counterpart of share_result_panel: the
# verdict box for every submitted share with the PoW hash and
# both targets, so a rejected share can be debugged straight
# from the logs.
#
# Used by:
#   - families/cryptonote/server.py — process_share()
############################################################

def cn_share_result_panel(is_accepted: bool, is_block: bool, job_id: str, height: int,
                          worker: str, pow_hash: str,
                          pool_difficulty: int, network_difficulty: int) -> None:

    pool_target = (2 ** 256 - 1) // pool_difficulty
    network_target = (2 ** 256 - 1) // network_difficulty

    # CryptoNote compares the hash as a little-endian integer, so
    # show that value next to the targets it is judged against.
    hash_value = int.from_bytes(bytes.fromhex(pow_hash), "little")

    to_print = []

    if is_accepted and is_block:
        to_print.append(" --- YOUR MINER HAS FOUND A NEW BLOCK! 🎉🎉🎉🎉 ✅✅✅✅ ---")
        to_print.append("Share Status: 🎉 FOUND A BLOCK! 🎉")
    elif is_accepted:
        to_print.append(" --- Your miner found a share, but it's not a block. Keep mining!")
        to_print.append("Share Status: ✅ ACCEPTED (NOT A BLOCK)")
    else:
        to_print.append("Share Status: ❌ REJECTED - Hash too high")

    to_print.append("")
    to_print.append("Job ID:".ljust(25) +                f"{job_id}")
    to_print.append("Worker:".ljust(25) +                f"{worker}")
    to_print.append("Mined for Height:".ljust(25) +      f"{height}")
    to_print.append("")
    to_print.append("PoW Hash:".ljust(25) +              f"{pow_hash}")
    to_print.append("Hash as LE value:".ljust(25) +      f"{hash_value:064x}")
    to_print.append("Pool Target:".ljust(25) +           f"{pool_target:064x}")
    to_print.append("Network Target:".ljust(25) +        f"{network_target:064x}")
    to_print.append("")
    to_print.append("Pool Difficulty:".ljust(25) +       f"{pool_difficulty:,}")
    to_print.append("Network Difficulty:".ljust(25) +    f"{network_difficulty:,}")

    print()
    print(
        boxen(
            "\n".join(to_print),
            title=f"{timestamp()} - Mined share validation result 👷  👷  👷 ",
            color="green" if is_accepted else "red",
            padding=1,
        )
    )
