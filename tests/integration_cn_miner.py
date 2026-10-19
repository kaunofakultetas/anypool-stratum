#!/usr/bin/env python3
############################################################
#  [*] Integration — CryptoNote Fake Miner
#
#  A minimal real miner speaking the CryptoNote stratum
#  dialect, used to prove the whole pool end to end against
#  a LIVE daemon. It logs in, takes the personalized job the
#  pool hands it, brute-forces nonces on the CPU with the
#  real CryptoNight hash until one meets the job's target,
#  submits that share and expects an OK status — then
#  deliberately submits a WRONG result and expects it
#  refused.
#
#  Run it inside the stratum image (py-cryptonight lives
#  there), on the same docker network as the pool, from the
#  repo root as a module of the tests package — the way
#  tests/integration_mweb_regtest.py is run. Run as a plain
#  script by its path it cannot import the anypool package:
#  Python puts the script's own folder, not the repo root, on
#  the import path. It takes the pool's host and port (the
#  loopback and 3333 when left out), then optionally a time
#  budget in seconds (300 by default) and a difficulty to
#  request for the connection through the password
#  convention.
#
#  The exit code is 0 only when a share was accepted AND the
#  bogus share was refused; anything else is a failure.
#
#  Used by:
#    - manual integration runs against a CryptoNote pool;
#      unittest discovery never picks it up (its name does
#      not start with test)
############################################################


import json
import socket
import sys
import time

from anypool.crypto.cryptonight import cn_slow_hash, hash_meets_difficulty








############################################################
# read_line
############################################################
#
# One JSON frame off the pool socket; EOF means the pool
# dropped us and the run must fail.
#
# Used by:
#   - main() (below)
############################################################

def read_line(sock_file):
    line = sock_file.readline()
    if not line:
        raise ConnectionError("pool closed the connection")
    return json.loads(line)








############################################################
# difficulty_from_compact_target
############################################################
#
# Inverse of the pool's compact_target(): the target's top
# 32 bits travel little-endian; ceil-divide so the recovered
# difficulty is never easier than what the pool set.
#
# Used by:
#   - main() (below) — before brute-forcing each job
############################################################

def difficulty_from_compact_target(target_hex: str) -> int:
    top = int.from_bytes(bytes.fromhex(target_hex), "little")
    return (0xFFFFFFFF + top - 1) // top








############################################################
# main
############################################################
#
# The whole integration scenario in one pass: login, brute
# a real share, submit it, then submit a deliberately wrong
# result. Returns the process exit code — zero only when the
# pool accepted the honest share AND refused the lying one.
#
# Used by:
#   - the __main__ guard below
############################################################

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3333
    deadline = time.time() + (int(sys.argv[3]) if len(sys.argv) > 3 else 300)

    # Optional 4th arg: request a per-connection difficulty via the
    # password convention, exercising the pool's variable-diff path.
    password = f"d={sys.argv[4]}" if len(sys.argv) > 4 else "x"

    sock = socket.create_connection((host, port), timeout=30)
    sock_file = sock.makefile("r")

    def send(obj):
        sock.sendall((json.dumps(obj) + "\n").encode())


    # STEP 1: login and take the first personalized job
    # =================================================
    send({"id": 1, "jsonrpc": "2.0", "method": "login",
          "params": {"login": "integration-test", "pass": password,
                     "agent": "anypool-integration/1.0"}})
    reply = read_line(sock_file)
    assert reply.get("result", {}).get("status") == "OK", f"login failed: {reply}"
    session = reply["result"]["id"]
    job = reply["result"]["job"]
    print(f"[MINER] logged in, session {session}, job {job['job_id']} "
          f"target {job['target']} height {job['height']}")


    # STEP 2: brute nonces with real CryptoNight until a share
    # is accepted (switching jobs when the pool pushes new ones)
    # ==========================================================
    accepted = False
    while time.time() < deadline:
        blob = bytearray(bytes.fromhex(job["blob"]))
        difficulty = difficulty_from_compact_target(job["target"])
        print(f"[MINER] mining job {job['job_id']} at difficulty {difficulty}...")

        found_nonce = None
        for nonce in range(1_000_000):
            blob[39:43] = nonce.to_bytes(4, "little")
            pow_hash = cn_slow_hash(bytes(blob), 0)
            if hash_meets_difficulty(pow_hash, difficulty):
                found_nonce = blob[39:43].hex()
                break
            if time.time() > deadline:
                print("[MINER] FAIL: deadline before a share was found")
                return 1

        print(f"[MINER] share found after {nonce + 1} hashes, nonce {found_nonce}")
        send({"id": 2, "jsonrpc": "2.0", "method": "submit",
              "params": {"id": session, "job_id": job["job_id"],
                         "nonce": found_nonce, "result": pow_hash.hex()}})

        # Read until the response with id=2 (job pushes may interleave)
        while True:
            reply = read_line(sock_file)
            if reply.get("method") == "job":
                job = reply["params"]  # tip moved mid-mine: switch and retry
                print(f"[MINER] new job pushed mid-flight: {job['job_id']}")
                break
            if reply.get("id") == 2:
                if reply.get("result", {}) and reply["result"].get("status") == "OK":
                    print("[MINER] ✅ SHARE ACCEPTED by pool")
                    accepted = True
                else:
                    print(f"[MINER] share rejected: {reply.get('error')} (retrying)")
                break
        if accepted:
            break

    if not accepted:
        print("[MINER] FAIL: no share accepted before deadline")
        return 1


    # STEP 3: negative path — a lying share must be rejected
    # ======================================================
    send({"id": 3, "jsonrpc": "2.0", "method": "submit",
          "params": {"id": session, "job_id": job["job_id"],
                     "nonce": "ffffffff", "result": "00" * 32}})

    # Every frame before the answer is skipped — job pushes
    # and leftovers alike; the explicit continue for a job
    # push changes nothing
    while True:
        reply = read_line(sock_file)
        if reply.get("id") == 3:
            break
        if reply.get("method") == "job":
            continue
    error = (reply.get("error") or {}).get("message", "")
    if reply.get("result") is None and error:
        print(f"[MINER] ✅ bogus share correctly rejected ({error})")
    else:
        print(f"[MINER] FAIL: bogus share was not rejected: {reply}")
        return 1

    print("[MINER] integration test PASSED")
    return 0








if __name__ == "__main__":
    sys.exit(main())
