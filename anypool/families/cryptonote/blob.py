############################################################
#  [*] CryptoNote Block Blob Tools
#
#  Everything the pool must know about the byte layout of a
#  CryptoNote block template. The daemon hands us ONE opaque
#  hex blob (blocktemplate_blob) and two numbers (its
#  reserved_offset and the network difficulty); this module
#  turns that into mineable work:
#
#    parse_block()      — split the blob into header fields,
#                         the miner transaction and the tx
#                         hash list (validates every byte)
#    hashing_blob()     — derive the blob miners actually
#                         hash (usually 76 bytes): header +
#                         merkle tree root + tx count
#    block_id()         — a block's id (keccak of the size-
#                         prefixed hashing blob); verifies the
#                         parse against real blocks and names
#                         found blocks in the log
#    with_nonce() /
#    with_extranonce()  — byte-level injection of the miner
#                         nonce and the pool's extranonce
#    tree_hash()        — CryptoNote's merkle variant
#
#  Only transaction version 1 is supported for the miner tx —
#  which is what this chain (block major version 1, pre-
#  RingCT) produces. A v2 miner tx would mean a hardfork this
#  pool predates, so it raises loudly instead of mis-hashing.
#
#  Used by:
#    - families/cryptonote/jobs.py   — job construction
#    - families/cryptonote/server.py — share validation and
#                                      block submission
############################################################


from typing import Dict, List

from anypool.crypto.cn_base58 import read_varint, write_varint
from anypool.crypto.keccak import keccak_256


# Transaction output type tag: txout_to_key
_TXOUT_TO_KEY = 0x02

# Transaction input type tag: txin_gen (coinbase)
_TXIN_GEN = 0xFF








############################################################
# tree_hash
############################################################
#
# CryptoNote's merkle tree (tree-hash.c): NOT Bitcoin's. The
# leaf count is first reduced to the largest power of two
# not above it by pair-hashing leaves at the TAIL of the
# list, then halved level by level. One leaf is its own
# root; an empty list raises ValueError.
#
# Used by:
#   - hashing_blob() (below)
#   - tests/test_cn_blob.py — against real multi-tx blocks
############################################################

def tree_hash(hashes: List[bytes]) -> bytes:
    count = len(hashes)
    if count == 0:
        raise ValueError("tree_hash of empty list")
    if count == 1:
        return hashes[0]
    if count == 2:
        return keccak_256(hashes[0] + hashes[1])

    # Largest power of two <= count. When count is an exact power
    # of two, 2*cnt - count == count: the copy below takes every
    # leaf and the pair-hashing loop is empty.
    cnt = 1 << (count.bit_length() - 1)

    ints = list(hashes[: 2 * cnt - count])
    i = 2 * cnt - count
    while len(ints) < cnt:
        ints.append(keccak_256(hashes[i] + hashes[i + 1]))
        i += 2

    while cnt > 2:
        cnt >>= 1
        ints = [keccak_256(ints[2 * j] + ints[2 * j + 1]) for j in range(cnt)]

    return keccak_256(ints[0] + ints[1])








############################################################
# _parse_miner_tx
############################################################
#
# Walks a serialized version-1 miner transaction and returns
# the offset one past its end. A miner tx is:
#
#   varint version | varint unlock_time
#   varint vin_count  | per vin:  0xFF tag + varint height
#   varint vout_count | per vout: varint amount + 0x02 tag
#                                 + 32-byte one-time key
#   varint extra_len  | extra bytes  (the pool's reserved
#                                     space lives in here)
#
# v1 coinbase txs carry no signatures (txin_gen needs none),
# so the tx ends right after extra.
#
# Used by:
#   - parse_block() (below)
############################################################

def _parse_miner_tx(blob: bytes, offset: int) -> int:
    version, offset = read_varint(blob, offset)
    if version != 1:
        raise ValueError(f"unsupported miner tx version {version} (only v1 supported)")

    _unlock_time, offset = read_varint(blob, offset)

    vin_count, offset = read_varint(blob, offset)
    for _ in range(vin_count):
        tag = blob[offset]
        offset += 1
        if tag != _TXIN_GEN:
            raise ValueError(f"unexpected miner tx input tag {tag:#x}")
        _height, offset = read_varint(blob, offset)

    vout_count, offset = read_varint(blob, offset)
    for _ in range(vout_count):
        _amount, offset = read_varint(blob, offset)
        tag = blob[offset]
        offset += 1
        if tag != _TXOUT_TO_KEY:
            raise ValueError(f"unexpected miner tx output tag {tag:#x}")
        offset += 32  # one-time public key

    extra_len, offset = read_varint(blob, offset)
    offset += extra_len

    if offset > len(blob):
        raise ValueError("miner tx runs past end of blob")
    return offset








############################################################
# parse_block
############################################################
#
# Full structural parse of a block (template) blob. Raises
# unless every byte is accounted for — a pool must never
# mine on a blob it does not fully understand. Structural
# checks raise ValueError, but a blob cut short mostly
# surfaces as IndexError from the byte reads, so callers
# must not catch ValueError alone.
#
# Returns a dict of offsets and parts; all offsets are into
# the ORIGINAL blob so injection helpers can patch bytes
# in place.
#
# Used by:
#   - hashing_blob() (below)
#   - families/cryptonote/jobs.py   — set_template()
#   - families/cryptonote/server.py — create_job(), the tx
#     count for the new-job panel
#   - tests/test_cn_blob.py
############################################################

def parse_block(blob: bytes) -> Dict:
    offset = 0
    major_version, offset = read_varint(blob, offset)
    minor_version, offset = read_varint(blob, offset)
    timestamp, offset = read_varint(blob, offset)

    prev_id = blob[offset:offset + 32]
    offset += 32

    nonce_offset = offset
    nonce = blob[offset:offset + 4]
    offset += 4

    header_end = offset

    miner_tx_start = offset
    miner_tx_end = _parse_miner_tx(blob, offset)

    tx_count, offset = read_varint(blob, miner_tx_end)
    tx_hashes = []
    for _ in range(tx_count):
        tx_hashes.append(blob[offset:offset + 32])
        offset += 32

    if offset != len(blob):
        raise ValueError(f"trailing bytes in block blob ({len(blob) - offset})")

    return {
        "major_version": major_version,
        "minor_version": minor_version,
        "timestamp": timestamp,
        "prev_id": prev_id,
        "nonce": nonce,
        "nonce_offset": nonce_offset,
        "header_end": header_end,
        "miner_tx_start": miner_tx_start,
        "miner_tx_end": miner_tx_end,
        "tx_hashes": tx_hashes,
    }








############################################################
# hashing_blob
############################################################
#
# The blob miners hash (and the input to the PoW function):
#
#   header (up to and incl. nonce) | tree root | tx count
#
# where the tree root covers the miner tx hash followed by
# the other tx hashes, and the tx count is a varint that
# counts the miner tx too. 76 bytes for a typical block. The
# miner tx hash for v1 txs is the keccak of its raw bytes.
#
# Used by:
#   - families/cryptonote/jobs.py — make_job(); the result is
#     the blob each miner receives and the one
#     process_share() re-hashes
#   - block_id() (below)
############################################################

def hashing_blob(blob: bytes) -> bytes:
    parsed = parse_block(blob)

    miner_tx_hash = keccak_256(blob[parsed["miner_tx_start"]:parsed["miner_tx_end"]])
    root = tree_hash([miner_tx_hash] + parsed["tx_hashes"])

    return (blob[:parsed["header_end"]]
            + root
            + write_varint(1 + len(parsed["tx_hashes"])))








############################################################
# block_id
############################################################
#
# A block's id as the network knows it: keccak over the
# hashing blob prefixed with its own length varint. Lets the
# tests prove the whole parse/tree/keccak pipeline against
# real blocks of the live chain.
#
# Used by:
#   - tests/test_cn_blob.py
#   - families/cryptonote/server.py — logging found blocks
############################################################

def block_id(blob: bytes) -> bytes:
    hb = hashing_blob(blob)
    return keccak_256(write_varint(len(hb)) + hb)








############################################################
# with_nonce
############################################################
#
# Byte-level injection of the miner's 4-byte nonce into a
# (hashing or template) blob at the header nonce offset —
# both blobs open with the same header, so one offset
# serves both. Returns a NEW bytes object; a nonce of any
# other length raises ValueError.
#
# Used by:
#   - families/cryptonote/server.py — share validation and
#     block submission
############################################################

def with_nonce(blob: bytes, nonce: bytes, nonce_offset: int) -> bytes:
    if len(nonce) != 4:
        raise ValueError("nonce must be 4 bytes")
    return blob[:nonce_offset] + nonce + blob[nonce_offset + 4:]








############################################################
# with_extranonce
############################################################
#
# Byte-level injection of the pool's extranonce into the
# template blob at reserved_offset — the daemon's
# TX_EXTRA_NONCE space inside the miner tx. Changing it
# changes the miner tx hash and thus the tree root, which is
# what gives every client distinct work. Returns a NEW bytes
# object.
#
# Used by:
#   - families/cryptonote/jobs.py — make_job()
############################################################

def with_extranonce(template_blob: bytes, extranonce: bytes, reserved_offset: int,
                    reserve_size: int) -> bytes:
    if len(extranonce) > reserve_size:
        raise ValueError("extranonce larger than reserved space")
    if reserved_offset + reserve_size > len(template_blob):
        raise ValueError("reserved space outside blob")
    return (template_blob[:reserved_offset]
            + extranonce
            + template_blob[reserved_offset + len(extranonce):])
