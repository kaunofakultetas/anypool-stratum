############################################################
#  [*] CryptoNote Base58
#
#  CryptoNote's base58 is NOT Bitcoin's: the payload is
#  encoded in fixed 8-byte blocks of 11 characters each
#  (final partial block shorter, per the size table below),
#  which makes encoded addresses fixed-length and decoding
#  O(1) per block. Same alphabet as Bitcoin.
#
#  An address is:  varint(prefix) || spend_pub(32) ||
#                  view_pub(32) || checksum(4)
#  where checksum = keccak_256(everything before it)[:4].
#
#  Used by:
#    - coins/address.py — CryptoNoteAddress scheme (validate
#      REWARD_ADDR at startup)
#    - families/cryptonote/blob.py — the varint helpers
#    - tests/test_cn_crypto.py
############################################################


from typing import Tuple

from anypool.crypto.keccak import keccak_256


_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_INDEX = {c: i for i, c in enumerate(_ALPHABET)}

# Encoded size (chars) of a partial final block of N bytes
_ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]

_FULL_BLOCK_BYTES = 8
_FULL_BLOCK_CHARS = 11








############################################################
# _encode_block
############################################################
#
# One block (up to 8 bytes) to its fixed-width base58 run,
# per the _ENCODED_BLOCK_SIZES table.
#
# Used by:
#   - encode (below)
############################################################

def _encode_block(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out_len = _ENCODED_BLOCK_SIZES[len(data)]
    chars = []
    for _ in range(out_len):
        num, rem = divmod(num, 58)
        chars.append(_ALPHABET[rem])
    return "".join(reversed(chars))








############################################################
# _decode_block
############################################################
#
# One base58 character run back to its exact byte count.
# Rejects foreign characters and values that overflow the
# declared block size (a corruption base58 alone would hide).
#
# Used by:
#   - decode (below)
############################################################

def _decode_block(chars: str, out_bytes: int) -> bytes:
    num = 0
    for c in chars:
        if c not in _ALPHABET_INDEX:
            raise ValueError(f"invalid base58 character {c!r}")
        num = num * 58 + _ALPHABET_INDEX[c]
    if num >= 1 << (8 * out_bytes):
        raise ValueError("base58 block overflows its byte size")
    return num.to_bytes(out_bytes, "big")








############################################################
# encode
############################################################
#
# Raw block-wise base58, no checksum handling — the address
# layer below adds the checksum.
#
# Used by:
#   - encode_addr (below)
############################################################

def encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data), _FULL_BLOCK_BYTES):
        out.append(_encode_block(data[i:i + _FULL_BLOCK_BYTES]))
    return "".join(out)








############################################################
# decode
############################################################
#
# Raw block-wise base58 back to bytes. The length alone
# fixes the byte size of the final partial block, so any
# length not reachable by the size table is rejected.
#
# Used by:
#   - decode_addr (below)
############################################################

def decode(s: str) -> bytes:
    full_blocks, rem_chars = divmod(len(s), _FULL_BLOCK_CHARS)
    if rem_chars and rem_chars not in _ENCODED_BLOCK_SIZES:
        raise ValueError("invalid base58 length")
    rem_bytes = _ENCODED_BLOCK_SIZES.index(rem_chars) if rem_chars else 0

    out = bytearray()
    for i in range(full_blocks):
        out += _decode_block(s[i * _FULL_BLOCK_CHARS:(i + 1) * _FULL_BLOCK_CHARS],
                             _FULL_BLOCK_BYTES)
    if rem_chars:
        out += _decode_block(s[full_blocks * _FULL_BLOCK_CHARS:], rem_bytes)
    return bytes(out)








############################################################
# write_varint
############################################################
#
# The LEB128 varint CryptoNote uses everywhere: 7 bits per
# byte, high bit = continuation.
#
# Used by:
#   - encode_addr (below) — the address prefix
#   - families/cryptonote/blob.py — block reserialization
#     and the tree-hash blob count
############################################################

def write_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)








############################################################
# read_varint
############################################################
#
# Reads one varint at `offset`; returns (value, new offset)
# so parsers can chain calls. Truncated input surfaces as a
# plain IndexError.
#
# Used by:
#   - decode_addr (below) — the address prefix
#   - families/cryptonote/blob.py — miner-tx/block parsing
############################################################

def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7








############################################################
# encode_addr
############################################################
#
# The address layer, encode side: varint(prefix) + payload,
# sealed with the 4-byte keccak checksum.
#
# Used by:
#   - tests/test_cn_crypto.py — address round-trips (nothing
#     in the pool itself constructs addresses)
############################################################

def encode_addr(prefix: int, payload: bytes) -> str:
    body = write_varint(prefix) + payload
    checksum = keccak_256(body)[:4]
    return encode(body + checksum)








############################################################
# decode_addr
############################################################
#
# The address layer, decode side: verifies the keccak
# checksum and splits off the prefix varint. Raises
# ValueError on any corruption, which config.validate()
# turns into a readable startup error.
#
# Used by:
#   - coins/address.py — CryptoNoteAddress.validate_address()
############################################################

def decode_addr(address: str) -> Tuple[int, bytes]:
    raw = decode(address)
    if len(raw) < 5:
        raise ValueError("address too short")
    body, checksum = raw[:-4], raw[-4:]
    if keccak_256(body)[:4] != checksum:
        raise ValueError("address checksum mismatch")
    prefix, offset = read_varint(body, 0)
    return prefix, body[offset:]
