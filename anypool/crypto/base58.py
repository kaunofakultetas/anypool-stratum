############################################################
#  [*] Base58Check Address Decoding
#
#  The legacy address format of Bitcoin Core forks that
#  predate (or never adopted) segwit — Dogecoin being the
#  prime example. Used for one single purpose, mirroring
#  crypto/bech32.py: turning the pool's REWARD_ADDR into the
#  P2PKH scriptPubKey that receives the block reward.
#
#  A base58check address is the base58 rendering of three
#  parts in order: a version byte naming coin and network
#  (Dogecoin's mainnet byte is why its addresses start with
#  a D), the payload — the 20-byte hash160 of the public
#  key — and a 4-byte checksum, the start of the double
#  SHA256 of the two parts before it.
#
#  Used by:
#    - coins/address.py — the Base58P2PKH address scheme
############################################################


from typing import Tuple

from anypool.crypto.hashing import sha256d


# Bitcoin's base58 alphabet — no 0, O, I or l, the characters
# people misread when copying an address by hand — and each
# character's digit value
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {c: i for i, c in enumerate(BASE58_ALPHABET)}








############################################################
# base58_decode
############################################################
#
# Decodes raw base58 into bytes. The string is read as one
# big base-58 number; each leading '1' character encodes one
# leading zero byte (base58's quirk, since '1' is digit 0).
# Raises ValueError on characters outside the alphabet.
#
# Used by:
#   - base58check_decode() (below)
############################################################

def base58_decode(s: str) -> bytes:
    num = 0
    for c in s:
        if c not in BASE58_INDEX:
            raise ValueError(f"Invalid base58 character: '{c}'")
        num = num * 58 + BASE58_INDEX[c]

    body = num.to_bytes((num.bit_length() + 7) // 8, "big")

    # Each leading '1' is one leading zero byte
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body








############################################################
# base58check_decode
############################################################
#
# Decodes an address (surrounding whitespace ignored),
# validates the 4-byte double-SHA256 checksum and returns the
# version byte and the payload behind it. Raises ValueError
# on anything malformed — a character outside the alphabet,
# too short, bad checksum.
#
# Used by:
#   - p2pkh_script_for_address() (below)
############################################################

def base58check_decode(addr: str) -> Tuple[int, bytes]:
    raw = base58_decode(addr.strip())

    if len(raw) < 5:
        raise ValueError("Base58check string too short")

    payload, checksum = raw[:-4], raw[-4:]

    if sha256d(payload)[:4] != checksum:
        raise ValueError("Invalid base58check checksum")

    return payload[0], payload[1:]








############################################################
# p2pkh_script_for_address
############################################################
#
# The public entry point of this module: decodes a legacy
# address, checks it belongs to the expected network (by its
# version byte), and returns the P2PKH scriptPubKey as hex —
# OP_DUP, OP_HASH160 and a 20-byte push (76a914), the pubkey
# hash, then OP_EQUALVERIFY and OP_CHECKSIG (88ac).
#
# Raises ValueError for a wrong-network address or a payload
# that is not exactly 20 bytes.
#
# Used by:
#   - coins/address.py — Base58P2PKH.payout_script()
############################################################

def p2pkh_script_for_address(addr: str, expected_version: int) -> str:
    version, pubkey_hash = base58check_decode(addr)

    if version != expected_version:
        raise ValueError(f"Wrong address version byte 0x{version:02x} (expected 0x{expected_version:02x})")

    if len(pubkey_hash) != 20:
        raise ValueError("P2PKH payload must be 20 bytes")

    return "76a914" + pubkey_hash.hex() + "88ac"
