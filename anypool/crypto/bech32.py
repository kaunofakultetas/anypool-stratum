# -----------------------------------------------------------
#  [*] Bech32 Address Decoding
#
#  A self-contained bech32 (BIP-173) decoder, used for one
#  single purpose: turning the pool's REWARD_ADDR into the
#  P2WPKH scriptPubKey that receives the block reward inside
#  the coinbase transaction.
#
#  Only witness-version-0 P2WPKH (20-byte program) addresses
#  are supported — that is the "native segwit" address the
#  README asks the operator to configure.
#
#  Used by:
#    - mining/coinbase.py — p2wpkh_script_for_address() when
#                    building the payout output
# -----------------------------------------------------------

from typing import List, Optional, Tuple


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CHARKEY = {c: i for i, c in enumerate(BECH32_CHARSET)}




# -----------------------------------------------------------
# bech32_polymod
# -----------------------------------------------------------
#
# The BIP-173 checksum polynomial. Internal building block of
# checksum verification — not meant to be called directly.
#
# Used by:
#   - bech32.py — bech32_verify_checksum()
# -----------------------------------------------------------
def bech32_polymod(values: List[int]) -> int:
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xff
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk










# -----------------------------------------------------------
# bech32_hrp_expand
# -----------------------------------------------------------
#
# Expands the human-readable part ("tltc", "knf", ...) into
# the value sequence the checksum is computed over.
#
# Used by:
#   - bech32.py — bech32_verify_checksum()
# -----------------------------------------------------------
def bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]










# -----------------------------------------------------------
# bech32_verify_checksum
# -----------------------------------------------------------
#
# True if the address checksum is valid for the given
# human-readable part and data values.
#
# Used by:
#   - bech32.py — bech32_decode()
# -----------------------------------------------------------
def bech32_verify_checksum(hrp: str, data: List[int]) -> bool:
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1










# -----------------------------------------------------------
# bech32_decode
# -----------------------------------------------------------
#
# Splits and validates a bech32 string. Returns the tuple
# (hrp, data-values-without-checksum) or (None, None) on any
# malformation: mixed case, bad charset, bad checksum, etc.
#
# Used by:
#   - bech32.py — p2wpkh_script_for_address()
# -----------------------------------------------------------
def bech32_decode(addr: str) -> Tuple[Optional[str], Optional[List[int]]]:
    addr = addr.strip()

    if any(ord(x) < 33 or ord(x) > 126 for x in addr):
        return None, None

    # Mixed-case addresses are invalid per BIP-173
    if addr.lower() != addr and addr.upper() != addr:
        return None, None
    addr = addr.lower()

    if '1' not in addr:
        return None, None

    # Last '1' separates the human-readable part from the data
    pos = addr.rfind('1')
    hrp, data = addr[:pos], addr[pos+1:]
    if len(data) < 6:
        return None, None

    try:
        decoded = [BECH32_CHARKEY[c] for c in data]
    except KeyError:
        return None, None

    if not bech32_verify_checksum(hrp, decoded):
        return None, None

    # Strip the 6 checksum values off the end
    return hrp, decoded[:-6]










# -----------------------------------------------------------
# convertbits
# -----------------------------------------------------------
#
# General power-of-2 base conversion (BIP-173 reference
# implementation). Used to regroup the 5-bit bech32 values
# into the 8-bit bytes of the witness program.
#
# Used by:
#   - bech32.py — p2wpkh_script_for_address()
# -----------------------------------------------------------
def convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1

    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        return None

    return ret










# -----------------------------------------------------------
# p2wpkh_script_for_address
# -----------------------------------------------------------
#
# The public entry point of this module: decodes a native
# segwit address, checks it belongs to the expected network
# (by its prefix), and returns the P2WPKH scriptPubKey hex:
#
#     0014 + <20-byte pubkey hash>
#     ^^^^
#     OP_0 + push-20
#
# Raises ValueError for a wrong-network address or anything
# that is not witness v0 / 20 bytes.
#
# Used by:
#   - mining/coinbase.py — payout output of the coinbase tx
# -----------------------------------------------------------
def p2wpkh_script_for_address(addr: str, expected_prefix: str) -> str:
    hrp, data = bech32_decode(addr)

    if hrp != expected_prefix or data is None:
        raise ValueError(f"Invalid bech32 address (expected prefix: {expected_prefix})")

    witver = data[0]
    prog5 = data[1:]
    prog = bytes(convertbits(prog5, 5, 8, False))

    if witver != 0 or len(prog) != 20:
        raise ValueError("Only v0 P2WPKH supported")

    return "0014" + prog.hex()
