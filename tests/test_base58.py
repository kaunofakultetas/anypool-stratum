# -----------------------------------------------------------
#  [*] Tests — Base58Check Address Decoding
#
#  Covers anypool/crypto/base58.py. The anchor vector is the
#  well-known Dogecoin Foundation donation address; the rest
#  is a round-trip property test against a test-local ENCODER
#  (so decode is verified against independent logic, not
#  against itself) plus the malformed-input paths.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.crypto.base58 import BASE58_ALPHABET, base58check_decode, p2pkh_script_for_address
from anypool.crypto.hashing import sha256d


# Well-known Dogecoin mainnet address and its hash160
DOGE_ADDR = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
DOGE_HASH160 = "830a7420e63d76244ff7cbd1c248e94c14463259"
DOGE_VERSION_MAINNET = 0x1e




# -----------------------------------------------------------
# reference_base58check_encode
# -----------------------------------------------------------
#
# Independent encoder used to generate test inputs, so the
# decoder is checked against separate logic rather than a
# round-trip through itself.
#
# Used by:
#   - tests/test_base58.py — property tests below
# -----------------------------------------------------------
def reference_base58check_encode(version: int, payload: bytes) -> str:
    raw = bytes([version]) + payload
    raw += sha256d(raw)[:4]

    num = int.from_bytes(raw, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = BASE58_ALPHABET[rem] + encoded

    # Leading zero bytes encode as '1'
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + encoded










class TestDogecoinAddress(unittest.TestCase):


    # -----------------------------------------------------------
    # The known Dogecoin address must decode to its documented
    # version byte and hash160.
    # -----------------------------------------------------------
    def test_known_address_decodes(self):
        version, payload = base58check_decode(DOGE_ADDR)
        self.assertEqual(version, DOGE_VERSION_MAINNET)
        self.assertEqual(payload.hex(), DOGE_HASH160)






    # -----------------------------------------------------------
    # And it must produce the standard P2PKH scriptPubKey.
    # -----------------------------------------------------------
    def test_known_address_to_script(self):
        script = p2pkh_script_for_address(DOGE_ADDR, DOGE_VERSION_MAINNET)
        self.assertEqual(script, "76a914" + DOGE_HASH160 + "88ac")






    # -----------------------------------------------------------
    # The same address with a wrong expected version (e.g. the
    # testnet byte) must be refused — wrong-network guard.
    # -----------------------------------------------------------
    def test_wrong_network_rejected(self):
        with self.assertRaises(ValueError):
            p2pkh_script_for_address(DOGE_ADDR, 0x71)










class TestBase58checkDecode(unittest.TestCase):


    # -----------------------------------------------------------
    # Round trip: whatever the reference encoder produces, the
    # decoder must take apart again — including payloads with
    # leading zero bytes (the '1'-padding corner case).
    # -----------------------------------------------------------
    def test_round_trip(self):
        payloads = [
            bytes.fromhex(DOGE_HASH160),
            b"\x00" * 20,
            b"\x00\x01" + b"\xff" * 18,
            sha256d(b"anything")[:20],
        ]

        for version in (0x00, 0x1e, 0x71):
            for payload in payloads:
                with self.subTest(version=version, payload=payload.hex()):
                    addr = reference_base58check_encode(version, payload)
                    decoded_version, decoded_payload = base58check_decode(addr)
                    self.assertEqual(decoded_version, version)
                    self.assertEqual(decoded_payload, payload)






    # -----------------------------------------------------------
    # Corrupted checksums, invalid characters and too-short
    # strings must all raise.
    # -----------------------------------------------------------
    def test_malformed_inputs(self):
        corrupted = DOGE_ADDR[:-1] + ("2" if DOGE_ADDR[-1] != "2" else "3")
        with self.assertRaises(ValueError):
            base58check_decode(corrupted)

        with self.assertRaises(ValueError):
            base58check_decode("D0OIl")  # 0, O, I, l are not base58

        with self.assertRaises(ValueError):
            base58check_decode("111")    # shorter than checksum




if __name__ == "__main__":
    unittest.main()
