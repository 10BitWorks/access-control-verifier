#!/usr/bin/env python3
"""pylibsdm-backed NTAG 424 DNA SUN golden-vector generator.

Binding spec for todo 1 (real SUN CMAC verification in access-control-verifier).
All crypto below is delegated to pylibsdm's OWN reference code paths so the
golden values are bit-exact against the reference implementation:

  session keys       -> pylibsdm.backend.validate.ParamValidator.generate_sdm_session_keys
                       (validate.py:159-179): sv2 = b"\\x3c\\xc3\\x00\\x01\\x00\\x80"
                       + uid(7B) + pack("<L", read_ctr)[:3], then
                       k_ses_sdm_file_read_mac = AES-CMAC(k_sdm_file_read, sv2)
  mac_input slice    -> ParamValidator.cmac_input_from_uri (validate.py:143-152),
                       raw URI slice, chip byte-for-byte
  truncated SUN CMAC -> validate.py:259-262: full = AES-CMAC(k_ses_sdm_file_read_mac,
                       mac_input.encode()); truncated = full.digest()[1::2]

PINNED WIRE FORMAT (kept in sync with src/crypto.rs cmac_for_key):

  mac_input = "{UID:14 UPPERCASE hex}&c={CTR:06 UPPERCASE hex}&cmac="
  - UID mirror:     14 ASCII chars, UPPERCASE hex. NXP AN12196 sec.4.4.1 example
                     SUN mapping `uid=04C767F2066180`; real-tag captures (androidcrypto/
                     ntag424sdmfeature demo `uid=049F50824F1390`; NXP datasheet worked
                     examples) emit UPPERCASE hex with A-F present.
  - counter mirror: 6 ASCII chars, UPPERCASE hex, fixed width (AN12196 sec.4.4.1
                     `SDMReadCtrOffsetLength: 6`, example `ctr=000001`). HEX not
                     decimal: a 3-byte counter (max 16777215) needs 8 decimal digits,
                     the mirror is fixed at 6 chars.
  - "&c=" / "&cmac=": static separator + terminator from OUR NDEF URL template
                     (separators are configurable per AN12196; param name `c` matches
                     the provisioned tag layout).

  NOTE: the UPPERCASE pin overrides the provisional "uid lowercase hex" wording in
  the plan todo. The chip emits UPPERCASE hex mirrors, so mac_input recomputation
  must reproduce those exact bytes. pylibsdm's validate_cmac() consumes the raw URI
  slice (validate.py:260-261), preserving chip case - it pins no case itself, which
  is why the AN12196 primary text is authoritative here.
  Session-key derivation is case-INDEPENDENT (input is raw bytes, not the mirror).

Diversification (AN10922 SV1: AES-CMAC(master, 0x01 || uid)) is NOT part of
pylibsdm - it takes the per-tag file-read key directly. It is pinned independently:
for MASTER + uid 046522CABC5D80 it must reproduce the known diversified key
71A4EC87107F7FC71B2220E23D8CE93A, already asserted in test_golden_vectors_from_script.
"""

import sys
from binascii import hexlify

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from pylibsdm.backend.validate import ParamValidator

MASTER = "000102030405060708090a0b0c0d0e0f"
UIDS = ["046522cabc5d80", "04112233445566"]
COUNTERS = [1, 8, 11, 255]

PARAM_UID = "uid"
PARAM_CTR = "c"
PARAM_CMAC = "cmac"
URL_TEMPLATE = "https://10bitworks.org/k"


def diversify(master_hex: str, uid_hex: str) -> bytes:
    """AN10922 SV1 diversification: AES-CMAC(master, 0x01 || uid)."""
    mac = CMAC.new(bytes.fromhex(master_hex), ciphermod=AES)
    mac.update(b"\x01" + bytes.fromhex(uid_hex))
    return mac.digest()


def main() -> int:
    print(f"# pylibsdm golden vectors (master={MASTER}, template={URL_TEMPLATE})")
    print(f"# pylibsdm backend: {ParamValidator.__module__}")
    print(f"# mirror format: UID {6*2} UPPERCASE hex, CTR {3*2} UPPERCASE hex")
    for uid in UIDS:
        tag_key = diversify(MASTER, uid)
        pv = ParamValidator(
            k_sdm_file_read=hexlify(tag_key).decode(),
            param_cmac=PARAM_CMAC,
            param_cmac_input=PARAM_UID,
        )
        pv.uid = bytes.fromhex(uid)
        # truthy sentinel: decrypt_picc_data is skipped, uid/read_ctr preset directly
        pv.picc_data = b"\x00"
        for ctr in COUNTERS:
            pv.read_ctr = ctr
            pv.generate_sdm_session_keys()
            session = pv.k_ses_sdm_file_read_mac

            uid_upper = uid.upper()
            ctr_upper = f"{ctr:06X}"
            uri = (
                f"{URL_TEMPLATE}?{PARAM_UID}={uid_upper}"
                f"&{PARAM_CTR}={ctr_upper}&{PARAM_CMAC}="
            )
            mac_input = ParamValidator.cmac_input_from_uri(uri, PARAM_UID, PARAM_CMAC)

            # validate.py:259-262 verbatim
            cmac = CMAC.new(session, ciphermod=AES)
            cmac.update(mac_input.encode())
            truncated = cmac.digest()[1::2]
            sun_hex = hexlify(truncated).decode().upper()

            # close the loop through pylibsdm's own verifier
            assert pv.validate_cmac(
                cmac_provided=sun_hex,
                e_picc_data="00" * 16,
                mac_input=mac_input,
            ), "pylibsdm validate_cmac rejected our own output"

            print(f"uid={uid_upper} ctr={ctr:06d}")
            print(f"  tag_key   = {hexlify(tag_key).decode().upper()}")
            print(f"  session   = {hexlify(session).decode().upper()}")
            print(f"  mac_input = {mac_input}")
            print(f"  sun_cmac  = {sun_hex}")
    return 0


if __name__ == "__main__":
    sys.exit(main())