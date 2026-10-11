use aes::Aes128;
use cmac::{Cmac, Mac};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SunError {
    #[error("invalid UID length/hex")]
    BadUid,
    #[error("invalid Counter length/hex")]
    BadCounter,
    #[error("invalid CMAC length/hex")]
    BadCmac,
    #[error("CMAC mismatch")]
    CmacMismatch,
}

#[derive(Debug)]
pub struct Uid(pub [u8; 7]);

impl Uid {
    pub fn from_hex(s: &str) -> Result<Self, SunError> {
        let mut bytes = [0u8; 7];
        if s.len() != 14 {
            return Err(SunError::BadUid);
        }
        hex::decode_to_slice(s, &mut bytes).map_err(|_| SunError::BadUid)?;
        Ok(Self(bytes))
    }
}
#[derive(Debug)]
pub struct TapCounter(pub [u8; 3]);

impl TapCounter {
    pub fn from_u32(val: u32) -> Self {
        let bytes = val.to_be_bytes();
        Self([bytes[1], bytes[2], bytes[3]])
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }

    pub fn from_hex(s: &str) -> Result<Self, SunError> {
        let mut bytes = [0u8; 3];
        if s.len() != 6 {
            return Err(SunError::BadCounter);
        }
        hex::decode_to_slice(s, &mut bytes).map_err(|_| SunError::BadCounter)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug)]
pub struct SunCmac(pub [u8; 8]);

impl SunCmac {
    pub fn from_hex(s: &str) -> Result<Self, SunError> {
        let mut bytes = [0u8; 8];
        if s.len() != 16 {
            return Err(SunError::BadCmac);
        }
        hex::decode_to_slice(s, &mut bytes).map_err(|_| SunError::BadCmac)?;
        Ok(Self(bytes))
    }
}
#[derive(Clone)]
pub struct Key(pub [u8; 16]);

impl Key {
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

pub struct TagKey(pub [u8; 16]);

type Aes128Cmac = Cmac<Aes128>;

pub const SUN_CMAC_COMPARE_BYTES: usize = 8;

// AN12196 SV2 constant prefix (sec.3.3): 3CC3 0001 0080
const SV2_PREFIX: [u8; 6] = [0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80];

/// Raw single-block/multi-block AES-CMAC (RFC 4493).
pub fn aes_cmac(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut mac = Aes128Cmac::new_from_slice(key).expect("AES-128 key length is correct");
    mac.update(msg);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// AN12196 SV1 diversification: AES-CMAC(master, [0x01] || uid_bytes)
pub fn diversify(master: &Key, uid: &Uid) -> TagKey {
    let mut input = [0u8; 8];
    input[0] = 0x01;
    input[1..].copy_from_slice(&uid.0);
    TagKey(aes_cmac(&master.0, &input))
}

/// Per-tap session MAC key: AES-CMAC(tag_key, SV2) where
/// SV2 = 3CC3 0001 0080 ‖ uid(7B) ‖ counter(3B LSB-first)  (16 B).
/// AN12196 sec.3.3 step 13-14; pylibsdm validate.py:159-179.
pub fn session_mac_key(tag_key: &TagKey, uid: &Uid, counter: &TapCounter) -> [u8; 16] {
    let mut sv2 = [0u8; 16];
    sv2[..6].copy_from_slice(&SV2_PREFIX);
    sv2[6..13].copy_from_slice(&uid.0);
    sv2[13] = counter.0[2];
    sv2[14] = counter.0[1];
    sv2[15] = counter.0[0];
    aes_cmac(&tag_key.0, &sv2)
}

/// MACt: odd-index bytes of the full 16-byte CMAC, `digest()[1::2]`.
/// AN12196 sec.3.4.4.2; pylibsdm validate.py:262.
pub fn truncate_sun_mac(full: &[u8; 16]) -> [u8; 8] {
    [
        full[1], full[3], full[5], full[7], full[9], full[11], full[13], full[15],
    ]
}

/// Truncated 8-byte SUN MAC over raw mac_input bytes with a pre-derived session key.
pub fn sun_mac(session: &[u8; 16], mac_input: &[u8]) -> [u8; 8] {
    let full = aes_cmac(session, mac_input);
    truncate_sun_mac(&full)
}

fn write_hex_upper(dst: &mut [u8], src: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (i, b) in src.iter().enumerate() {
        dst[2 * i] = HEX[(b >> 4) as usize];
        dst[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
}

// v1 pins the plaintext mirror layout. AN12196 + pylibsdm pin mac_input as the EXACT
// ASCII the chip signs: UID and counter mirrored as UPPERCASE fixed-width hex
// (uid 14 chars, counter 6 chars) between the static "&c=" / "&cmac=" separators,
// width/case pinned in scripts/sun_golden.py. If the physical bench drill at task-12
// disagrees, change ONLY the mac_input construction here.
pub fn verify_sun(
    uid: &Uid,
    counter: &TapCounter,
    cmac: &SunCmac,
    tag_key: &TagKey,
) -> Result<(), SunError> {
    let computed_cmac = cmac_for_key(tag_key, uid, counter);
    if bool::from(
        computed_cmac.0[..SUN_CMAC_COMPARE_BYTES].ct_eq(&cmac.0[..SUN_CMAC_COMPARE_BYTES]),
    ) {
        Ok(())
    } else {
        Err(SunError::CmacMismatch)
    }
}

fn cmac_for_key(tag_key: &TagKey, uid: &Uid, counter: &TapCounter) -> SunCmac {
    let session = session_mac_key(tag_key, uid, counter);
    let mut input = [0u8; 29]; // 14 (uid) + 3 (&c=) + 6 (ctr) + 6 (&cmac=)
    write_hex_upper(&mut input[..14], &uid.0);
    input[14..17].copy_from_slice(b"&c=");
    write_hex_upper(&mut input[17..23], &counter.0);
    input[23..].copy_from_slice(b"&cmac=");
    SunCmac(sun_mac(&session, &input))
}

pub fn cmac_for(master: &Key, uid: &Uid, counter: &TapCounter) -> SunCmac {
    let tag_key = diversify(master, uid);
    cmac_for_key(&tag_key, uid, counter)
}
