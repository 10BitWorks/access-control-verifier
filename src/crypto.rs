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
pub struct SunCmac(pub [u8; 16]);

impl SunCmac {
    pub fn from_hex(s: &str) -> Result<Self, SunError> {
        let mut bytes = [0u8; 16];
        if s.len() != 32 {
            return Err(SunError::BadCmac);
        }
        hex::decode_to_slice(s, &mut bytes).map_err(|_| SunError::BadCmac)?;
        Ok(Self(bytes))
    }
}
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

pub const SUN_CMAC_COMPARE_BYTES: usize = 16;

// AN12196 SV1 diversification: AES-CMAC(master, [0x01] || uid_bytes)
pub fn diversify(master: &Key, uid: &Uid) -> TagKey {
    let mut mac = Aes128Cmac::new_from_slice(&master.0).expect("AES-128 key length is correct");
    let mut input = [0u8; 8];
    input[0] = 0x01;
    input[1..].copy_from_slice(&uid.0);
    mac.update(&input);
    let result = mac.finalize().into_bytes();

    let mut tag_key = [0u8; 16];
    tag_key.copy_from_slice(&result);
    TagKey(tag_key)
}

// v1 pins plaintext mirror layout uid||counter (3B BE); if datasheet verification at task-12 integration disagrees, change ONLY the cmac_input construction here.
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
    let mut mac = Aes128Cmac::new_from_slice(&tag_key.0).expect("AES-128 key length is correct");
    let mut input = [0u8; 10];
    input[0..7].copy_from_slice(&uid.0);
    input[7..].copy_from_slice(&counter.0);
    mac.update(&input);

    let mut out = [0u8; 16];
    let result = mac.finalize().into_bytes();
    // Full 16-byte CMAC is computed and compared; real NTAG424 SUN mirrors may carry an 8-byte truncated CMAC — see SUN_CMAC_COMPARE_BYTES.
    out.copy_from_slice(&result);
    SunCmac(out)
}

pub fn cmac_for(master: &Key, uid: &Uid, counter: &TapCounter) -> SunCmac {
    let tag_key = diversify(master, uid);
    cmac_for_key(&tag_key, uid, counter)
}

#[cfg(test)]
pub fn aes_cmac(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut mac = Aes128Cmac::new_from_slice(key).expect("AES-128 key length is correct");
    mac.update(msg);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}
