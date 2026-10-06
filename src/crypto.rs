use aes::Aes128;
use cmac::{Cmac, Mac};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SunError {
    #[error("CMAC mismatch")]
    CmacMismatch,
}

pub struct Uid(pub [u8; 7]);
pub struct TapCounter(pub [u8; 3]);

impl TapCounter {
    pub fn from_u32(val: u32) -> Self {
        let bytes = val.to_be_bytes();
        Self([bytes[1], bytes[2], bytes[3]])
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }
}

pub struct SunCmac(pub [u8; 16]);
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
    if bool::from(computed_cmac.0.ct_eq(&cmac.0)) {
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
    // AN12196 states SUN is truncated to 8 bytes, but we might verify full 16 or 8 depending on the tag setup.
    // Assuming full 16 for SunCmac here. Wait, NTAG424 DNA SUN is typically 8 bytes, but your requirement specifies SunCmac(pub [u8;16]). I will compute the full 16-byte CMAC. Wait, let me check the requirements again. "v1 pins plaintext mirror layout uid||counter (3B BE); if datasheet verification at task-12 integration disagrees, change ONLY the cmac_input construction here. Compute AES-CMAC(tag_key, cmac_input), compare to cmac.0 via subtle::ConstantTimeEq"
    // Wait! A standard CMAC is 16 bytes. SUN might be truncated, but the struct is 16 bytes. Let's return full 16 bytes. If the tag sends only 8, this will need to be changed in wave 12. Oh wait! I'll just return 16.
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
