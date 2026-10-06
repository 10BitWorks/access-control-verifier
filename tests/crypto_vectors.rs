#[path = "../src/crypto.rs"]
mod crypto;

use crypto::{aes_cmac, cmac_for, diversify, verify_sun, Key, SunCmac, SunError, TapCounter, Uid};

#[test]
fn test_rfc4493_aes_cmac_vectors() {
    // RFC 4493 AES-CMAC Test Vectors
    // K = 2b7e1516 28aed2a6 abf71588 09cf4f3c
    let k = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

    // Subkey generation vectors not easily testable directly here, focus on message vectors

    // Message empty
    let m1: [u8; 0] = [];
    let t1 = hex::decode("bb1d6929e95937287fa37d129b756746").unwrap();
    assert_eq!(&aes_cmac(&k, &m1)[..], &t1[..]);

    // Message 16 bytes
    let m2 = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let t2 = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();
    assert_eq!(&aes_cmac(&k, &m2)[..], &t2[..]);

    // RFC 4493 test vectors:
    // M = 6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 30c81c46a35ce411
    // Wait, the string "30c81c46a35ce411" is only 8 bytes. So 16+16+8 = 40 bytes.
    // Let me check my m3 hex string:
    // Message 40 bytes
    let m3 = hex::decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
    )
    .unwrap();
    let t3 = hex::decode("dfa66747de9ae63030ca32611497c827").unwrap();
    assert_eq!(&aes_cmac(&k, &m3)[..], &t3[..]);

    // Message 64 bytes
    let m3 = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
    let t3 = hex::decode("51f0bebf7e3b9d92fc49741779363cfe").unwrap();
    assert_eq!(&aes_cmac(&k, &m3)[..], &t3[..]);
}

#[test]
fn test_golden_vectors_from_script() {
    // Master key: 000102030405060708090a0b0c0d0e0f
    let master = Key::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();

    // Vector 1
    // UID: 046522cabc5d80 (7 bytes)
    // Counter: 000001
    // Expected Diversified Key: [0x01] || 046522cabc5d80 -> AES-CMAC
    let mut uid1_bytes = [0u8; 7];
    hex::decode_to_slice("046522cabc5d80", &mut uid1_bytes).unwrap();
    let uid1 = Uid(uid1_bytes);

    let counter1 = TapCounter::from_u32(1);

    // Computed with openssl dgst -mac cmac -macopt hexkey:000102030405060708090a0b0c0d0e0f -hex (01046522cabc5d80)
    // Wait, the test expects verification success. Let's make sure `cmac1` computation works.
    // The previous openssl call output was:
    // Diversified Key: 71A4EC87107F7FC71B2220E23D8CE93A
    // SUN CMAC: 6B1002C48D3F8A7B190B44897CDD70BF
    let tag_key1 = diversify(&master, &uid1);
    let expected_tag_key = hex::decode("71A4EC87107F7FC71B2220E23D8CE93A").unwrap();
    assert_eq!(&tag_key1.0[..], &expected_tag_key[..]);

    let cmac1 = cmac_for(&master, &uid1, &counter1);
    let expected_cmac = hex::decode("6B1002C48D3F8A7B190B44897CDD70BF").unwrap();
    assert_eq!(&cmac1.0[..], &expected_cmac[..]);

    assert!(verify_sun(&uid1, &counter1, &cmac1, &tag_key1).is_ok());
}

#[test]
fn test_wire_constructors() {
    assert_eq!(
        Uid::from_hex("046522cabc5d8").unwrap_err(),
        SunError::BadUid
    );
    assert_eq!(
        Uid::from_hex("046522cabc5d800").unwrap_err(),
        SunError::BadUid
    );
    assert_eq!(
        Uid::from_hex("invalidhexstrg").unwrap_err(),
        SunError::BadUid
    );
    assert!(Uid::from_hex("046522cabc5d80").is_ok());

    assert_eq!(
        TapCounter::from_hex("00000").unwrap_err(),
        SunError::BadCounter
    );
    assert_eq!(
        TapCounter::from_hex("0000001").unwrap_err(),
        SunError::BadCounter
    );
    assert_eq!(
        TapCounter::from_hex("nothex").unwrap_err(),
        SunError::BadCounter
    );
    assert!(TapCounter::from_hex("000001").is_ok());

    assert_eq!(
        SunCmac::from_hex("6B1002C48D3F8A7B190B44897CDD70B").unwrap_err(),
        SunError::BadCmac
    );
    assert_eq!(
        SunCmac::from_hex("6B1002C48D3F8A7B190B44897CDD70BFF").unwrap_err(),
        SunError::BadCmac
    );
    assert_eq!(
        SunCmac::from_hex("invalidhexinvalidhexinvalidhexin").unwrap_err(),
        SunError::BadCmac
    );
    assert!(SunCmac::from_hex("6B1002C48D3F8A7B190B44897CDD70BF").is_ok());
}

#[test]
fn test_truncation_constant() {
    let master = Key::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let uid1 = Uid::from_hex("046522cabc5d80").unwrap();
    let counter1 = TapCounter::from_hex("000001").unwrap();
    let tag_key1 = diversify(&master, &uid1);

    // Compute original 16-byte CMAC
    let cmac1 = cmac_for(&master, &uid1, &counter1);

    // Copy the correct 16 bytes into an array
    let mut modified_cmac_bytes = cmac1.0;

    // Modify bytes beyond the SUN_CMAC_COMPARE_BYTES index
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        if i >= crypto::SUN_CMAC_COMPARE_BYTES {
            modified_cmac_bytes[i] ^= 0xFF; // Invert to guarantee mismatch if checked
        }
    }

    // If SUN_CMAC_COMPARE_BYTES is 16, the loop won't execute, so we need to ensure the test asserts
    // the current logic. If it is 16, modifying won't happen, so we assert true anyway.
    // If it is smaller, modifying happens and it should STILL assert true because verify_sun only compares the prefix.
    let modified_cmac = SunCmac(modified_cmac_bytes);

    // Should still pass because verify_sun only compares the first SUN_CMAC_COMPARE_BYTES
    assert!(verify_sun(&uid1, &counter1, &modified_cmac, &tag_key1).is_ok());
}
#[test]
fn test_tap_counter_conversion() {
    let c = TapCounter::from_u32(1);
    assert_eq!(c.0, [0x00, 0x00, 0x01]);
    assert_eq!(c.to_u32(), 1);

    let c = TapCounter::from_u32(256);
    assert_eq!(c.0, [0x00, 0x01, 0x00]);
    assert_eq!(c.to_u32(), 256);

    let c = TapCounter::from_u32(0xFFFFFF);
    assert_eq!(c.0, [0xFF, 0xFF, 0xFF]);
    assert_eq!(c.to_u32(), 0xFFFFFF);
}
