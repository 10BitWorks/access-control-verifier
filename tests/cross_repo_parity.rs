//! Cross-repo parity test suite (Plan S0 / Checkbox 13).
//!
//! Validates:
//! 1. SUN crypto parity against keygate-esp-access-devices (SV1 diversification, SV2 session MAC,
//!    uppercase ASCII mirror input, truncated 8-byte CMAC).
//! 2. 20-byte RosterEntry binary layout parity.
//! 3. Reason vocabulary parity (Plan D2 10 normative strings).
//! 4. Full chunk-level sync wire codec vectors (unified 0-based).

use access_control_verifier::api::reasons;
use access_control_verifier::crypto::{
    cmac_for, diversify, session_mac_key, verify_sun, Key, SunCmac, TagKey, TapCounter, Uid,
};
use access_control_verifier::sync_projection::{
    crc32_ieee, RosterEntry, SyncChunk, HEADER_SIZE, ROSTER_ENTRY_SIZE, TRAILER_SIZE,
};

/// Master key shared across both repos for golden vector testing.
pub const TEST_MASTER_HEX: &str = "000102030405060708090a0b0c0d0e0f";

/// Tuple: (master_hex, uid_hex, counter, session_hex, cmac_hex)
pub const SHARED_SUN_CRYPTO_VECTORS: &[(&str, &str, u32, &str, &str)] = &[
    // Vector set 1: existing golden UID 046522cabc5d80
    (
        TEST_MASTER_HEX,
        "046522cabc5d80",
        1,
        "c30319ac9b924d5d42f1db871821e65b",
        "4be403ba3e9b7bd0",
    ),
    (
        TEST_MASTER_HEX,
        "046522cabc5d80",
        8,
        "08d4380c34f41ed6506c6362aa43b287",
        "c894c366c5802e34",
    ),
    (
        TEST_MASTER_HEX,
        "046522cabc5d80",
        255,
        "3048e917d855466160e73e37e4622c94",
        "30a08b95baad09a4",
    ),
    (
        TEST_MASTER_HEX,
        "046522cabc5d80",
        0x000105,
        "fe3394969315ba9c77eb7ba593aaae49",
        "0e96df7a907722ea",
    ),
    (
        TEST_MASTER_HEX,
        "046522cabc5d80",
        0x123456,
        "1dcf65fe6b2eeedb4563e5934e7f9fda",
        "51d62d0c5550d63b",
    ),
    (
        TEST_MASTER_HEX,
        "046522cabc5d80",
        0xffffff,
        "68e21bb8aa8efc9e0d2087dfc1b7be72",
        "9d03d07733279347",
    ),
    // Vector set 2: production-format UID 04123456789abc (from 20B golden roster entry)
    (
        TEST_MASTER_HEX,
        "04123456789abc",
        1,
        "4961dcbf964f7421bfb2525f0e51ad6c",
        "6119146c1570fc19",
    ),
    (
        TEST_MASTER_HEX,
        "04123456789abc",
        8,
        "baecf0bb61ea276e9764431915e40a4f",
        "3e2f6693beeeb4fc",
    ),
    (
        TEST_MASTER_HEX,
        "04123456789abc",
        255,
        "0aa6f43ed6c7a1abf471337bb0e86792",
        "18d517fea217ffc2",
    ),
    (
        TEST_MASTER_HEX,
        "04123456789abc",
        0x000105,
        "50981ea5a895395ecf3303fb3551e7a2",
        "a7dfac41e88e7ecc",
    ),
    (
        TEST_MASTER_HEX,
        "04123456789abc",
        0x123456,
        "a757859bbb1116384c5019fd5303ebc5",
        "539425aef96d0385",
    ),
    (
        TEST_MASTER_HEX,
        "04123456789abc",
        0xffffff,
        "520bd5b9c96d167a492accd025a31ff7",
        "186c9fecc2850411",
    ),
];

/// Shared golden 20-byte roster entry:
/// UID: 04123456789abc
/// Counter: 0x000105
/// Expiry: 1798761600 (0x6B36EC80)
/// Key Version: 1
/// Entry Gen: 1
/// Flags: 0
pub const GOLDEN_ROSTER_ENTRY_BYTES: [u8; 20] = [
    0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x05, 0x01, 0x00, 0x80, 0xec, 0x36, 0x6b, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00,
];

/// Shared chunk payload for 1 chunk of 1 (roster_gen = 100):
/// Unified wire format (0-based: chunk = 0, of = 1):
/// Header (14B) + Entry (20B) + CRC-32 (4B) = 38 bytes.
pub const GOLDEN_CHUNK_0BASED: [u8; 38] = [
    0x47, 0x4b, // magic: 0x4B47 "KG"
    0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // roster_gen: 100 u64
    0x00, 0x00, // chunk: 0 u16
    0x01, 0x00, // of: 1 u16
    // 20B entry:
    0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x05, 0x01, 0x00, 0x80, 0xec, 0x36, 0x6b, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, // CRC-32 IEEE 802.3: 0x1877018E
    0x8e, 0x01, 0x77, 0x18,
];

/// Legacy constant kept for historical reference or backwards-compat test if needed.
pub const GOLDEN_CHUNK_FIRMWARE_0BASED: [u8; 38] = GOLDEN_CHUNK_0BASED;

/// Normative 10-reason vocabulary (Plan D2).
pub const EXPECTED_REASONS: &[&str] = &[
    "unknown_tag",
    "counter_replay",
    "counter_saturated",
    "expired",
    "inactive",
    "overridden",
    "cmac_fail",
    "uncommissioned",
    "policy_denied",
    "granted",
];

#[test]
fn test_sun_crypto_parity_vectors() {
    for &(master_hex, uid_hex, ctr, session_hex, cmac_hex) in SHARED_SUN_CRYPTO_VECTORS {
        let master = Key::from_hex(master_hex).expect("valid master hex");
        let uid = Uid::from_hex(uid_hex).expect("valid uid hex");
        let counter = TapCounter::from_u32(ctr);

        // 1. Diversification: tag_key = aes_cmac(master, [0x01 || uid])
        let tag_key: TagKey = diversify(&master, &uid);

        // 2. Session key: SV2 = 3CC300010080 || uid || counter_le
        let session = session_mac_key(&tag_key, &uid, &counter);
        assert_eq!(
            hex::encode(session),
            session_hex,
            "Session key mismatch for uid={} ctr={}",
            uid_hex,
            ctr
        );

        // 3. CMAC computation
        let cmac = cmac_for(&master, &uid, &counter);
        assert_eq!(
            hex::encode(cmac.0),
            cmac_hex,
            "CMAC mismatch for uid={} ctr={}",
            uid_hex,
            ctr
        );

        // 4. Verification
        let sun_cmac = SunCmac::from_hex(cmac_hex).expect("valid sun cmac hex");
        assert!(
            verify_sun(&uid, &counter, &sun_cmac, &tag_key).is_ok(),
            "verify_sun failed for uid={} ctr={}",
            uid_hex,
            ctr
        );
    }
}

#[test]
fn test_20b_roster_entry_layout_parity() {
    let entry = RosterEntry {
        uid: [0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        counter: 0x000105,
        expiry_epoch: 1798761600,
        key_version: 1,
        entry_gen: 1,
        flags: 0,
    };

    let encoded = entry.to_bytes();
    assert_eq!(
        encoded, GOLDEN_ROSTER_ENTRY_BYTES,
        "20B RosterEntry wire layout mismatch"
    );

    let decoded = RosterEntry::decode(&encoded);
    assert_eq!(decoded, entry, "RosterEntry decode mismatch");
}

#[test]
fn test_reason_vocabulary_parity() {
    assert_eq!(
        reasons::ALL.len(),
        EXPECTED_REASONS.len(),
        "Reason count must be exactly 10"
    );
    for &expected in EXPECTED_REASONS {
        assert!(
            reasons::ALL.contains(&expected),
            "Missing reason in verifier reasons::ALL: {}",
            expected
        );
    }
}

#[test]
fn test_full_chunk_sync_codec_vectors() {
    // Verifier encodes unified 0-based chunk
    let entry = RosterEntry::decode(&GOLDEN_ROSTER_ENTRY_BYTES);
    let chunk_0based = SyncChunk {
        roster_gen: 100,
        chunk: 0,
        of: 1,
        entries: vec![entry],
    };
    let encoded = chunk_0based.encode().expect("encode 0-based chunk");
    assert_eq!(
        encoded,
        GOLDEN_CHUNK_0BASED.to_vec(),
        "Verifier 0-based chunk wire bytes mismatch"
    );

    let decoded = SyncChunk::decode(&encoded).expect("decode 0-based chunk");
    assert_eq!(decoded, chunk_0based);

    // Validate CRC on unified 0-based chunk format
    let data_len = HEADER_SIZE + ROSTER_ENTRY_SIZE;
    let computed_crc = crc32_ieee(&GOLDEN_CHUNK_0BASED[..data_len]);
    let stored_crc = u32::from_le_bytes(
        GOLDEN_CHUNK_0BASED[data_len..data_len + TRAILER_SIZE]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        computed_crc, stored_crc,
        "CRC32 mismatch on 0-based chunk literal"
    );
    assert_eq!(computed_crc, 0x1877018E);
}
