use access_control_verifier::sync_projection::*;

#[test]
fn test_golden_vector_entry_layout() {
    // Contract vector from Plan D2 / Task 11 / Task 12 spec:
    // uid: 04123456789abc
    // counter: 0x000105
    // expiry_epoch: 1798761600 (2027-01-01T00:00:00Z)
    // key_version: 1
    // entry_gen: 1
    // flags: 0
    let entry = RosterEntry {
        uid: [0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        counter: 0x000105,
        expiry_epoch: 1798761600,
        key_version: 1,
        entry_gen: 1,
        flags: 0,
    };

    let encoded = entry.to_bytes();
    let expected: [u8; 20] = [
        0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // uid[7]
        0x05, 0x01, 0x00, // counter u24 little-endian (0x000105)
        0x80, 0xec, 0x36, 0x6b, // expiry_epoch 1798761600 (0x6B36EC80)
        0x01, // key_version u8
        0x01, 0x00, 0x00, 0x00, // entry_gen 1 u32
        0x00, // flags u8
    ];
    assert_eq!(encoded, expected, "Golden vector 20B match");

    let decoded = RosterEntry::decode(&encoded);
    assert_eq!(decoded, entry);
}

#[test]
fn test_round_trip_chunk() {
    let entry1 = RosterEntry {
        uid: [0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        counter: 42,
        expiry_epoch: 1700000000,
        key_version: 2,
        entry_gen: 10,
        flags: FLAG_REVOKED,
    };
    let chunk = SyncChunk {
        roster_gen: 12345,
        chunk: 0,
        of: 1,
        entries: vec![entry1],
    };

    let bytes = chunk.encode().expect("encode");
    assert_eq!(bytes.len(), 14 + 20 + 4); // 38 bytes
    let decoded = SyncChunk::decode(&bytes).expect("decode");
    assert_eq!(decoded, chunk);
}

#[test]
fn test_boundary_36_and_37_entries() {
    let dummy = RosterEntry {
        uid: [1, 2, 3, 4, 5, 6, 7],
        counter: 100,
        expiry_epoch: 1800000000,
        key_version: 1,
        entry_gen: 5,
        flags: 0,
    };

    // 36 entries -> exactly 1 chunk
    let entries36: Vec<RosterEntry> = vec![dummy; 36];
    let chunks36 = split_into_chunks(99, &entries36);
    assert_eq!(chunks36.len(), 1);
    assert_eq!(chunks36[0].chunk, 0);
    assert_eq!(chunks36[0].of, 1);
    assert_eq!(chunks36[0].entries.len(), 36);
    let encoded36 = chunks36[0].encode().expect("encode 36");
    assert_eq!(encoded36.len(), 14 + 36 * 20 + 4); // 738 bytes
    assert!(encoded36.len() <= 800);
    let decoded36 = SyncChunk::decode(&encoded36).expect("decode 36");
    assert_eq!(decoded36.entries.len(), 36);

    // 37 entries -> exactly 2 chunks (36 + 1)
    let entries37: Vec<RosterEntry> = vec![dummy; 37];
    let chunks37 = split_into_chunks(99, &entries37);
    assert_eq!(chunks37.len(), 2);
    assert_eq!(chunks37[0].chunk, 0);
    assert_eq!(chunks37[0].of, 2);
    assert_eq!(chunks37[0].entries.len(), 36);
    assert_eq!(chunks37[1].chunk, 1);
    assert_eq!(chunks37[1].of, 2);
    assert_eq!(chunks37[1].entries.len(), 1);

    for ch in &chunks37 {
        let enc = ch.encode().expect("encode split chunk");
        let dec = SyncChunk::decode(&enc).expect("decode split chunk");
        assert_eq!(&dec, ch);
    }
}

#[test]
fn test_corrupted_crc_rejected() {
    let chunk = SyncChunk {
        roster_gen: 1,
        chunk: 0,
        of: 1,
        entries: vec![],
    };
    let mut bytes = chunk.encode().expect("encode");
    // Corrupt last CRC byte
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    let err = SyncChunk::decode(&bytes).expect_err("should reject bad crc");
    assert!(matches!(err, CodecError::CrcMismatch { .. }));
}

#[test]
fn test_truncated_chunk_rejected() {
    let chunk = SyncChunk {
        roster_gen: 1,
        chunk: 0,
        of: 1,
        entries: vec![],
    };
    let bytes = chunk.encode().expect("encode");
    assert_eq!(bytes.len(), 18);

    // Less than 18 bytes
    let err = SyncChunk::decode(&bytes[0..17]).expect_err("truncated");
    assert_eq!(err, CodecError::Truncated(17));

    // Incomplete entry payload
    let mut bytes_with_entry = SyncChunk {
        roster_gen: 1,
        chunk: 0,
        of: 1,
        entries: vec![RosterEntry {
            uid: [1; 7],
            counter: 0,
            expiry_epoch: 0,
            key_version: 1,
            entry_gen: 1,
            flags: 0,
        }],
    }
    .encode()
    .expect("encode");

    // Strip 5 bytes from middle
    bytes_with_entry.truncate(bytes_with_entry.len() - 5);
    let err2 = SyncChunk::decode(&bytes_with_entry).expect_err("misaligned");
    assert!(matches!(err2, CodecError::MisalignedPayload(_)));
}
