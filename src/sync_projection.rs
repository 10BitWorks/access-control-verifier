//! Binary sync chunk codec for offline-first reader synchronization (Plan D2).
//!
//! # Wire Format (Byte-exact)
//! - Chunk envelope:
//!   `[magic u16 = 0x4B47][roster_gen u64][chunk u16][of u16][entries... 20B each][crc32 u32]`
//! - Entry layout (20 bytes):
//!   `uid[7] counter u24 expiry_epoch u32 key_version u8 entry_gen u32 flags u8`
//!
//! Maximum 36 entries per chunk, keeping published payload ≤ 800 B (738 B max).
//! CRC-32 IEEE 802.3 covers all bytes preceding the 4-byte CRC trailer.

use thiserror::Error;

pub const MAGIC: u16 = 0x4B47;
pub const HEADER_SIZE: usize = 14;
pub const TRAILER_SIZE: usize = 4;
pub const MIN_CHUNK_SIZE: usize = HEADER_SIZE + TRAILER_SIZE;
pub const ROSTER_ENTRY_SIZE: usize = 20;
pub const MAX_ENTRIES_PER_CHUNK: usize = 36;
pub const MAX_CHUNK_PAYLOAD_SIZE: usize =
    HEADER_SIZE + (MAX_ENTRIES_PER_CHUNK * ROSTER_ENTRY_SIZE) + TRAILER_SIZE;

// Roster entry flags (1 byte)
pub const FLAG_REVOKED: u8 = 1 << 0;
pub const FLAG_OVERRIDDEN_BAN: u8 = 1 << 1;
pub const FLAG_OVERRIDDEN_ALLOW: u8 = 1 << 2;
pub const FLAG_EXPIRY_ABSENT: u8 = 1 << 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("truncated chunk: length {0} less than minimum {MIN_CHUNK_SIZE}")]
    Truncated(usize),
    #[error("invalid magic: 0x{0:04X}, expected 0x{MAGIC:04X}")]
    InvalidMagic(u16),
    #[error("misaligned entries: payload length {0} not a multiple of {ROSTER_ENTRY_SIZE}")]
    MisalignedPayload(usize),
    #[error("chunk index {chunk} exceeds total chunks {of}")]
    InvalidChunkIndex { chunk: u16, of: u16 },
    #[error("chunk contains {0} entries, exceeding maximum {MAX_ENTRIES_PER_CHUNK}")]
    TooManyEntries(usize),
    #[error("crc32 mismatch: stored 0x{stored:08X}, calculated 0x{calculated:08X}")]
    CrcMismatch { stored: u32, calculated: u32 },
}

/// Standard IEEE 802.3 CRC-32 (polynomial 0xEDB88320).
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A single 20-byte roster entry in the binary sync format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterEntry {
    pub uid: [u8; 7],
    pub counter: u32, // 24-bit counter (0..0xFF_FFFF)
    pub expiry_epoch: u32,
    pub key_version: u8,
    pub entry_gen: u32,
    pub flags: u8,
}

impl RosterEntry {
    pub fn encode(&self, buf: &mut [u8; ROSTER_ENTRY_SIZE]) {
        buf[0..7].copy_from_slice(&self.uid);
        let ctr_bytes = self.counter.to_le_bytes();
        buf[7..10].copy_from_slice(&ctr_bytes[0..3]);
        buf[10..14].copy_from_slice(&self.expiry_epoch.to_le_bytes());
        buf[14] = self.key_version;
        buf[15..19].copy_from_slice(&self.entry_gen.to_le_bytes());
        buf[19] = self.flags;
    }

    pub fn to_bytes(&self) -> [u8; ROSTER_ENTRY_SIZE] {
        let mut buf = [0u8; ROSTER_ENTRY_SIZE];
        self.encode(&mut buf);
        buf
    }

    pub fn decode(buf: &[u8; ROSTER_ENTRY_SIZE]) -> Self {
        let mut uid = [0u8; 7];
        uid.copy_from_slice(&buf[0..7]);
        let counter = buf[7] as u32 | ((buf[8] as u32) << 8) | ((buf[9] as u32) << 16);
        let expiry_epoch = u32::from_le_bytes(buf[10..14].try_into().unwrap());
        let key_version = buf[14];
        let entry_gen = u32::from_le_bytes(buf[15..19].try_into().unwrap());
        let flags = buf[19];
        Self {
            uid,
            counter,
            expiry_epoch,
            key_version,
            entry_gen,
            flags,
        }
    }
}

/// A chunk of roster entries for MQTT synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncChunk {
    pub roster_gen: u64,
    pub chunk: u16, // 0-based index (0..of)
    pub of: u16,    // Total chunk count (>= 1)
    pub entries: Vec<RosterEntry>,
}

impl SyncChunk {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.entries.len() > MAX_ENTRIES_PER_CHUNK {
            return Err(CodecError::TooManyEntries(self.entries.len()));
        }
        if self.of == 0 || self.chunk >= self.of {
            return Err(CodecError::InvalidChunkIndex {
                chunk: self.chunk,
                of: self.of,
            });
        }
        let total_size = HEADER_SIZE + (self.entries.len() * ROSTER_ENTRY_SIZE) + TRAILER_SIZE;
        let mut buf = Vec::with_capacity(total_size);

        buf.extend_from_slice(&MAGIC.to_le_bytes());
        buf.extend_from_slice(&self.roster_gen.to_le_bytes());
        buf.extend_from_slice(&self.chunk.to_le_bytes());
        buf.extend_from_slice(&self.of.to_le_bytes());

        let mut entry_buf = [0u8; ROSTER_ENTRY_SIZE];
        for entry in &self.entries {
            entry.encode(&mut entry_buf);
            buf.extend_from_slice(&entry_buf);
        }

        let crc = crc32_ieee(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < MIN_CHUNK_SIZE {
            return Err(CodecError::Truncated(bytes.len()));
        }
        let payload_len = bytes.len() - HEADER_SIZE - TRAILER_SIZE;
        if !payload_len.is_multiple_of(ROSTER_ENTRY_SIZE) {
            return Err(CodecError::MisalignedPayload(payload_len));
        }

        let magic = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        if magic != MAGIC {
            return Err(CodecError::InvalidMagic(magic));
        }

        let stored_crc = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
        let calculated_crc = crc32_ieee(&bytes[0..bytes.len() - 4]);
        if stored_crc != calculated_crc {
            return Err(CodecError::CrcMismatch {
                stored: stored_crc,
                calculated: calculated_crc,
            });
        }

        let roster_gen = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        let chunk = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        let of = u16::from_le_bytes(bytes[12..14].try_into().unwrap());

        if of == 0 || chunk >= of {
            return Err(CodecError::InvalidChunkIndex { chunk, of });
        }

        let entry_count = payload_len / ROSTER_ENTRY_SIZE;
        if entry_count > MAX_ENTRIES_PER_CHUNK {
            return Err(CodecError::TooManyEntries(entry_count));
        }

        let mut entries = Vec::with_capacity(entry_count);
        let mut offset = HEADER_SIZE;
        let mut entry_buf = [0u8; ROSTER_ENTRY_SIZE];
        for _ in 0..entry_count {
            entry_buf.copy_from_slice(&bytes[offset..offset + ROSTER_ENTRY_SIZE]);
            entries.push(RosterEntry::decode(&entry_buf));
            offset += ROSTER_ENTRY_SIZE;
        }

        Ok(Self {
            roster_gen,
            chunk,
            of,
            entries,
        })
    }
}

/// Split a collection of roster entries into chunked payloads (≤ 36 entries per chunk).
pub fn split_into_chunks(roster_gen: u64, entries: &[RosterEntry]) -> Vec<SyncChunk> {
    if entries.is_empty() {
        return vec![SyncChunk {
            roster_gen,
            chunk: 0,
            of: 1,
            entries: Vec::new(),
        }];
    }

    let of = entries
        .len()
        .div_ceil(MAX_ENTRIES_PER_CHUNK)
        .try_into()
        .unwrap_or(u16::MAX);

    entries
        .chunks(MAX_ENTRIES_PER_CHUNK)
        .enumerate()
        .map(|(idx, chunk_entries)| SyncChunk {
            roster_gen,
            chunk: idx as u16,
            of,
            entries: chunk_entries.to_vec(),
        })
        .collect()
}
