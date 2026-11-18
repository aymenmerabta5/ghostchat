//! Reassembly of group images, voice notes, and files.
//!
//! A group attachment is a file cut into chunks, each sealed as its own signed
//! `0x25` message (`GroupAttachment` inner TLV 7). Chunks arrive in any order,
//! may be duplicated by relays, and never carry an acknowledgement, so this is
//! the whole receive-side state machine: hold partial files for a bounded time,
//! reject anything that does not describe the same file, and release the bytes
//! only when every chunk is present and the digest matches.
//!
//! Nothing here touches the disk or the radio. The worker saves a completed
//! file through [`crate::media`] and decides which notices the user sees.
//! Group media is live-only, like group text: there is no backfill, so a file
//! that loses a chunk simply expires and says so.

use ghostchat_protocol::group::{
    GroupAttachment, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_CHUNKS, MAX_ATTACHMENT_CHUNK_BYTES,
};
use ghostchat_protocol::MediaKind;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a partial file waits for its missing chunks. Long enough for a
/// 1 MiB file over a slow link, short enough that a lost chunk does not hold
/// memory for the rest of the session.
pub(crate) const ASSEMBLY_TTL: Duration = Duration::from_secs(10 * 60);
/// Concurrent partial files. A busy group cannot make the app hold more.
const MAX_ASSEMBLIES: usize = 8;
/// Total bytes held across all partial files.
const MAX_BUFFERED_BYTES: usize = 8 * MAX_ATTACHMENT_BYTES;

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    group: String,
    sender: [u8; 32],
    attachment_id: [u8; 8],
}

struct Partial {
    group: String,
    sender: [u8; 32],
    sender_nickname: String,
    kind: MediaKind,
    count: u16,
    total_bytes: u32,
    digest: [u8; 8],
    name: String,
    mime: String,
    chunks: Vec<Option<Vec<u8>>>,
    received: u16,
    /// Local receipt time of the first chunk, used for the saved file name.
    timestamp_ms: u64,
    updated: Instant,
}

impl Partial {
    fn held_bytes(&self) -> usize {
        self.chunks.iter().flatten().map(Vec::len).sum()
    }

    /// The metadata every chunk of one file must repeat. A chunk that disagrees
    /// cannot belong to this file, and keeping either half would be a guess.
    fn describes_same_file(&self, chunk: &GroupAttachment) -> bool {
        self.kind == chunk.kind
            && self.count == chunk.count
            && self.total_bytes == chunk.total_bytes
            && self.digest == chunk.digest
            && self.name == chunk.name
            && self.mime == chunk.mime
    }
}

/// A complete, digest-verified file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Assembled {
    pub group: String,
    pub sender: [u8; 32],
    pub sender_nickname: String,
    pub attachment_id: [u8; 8],
    pub kind: MediaKind,
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
    pub timestamp_ms: u64,
}

/// A partial file that ran out of time, for one user-visible notice.
pub(crate) struct Expired {
    pub group: String,
    pub sender_nickname: String,
    pub kind: MediaKind,
    pub name: String,
    pub received: u16,
    pub count: u16,
}

/// What one chunk did to the assembler.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Insert {
    /// More chunks are needed; no line is shown for this one.
    Pending,
    Complete(Box<Assembled>),
    /// The chunk contradicted a partial file or its own digest, so the partial
    /// file was discarded. The worker may tell the user once.
    Rejected,
}

#[derive(Default)]
pub(crate) struct GroupMedia {
    assemblies: HashMap<Key, Partial>,
    buffered: usize,
}

impl GroupMedia {
    /// Accepts one authenticated chunk. The caller has already checked that the
    /// sender is a roster member and is not blocked.
    pub(crate) fn insert(
        &mut self,
        group: &str,
        sender: [u8; 32],
        sender_nickname: &str,
        chunk: GroupAttachment,
        timestamp_ms: u64,
        now: Instant,
    ) -> Insert {
        if !Self::plausible(&chunk) {
            return Insert::Rejected;
        }
        let key = Key { group: group.to_string(), sender, attachment_id: chunk.attachment_id };

        if let Some(partial) = self.assemblies.get(&key) {
            if !partial.describes_same_file(&chunk) {
                self.discard(&key);
                return Insert::Rejected;
            }
        } else {
            let partial = Partial {
                group: group.to_string(),
                sender,
                sender_nickname: sender_nickname.to_string(),
                kind: chunk.kind,
                count: chunk.count,
                total_bytes: chunk.total_bytes,
                digest: chunk.digest,
                name: chunk.name.clone(),
                mime: chunk.mime.clone(),
                chunks: vec![None; chunk.count as usize],
                received: 0,
                timestamp_ms,
                updated: now,
            };
            self.buffered += partial.held_bytes();
            self.assemblies.insert(key.clone(), partial);
            self.enforce_limits();
        }

        if let Some(existing) = self.assemblies.get(&key).and_then(|p| p.chunks[chunk.index as usize].as_ref()) {
            // Relays duplicate packets; the same signed bytes are harmless.
            if *existing == chunk.data {
                return Insert::Pending;
            }
            // Two different payloads for one index cannot both be the file.
            self.discard(&key);
            return Insert::Rejected;
        }

        let Some(partial) = self.assemblies.get_mut(&key) else {
            // `enforce_limits` dropped what we just created; the cap is small
            // and the oldest partial went first only if this was newer than
            // every other one, which cannot happen on a fresh insert unless the
            // caps are zero.
            return Insert::Rejected;
        };
        partial.updated = now;

        partial.chunks[chunk.index as usize] = Some(chunk.data);
        partial.received += 1;
        self.buffered += partial.chunks[chunk.index as usize].as_ref().map_or(0, Vec::len);
        if partial.received < partial.count {
            return Insert::Pending;
        }

        let Some(partial) = self.assemblies.remove(&key) else { return Insert::Rejected };
        self.buffered = self.buffered.saturating_sub(partial.held_bytes());
        let mut data = Vec::with_capacity(partial.total_bytes as usize);
        for chunk in partial.chunks.iter().flatten() {
            data.extend_from_slice(chunk);
        }
        if data.len() != partial.total_bytes as usize || !digest_matches(&partial.digest, &data) {
            return Insert::Rejected;
        }
        Insert::Complete(Box::new(Assembled {
            group: partial.group,
            sender: partial.sender,
            sender_nickname: partial.sender_nickname,
            attachment_id: key.attachment_id,
            kind: partial.kind,
            name: partial.name,
            mime: partial.mime,
            data,
            timestamp_ms: partial.timestamp_ms,
        }))
    }

    /// Drops partial files older than [`ASSEMBLY_TTL`]. Returns one summary per
    /// file so the worker can say why nothing appeared.
    pub(crate) fn prune(&mut self, now: Instant) -> Vec<Expired> {
        let stale: Vec<Key> = self
            .assemblies
            .iter()
            .filter(|(_, partial)| now.duration_since(partial.updated) >= ASSEMBLY_TTL)
            .map(|(key, _)| key.clone())
            .collect();
        stale
            .into_iter()
            .filter_map(|key| {
                let partial = self.assemblies.remove(&key)?;
                self.buffered = self.buffered.saturating_sub(partial.held_bytes());
                Some(Expired {
                    group: partial.group,
                    sender_nickname: partial.sender_nickname,
                    kind: partial.kind,
                    name: partial.name,
                    received: partial.received,
                    count: partial.count,
                })
            })
            .collect()
    }

    /// Panic wipe: nothing partially received survives.
    pub(crate) fn clear(&mut self) {
        self.assemblies.clear();
        self.buffered = 0;
    }

    fn plausible(chunk: &GroupAttachment) -> bool {
        let total = chunk.total_bytes as usize;
        total > 0
            && total <= MAX_ATTACHMENT_BYTES
            && chunk.count > 0
            && chunk.count <= MAX_ATTACHMENT_CHUNKS
            && chunk.index < chunk.count
            && !chunk.data.is_empty()
            && chunk.data.len() <= MAX_ATTACHMENT_CHUNK_BYTES
    }

    /// Keeps the assembler bounded by count and bytes, dropping the partial
    /// files that have waited longest.
    fn enforce_limits(&mut self) {
        while self.assemblies.len() > MAX_ASSEMBLIES || self.buffered > MAX_BUFFERED_BYTES {
            let Some(oldest) =
                self.assemblies.iter().min_by_key(|(_, partial)| partial.updated).map(|(key, _)| key.clone())
            else {
                break;
            };
            self.discard(&oldest);
        }
    }

    fn discard(&mut self, key: &Key) {
        if let Some(partial) = self.assemblies.remove(key) {
            self.buffered = self.buffered.saturating_sub(partial.held_bytes());
        }
    }
}

fn digest_matches(expected: &[u8; 8], data: &[u8]) -> bool {
    let digest = Sha256::digest(data);
    digest[..8] == *expected
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "00112233445566778899aabbccddeeff";
    const SENDER: [u8; 32] = [0x11; 32];

    fn chunk(index: u16, count: u16, total: usize, data: &[u8]) -> GroupAttachment {
        GroupAttachment {
            kind: MediaKind::File,
            attachment_id: [0x42; 8],
            index,
            count,
            total_bytes: total as u32,
            digest: Sha256::digest(vec![0x5A; total])[..8].try_into().unwrap(),
            name: "notes.txt".into(),
            mime: "text/plain".into(),
            data: data.to_vec(),
            signature: [0u8; 64],
        }
    }

    fn two_chunks() -> (GroupAttachment, GroupAttachment, Vec<u8>) {
        let data = vec![0x5A; 7];
        (chunk(0, 2, data.len(), &data[..3]), chunk(1, 2, data.len(), &data[3..]), data)
    }

    #[test]
    fn out_of_order_chunks_reassemble_once() {
        let (first, second, data) = two_chunks();
        let now = Instant::now();
        let mut media = GroupMedia::default();
        assert_eq!(media.insert(GROUP, SENDER, "bob", second, 7, now), Insert::Pending);
        let Insert::Complete(done) = media.insert(GROUP, SENDER, "bob", first, 7, now) else {
            panic!("expected completion");
        };
        assert_eq!(done.data, data);
        assert_eq!(done.name, "notes.txt");
        assert_eq!(done.sender_nickname, "bob");
        assert_eq!(done.timestamp_ms, 7, "the first chunk's arrival names the file");
    }

    #[test]
    fn a_relayed_duplicate_does_not_break_the_file() {
        let (first, second, data) = two_chunks();
        let now = Instant::now();
        let mut media = GroupMedia::default();
        assert_eq!(media.insert(GROUP, SENDER, "bob", first.clone(), 7, now), Insert::Pending);
        assert_eq!(media.insert(GROUP, SENDER, "bob", first, 7, now), Insert::Pending);
        let Insert::Complete(done) = media.insert(GROUP, SENDER, "bob", second, 7, now) else {
            panic!("expected completion");
        };
        assert_eq!(done.data, data);
    }

    #[test]
    fn two_payloads_for_one_index_discard_the_partial() {
        let (first, mut conflicting, _) = two_chunks();
        conflicting.index = 0;
        conflicting.data = b"XXX".to_vec();
        let now = Instant::now();
        let mut media = GroupMedia::default();
        assert_eq!(media.insert(GROUP, SENDER, "bob", first, 7, now), Insert::Pending);
        assert_eq!(media.insert(GROUP, SENDER, "bob", conflicting, 7, now), Insert::Rejected);
        assert_eq!(media.assemblies.len(), 0, "neither payload is kept");
        assert_eq!(media.buffered, 0);
    }

    #[test]
    fn a_chunk_that_describes_another_file_discards_the_partial() {
        let (first, mut second, _) = two_chunks();
        second.name = "other.txt".into();
        let now = Instant::now();
        let mut media = GroupMedia::default();
        media.insert(GROUP, SENDER, "bob", first, 7, now);
        assert_eq!(media.insert(GROUP, SENDER, "bob", second, 7, now), Insert::Rejected);
        assert_eq!(media.assemblies.len(), 0, "neither half is kept");
    }

    #[test]
    fn a_different_sender_or_group_never_merges() {
        let (first, second, _) = two_chunks();
        let now = Instant::now();
        let mut media = GroupMedia::default();
        assert_eq!(media.insert(GROUP, SENDER, "bob", first, 7, now), Insert::Pending);
        assert_eq!(media.insert("ffff", SENDER, "bob", second.clone(), 7, now), Insert::Pending);
        assert_eq!(media.insert(GROUP, [0x22; 32], "carol", second, 7, now), Insert::Pending);
        assert_eq!(media.assemblies.len(), 3, "the first file still waits on its own second chunk");
    }

    #[test]
    fn a_digest_mismatch_is_refused() {
        let (first, mut second, _) = two_chunks();
        second.digest[0] ^= 0xFF;
        // The digest is part of the descriptor, so a mismatch also means the
        // two chunks disagree; either way no file is produced.
        let now = Instant::now();
        let mut media = GroupMedia::default();
        media.insert(GROUP, SENDER, "bob", first, 7, now);
        assert_eq!(media.insert(GROUP, SENDER, "bob", second, 7, now), Insert::Rejected);

        // Same descriptors, but the assembled bytes do not hash to the digest.
        let (first, second, _) = two_chunks();
        let mut forged = second;
        forged.data[0] ^= 0xFF;
        let mut media = GroupMedia::default();
        media.insert(GROUP, SENDER, "bob", first, 7, now);
        let outcome = media.insert(GROUP, SENDER, "bob", forged, 7, now);
        assert_eq!(outcome, Insert::Rejected);
    }

    #[test]
    fn impossible_chunk_shapes_are_refused_before_buffering() {
        let now = Instant::now();
        let mut media = GroupMedia::default();

        let mut no_chunks = chunk(0, 1, 9, b"123456789");
        no_chunks.count = 0;
        assert_eq!(media.insert(GROUP, SENDER, "bob", no_chunks, 7, now), Insert::Rejected);

        let mut index_past_count = chunk(0, 1, 9, b"123456789");
        index_past_count.index = 1;
        assert_eq!(media.insert(GROUP, SENDER, "bob", index_past_count, 7, now), Insert::Rejected);

        let mut empty = chunk(0, 1, 9, b"123456789");
        empty.data.clear();
        assert_eq!(media.insert(GROUP, SENDER, "bob", empty, 7, now), Insert::Rejected);

        let mut oversized = chunk(0, 1, MAX_ATTACHMENT_CHUNK_BYTES + 1, &[0u8; 9]);
        oversized.data = vec![0u8; MAX_ATTACHMENT_CHUNK_BYTES + 1];
        assert_eq!(media.insert(GROUP, SENDER, "bob", oversized, 7, now), Insert::Rejected);

        let mut over = chunk(0, 1, MAX_ATTACHMENT_BYTES + 1, b"x");
        over.total_bytes = (MAX_ATTACHMENT_BYTES + 1) as u32;
        assert_eq!(media.insert(GROUP, SENDER, "bob", over, 7, now), Insert::Rejected);
        assert_eq!(media.assemblies.len(), 0, "nothing was buffered");
    }

    #[test]
    fn partials_expire_with_one_summary() {
        let (first, _, _) = two_chunks();
        let now = Instant::now();
        let mut media = GroupMedia::default();
        media.insert(GROUP, SENDER, "bob", first, 7, now);
        let expired = media.prune(now + ASSEMBLY_TTL);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].received, 1);
        assert_eq!(expired[0].count, 2);
        assert_eq!(expired[0].name, "notes.txt");
        assert!(media.prune(now + ASSEMBLY_TTL * 2).is_empty(), "reported once");
        assert_eq!(media.buffered, 0);
    }

    #[test]
    fn the_assembler_stays_bounded() {
        let now = Instant::now();
        let mut media = GroupMedia::default();
        for n in 0..MAX_ASSEMBLIES + 3 {
            let mut chunk = chunk(0, 2, 18, b"123456789");
            chunk.attachment_id = [n as u8; 8];
            media.insert(GROUP, SENDER, "bob", chunk, 7, now + Duration::from_secs(n as u64));
        }
        assert_eq!(media.assemblies.len(), MAX_ASSEMBLIES);
        assert!(media.buffered <= MAX_BUFFERED_BYTES);
    }

    #[test]
    fn clear_forgets_everything() {
        let (first, _, _) = two_chunks();
        let now = Instant::now();
        let mut media = GroupMedia::default();
        media.insert(GROUP, SENDER, "bob", first, 7, now);
        media.clear();
        assert_eq!(media.assemblies.len(), 0);
        assert_eq!(media.buffered, 0);
    }
}
