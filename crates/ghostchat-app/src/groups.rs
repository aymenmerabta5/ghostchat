//! Persisted private groups.
//!
//! Only the creator-signed [`GroupState`] is written, in its canonical encoded
//! form, sealed with the OS keystore (Windows DPAPI, or a Linux Secret Service
//! wrap key). The epoch key lives inside that blob, so the whole file is a
//! secret: a group's message traffic is readable by anyone who has it.
//!
//! Where no keystore answers the book stays in memory, exactly like the DM
//! outbox: group keys are never written to disk in the clear. A saved state
//! that no longer verifies, or that no longer names us, is dropped on load
//! rather than trusted.
//!
//! The book itself lives in `ghostchat-core`; this module is only the disk and
//! UI-facing view of it.

use crate::{app_dirs, key_protect};
use ghostchat_core::groups::{peer_id_for_fingerprint, GroupBook};
use ghostchat_protocol::group::GroupMember;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// On-disk shape. A list of hex-encoded canonical `GroupState` blobs.
#[derive(Serialize, Deserialize)]
struct Saved {
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Default)]
pub struct Groups {
    book: GroupBook,
    path: Option<PathBuf>,
}

impl Groups {
    /// Loads the sealed book for this identity's fingerprint.
    pub fn open(path: Option<PathBuf>, my_fingerprint: [u8; 32]) -> Self {
        let mut groups = Self { book: GroupBook::default(), path };
        groups.load(my_fingerprint);
        groups
    }

    pub fn open_default(my_fingerprint: [u8; 32]) -> Self {
        let path = app_dirs::data_local_dir().map(|d| d.join("groups.sealed"));
        Self::open(path, my_fingerprint)
    }

    fn load(&mut self, my_fingerprint: [u8; 32]) {
        let Some(path) = &self.path else { return };
        if !key_protect::Protection::current().persists_sealed() {
            return;
        }
        let Ok(sealed) = fs::read(path) else { return };
        let Ok(plain) = key_protect::unprotect(&sealed) else {
            tracing::warn!("groups: could not unseal; starting with none");
            let _ = fs::remove_file(path);
            return;
        };
        let saved: Saved = match serde_json::from_slice(&plain) {
            Ok(saved) => saved,
            Err(err) => {
                tracing::warn!(error = %err, "groups: unreadable file; starting with none");
                let _ = fs::remove_file(path);
                return;
            }
        };
        let states: Vec<Vec<u8>> =
            saved.groups.iter().filter_map(|hex| ghostchat_protocol::hexutil::decode(hex).ok()).collect();
        let (book, skipped) = GroupBook::from_encoded_states(states, my_fingerprint);
        if skipped > 0 {
            tracing::warn!(skipped, "groups: dropped saved states that no longer verify");
        }
        tracing::info!(groups = book.len(), "groups: loaded");
        self.book = book;
    }

    pub fn book(&self) -> &GroupBook {
        &self.book
    }

    pub fn book_mut(&mut self) -> &mut GroupBook {
        &mut self.book
    }

    pub fn len(&self) -> usize {
        self.book.len()
    }

    pub fn is_empty(&self) -> bool {
        self.book.is_empty()
    }

    /// Writes the current book. Called after every accepted state change.
    pub fn save(&self) {
        let Some(path) = &self.path else { return };
        if !key_protect::Protection::current().persists_sealed() {
            return;
        }
        if let Err(err) = self.write(path) {
            tracing::warn!(error = %err, "groups: could not save; groups last until exit");
        }
    }

    fn write(&self, path: &PathBuf) -> anyhow::Result<()> {
        let states = self.book.encoded_states();
        if states.is_empty() {
            let _ = fs::remove_file(path);
            return Ok(());
        }
        let saved = Saved { groups: states.iter().map(|bytes| ghostchat_protocol::hexutil::encode(bytes)).collect() };
        let sealed = key_protect::protect(&serde_json::to_vec(&saved)?)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("sealed.tmp");
        fs::write(&tmp, sealed)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Panic wipe and identity roll: forget every group and its key.
    pub fn clear(&mut self) {
        self.book = GroupBook::default();
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }

    /// What the sidebar shows, sorted by name. `online` reports whether a
    /// member's mesh peer is in range right now.
    pub fn summaries(&self, online: impl Fn(&ghostchat_protocol::PeerId) -> bool) -> Vec<GroupSummary> {
        self.book
            .list()
            .into_iter()
            .map(|group| {
                let members = group
                    .members()
                    .iter()
                    .map(|member| {
                        let peer_id = peer_id_for_fingerprint(&member.fingerprint);
                        let is_me = member.fingerprint == group.my_fingerprint;
                        GroupMemberSummary {
                            online: is_me || peer_id.as_ref().is_some_and(&online),
                            peer_id: peer_id.map(|id| id.hex.clone()),
                            nickname: member.nickname.clone(),
                            fingerprint: member.fingerprint_hex(),
                            is_me,
                            is_creator: member.fingerprint == group.state.creator,
                        }
                    })
                    .collect();
                GroupSummary {
                    id: group.id().hex(),
                    name: group.name().to_string(),
                    epoch: group.epoch(),
                    is_creator: group.is_creator(),
                    members,
                }
            })
            .collect()
    }
}

/// One group as the GUI needs it: no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    pub epoch: u32,
    pub is_creator: bool,
    pub members: Vec<GroupMemberSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMemberSummary {
    /// The mesh peer id, when the fingerprint can be shortened to one.
    pub peer_id: Option<String>,
    /// That peer is in range right now.
    pub online: bool,
    pub nickname: String,
    pub fingerprint: String,
    pub is_me: bool,
    pub is_creator: bool,
}

impl GroupSummary {
    pub fn display_members(&self) -> String {
        self.members.iter().map(|m| m.nickname.as_str()).collect::<Vec<_>>().join(", ")
    }
}

/// Turns a peer's announce data into the roster entry a group stores.
pub fn member_from_peer(fingerprint: [u8; 32], signing_key: &[u8], nickname: &str) -> Option<GroupMember> {
    let key: [u8; 32] = signing_key.try_into().ok()?;
    Some(GroupMember::new(fingerprint, key, nickname))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostchat_core::Group;
    use ghostchat_protocol::group::GroupState;

    /// `(fingerprint, signing seed)`. The seed stays local; the roster gets
    /// the public key derived from it, or nothing verifies.
    fn identity(seed: u8) -> ([u8; 32], [u8; 32]) {
        let mut fingerprint = [0u8; 32];
        let mut signing = [0u8; 32];
        for i in 0..32 {
            fingerprint[i] = seed.wrapping_mul(31).wrapping_add(i as u8);
            signing[i] = seed.wrapping_add(i as u8).wrapping_mul(7);
        }
        (fingerprint, signing)
    }

    fn public_of(seed: &[u8; 32]) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn signer(key: &[u8; 32]) -> impl Fn(&[u8]) -> Option<[u8; 64]> + '_ {
        move |message| {
            use ed25519_dalek::Signer;
            let signing = ed25519_dalek::SigningKey::from_bytes(key);
            Some(signing.sign(message).to_bytes())
        }
    }

    fn new_group(id: u8, name: &str) -> (([u8; 32], [u8; 32]), Group) {
        let (fingerprint, signing) = identity(id);
        let group = Group::create(name, fingerprint, public_of(&signing), "me", signer(&signing)).unwrap();
        ((fingerprint, signing), group)
    }

    #[test]
    fn an_unsaved_book_stays_in_memory() {
        let mut groups = Groups::open(None, [0u8; 32]);
        assert!(groups.is_empty());
        let (me, group) = new_group(1, "Pharmacy");
        groups.book_mut().insert(group);
        groups.save();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups.summaries(|_| false)[0].name, "Pharmacy");
        groups.clear();
        assert!(groups.is_empty());
        assert!(!me.0.is_empty());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn survives_a_restart_sealed_without_plaintext_keys() {
        if !key_protect::Protection::current().persists_sealed() {
            return;
        }
        let path = std::env::temp_dir().join(format!("ghostchat-groups-{}.sealed", uuid::Uuid::new_v4()));
        let (me, group) = new_group(2, "Ward Round");
        let grouped = group.state.clone();
        let mut groups = Groups::open(Some(path.clone()), me.0);
        groups.book_mut().insert(group);
        groups.save();

        let raw = fs::read(&path).unwrap();
        let plain_key = grouped.key;
        assert!(!raw.windows(32).any(|w| w == plain_key.as_slice()), "the epoch key is sealed on disk");

        let reopened = Groups::open(Some(path.clone()), me.0);
        assert_eq!(reopened.len(), 1);
        let summaries = reopened.summaries(|_| false);
        let summary = &summaries[0];
        assert_eq!(summary.name, "Ward Round");
        assert!(summary.is_creator);
        assert_eq!(summary.members.len(), 1);
        assert!(summary.members[0].is_me);

        // Another identity's key does not open the file.
        let other = Groups::open(Some(path.clone()), identity(9).0);
        assert!(other.is_empty(), "saved states for another identity are dropped");

        fs::write(&path, b"garbage").unwrap();
        assert!(Groups::open(Some(path.clone()), me.0).is_empty());
        assert!(!path.exists(), "unreadable files are discarded");
    }

    #[test]
    fn saved_states_round_trip_through_the_encoder() {
        let (me, group) = new_group(3, "Triage");
        let encoded = group.state.encode().unwrap();
        let (book, skipped) = GroupBook::from_encoded_states([encoded], me.0);
        assert_eq!(skipped, 0);
        assert_eq!(book.len(), 1);
        assert_eq!(book.list()[0].name(), "Triage");
    }

    #[test]
    fn a_tampered_state_is_dropped_on_load() {
        let (me, group) = new_group(4, "Dispensary");
        let mut encoded = group.state.encode().unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        let (book, skipped) = GroupBook::from_encoded_states([encoded], me.0);
        assert_eq!(skipped, 1);
        assert!(book.is_empty());
    }

    #[test]
    fn summaries_flag_me_the_creator_and_online_members() {
        let (me, mut group) = new_group(5, "Stock");
        let (them, them_sign) = identity(6);
        group.add_member(GroupMember::new(them, public_of(&them_sign), "bob"), signer(&me.1)).unwrap();
        let mut groups = Groups::open(None, me.0);
        groups.book_mut().insert(group);
        let bob_peer = peer_id_for_fingerprint(&them).unwrap();
        let list = groups.summaries(|id| id == &bob_peer);
        let summary = &list[0];
        assert_eq!(summary.members.len(), 2);
        assert!(summary.is_creator);
        assert!(summary.members.iter().any(|m| m.is_me && m.is_creator));
        let bob = summary.members.iter().find(|m| !m.is_me).expect("bob is listed");
        assert_eq!(bob.nickname, "bob");
        assert!(bob.online, "the online predicate matched bob's peer id");
        assert_eq!(summary.display_members(), "me, bob");
    }

    #[test]
    fn a_removed_state_is_not_loaded_back() {
        let (me, mut group) = new_group(7, "Rota");
        let (them, them_sign) = identity(8);
        group.add_member(GroupMember::new(them, public_of(&them_sign), "carol"), signer(&me.1)).unwrap();
        // Remove Carol: the rotated roster no longer names her, so her copy of
        // the file is dropped on load rather than trusted.
        let removal = group.remove_member(&them, signer(&me.1)).unwrap();
        let rotated = removal.state.encode().unwrap();
        let (book, skipped) = GroupBook::from_encoded_states([rotated.clone()], them);
        assert_eq!(skipped, 1);
        assert!(book.is_empty());
        // Her own identity still opens the group's own file.
        let (mine, skipped) = GroupBook::from_encoded_states([rotated], me.0);
        assert_eq!(skipped, 0);
        assert_eq!(mine.len(), 1);
        assert_eq!(mine.list()[0].members().len(), 1);
        // The notice is a decodable state under the throwaway key.
        assert_eq!(GroupState::decode(&removal.notice.encode().unwrap()).unwrap().key, [0u8; 32]);
    }
}
