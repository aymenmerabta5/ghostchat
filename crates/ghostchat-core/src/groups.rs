//! Private groups: the state machine on top of the wire format in
//! [`ghostchat_protocol::group`].
//!
//! A group is identified by 16 random bytes and owned by the peer that created
//! it. Only the creator may change the roster, and every change increments the
//! epoch and rotates the symmetric key, which is what makes a removal take
//! effect: the removed member keeps the old key, and the old key no longer
//! opens anything.
//!
//! This module holds no I/O, no platform state, and no private key material. It
//! decides what a received payload means and what a locally requested change
//! should produce; the app layer persists it, the router relays it, and the
//! worker signs and transmits it.
//!
//! Acceptance rules mirror the iOS reference (`ChatGroupCoordinator`):
//!
//! * a state must be signed by the creator named in its own roster, and the
//!   authenticated Noise peer that delivered it must be that creator;
//! * a known group keeps the creator it was created with — fingerprint *and*
//!   signing key — because a self-signed state naming a new creator verifies
//!   perfectly well on its own terms;
//! * an epoch never goes backwards, so a stale invite cannot undo a removal;
//! * a creator-signed roster that no longer names us is a removal;
//! * a group message is accepted only under the current epoch, from a signing
//!   key pinned in the roster, and never twice.
//!
//! Timestamps inside messages are authenticated but a peer's clock is not, so
//! a future-dated message is clamped to the local clock rather than allowed to
//! pin itself to the bottom of the timeline.

use std::collections::{BTreeMap, HashSet, VecDeque};

use ghostchat_protocol::group::{
    GroupEnvelope, GroupError as WireError, GroupId, GroupMember, GroupState, KEY_LEN, MAX_MEMBERS, MAX_NAME_CHARS,
};
use ghostchat_protocol::{Packet, PeerId};

use crate::router::MeshRouter;

/// Message ids remembered per group for replay suppression. Ids are UUIDs, so
/// the cap only matters for a member that floods.
const SEEN_CAP: usize = 4096;
/// iOS `InputValidator.Limits.maxMessageLength`, enforced on send only.
pub const MAX_MESSAGE_CHARS: usize = 60_000;

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("group wire error: {0}")]
    Wire(#[from] WireError),
    #[error("only the creator can change the roster")]
    CreatorOnly,
    #[error("the creator cannot be removed")]
    CannotRemoveCreator,
    #[error("this identity is already a member")]
    AlreadyMember,
    #[error("a group holds at most {MAX_MEMBERS} members")]
    Full,
    #[error("a group name must be 1 to {MAX_NAME_CHARS} characters")]
    BadName,
    #[error("this identity is not named in the roster")]
    NotAMember,
    #[error("a group message holds at most {MAX_MESSAGE_CHARS} characters")]
    TooLong,
    #[error("this group does not exist locally")]
    UnknownGroup,
    #[error("group state names a different creator")]
    CreatorChanged,
    #[error("group state epoch {found} is older than the stored epoch {current}")]
    StaleEpoch { found: u32, current: u32 },
    #[error("group state was not delivered by the creator")]
    NotFromCreator,
    #[error("group message epoch {found} is not the current epoch {current}")]
    EpochMismatch { found: u32, current: u32 },
    #[error("the sender's signing key is not in the roster")]
    SenderNotMember,
}

/// A group this device belongs to.
pub struct Group {
    /// The latest creator-signed state, including the epoch key.
    pub state: GroupState,
    /// Our own roster fingerprint, so echo and removal checks need no lookup.
    pub my_fingerprint: [u8; 32],
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
}

impl Group {
    fn new(state: GroupState, my_fingerprint: [u8; 32]) -> Self {
        Self { state, my_fingerprint, seen: HashSet::new(), seen_order: VecDeque::new() }
    }

    pub fn id(&self) -> &GroupId {
        &self.state.group_id
    }

    pub fn name(&self) -> &str {
        &self.state.name
    }

    pub fn epoch(&self) -> u32 {
        self.state.epoch
    }

    pub fn members(&self) -> &[GroupMember] {
        &self.state.members
    }

    /// Creates a group owned by us, with us as its only member. Epoch starts at
    /// 1 and the key is freshly random, exactly as the reference does.
    ///
    /// `my_signing_public` is the Ed25519 **public** key from our announce; it
    /// is what the roster pins and what receivers verify against. The private
    /// half only enters through `sign`.
    pub fn create(
        name: &str,
        my_fingerprint: [u8; 32],
        my_signing_public: [u8; 32],
        nickname: &str,
        sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<Self, GroupError> {
        validate_name(name)?;
        let me = GroupMember::new(my_fingerprint, my_signing_public, nickname);
        let state = GroupState::make_signed(
            GroupId::random(),
            name,
            ghostchat_protocol::group::random_key(),
            1,
            vec![me],
            my_fingerprint,
            sign,
        )?;
        Ok(Self::new(state, my_fingerprint))
    }

    pub fn is_creator(&self) -> bool {
        self.state.creator == self.my_fingerprint
    }

    /// A rename, epoch bump, or roster change that keeps us a member. Only the
    /// creator can produce a state the rest of the group will accept.
    fn rotate(
        &mut self,
        members: Vec<GroupMember>,
        name: &str,
        sign: impl Fn(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<GroupState, GroupError> {
        if !self.is_creator() {
            return Err(GroupError::CreatorOnly);
        }
        validate_name(name)?;
        if members.len() > MAX_MEMBERS {
            return Err(GroupError::Full);
        }
        let epoch = self.state.epoch.saturating_add(1);
        let state = GroupState::make_signed(
            self.state.group_id,
            name,
            ghostchat_protocol::group::random_key(),
            epoch,
            members,
            self.state.creator,
            sign,
        )?;
        self.state = state.clone();
        Ok(state)
    }

    /// Adds a member and rotates the key. Returns the signed state to deliver.
    pub fn add_member(
        &mut self,
        member: GroupMember,
        sign: impl Fn(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<GroupState, GroupError> {
        if self.state.is_member(&member.fingerprint) {
            return Err(GroupError::AlreadyMember);
        }
        if self.state.members.len() >= MAX_MEMBERS {
            return Err(GroupError::Full);
        }
        let mut members = self.state.members.clone();
        members.push(member);
        let name = self.state.name.clone();
        self.rotate(members, &name, sign)
    }

    /// Removes a member, rotates the key, and builds the two payloads a removal
    /// needs: the new state for the remaining members, and a notice for the
    /// removee.
    ///
    /// The notice carries an all-zero throwaway key on purpose. The removee's
    /// client only reads the roster from it — the roster no longer names them,
    /// so it drops the group instead of quietly going dark holding a key that
    /// opens nothing. Sending the rotated key there would hand post-removal
    /// traffic straight back to the person who was just removed.
    pub fn remove_member(
        &mut self,
        fingerprint: &[u8; 32],
        sign: impl Fn(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<Removal, GroupError> {
        if !self.is_creator() {
            return Err(GroupError::CreatorOnly);
        }
        if *fingerprint == self.state.creator {
            return Err(GroupError::CannotRemoveCreator);
        }
        if !self.state.is_member(fingerprint) {
            return Err(GroupError::NotAMember);
        }
        let remaining: Vec<_> = self.state.members.iter().filter(|m| &m.fingerprint != fingerprint).cloned().collect();
        let name = self.state.name.clone();
        let state = self.rotate(remaining, &name, &sign)?;

        // The notice is the same signed roster under a throwaway key. It costs
        // one extra signature and tells the removee to drop the group instead
        // of silently holding a key that opens nothing.
        let notice = GroupState::make_signed(
            state.group_id,
            &state.name,
            [0u8; KEY_LEN],
            state.epoch,
            state.members.clone(),
            state.creator,
            sign,
        )?;
        Ok(Removal { state, notice })
    }

    /// Seals `content` under the current epoch. `my_signing_public` must be the
    /// key the roster pins to us, otherwise the sender signature would be
    /// rejected by every receiver; `sign` holds the matching private key.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        &self,
        content: &str,
        message_id: &str,
        nickname: &str,
        my_signing_public: &[u8; 32],
        timestamp_ms: u64,
        sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<Vec<u8>, GroupError> {
        if content.chars().count() > MAX_MESSAGE_CHARS {
            return Err(GroupError::TooLong);
        }
        let member = self.state.member_by_signing_key(my_signing_public).ok_or(GroupError::NotAMember)?;
        if member.fingerprint != self.my_fingerprint {
            return Err(GroupError::NotAMember);
        }
        Ok(ghostchat_protocol::group::seal_message(
            &self.state.group_id,
            self.state.epoch,
            &self.state.key,
            message_id,
            my_signing_public,
            nickname,
            timestamp_ms,
            content,
            sign,
        )?)
    }

    /// Decrypts and authenticates an envelope, then applies the receive-time
    /// rules. `now_ms` clamps a peer's future clock.
    pub fn open(&mut self, envelope: &GroupEnvelope, now_ms: u64) -> Result<OpenOutcome, GroupError> {
        if envelope.epoch != self.state.epoch {
            return Err(GroupError::EpochMismatch { found: envelope.epoch, current: self.state.epoch });
        }
        let plaintext = ghostchat_protocol::group::open_message(envelope, &self.state.key)?;
        let sender = self
            .state
            .member_by_signing_key(&plaintext.sender_signing_key)
            .cloned()
            .ok_or(GroupError::SenderNotMember)?;
        // Our own broadcast comes back through relay or sync replay.
        if sender.fingerprint == self.my_fingerprint {
            return Ok(OpenOutcome::OwnEcho);
        }
        if !self.mark_seen(&plaintext.message_id) {
            return Ok(OpenOutcome::Duplicate);
        }
        Ok(OpenOutcome::Message(OpenedMessage {
            message_id: plaintext.message_id,
            sender: sender.clone(),
            content: plaintext.content,
            timestamp_ms: plaintext.timestamp_ms.min(now_ms),
            epoch: envelope.epoch,
        }))
    }

    /// False when this id was already accepted. Only successful opens consume
    /// an id, so a payload that failed verification can be retried.
    fn mark_seen(&mut self, message_id: &str) -> bool {
        if !self.seen.insert(message_id.to_string()) {
            return false;
        }
        self.seen_order.push_back(message_id.to_string());
        if self.seen_order.len() > SEEN_CAP {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

/// A removal handed back by [`Group::remove_member`]: the rotated state for
/// the remaining members, and the throwaway-key notice for the removee.
pub struct Removal {
    /// Rotated state, signed, with the new epoch key. Send to remaining members.
    pub state: GroupState,
    /// Same roster, same signature domain, all-zero key. Send only to the
    /// removee, whose roster check will drop the group.
    pub notice: GroupState,
}

fn validate_name(name: &str) -> Result<(), GroupError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_NAME_CHARS {
        return Err(GroupError::BadName);
    }
    Ok(())
}

/// The mesh peer id a roster fingerprint belongs to. Short peer ids are the
/// fingerprint's first 16 hex characters, so this is a direct derivation and
/// not a lookup — the same rule iOS uses (`connectedPeerID(forFingerprint:)`).
pub fn peer_id_for_fingerprint(fingerprint: &[u8; 32]) -> Option<PeerId> {
    let hex = ghostchat_protocol::hexutil::encode(fingerprint);
    Some(PeerId::from_hex(hex.get(..16)?.to_string()))
}

impl MeshRouter {
    /// Our own fingerprint as raw bytes, for roster comparisons.
    pub fn local_fingerprint_bytes(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.identity.noise_public()).into()
    }

    /// Wraps a sealed envelope in the `0x25` broadcast packet. The outer
    /// packet is unsigned, exactly like the reference: the sender's signature
    /// is inside the ciphertext and survives sync backfill after the announce
    /// has expired.
    pub fn build_group_message(&self, payload: Vec<u8>) -> Packet {
        let mut packet =
            Packet::new(ghostchat_protocol::MessageType::GroupMessage as u8, self.identity.sender_id(), payload);
        packet.ttl = ghostchat_protocol::DEFAULT_TTL;
        packet
    }

    /// Sends creator-signed state over the peer's Noise session. Fails when
    /// no session is established yet; the caller then handshakes and retries.
    pub fn send_group_state(&mut self, peer: &PeerId, invite: bool, payload: &[u8]) -> Result<Packet, String> {
        let kind = if invite {
            ghostchat_protocol::NoisePayloadType::GroupInvite
        } else {
            ghostchat_protocol::NoisePayloadType::GroupKeyUpdate
        };
        self.encrypt_typed(peer, kind, payload)
    }
}

/// What [`Group::open`] decided about a verified envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    Message(OpenedMessage),
    /// Our own message, echoed back by a relay or a sync replay.
    OwnEcho,
    /// An id we already accepted.
    Duplicate,
}

/// A group message that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessage {
    pub message_id: String,
    pub sender: GroupMember,
    pub content: String,
    /// Authenticated, then clamped to the local clock if it was in the future.
    pub timestamp_ms: u64,
    pub epoch: u32,
}

/// What an incoming creator-signed state did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateOutcome {
    /// A new group, from an invite.
    Joined { name: String, creator_nickname: String },
    /// A roster change or rename for a group we already had.
    Updated { name: String, from_epoch: u32, to_epoch: u32 },
    /// The state was the one we already hold.
    Unchanged,
    /// The roster no longer names us; the group is gone locally.
    Removed { name: String },
}

/// Every group this device belongs to, keyed by id.
#[derive(Default)]
pub struct GroupBook {
    groups: BTreeMap<String, Group>,
}

impl GroupBook {
    pub fn insert(&mut self, group: Group) {
        self.groups.insert(group.id().hex(), group);
    }

    pub fn get(&self, id: &GroupId) -> Option<&Group> {
        self.groups.get(&id.hex())
    }

    pub fn get_mut(&mut self, id: &GroupId) -> Option<&mut Group> {
        self.groups.get_mut(&id.hex())
    }

    pub fn remove(&mut self, id: &GroupId) -> Option<Group> {
        self.groups.remove(&id.hex())
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Sorted by name so a sidebar does not reshuffle on every epoch.
    pub fn list(&self) -> Vec<&Group> {
        let mut groups: Vec<_> = self.groups.values().collect();
        groups.sort_by(|a, b| a.name().to_lowercase().cmp(&b.name().to_lowercase()).then(a.id().cmp(b.id())));
        groups
    }

    pub fn iter(&self) -> impl Iterator<Item = &Group> {
        self.groups.values()
    }

    /// Applies a creator-signed invite or key update that arrived over an
    /// authenticated Noise session with `from_fingerprint`.
    ///
    /// `my_fingerprint` is this device's Noise fingerprint. Nothing here trusts
    /// the payload's own claim about who sent it: the sender is the session
    /// peer, and the state must have been signed by the creator it names.
    pub fn apply_state(
        &mut self,
        state: GroupState,
        from_fingerprint: [u8; 32],
        my_fingerprint: [u8; 32],
    ) -> Result<StateOutcome, GroupError> {
        if from_fingerprint != state.creator {
            return Err(GroupError::NotFromCreator);
        }
        if !state.verify() {
            return Err(GroupError::Wire(WireError::BadCreatorSignature));
        }

        let key = state.group_id.hex();
        if let Some(existing) = self.groups.get(&key) {
            // A state from a different creator is a forged or confused invite.
            // `state.verify` alone cannot catch this: a self-signed state
            // naming its own author verifies by construction.
            if existing.state.creator != state.creator {
                return Err(GroupError::CreatorChanged);
            }
            let stored_creator = existing.state.creator_member().ok_or(GroupError::CreatorChanged)?;
            let incoming_creator = state.creator_member().ok_or(GroupError::CreatorChanged)?;
            if stored_creator.signing_key != incoming_creator.signing_key {
                return Err(GroupError::CreatorChanged);
            }
            if state.epoch < existing.state.epoch {
                return Err(GroupError::StaleEpoch { found: state.epoch, current: existing.state.epoch });
            }
        }

        if !state.is_member(&my_fingerprint) {
            if let Some(removed) = self.groups.remove(&key) {
                return Ok(StateOutcome::Removed { name: removed.state.name });
            }
            // An invite we are not in, or a rotation for a group we never had.
            return Err(GroupError::NotAMember);
        }

        // A zero key marks a removal notice: it exists only to tell the person
        // removed that the roster dropped them. Any remaining member already
        // holds a usable epoch key and must not overwrite it with one nobody
        // can send under, however that notice reached them.
        if state.key == [0u8; KEY_LEN] {
            return Ok(StateOutcome::Unchanged);
        }

        match self.groups.get_mut(&key) {
            Some(group) => {
                let from_epoch = group.state.epoch;
                if from_epoch == state.epoch && group.state == state {
                    return Ok(StateOutcome::Unchanged);
                }
                let name = state.name.clone();
                let to_epoch = state.epoch;
                group.state = state;
                Ok(StateOutcome::Updated { name, from_epoch, to_epoch })
            }
            None => {
                let nickname = state.creator_member().map(|m| m.nickname.clone()).unwrap_or_default();
                let name = state.name.clone();
                self.groups.insert(key, Group::new(state, my_fingerprint));
                Ok(StateOutcome::Joined { name, creator_nickname: nickname })
            }
        }
    }

    /// Decrypts an envelope against the group it names. Unknown groups, wrong
    /// epochs, and bad signatures are errors; own echoes and replays are
    /// `OpenOutcome` values so the caller can drop them without logging noise.
    pub fn open(&mut self, envelope: &GroupEnvelope, now_ms: u64) -> Result<OpenOutcome, GroupError> {
        let group = self.groups.get_mut(&envelope.group_id.hex()).ok_or(GroupError::UnknownGroup)?;
        group.open(envelope, now_ms)
    }

    /// Rebuilds the book from states saved on disk (see `Group::state`). A
    /// state that no longer verifies is dropped rather than trusted, which is
    /// what makes the on-disk form safe to hand-edit.
    pub fn from_encoded_states(encoded: impl IntoIterator<Item = Vec<u8>>, my_fingerprint: [u8; 32]) -> (Self, usize) {
        let mut book = Self::default();
        let mut skipped = 0usize;
        for bytes in encoded {
            match GroupState::decode(&bytes) {
                Some(state) if state.verify() && state.is_member(&my_fingerprint) => {
                    book.insert(Group::new(state, my_fingerprint));
                }
                _ => skipped += 1,
            }
        }
        (book, skipped)
    }

    /// States to persist. Encoded canonical bytes, one per group.
    pub fn encoded_states(&self) -> Vec<Vec<u8>> {
        self.groups.values().filter_map(|group| group.state.encode().ok()).collect()
    }
}

#[cfg(test)]
mod tests;
