//! Private groups: creator-signed state (invites and key updates, carried
//! inside Noise) and ChaCha20-Poly1305 broadcasts (`MessageType::GroupMessage`).
//!
//! Wire-compatible with the iOS `GroupProtocol.swift` reference:
//!
//! ```text
//! roster   = count(1) || { fingerprint(32) || signingKey(32) || len(1) || nickname }
//! state    = TLV 1 groupID | 2 name | 3 key | 4 epoch | 5 roster | 6 creator | 7 signature
//! envelope = TLV 1 groupID | 2 epoch | 3 nonce   | 4 ciphertext||tag
//! inner    = TLV 1 id      | 2 senderKey | 3 senderNickname | 4 timestamp | 5 content | 6 signature
//! ```
//!
//! TLVs are `type(1) || length(2, big-endian) || value`. Unknown fields are
//! ignored on decode, so a later revision can add one without a version bump.
//!
//! Two signatures are in play and they cover different things:
//!
//! * the creator signs group **state** — `"bitchat-group-v1" | groupID | epoch |
//!   SHA256(key) | SHA256(roster) | SHA256(name)` — binding the roster and the
//!   name by hash so the signed blob stays fixed-size;
//! * each sender signs the **message** — `"bitchat-group-msg-v1" | groupID |
//!   epoch | messageID | timestamp | content` — so key possession alone is not
//!   authorship. Covering the epoch stops a current member from re-sealing a
//!   decrypted inner blob under a later key: the signature would not verify.
//!
//! The cleartext `groupID` and `epoch` are bound as AEAD associated data, which
//! stops a ciphertext being replayed across groups or epochs. A relay therefore
//! learns that *some* group exists and how active it is, and nothing else.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;

use crate::hexutil;

/// Rosters are capped by the reference implementation. A signed roster naming
/// more members than this is rejected rather than truncated.
pub const MAX_MEMBERS: usize = 16;
pub const GROUP_ID_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
/// Nicknames in the signed roster are byte-capped, on a character boundary.
pub const MAX_NICKNAME_BYTES: usize = 64;
/// The iOS command layer caps a group name at 40 characters.
pub const MAX_NAME_CHARS: usize = 40;

/// Domain-separation prefixes, byte-identical to the reference.
const STATE_DOMAIN: &[u8] = b"bitchat-group-v1";
const MESSAGE_DOMAIN: &[u8] = b"bitchat-group-msg-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupError {
    /// A TLV value did not fit the 16-bit length field.
    #[error("group value does not fit the 16-bit length field")]
    ValueTooLong,
    /// Framing, field sizes, or UTF-8 were not what the format requires.
    #[error("malformed group payload")]
    Malformed,
    /// The creator signature did not verify against the pinned roster key.
    #[error("group state signature does not verify")]
    BadCreatorSignature,
    /// The sender signature did not verify against the included signing key.
    #[error("group message signature does not verify")]
    BadSenderSignature,
    /// AEAD open failed: wrong key, wrong epoch, or tampered ciphertext.
    #[error("group message could not be decrypted")]
    DecryptionFailed,
    /// Sealing failed (in practice only on allocation failure).
    #[error("group message could not be sealed")]
    SealFailed,
}

// MARK: - Identifiers

/// 16 random bytes, carried in cleartext so relays can dedup without keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(pub [u8; GROUP_ID_LEN]);

impl GroupId {
    pub fn random() -> Self {
        let mut bytes = [0u8; GROUP_ID_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(<[u8; GROUP_ID_LEN]>::try_from(bytes).ok()?))
    }

    pub fn hex(&self) -> String {
        hexutil::encode(&self.0)
    }

    pub fn from_hex(text: &str) -> Option<Self> {
        Self::from_bytes(&hexutil::decode(text).ok()?)
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

/// A fresh 32-byte symmetric group key.
pub fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

// MARK: - TLV

fn put(out: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), GroupError> {
    if value.len() > u16::MAX as usize {
        return Err(GroupError::ValueTooLong);
    }
    out.push(kind);
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Returns `None` on malformed framing (a truncated length or value).
fn parse(data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if data.len() - offset < 3 {
            return None;
        }
        let kind = data[offset];
        let length = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        let start = offset + 3;
        let end = start.checked_add(length)?;
        if end > data.len() {
            return None;
        }
        fields.push((kind, &data[start..end]));
        offset = end;
    }
    Some(fields)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// MARK: - Members and rosters

#[derive(Clone, PartialEq, Eq)]
pub struct GroupMember {
    /// SHA-256 of the member's Noise static key — 32 raw bytes in the roster.
    pub fingerprint: [u8; 32],
    /// The member's Ed25519 signing key, from their announce.
    pub signing_key: [u8; 32],
    /// Nickname at invite time; the display fallback when the peer is offline.
    pub nickname: String,
}

impl GroupMember {
    pub fn new(fingerprint: [u8; 32], signing_key: [u8; 32], nickname: impl Into<String>) -> Self {
        Self { fingerprint, signing_key, nickname: nickname.into() }
    }

    /// The 64-hex form used by the rest of the app (`Peer.fingerprint`).
    pub fn fingerprint_hex(&self) -> String {
        hexutil::encode(&self.fingerprint)
    }

    pub fn signing_key_hex(&self) -> String {
        hexutil::encode(&self.signing_key)
    }
}

impl fmt::Debug for GroupMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupMember")
            .field("fingerprint", &self.fingerprint_hex())
            .field("signing_key", &self.signing_key_hex())
            .field("nickname", &self.nickname)
            .finish()
    }
}

/// Trims a nickname to at most [`MAX_NICKNAME_BYTES`], dropping whole `char`s
/// so the result is never split mid-scalar. A byte-prefix could split a
/// multi-byte character and make the whole signed roster undecodable.
pub fn truncate_nickname(nickname: &str) -> Vec<u8> {
    let mut candidate = nickname.to_string();
    while candidate.len() > MAX_NICKNAME_BYTES {
        if candidate.pop().is_none() {
            break;
        }
    }
    candidate.into_bytes()
}

/// Deterministic roster blob. The creator signature covers `SHA256` of exactly
/// these bytes, so encode is required to be canonical: same members in, same
/// bytes out, regardless of how they were decoded.
pub fn encode_roster(members: &[GroupMember]) -> Option<Vec<u8>> {
    if members.len() > MAX_MEMBERS {
        return None;
    }
    let mut out = Vec::with_capacity(1 + members.len() * (32 + 32 + 1));
    out.push(members.len() as u8);
    for member in members {
        let nickname = truncate_nickname(&member.nickname);
        out.extend_from_slice(&member.fingerprint);
        out.extend_from_slice(&member.signing_key);
        out.push(nickname.len() as u8);
        out.extend_from_slice(&nickname);
    }
    Some(out)
}

/// Rejects anything that is not exactly the canonical encoding: a trailing
/// byte would let two different blobs hash the same roster.
pub fn decode_roster(data: &[u8]) -> Option<Vec<GroupMember>> {
    let count = *data.first()? as usize;
    if count > MAX_MEMBERS {
        return None;
    }
    let mut members = Vec::with_capacity(count);
    let mut offset = 1usize;
    for _ in 0..count {
        if data.len() - offset < 32 + 32 + 1 {
            return None;
        }
        let fingerprint = <[u8; 32]>::try_from(&data[offset..offset + 32]).ok()?;
        offset += 32;
        let signing_key = <[u8; 32]>::try_from(&data[offset..offset + 32]).ok()?;
        offset += 32;
        let length = data[offset] as usize;
        offset += 1;
        if data.len() - offset < length {
            return None;
        }
        let nickname = std::str::from_utf8(&data[offset..offset + length]).ok()?.to_string();
        offset += length;
        members.push(GroupMember { fingerprint, signing_key, nickname });
    }
    if offset != data.len() {
        return None;
    }
    Some(members)
}

// MARK: - Group state (invite 0x06 / key update 0x07, inside Noise)

#[derive(Clone, PartialEq, Eq)]
pub struct GroupState {
    pub group_id: GroupId,
    pub name: String,
    /// Symmetric key for `epoch`.
    pub key: [u8; KEY_LEN],
    /// Bumps on every roster change, so out-of-order states have a total order.
    pub epoch: u32,
    pub members: Vec<GroupMember>,
    /// Fingerprint of the only identity allowed to sign state in v1.
    pub creator: [u8; 32],
    /// Ed25519 signature by the creator over [`GroupState::signing_content`].
    pub signature: [u8; 64],
}

impl fmt::Debug for GroupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupState")
            .field("group_id", &self.group_id)
            .field("name", &self.name)
            .field("epoch", &self.epoch)
            .field("members", &self.members.len())
            .field("creator", &hexutil::encode(&self.creator))
            .finish_non_exhaustive()
    }
}

impl GroupState {
    /// The bytes the creator signs. Key, roster, and name are bound by hash so
    /// the signed content stays fixed-size; the name is covered so a relay that
    /// replays a cached state cannot swap the display name.
    pub fn signing_content(
        group_id: &GroupId,
        epoch: u32,
        key: &[u8; KEY_LEN],
        roster_blob: &[u8],
        name: &str,
    ) -> Vec<u8> {
        let mut content = Vec::with_capacity(STATE_DOMAIN.len() + GROUP_ID_LEN + 4 + 96);
        content.extend_from_slice(STATE_DOMAIN);
        content.extend_from_slice(&group_id.0);
        content.extend_from_slice(&epoch.to_be_bytes());
        content.extend_from_slice(&sha256(key));
        content.extend_from_slice(&sha256(roster_blob));
        content.extend_from_slice(&sha256(name.as_bytes()));
        content
    }

    /// Builds a signed state. `sign` is the local Ed25519 signing key's
    /// operation, so this crate never holds private key material.
    pub fn make_signed(
        group_id: GroupId,
        name: &str,
        key: [u8; KEY_LEN],
        epoch: u32,
        members: Vec<GroupMember>,
        creator: [u8; 32],
        sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<Self, GroupError> {
        let roster_blob = encode_roster(&members).ok_or(GroupError::Malformed)?;
        let content = Self::signing_content(&group_id, epoch, &key, &roster_blob, name);
        let signature = sign(&content).ok_or(GroupError::BadCreatorSignature)?;
        Ok(Self { group_id, name: name.to_string(), key, epoch, members, creator, signature })
    }

    pub fn encode(&self) -> Result<Vec<u8>, GroupError> {
        let roster_blob = encode_roster(&self.members).ok_or(GroupError::Malformed)?;
        let mut out = Vec::with_capacity(roster_blob.len() + 160);
        put(&mut out, 0x01, &self.group_id.0)?;
        put(&mut out, 0x02, self.name.as_bytes())?;
        put(&mut out, 0x03, &self.key)?;
        put(&mut out, 0x04, &self.epoch.to_be_bytes())?;
        put(&mut out, 0x05, &roster_blob)?;
        put(&mut out, 0x06, &self.creator)?;
        put(&mut out, 0x07, &self.signature)?;
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let fields = parse(data)?;
        let mut group_id = None;
        let mut name = None;
        let mut key = None;
        let mut epoch = None;
        let mut members = None;
        let mut creator = None;
        let mut signature = None;

        for (kind, value) in fields {
            match kind {
                0x01 => group_id = GroupId::from_bytes(value),
                0x02 => name = std::str::from_utf8(value).ok().map(str::to_string),
                0x03 => key = <[u8; KEY_LEN]>::try_from(value).ok(),
                0x04 if value.len() == 4 => {
                    epoch = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
                0x05 => members = decode_roster(value),
                0x06 => creator = <[u8; 32]>::try_from(value).ok(),
                0x07 => signature = <[u8; 64]>::try_from(value).ok(),
                // Forward compatible: an unknown TLV is ignored on purpose.
                _ => {}
            }
        }

        let members = members.filter(|m| !m.is_empty())?;
        Some(Self {
            group_id: group_id?,
            name: name?,
            key: key?,
            epoch: epoch?,
            members,
            creator: creator?,
            signature: signature?,
        })
    }

    /// Verifies the creator signature against the signing key pinned in the
    /// roster, and that the creator is actually named in it.
    ///
    /// This is self-referential — the state names its own creator — so a caller
    /// holding an existing group must *also* check that the creator matches the
    /// stored one. See `GroupBook::apply_state`.
    pub fn verify(&self) -> bool {
        if self.members.len() > MAX_MEMBERS {
            return false;
        }
        let Some(creator) = self.members.iter().find(|m| m.fingerprint == self.creator) else {
            return false;
        };
        let Some(roster_blob) = encode_roster(&self.members) else {
            return false;
        };
        let content = Self::signing_content(&self.group_id, self.epoch, &self.key, &roster_blob, &self.name);
        let Ok(verifying) = VerifyingKey::from_bytes(&creator.signing_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        verifying.verify(&content, &signature).is_ok()
    }

    pub fn is_member(&self, fingerprint: &[u8; 32]) -> bool {
        self.members.iter().any(|m| &m.fingerprint == fingerprint)
    }

    pub fn member_by_signing_key(&self, signing_key: &[u8; 32]) -> Option<&GroupMember> {
        self.members.iter().find(|m| &m.signing_key == signing_key)
    }

    pub fn creator_member(&self) -> Option<&GroupMember> {
        self.members.iter().find(|m| m.fingerprint == self.creator)
    }
}

// MARK: - Group message (0x25 payload)

#[derive(Clone, PartialEq, Eq)]
pub struct GroupEnvelope {
    pub group_id: GroupId,
    pub epoch: u32,
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 ciphertext with the 16-byte tag appended.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for GroupEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupEnvelope")
            .field("group_id", &self.group_id)
            .field("epoch", &self.epoch)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl GroupEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, GroupError> {
        let mut out = Vec::with_capacity(self.ciphertext.len() + 48);
        put(&mut out, 0x01, &self.group_id.0)?;
        put(&mut out, 0x02, &self.epoch.to_be_bytes())?;
        put(&mut out, 0x03, &self.nonce)?;
        put(&mut out, 0x04, &self.ciphertext)?;
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let fields = parse(data)?;
        let mut group_id = None;
        let mut epoch = None;
        let mut nonce = None;
        let mut ciphertext = None;
        for (kind, value) in fields {
            match kind {
                0x01 => group_id = GroupId::from_bytes(value),
                0x02 if value.len() == 4 => {
                    epoch = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
                0x03 => nonce = <[u8; 12]>::try_from(value).ok(),
                0x04 if !value.is_empty() => ciphertext = Some(value.to_vec()),
                _ => {}
            }
        }
        Some(Self { group_id: group_id?, epoch: epoch?, nonce: nonce?, ciphertext: ciphertext? })
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(GROUP_ID_LEN + 4);
        aad.extend_from_slice(&self.group_id.0);
        aad.extend_from_slice(&self.epoch.to_be_bytes());
        aad
    }
}

/// Decrypted, signature-verified inner content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPlaintext {
    pub message_id: String,
    pub sender_signing_key: [u8; 32],
    pub sender_nickname: String,
    pub timestamp_ms: u64,
    pub content: String,
}

/// Bytes a sender signs. Not length-prefixed — exactly as the reference builds
/// them — so a port must concatenate the same way.
pub fn message_signing_content(
    group_id: &GroupId,
    epoch: u32,
    message_id: &str,
    timestamp_ms: u64,
    content: &str,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(MESSAGE_DOMAIN.len() + GROUP_ID_LEN + 12 + message_id.len() + content.len());
    data.extend_from_slice(MESSAGE_DOMAIN);
    data.extend_from_slice(&group_id.0);
    data.extend_from_slice(&epoch.to_be_bytes());
    data.extend_from_slice(message_id.as_bytes());
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    data.extend_from_slice(content.as_bytes());
    data
}

/// Seals a message into the encoded `0x25` payload.
#[allow(clippy::too_many_arguments)]
pub fn seal_message(
    group_id: &GroupId,
    epoch: u32,
    key: &[u8; KEY_LEN],
    message_id: &str,
    sender_signing_key: &[u8; 32],
    sender_nickname: &str,
    timestamp_ms: u64,
    content: &str,
    sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
) -> Result<Vec<u8>, GroupError> {
    let signing_content = message_signing_content(group_id, epoch, message_id, timestamp_ms, content);
    let signature = sign(&signing_content).ok_or(GroupError::BadSenderSignature)?;

    let mut inner = Vec::with_capacity(content.len() + 200);
    put(&mut inner, 0x01, message_id.as_bytes())?;
    put(&mut inner, 0x02, sender_signing_key)?;
    put(&mut inner, 0x03, sender_nickname.as_bytes())?;
    put(&mut inner, 0x04, &timestamp_ms.to_be_bytes())?;
    put(&mut inner, 0x05, content.as_bytes())?;
    put(&mut inner, 0x06, &signature)?;

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(key.into());
    let mut aad = Vec::with_capacity(GROUP_ID_LEN + 4);
    aad.extend_from_slice(&group_id.0);
    aad.extend_from_slice(&epoch.to_be_bytes());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &inner, aad: &aad })
        .map_err(|_| GroupError::SealFailed)?;

    GroupEnvelope { group_id: *group_id, epoch, nonce, ciphertext }.encode()
}

/// Opens an envelope with the epoch key: decrypts, parses the inner TLV, and
/// verifies the sender's Ed25519 signature.
///
/// Roster membership of the sender is the *caller's* check — this only proves
/// the payload was authored by `sender_signing_key`. Key possession is not
/// authorship, and a removed member still holds an old key.
pub fn open_message(envelope: &GroupEnvelope, key: &[u8; KEY_LEN]) -> Result<GroupPlaintext, GroupError> {
    if envelope.ciphertext.len() <= 16 {
        return Err(GroupError::DecryptionFailed);
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let aad = envelope.aad();
    let inner = cipher
        .decrypt(Nonce::from_slice(&envelope.nonce), Payload { msg: &envelope.ciphertext, aad: &aad })
        .map_err(|_| GroupError::DecryptionFailed)?;

    let fields = parse(&inner).ok_or(GroupError::Malformed)?;
    let mut message_id = None;
    let mut sender_signing_key = None;
    let mut sender_nickname = None;
    let mut timestamp_ms = None;
    let mut content = None;
    let mut signature = None;

    for (kind, value) in fields {
        match kind {
            0x01 => message_id = std::str::from_utf8(value).ok().map(str::to_string),
            0x02 => sender_signing_key = <[u8; 32]>::try_from(value).ok(),
            0x03 => sender_nickname = std::str::from_utf8(value).ok().map(str::to_string),
            0x04 if value.len() == 8 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(value);
                timestamp_ms = Some(u64::from_be_bytes(bytes));
            }
            0x05 => content = std::str::from_utf8(value).ok().map(str::to_string),
            0x06 => signature = <[u8; 64]>::try_from(value).ok(),
            _ => {}
        }
    }

    let message_id = message_id.filter(|id| !id.is_empty()).ok_or(GroupError::Malformed)?;
    let sender_signing_key = sender_signing_key.ok_or(GroupError::Malformed)?;
    let sender_nickname = sender_nickname.ok_or(GroupError::Malformed)?;
    let timestamp_ms = timestamp_ms.ok_or(GroupError::Malformed)?;
    let content = content.ok_or(GroupError::Malformed)?;
    let signature = signature.ok_or(GroupError::Malformed)?;

    let signing_content =
        message_signing_content(&envelope.group_id, envelope.epoch, &message_id, timestamp_ms, &content);
    let verifying = VerifyingKey::from_bytes(&sender_signing_key).map_err(|_| GroupError::BadSenderSignature)?;
    let signature = Signature::from_slice(&signature).map_err(|_| GroupError::BadSenderSignature)?;
    verifying.verify(&signing_content, &signature).map_err(|_| GroupError::BadSenderSignature)?;

    Ok(GroupPlaintext { message_id, sender_signing_key, sender_nickname, timestamp_ms, content })
}

#[cfg(test)]
mod tests;
