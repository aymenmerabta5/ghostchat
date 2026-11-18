//! Group chat in the mesh worker.
//!
//! Two directions live here:
//!
//! * the commands the user types (`/group create|invite|remove|leave|send|
//!   list|info`), which build creator-signed state and broadcast sealed
//!   messages;
//! * the receive path, which applies invites and key updates that arrived over
//!   authenticated Noise sessions and decrypts `0x25` broadcasts with the
//!   epoch key kept in [`crate::groups`].
//!
//! State changes are delivered 1:1 inside Noise, exactly like the reference, so
//! a non-member can never learn a group's name, roster, or key. Messages are
//! fire-and-flood broadcasts: no per-member acknowledgments in v1, which is why
//! the local echo is shown as sent as soon as the packet leaves.

use crate::group_media::Insert;
use crate::mesh_worker::{send, UiEvent, Worker};
use crate::worker_commands::resolve_peer;
use ed25519_dalek::Signer;
use ghostchat_core::groups::{peer_id_for_fingerprint, OpenOutcome, StateOutcome};
use ghostchat_core::router::IncomingGroup;
use ghostchat_core::{ChatLine, MeshRouter};
use ghostchat_protocol::group::{
    GroupAttachment, GroupId, GroupMember, GroupState, MAX_ATTACHMENT_CHUNKS, MAX_ATTACHMENT_CHUNK_BYTES,
    MAX_ATTACHMENT_MIME_BYTES, MAX_ATTACHMENT_NAME_BYTES, MAX_MEMBERS,
};
use ghostchat_protocol::{FilePacket, MediaKind, PeerId};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Instant;

/// A creator-signed state waiting for a peer's Noise session to come up.
pub(crate) struct PendingGroupState {
    pub(crate) peer: PeerId,
    /// A fresh invite rather than a key update or a removal notice.
    pub(crate) invite: bool,
    pub(crate) payload: Vec<u8>,
}

/// Signer over the identity's Ed25519 key, the key the roster pins to us.
fn signer(router: &MeshRouter) -> impl Fn(&[u8]) -> Option<[u8; 64]> + '_ {
    move |message| Some(router.identity.signing_key().sign(message).to_bytes())
}

impl Worker {
    // MARK: - Commands

    pub(crate) fn group_create(&mut self, name: &str) {
        let fingerprint = self.router.local_fingerprint_bytes();
        // The roster pins the *public* signing key; the signature comes from
        // the matching private key inside `signer`.
        let signing = self.router.identity.signing_public();
        let nickname = self.router.identity.nickname.clone();
        let group = match ghostchat_core::Group::create(name, fingerprint, signing, &nickname, signer(&self.router)) {
            Ok(group) => group,
            Err(err) => return self.emit(UiEvent::Error(err.to_string())),
        };
        let id = group.id().hex();
        let name = group.name().to_string();
        self.groups.book_mut().insert(group);
        self.groups.save();
        self.current_group = Some(id.clone());
        self.emit(UiEvent::GroupOpened { id: id.clone(), name: name.clone() });
        self.emit(UiEvent::GroupNotice {
            group: Some(id),
            text: format!("* created group \u{201c}{name}\u{201d}; /group invite <nick> adds someone"),
        });
        self.push_groups();
    }

    pub(crate) fn group_focus(&mut self, id: &str) {
        let Some(group_id) = GroupId::from_hex(id) else { return };
        let Some(group) = self.groups.book().get(&group_id) else { return };
        let name = group.name().to_string();
        self.current_group = Some(group_id.hex());
        self.emit(UiEvent::GroupOpened { id: group_id.hex(), name });
    }

    pub(crate) fn group_invite(&mut self, token: &str) {
        let Some(group_id) = self.current_group_id() else {
            return self.emit(UiEvent::Error("open a group first: /group list, then click it".into()));
        };
        let Some(group) = self.groups.book().get(&group_id) else {
            return self.emit(UiEvent::Error("that group is no longer known".into()));
        };
        if !group.is_creator() {
            return self.emit(UiEvent::Error("only the creator can invite to this group".into()));
        }
        if group.members().len() >= MAX_MEMBERS {
            return self.emit(UiEvent::Error(format!("a group holds at most {MAX_MEMBERS} members")));
        }
        let Some(peer) = resolve_peer(&self.router, token) else {
            return self.emit(UiEvent::Error(format!("{token} is not on the mesh")));
        };
        if !self.router.peers.is_reachable(&peer) {
            return self.emit(UiEvent::Error(format!("{token} is not connected right now")));
        }
        let Some(fingerprint) = authenticated_fingerprint(&self.router, &peer) else {
            return self
                .emit(UiEvent::Error(format!("{token}'s identity is not verified yet; open a DM with them first")));
        };
        let Some(member) = member_for(&self.router, &peer, fingerprint) else {
            return self.emit(UiEvent::Error(format!("{token}'s signing key is unknown; wait for their announce")));
        };
        let nickname = member.nickname.clone();
        let group_name = group.name().to_string();

        let members = self.groups.book().get(&group_id).map(|g| g.members().to_vec()).unwrap_or_default();
        let state = {
            let Some(group) = self.groups.book_mut().get_mut(&group_id) else { return };
            match group.add_member(member, signer(&self.router)) {
                Ok(state) => state,
                Err(err) => return self.emit(UiEvent::Error(err.to_string())),
            }
        };
        self.groups.save();
        let Ok(payload) = state.encode() else {
            return self.emit(UiEvent::Error("could not encode the group state".into()));
        };

        self.deliver_group_state(&peer, true, payload.clone());
        for old in &members {
            if old.fingerprint == fingerprint || old.fingerprint == self.router.local_fingerprint_bytes() {
                continue;
            }
            if let Some(peer) = peer_id_for_fingerprint(&old.fingerprint) {
                self.deliver_group_state(&peer, false, payload.clone());
            }
        }

        self.emit(UiEvent::GroupNotice {
            group: Some(group_id.hex()),
            text: format!("* invited {nickname} to \u{201c}{group_name}\u{201d}"),
        });
        self.push_groups();
    }

    pub(crate) fn group_remove(&mut self, token: &str) {
        let Some(group_id) = self.current_group_id() else {
            return self.emit(UiEvent::Error("open a group first: /group list, then click it".into()));
        };
        let Some(group) = self.groups.book().get(&group_id) else {
            return self.emit(UiEvent::Error("that group is no longer known".into()));
        };
        if !group.is_creator() {
            return self.emit(UiEvent::Error("only the creator can remove members".into()));
        }
        let token = token.trim_start_matches('@');
        let Some(member) = group.members().iter().find(|m| m.nickname.eq_ignore_ascii_case(token)).cloned() else {
            return self.emit(UiEvent::Error(format!("{token} is not in this group")));
        };
        let nickname = member.nickname.clone();
        let removal = {
            let Some(group) = self.groups.book_mut().get_mut(&group_id) else { return };
            match group.remove_member(&member.fingerprint, signer(&self.router)) {
                Ok(removal) => removal,
                Err(err) => return self.emit(UiEvent::Error(err.to_string())),
            }
        };
        self.groups.save();
        let Ok(state_payload) = removal.state.encode() else {
            return self.emit(UiEvent::Error("could not encode the group state".into()));
        };
        let remaining = removal.state.members.clone();
        // The rotated state goes to everyone still in the group, including us
        // (skipped) so every remaining member holds the new epoch key.
        for peer_member in &remaining {
            if peer_member.fingerprint == self.router.local_fingerprint_bytes() {
                continue;
            }
            let Some(peer) = peer_id_for_fingerprint(&peer_member.fingerprint) else { continue };
            self.deliver_group_state(&peer, false, state_payload.clone());
        }
        // The removee gets the same roster under an all-zero key; their client
        // sees itself missing and drops the group instead of going dark.
        if let Some(peer) = peer_id_for_fingerprint(&member.fingerprint) {
            if let Ok(notice) = removal.notice.encode() {
                self.deliver_group_state(&peer, false, notice);
            }
        }

        self.emit(UiEvent::GroupNotice { group: Some(group_id.hex()), text: format!("* removed {nickname}") });
        self.push_groups();
    }

    pub(crate) fn group_leave(&mut self) {
        let Some(group_id) = self.current_group_id() else {
            return self.emit(UiEvent::Error("open a group first: /group list, then click it".into()));
        };
        let Some(group) = self.groups.book_mut().remove(&group_id) else { return };
        let name = group.name().to_string();
        self.current_group = None;
        self.groups.save();
        self.emit(UiEvent::GroupRemoved { group: group_id.hex(), name: name.clone(), local: true });
        self.emit(UiEvent::GroupNotice { group: None, text: format!("* left group \u{201c}{name}\u{201d}") });
        self.push_groups();
    }

    pub(crate) fn group_send(&mut self, content: &str) {
        let Some(group_id) = self.current_group_id() else {
            return self.emit(UiEvent::Error("open a group first: /group list, then click it".into()));
        };
        let Some(group) = self.groups.book().get(&group_id) else {
            return self.emit(UiEvent::Error("that group is no longer known".into()));
        };
        let nickname = self.router.identity.nickname.clone();
        let message_id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let timestamp_ms = ghostchat_protocol::packet::now_millis();
        // Roster entries hold the public signing key; `seal` finds us by it and
        // writes it into the inner payload, while `signer` holds the private
        // half that produces the signature.
        let signing = self.router.identity.signing_public();
        let sealed = match group.seal(content, &message_id, &nickname, &signing, timestamp_ms, signer(&self.router)) {
            Ok(payload) => payload,
            Err(err) => return self.emit(UiEvent::Error(err.to_string())),
        };
        let packet = self.router.build_group_message(sealed);
        self.router.remember_public(&packet);
        self.out.send_reported(&packet);

        let line = ChatLine {
            id: message_id,
            from: nickname,
            peer_id: None,
            content: content.to_string(),
            timestamp_ms,
            is_self: true,
            is_private: false,
        };
        self.emit(UiEvent::GroupLine { group: group_id.hex(), line });
    }

    /// Broadcasts a local image, voice note, or file to a named group as a
    /// sequence of signed chunks. Every chunk is an ordinary group message
    /// whose visible text is the caption, so the reference app shows a line
    /// per chunk instead of a file and everything else still verifies.
    pub(crate) fn group_send_file(&mut self, group: &str, path: &str) {
        let Some(group_id) = GroupId::from_hex(group) else {
            return self.emit(UiEvent::Error("that group id is not valid".into()));
        };
        let path = PathBuf::from(path.trim().trim_matches('"'));
        let file = match crate::media::load_outgoing(&path, None) {
            Ok(file) => file,
            Err(err) => return self.emit(UiEvent::Error(format!("send file: {err:#}"))),
        };
        let Some((kind, _)) = file.validate() else {
            return self.emit(UiEvent::Error("that file type cannot be sent".into()));
        };
        let mime = file.mime.clone().unwrap_or_default();
        if mime.len() > MAX_ATTACHMENT_MIME_BYTES {
            return self.emit(UiEvent::Error("the file type name is too long".into()));
        }
        let total_bytes = file.content.len();
        let count = total_bytes.div_ceil(MAX_ATTACHMENT_CHUNK_BYTES);
        if count == 0 || count > MAX_ATTACHMENT_CHUNKS as usize {
            return self.emit(UiEvent::Error(format!(
                "that file needs {count} chunks; a group file may use at most {MAX_ATTACHMENT_CHUNKS}"
            )));
        }
        let digest: [u8; 8] = Sha256::digest(&file.content)[..8].try_into().expect("SHA-256 has 32 bytes");
        let attachment_id: [u8; 8] = rand::random();
        let name = attachment_name(file.name.as_deref(), kind);
        let caption = crate::media::caption(kind, &path, total_bytes);
        let timestamp_ms = ghostchat_protocol::packet::now_millis();
        let nickname = self.router.identity.nickname.clone();
        let signing = self.router.identity.signing_public();
        let line_id = format!("group-file-{}-{timestamp_ms}", ghostchat_protocol::hexutil::encode(&attachment_id));

        let mut sealed = Vec::with_capacity(count);
        {
            let Some(group) = self.groups.book().get(&group_id) else {
                return self.emit(UiEvent::Error("that group is no longer known".into()));
            };
            let sign = signer(&self.router);
            for (index, data) in file.content.chunks(MAX_ATTACHMENT_CHUNK_BYTES).enumerate() {
                let attachment = GroupAttachment {
                    kind,
                    attachment_id,
                    index: index as u16,
                    count: count as u16,
                    total_bytes: total_bytes as u32,
                    digest,
                    name: name.clone(),
                    mime: mime.clone(),
                    data: data.to_vec(),
                    signature: [0u8; 64],
                };
                let message_id = uuid::Uuid::new_v4().to_string().to_uppercase();
                match group.seal_attachment(
                    &caption,
                    &message_id,
                    &nickname,
                    &signing,
                    timestamp_ms,
                    &attachment,
                    &sign,
                ) {
                    Ok(payload) => sealed.push(payload),
                    Err(err) => return self.emit(UiEvent::Error(err.to_string())),
                }
            }
        }

        let chunks = sealed.len();
        for (index, payload) in sealed.into_iter().enumerate() {
            let packet = self.router.build_group_message(payload);
            self.router.remember_public(&packet);
            let base = (index * 100 / chunks) as u8;
            let end = ((index + 1) * 100 / chunks) as u8;
            self.out.send_file_part(&packet, &line_id, base, end - base);
        }
        tracing::info!(group = %group_id.hex(), bytes = total_bytes, chunks, "group file: broadcasting");

        let line = ChatLine {
            id: line_id,
            from: nickname,
            peer_id: None,
            content: caption,
            timestamp_ms,
            is_self: true,
            is_private: false,
        };
        self.emit(UiEvent::GroupFile { group: group_id.hex(), line, path, kind });
    }

    pub(crate) fn group_list(&mut self) {
        let summaries = self.groups.summaries(|id| self.router.peers.is_reachable(id));
        let text = if self.groups.is_empty() {
            "* no groups yet; /group create <name> starts one".to_string()
        } else {
            let mut lines = vec![format!("* groups ({}):", self.groups.len())];
            for group in &summaries {
                let role = if group.is_creator { " (creator)" } else { "" };
                lines.push(format!(
                    "  #{} [{}]{role} - {}/{} - {}",
                    group.name,
                    &group.id[..8],
                    group.members.len(),
                    MAX_MEMBERS,
                    group.display_members()
                ));
            }
            lines.join("\n")
        };
        self.emit(UiEvent::GroupNotice { group: None, text });
    }

    pub(crate) fn group_info(&mut self) {
        let Some(group_id) = self.current_group_id() else {
            return self.emit(UiEvent::Error("open a group first: /group list, then click it".into()));
        };
        let Some(summary) =
            self.groups.summaries(|id| self.router.peers.is_reachable(id)).into_iter().find(|g| g.id == group_id.hex())
        else {
            return self.emit(UiEvent::Error("that group is no longer known".into()));
        };
        let mut lines = vec![format!(
            "* #{} - epoch {} - {}/{} members{}",
            summary.name,
            summary.epoch,
            summary.members.len(),
            MAX_MEMBERS,
            if summary.is_creator { " - you are the creator" } else { "" }
        )];
        for member in &summary.members {
            let tags = [
                member.is_me.then_some("you"),
                member.is_creator.then_some("creator"),
                member.online.then_some("online"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
            lines.push(format!(
                "  {} ({}){}",
                member.nickname,
                &member.fingerprint[..12],
                if tags.is_empty() { String::new() } else { format!(" [{tags}]") }
            ));
        }
        lines.push("* /group invite <nick> - /group remove <nick> - /group leave".into());
        self.emit(UiEvent::GroupNotice { group: Some(group_id.hex()), text: lines.join("\n") });
    }

    // MARK: - Incoming state

    /// Applies an invite or key update that arrived over a Noise session. The
    /// sender's fingerprint comes from the session, never from the payload.
    pub(crate) fn on_group_state(&mut self, from: PeerId, payload: &[u8], invite: bool) {
        let Some(state) = GroupState::decode(payload) else {
            tracing::warn!(peer = %from.hex, "groups: undecodable state");
            return;
        };
        let group_id = state.group_id.hex();
        let Some(from_fingerprint) = session_fingerprint(&self.router, &from) else {
            tracing::warn!(peer = %from.hex, "groups: state from a peer with no secured session");
            return;
        };
        let me = self.router.local_fingerprint_bytes();
        match self.groups.book_mut().apply_state(state, from_fingerprint, me) {
            Ok(StateOutcome::Joined { name, creator_nickname }) => {
                self.groups.save();
                tracing::info!(group = %group_id, %name, inviter = %creator_nickname, "groups: joined");
                // Land in the new group, so the invite is usable immediately:
                // the sidebar entry alone leaves `/group send` pointed nowhere.
                self.current_group = Some(group_id.clone());
                self.emit(UiEvent::GroupOpened { id: group_id.clone(), name: name.clone() });
                self.emit(UiEvent::GroupNotice {
                    group: Some(group_id.clone()),
                    text: format!(
                        "* {creator_nickname} added you to \u{201c}{name}\u{201d}; everyone here can read what you send"
                    ),
                });
                self.push_groups();
            }
            Ok(StateOutcome::Updated { name, from_epoch, to_epoch }) => {
                self.groups.save();
                tracing::info!(group = %group_id, from_epoch, to_epoch, "groups: key rotated");
                if !invite {
                    self.emit(UiEvent::GroupNotice {
                        group: Some(group_id.clone()),
                        text: format!("* \u{201c}{name}\u{201d} updated to epoch {to_epoch}"),
                    });
                }
                self.push_groups();
            }
            Ok(StateOutcome::Unchanged) => {}
            Ok(StateOutcome::Removed { name }) => {
                self.groups.save();
                tracing::info!(group = %group_id, %name, "groups: removed");
                if self.current_group.as_deref() == Some(group_id.as_str()) {
                    self.current_group = None;
                }
                self.emit(UiEvent::GroupRemoved { group: group_id, name, local: false });
                self.push_groups();
            }
            Err(err) => tracing::debug!(peer = %from.hex, %err, "groups: state rejected"),
        }
    }

    // MARK: - Incoming broadcasts

    /// Decrypts every `0x25` envelope the router handed over. Unknown groups,
    /// wrong epochs, and non-roster signatures drop silently, like the
    /// reference: a relay learns that a group exists and nothing else.
    pub(crate) fn on_group_broadcasts(&mut self, broadcasts: Vec<IncomingGroup>) {
        let now_ms = ghostchat_protocol::packet::now_millis();
        for broadcast in broadcasts {
            let group = broadcast.envelope.group_id.hex();
            match self.groups.book_mut().open(&broadcast.envelope, now_ms) {
                Ok(OpenOutcome::Message(mut message)) => {
                    if self.blocked.contains(&message.sender.fingerprint_hex()) {
                        tracing::debug!(group = %group, "groups: message from a blocked member dropped");
                        continue;
                    }
                    if let Some(chunk) = message.attachment.take() {
                        self.on_group_attachment(group, &message.sender, message.timestamp_ms, *chunk);
                        continue;
                    }
                    let line = ChatLine {
                        id: message.message_id,
                        from: message.sender.nickname.clone(),
                        peer_id: peer_id_for_fingerprint(&message.sender.fingerprint),
                        content: message.content,
                        timestamp_ms: message.timestamp_ms,
                        is_self: false,
                        is_private: false,
                    };
                    self.emit(UiEvent::GroupLine { group, line });
                }
                Ok(OpenOutcome::OwnEcho | OpenOutcome::Duplicate) => {}
                Err(err) => tracing::debug!(group = %group, %err, "groups: broadcast dropped"),
            }
        }
    }

    /// Feeds one verified chunk to the assembler. Only a completed file (or a
    /// contradiction that throws one away) produces a line; a file in progress
    /// stays invisible.
    fn on_group_attachment(&mut self, group: String, sender: &GroupMember, timestamp_ms: u64, chunk: GroupAttachment) {
        let nickname = sender.nickname.clone();
        match self.group_media.insert(&group, sender.fingerprint, &nickname, chunk, timestamp_ms, Instant::now()) {
            Insert::Pending => {}
            Insert::Rejected => self.emit(UiEvent::GroupNotice {
                group: Some(group),
                text: format!("* an attachment from {nickname} was dropped: its parts did not describe the same file"),
            }),
            Insert::Complete(done) => self.deliver_group_attachment(*done),
        }
    }

    /// Validates and saves a reassembled file exactly like a mesh/DM file: the
    /// MIME allow-list and magic bytes decide the extension, never the sender's
    /// name. The conversation gets one media line.
    fn deliver_group_attachment(&mut self, done: crate::group_media::Assembled) {
        let packet = FilePacket { name: Some(done.name.clone()), mime: Some(done.mime.clone()), content: done.data };
        let Some((kind, ext)) = packet.validate() else {
            return self.emit(UiEvent::GroupNotice {
                group: Some(done.group),
                text: format!(
                    "* an attachment from {} could not be saved: unsupported or corrupt contents",
                    done.sender_nickname
                ),
            });
        };
        if kind != done.kind {
            return self.emit(UiEvent::GroupNotice {
                group: Some(done.group),
                text: format!(
                    "* an attachment from {} could not be saved: its type did not match its contents",
                    done.sender_nickname
                ),
            });
        }
        match crate::media::save_bytes(Some(&done.name), kind, ext, done.timestamp_ms, &packet.content) {
            Ok(path) => {
                let caption = crate::media::caption(kind, &path, packet.content.len());
                let line = ChatLine {
                    id: format!(
                        "group-file-{}-{}",
                        ghostchat_protocol::hexutil::encode(&done.attachment_id),
                        done.timestamp_ms
                    ),
                    from: done.sender_nickname,
                    peer_id: peer_id_for_fingerprint(&done.sender),
                    content: caption,
                    timestamp_ms: done.timestamp_ms,
                    is_self: false,
                    is_private: false,
                };
                self.emit(UiEvent::GroupFile { group: done.group, line, path, kind });
            }
            Err(err) => self.emit(UiEvent::GroupNotice {
                group: Some(done.group),
                text: format!("* an attachment from {} could not be saved: {err:#}", done.sender_nickname),
            }),
        }
    }

    /// Partial group files that aged out. Called from the worker tick, so a
    /// file missing a chunk produces exactly one line.
    pub(crate) fn prune_group_media(&mut self, now: Instant) {
        for expired in self.group_media.prune(now) {
            self.emit(UiEvent::GroupNotice {
                group: Some(expired.group),
                text: format!(
                    "* {} {} from {} did not finish arriving ({}/{} parts); it may need sending again",
                    expired.kind.label(),
                    expired.name,
                    expired.sender_nickname,
                    expired.received,
                    expired.count
                ),
            });
        }
    }

    // MARK: - State delivery

    /// Sends state now, or queues it until the peer's session is secured.
    pub(crate) fn deliver_group_state(&mut self, peer: &PeerId, invite: bool, payload: Vec<u8>) {
        match self.router.send_group_state(peer, invite, &payload) {
            Ok(packet) => self.out.send_reported(&packet),
            Err(_) => {
                if !self
                    .pending_group_states
                    .iter()
                    .any(|p| p.peer == *peer && p.invite == invite && p.payload == payload)
                {
                    self.pending_group_states.push(PendingGroupState { peer: peer.clone(), invite, payload });
                }
                // A missing session is the usual cause; start one and let
                // `HandshakeProgress(secured)` flush the queue.
                if let Ok(packet) = self.router.begin_handshake(peer.clone()) {
                    self.emit(UiEvent::Session { id: peer.hex.clone(), state: "handshaking".into() });
                    self.out.send(&packet);
                }
            }
        }
    }

    /// Retries every queued state for a peer whose session just came up.
    pub(crate) fn flush_group_states(&mut self, peer: &PeerId) {
        if self.pending_group_states.iter().all(|p| p.peer != *peer) {
            return;
        }
        let pending = std::mem::take(&mut self.pending_group_states);
        let mut leftover = Vec::new();
        for state in pending {
            if state.peer != *peer {
                leftover.push(state);
                continue;
            }
            match self.router.send_group_state(peer, state.invite, &state.payload) {
                Ok(packet) => self.out.send_reported(&packet),
                Err(err) => {
                    tracing::debug!(peer = %peer.hex, %err, "groups: state still waiting");
                    leftover.push(state);
                }
            }
        }
        self.pending_group_states = leftover;
    }

    /// Retries queued state when a peer reappears, handshaking if needed.
    pub(crate) fn retry_group_states(&mut self, peer: &PeerId) {
        if self.pending_group_states.iter().all(|p| p.peer != *peer) {
            return;
        }
        self.flush_group_states(peer);
        if self.pending_group_states.iter().any(|p| p.peer == *peer) {
            if let Ok(packet) = self.router.begin_handshake(peer.clone()) {
                self.emit(UiEvent::Session { id: peer.hex.clone(), state: "handshaking".into() });
                self.out.send(&packet);
            }
        }
    }

    pub(crate) fn push_groups(&self) {
        let summaries = self.groups.summaries(|id| self.router.peers.is_reachable(id));
        send(&self.evt_tx, UiEvent::Groups(summaries));
    }

    fn current_group_id(&self) -> Option<GroupId> {
        self.current_group.as_deref().and_then(GroupId::from_hex)
    }

    /// Panic wipe: the new identity is not a member of anything.
    pub(crate) fn clear_groups(&mut self) {
        self.groups.clear();
        self.group_media.clear();
        self.current_group = None;
        self.pending_group_states.clear();
        self.push_groups();
    }
}

/// A file name that fits the attachment descriptor: leaf only, no control
/// characters, cut on a character boundary so the 96-byte field stays valid
/// UTF-8. The receiver still treats it as a suggestion and derives the real
/// extension from the MIME type.
fn attachment_name(original: Option<&str>, kind: MediaKind) -> String {
    let leaf = original.unwrap_or_default().rsplit(['/', '\\']).next().unwrap_or_default();
    let mut name: String = leaf.chars().filter(|c| !c.is_control()).collect();
    while name.len() > MAX_ATTACHMENT_NAME_BYTES {
        name.pop();
    }
    if name.is_empty() {
        kind.label().to_string()
    } else {
        name
    }
}

/// A roster entry for `peer`: its authenticated fingerprint, pinned signing
/// key, and the nickname its announce carried.
fn member_for(router: &MeshRouter, peer: &PeerId, fingerprint: [u8; 32]) -> Option<GroupMember> {
    let announced = router.peers.get(peer)?;
    let nickname = if announced.nickname.is_empty() { peer.short() } else { announced.nickname.clone() };
    crate::groups::member_from_peer(fingerprint, &announced.signing_public_key, &nickname)
}

/// The fingerprint the peer's Noise session proves, and nothing else. Group
/// state is only ever trusted from a path that is cryptographically bound to a
/// static key, so an announced-but-unproven identity cannot sign a roster.
pub(crate) fn session_fingerprint(router: &MeshRouter, peer: &PeerId) -> Option<[u8; 32]> {
    let key = router.sessions.get(peer)?.remote_static()?;
    Some(Sha256::digest(key).into())
}

/// The peer's fingerprint, preferring the one proven by its Noise session over
/// the one it merely announced. `None` when neither is known: an unverified
/// peer must never be signed into a roster.
pub(crate) fn authenticated_fingerprint(router: &MeshRouter, peer: &PeerId) -> Option<[u8; 32]> {
    if let Some(key) = router.sessions.get(peer).and_then(|session| session.remote_static()) {
        return Some(Sha256::digest(key).into());
    }
    let announced = router.peers.get(peer)?;
    if !announced.verified || announced.noise_public_key.len() != 32 {
        return None;
    }
    let key: [u8; 32] = announced.noise_public_key.as_slice().try_into().ok()?;
    Some(Sha256::digest(key).into())
}
