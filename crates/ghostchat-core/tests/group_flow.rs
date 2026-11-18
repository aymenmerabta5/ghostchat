//! End-to-end private-group chat between simulated PCs.
//!
//! The unit tests in `src/groups/tests.rs` decide what a state or a message
//! means. This file proves the whole path instead: real X25519 identities, real
//! Ed25519 roster signatures, and real wire bytes. Creator-signed state travels
//! inside a Noise session exactly as it does over Bluetooth (`0x06` invite,
//! `0x07` key update), and messages travel as `0x25` broadcasts that a
//! non-member relay forwards without being able to read.
//!
//! Nothing here reaches into private fields: it is the same API the mesh worker
//! uses, driven from four machines in one process.

use ed25519_dalek::{Signer, SigningKey};
use ghostchat_core::groups::{peer_id_for_fingerprint, OpenOutcome, StateOutcome};
use ghostchat_core::{Group, GroupBook, GroupError, MeshEvent, MeshRouter};
use ghostchat_crypto::Identity;
use ghostchat_protocol::group::{GroupEnvelope, GroupId, GroupMember, GroupState};
use ghostchat_protocol::{MessageType, Packet, PeerId, DEFAULT_TTL};
use sha2::{Digest, Sha256};

/// A fixed clock: peers' clocks disagree in the field, and the receiver clamps.
const NOW: u64 = 1_700_000_000_000;

fn signer(key: [u8; 32]) -> impl Fn(&[u8]) -> Option<[u8; 64]> {
    move |message| Some(SigningKey::from_bytes(&key).sign(message).to_bytes())
}

/// What one receiving PC made of one broadcast.
#[derive(Debug)]
enum Got {
    Text(String),
    /// Our own message, echoed back through a relay or a sync replay.
    Echo,
    /// An id this PC already accepted.
    Dup,
    Dropped(GroupError),
}

/// One simulated PC: its mesh identity, its groups, and its roster keys.
struct Pc {
    router: MeshRouter,
    book: GroupBook,
    fingerprint: [u8; 32],
    /// The Ed25519 private seed. Roster entries carry the public key derived
    /// from it; only `signer` ever sees this.
    signing_seed: [u8; 32],
    signing_public: [u8; 32],
    nickname: String,
}

impl Pc {
    fn new(nickname: &str) -> Self {
        let router = MeshRouter::new(Identity::generate(nickname));
        let fingerprint = router.local_fingerprint_bytes();
        let signing_seed = router.identity.signing_key().to_bytes();
        let signing_public = router.identity.signing_public();
        Self {
            router,
            book: GroupBook::default(),
            fingerprint,
            signing_seed,
            signing_public,
            nickname: nickname.into(),
        }
    }

    fn peer_id(&self) -> PeerId {
        self.router.local_peer_id()
    }

    /// What this PC announced about itself, as the creator would roster it.
    fn member_entry(&self) -> GroupMember {
        GroupMember::new(self.fingerprint, self.signing_public, self.nickname.clone())
    }

    fn create(&mut self, name: &str) -> GroupId {
        let group =
            Group::create(name, self.fingerprint, self.signing_public, &self.nickname, signer(self.signing_seed))
                .expect("a valid group");
        let id = *group.id();
        self.book.insert(group);
        id
    }

    fn group(&self, id: &GroupId) -> &Group {
        self.book.get(id).expect("this PC is in the group")
    }

    /// Signs a roster change and returns the payload to distribute.
    fn add(&mut self, id: &GroupId, member: GroupMember) -> Vec<u8> {
        let state = self
            .book
            .get_mut(id)
            .expect("this PC is in the group")
            .add_member(member, signer(self.signing_seed))
            .expect("the creator may add");
        state.encode().expect("state encodes")
    }

    /// Removes a member; returns the rotated state for the rest of the group and
    /// the throwaway-key notice for the person removed.
    fn remove(&mut self, id: &GroupId, fingerprint: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let removal = self
            .book
            .get_mut(id)
            .expect("this PC is in the group")
            .remove_member(&fingerprint, signer(self.signing_seed))
            .expect("the creator may remove");
        (removal.state.encode().expect("state encodes"), removal.notice.encode().expect("notice encodes"))
    }

    /// Seals one message under the current epoch, as the worker does.
    fn seal(&self, id: &GroupId, content: &str, message_id: &str, timestamp_ms: u64) -> Vec<u8> {
        self.group(id)
            .seal(content, message_id, &self.nickname, &self.signing_public, timestamp_ms, signer(self.signing_seed))
            .expect("a member may seal")
    }

    /// Wraps a sealed envelope in the unsigned `0x25` broadcast packet.
    fn wrap(&self, sealed: Vec<u8>) -> Packet {
        self.router.build_group_message(sealed)
    }

    /// Feeds one broadcast through the router and decrypts what it carried.
    fn receive(&mut self, packet: Packet, now_ms: u64) -> Vec<Got> {
        let ingest = self.router.ingest_packet(packet);
        ingest
            .groups
            .iter()
            .map(|arrived| match self.book.open(&arrived.envelope, now_ms) {
                Ok(OpenOutcome::Message(message)) => {
                    Got::Text(format!("{}: {}", message.sender.nickname, message.content))
                }
                Ok(OpenOutcome::OwnEcho) => Got::Echo,
                Ok(OpenOutcome::Duplicate) => Got::Dup,
                Err(err) => Got::Dropped(err),
            })
            .collect()
    }

    /// A node drops its own broadcast at the router (it carries our sender id)
    /// and the UI shows the line locally; the group layer still recognises the
    /// envelope as ours if a sync replay ever hands it back.
    fn own_broadcast_is_not_reflected(&mut self, packet: Packet, sealed: &[u8], now_ms: u64) {
        assert!(self.receive(packet, now_ms).is_empty(), "{} drops its own broadcast", self.nickname);
        let envelope = GroupEnvelope::decode(sealed).expect("envelope");
        match self.book.open(&envelope, now_ms) {
            Ok(OpenOutcome::OwnEcho) => {}
            other => panic!("{} should recognise its own message, got {other:?}", self.nickname),
        }
    }
}

/// Swaps announces so each side has the other's roster keys.
fn announce(a: &mut Pc, b: &mut Pc) {
    let from_a = a.router.build_announce().expect("announce");
    let from_b = b.router.build_announce().expect("announce");
    a.router.ingest_packet(from_b);
    b.router.ingest_packet(from_a);
}

/// Runs the Noise handshake to completion between two PCs.
fn secure(a: &mut Pc, b: &mut Pc) {
    let mut wire = vec![a.router.begin_handshake(b.peer_id()).expect("a handshake starts")];
    let mut towards_b = true;
    for _ in 0..8 {
        let mut next = Vec::new();
        for packet in wire.drain(..) {
            let ingest = if towards_b { b.router.ingest_packet(packet) } else { a.router.ingest_packet(packet) };
            next.extend(ingest.outbox);
        }
        if next.is_empty() {
            break;
        }
        wire = next;
        towards_b = !towards_b;
    }
    assert!(a.router.sessions.is_ready(&b.peer_id()), "{} finished the handshake", a.nickname);
    assert!(b.router.sessions.is_ready(&a.peer_id()), "{} finished the handshake", b.nickname);
}

/// The fingerprint the session proves, which is the one the receiver trusts.
fn session_fingerprint(router: &MeshRouter, peer: &PeerId) -> Option<[u8; 32]> {
    let static_key = router.sessions.get(peer)?.remote_static()?;
    Some(Sha256::digest(static_key).into())
}

/// Sends creator-signed state and applies it on the receiver. `invite` picks
/// the `0x06` payload type for a fresh add and `0x07` for every rotation.
fn deliver(from: &mut Pc, to: &mut Pc, invite: bool, payload: Vec<u8>) -> StateOutcome {
    let packet = from.router.send_group_state(&to.peer_id(), invite, &payload).expect("state needs a secured session");
    let ingest = to.router.ingest_packet(packet);
    let (sender, body) = ingest
        .events
        .iter()
        .find_map(|event| match (event, invite) {
            (MeshEvent::GroupInvite(peer, body), true) => Some((peer.clone(), body.clone())),
            (MeshEvent::GroupKeyUpdate(peer, body), false) => Some((peer.clone(), body.clone())),
            _ => None,
        })
        .expect("the state arrived inside the session");
    assert_eq!(body, payload, "the payload crosses the session unchanged");
    let proven = session_fingerprint(&to.router, &sender).expect("the session proves the sender");
    assert_eq!(proven, from.fingerprint, "the session fingerprint is the sender's identity");
    let state = GroupState::decode(&body).expect("the payload decodes as state");
    to.book.apply_state(state, proven, to.fingerprint).expect("the receiver accepts the state")
}

#[test]
fn three_pcs_create_invite_and_talk_in_one_group() {
    let mut alice = Pc::new("alice");
    let mut bob = Pc::new("bob");
    let mut carol = Pc::new("carol");
    announce(&mut alice, &mut bob);
    announce(&mut alice, &mut carol);
    secure(&mut alice, &mut bob);
    secure(&mut alice, &mut carol);

    // Alice starts the group; she is its only member, at epoch 1.
    let id = alice.create("Ward Round");
    assert_eq!(alice.group(&id).epoch(), 1);
    assert!(alice.group(&id).is_creator());
    assert_eq!(alice.group(&id).members().len(), 1);

    // The roster is addressed by fingerprint, which derives the mesh peer id —
    // no lookup table, exactly as iOS does it.
    assert_eq!(peer_id_for_fingerprint(&bob.fingerprint), Some(bob.peer_id()));
    assert_eq!(peer_id_for_fingerprint(&carol.fingerprint), Some(carol.peer_id()));

    // Invite Bob: a fresh add is `0x06` and bumps the epoch to 2.
    let payload = alice.add(&id, bob.member_entry());
    let joined = deliver(&mut alice, &mut bob, true, payload);
    assert_eq!(joined, StateOutcome::Joined { name: "Ward Round".into(), creator_nickname: "alice".into() });
    assert_eq!(bob.group(&id).epoch(), 2);
    assert_eq!(bob.group(&id).members().len(), 2);
    assert!(!bob.group(&id).is_creator());

    // Invite Carol: a `0x06` for her, and a `0x07` key update for Bob, who
    // must not keep sealing under the retired epoch key.
    let payload = alice.add(&id, carol.member_entry());
    let joined = deliver(&mut alice, &mut carol, true, payload.clone());
    assert!(matches!(joined, StateOutcome::Joined { .. }));
    let updated = deliver(&mut alice, &mut bob, false, payload);
    assert_eq!(updated, StateOutcome::Updated { name: "Ward Round".into(), from_epoch: 2, to_epoch: 3 });
    for pc in [&bob, &carol] {
        assert_eq!(pc.group(&id).epoch(), 3, "{} is on the new key", pc.nickname);
        assert_eq!(pc.group(&id).state.key, alice.group(&id).state.key, "everyone shares one epoch key");
    }

    // Bob speaks; Alice and Carol read it, Bob's own copy comes back as an echo.
    let sealed = bob.seal(&id, "meet at 4", "msg-bob-1", NOW);
    let packet = bob.wrap(sealed.clone());
    assert_eq!(packet.type_id, MessageType::GroupMessage as u8);
    assert!(packet.recipient_id.is_none(), "a group broadcast names no recipient");
    assert!(packet.signature.is_none(), "the sender signs inside the ciphertext");
    assert_eq!(packet.ttl, DEFAULT_TTL);

    for pc in [&mut alice, &mut carol] {
        match pc.receive(packet.clone(), NOW).as_slice() {
            [Got::Text(text)] => assert_eq!(text, "bob: meet at 4"),
            other => panic!("{} should read Bob's message, got {other:?}", pc.nickname),
        }
    }
    // Bob never re-ingests his own packet: the router drops anything carrying
    // his sender id, and the UI shows his line locally when he sends.
    bob.own_broadcast_is_not_reflected(packet, &sealed, NOW);

    // The same inner message id is accepted once, even inside a fresh packet.
    let replay = bob.wrap(sealed);
    match carol.receive(replay, NOW).as_slice() {
        [Got::Dup] => {}
        other => panic!("a replay is not a second message, got {other:?}"),
    }

    // Carol replies; both other PCs read her, so traffic flows every direction.
    let packet = carol.wrap(carol.seal(&id, "on my way", "msg-carol-1", NOW + 1));
    for pc in [&mut alice, &mut bob] {
        match pc.receive(packet.clone(), NOW + 1).as_slice() {
            [Got::Text(text)] => assert_eq!(text, "carol: on my way"),
            other => panic!("{} should read Carol's message, got {other:?}", pc.nickname),
        }
    }

    // Alice's own message reaches the others and never lands twice for her.
    let sealed = alice.seal(&id, "round starts", "msg-alice-1", NOW + 2);
    let packet = alice.wrap(sealed.clone());
    for pc in [&mut bob, &mut carol] {
        match pc.receive(packet.clone(), NOW + 2).as_slice() {
            [Got::Text(text)] => assert_eq!(text, "alice: round starts"),
            other => panic!("{} should read Alice's message, got {other:?}", pc.nickname),
        }
    }
    alice.own_broadcast_is_not_reflected(packet, &sealed, NOW + 2);
}

#[test]
fn a_removal_over_the_wire_rotates_the_key_for_everyone_else() {
    let mut alice = Pc::new("alice");
    let mut bob = Pc::new("bob");
    let mut carol = Pc::new("carol");
    announce(&mut alice, &mut bob);
    announce(&mut alice, &mut carol);
    secure(&mut alice, &mut bob);
    secure(&mut alice, &mut carol);

    let id = alice.create("Triage");
    let payload = alice.add(&id, bob.member_entry());
    deliver(&mut alice, &mut bob, true, payload);
    let payload = alice.add(&id, carol.member_entry());
    deliver(&mut alice, &mut carol, true, payload.clone());
    deliver(&mut alice, &mut bob, false, payload);
    assert_eq!(alice.group(&id).epoch(), 3);

    // What Bob keeps on disk before the removal, for the restart case below.
    let bob_saved = bob.group(&id).state.encode().expect("state encodes");
    let bob_seed = bob.signing_seed;

    let (rotated, notice) = alice.remove(&id, bob.fingerprint);
    assert_eq!(alice.group(&id).epoch(), 4);
    assert_eq!(alice.group(&id).members().len(), 2, "Bob is off the roster");

    // Carol gets the new epoch key; Bob gets the same roster under a throwaway
    // key, which tells his client it was removed instead of leaving it dark.
    let updated = deliver(&mut alice, &mut carol, false, rotated);
    assert_eq!(updated, StateOutcome::Updated { name: "Triage".into(), from_epoch: 3, to_epoch: 4 });
    let removed = deliver(&mut alice, &mut bob, false, notice.clone());
    assert_eq!(removed, StateOutcome::Removed { name: "Triage".into() });
    assert!(bob.book.get(&id).is_none(), "the removed PC drops the group entirely");
    assert_eq!(
        GroupState::decode(&notice).expect("the notice is a state").key,
        [0u8; 32],
        "the notice never carries the new key"
    );

    // The next message is for the remaining members only.
    let sealed = alice.seal(&id, "rotated key", "msg-alice-2", NOW + 10);
    match carol.receive(alice.wrap(sealed.clone()), NOW + 10).as_slice() {
        [Got::Text(text)] => assert_eq!(text, "alice: rotated key"),
        other => panic!("Carol reads the new epoch, got {other:?}"),
    }

    // Bob restarts from his saved state: same group, same old epoch. The
    // router still hands the envelope over, and his book refuses it by epoch.
    let (mut bob_stale, skipped) = GroupBook::from_encoded_states([bob_saved.clone()], bob.fingerprint);
    assert_eq!(skipped, 0);
    let ingest = bob.router.ingest_packet(alice.wrap(sealed.clone()));
    let got: Vec<Got> = ingest
        .groups
        .iter()
        .map(|arrived| match bob_stale.open(&arrived.envelope, NOW + 10) {
            Ok(_) => Got::Echo,
            Err(err) => Got::Dropped(err),
        })
        .collect();
    match got.as_slice() {
        [Got::Dropped(GroupError::EpochMismatch { found: 4, current: 3 })] => {}
        other => panic!("the removed PC is a full epoch behind, got {other:?}"),
    }

    // Even if he relabels his old key as the new epoch, the key is different:
    // rotation changed the secret, not just the counter.
    let stale = bob_stale.get(&id).expect("his saved group");
    let forged = ghostchat_protocol::group::seal_message(
        &stale.state.group_id,
        4,
        &stale.state.key,
        "msg-bob-forged",
        &bob.signing_public,
        "bob",
        NOW + 10,
        "let me in",
        signer(bob_seed),
    )
    .expect("sealing works");
    let envelope = GroupEnvelope::decode(&forged).expect("envelope");
    match carol.book.open(&envelope, NOW + 10) {
        Err(GroupError::Wire(ghostchat_protocol::group::GroupError::DecryptionFailed)) => {}
        Err(other) => panic!("the old key cannot open epoch 4, got {other:?}"),
        Ok(_) => panic!("the removed PC must not read the new epoch"),
    }

    // Bob cannot re-add himself: only the creator signs accepted state, and a
    // self-signed roster that names Bob as creator is not a state we keep.
    let mut forged = carol.group(&id).state.clone();
    forged.members.push(bob.member_entry());
    forged.creator = bob.fingerprint;
    let roster = ghostchat_protocol::group::encode_roster(&forged.members).expect("roster");
    let content = GroupState::signing_content(&forged.group_id, forged.epoch, &forged.key, &roster, &forged.name);
    forged.signature = signer(bob_seed)(&content).expect("signed");
    match carol.book.apply_state(forged, bob.fingerprint, carol.fingerprint) {
        Err(GroupError::CreatorChanged) => {}
        other => panic!("a creator swap is refused, got {other:?}"),
    }

    // A stale invite for a group we already hold cannot roll the roster back.
    let stale_state = GroupState::decode(&bob_saved).expect("state");
    match carol.book.apply_state(stale_state, alice.fingerprint, carol.fingerprint) {
        Err(GroupError::StaleEpoch { found: 3, current: 4 }) => {}
        other => panic!("an old epoch is refused, got {other:?}"),
    }
}

#[test]
fn a_non_member_relays_group_traffic_but_cannot_read_it() {
    let mut alice = Pc::new("alice");
    let mut bob = Pc::new("bob");
    let mut dave = Pc::new("dave");
    announce(&mut alice, &mut bob);
    announce(&mut alice, &mut dave);
    secure(&mut alice, &mut bob);

    let id = alice.create("Stock");
    let payload = alice.add(&id, bob.member_entry());
    deliver(&mut alice, &mut bob, true, payload);

    let sealed = alice.seal(&id, "count the fridge", "msg-alice-3", NOW);
    let ingest = dave.router.ingest_packet(alice.wrap(sealed.clone()));

    // A PC outside the group still parses the envelope and forwards it, like
    // public chat: that is what lets a group cross a mesh of strangers.
    assert_eq!(ingest.groups.len(), 1, "a relay decodes the envelope's framing");
    let relay = ingest.relay.expect("group traffic is relayed like public chat");
    assert_eq!(relay.type_id, MessageType::GroupMessage as u8);
    assert_eq!(relay.payload, sealed, "the relay carries the envelope untouched");
    assert!(relay.ttl < DEFAULT_TTL, "a hop spends one ttl");

    // But Dave holds no key for it, so he cannot read a single byte.
    match dave.book.open(&ingest.groups[0].envelope, NOW) {
        Err(GroupError::UnknownGroup) => {}
        other => panic!("a non-member has no key, got {other:?}"),
    }

    // The relayed copy is what Bob reads: two hops, still one message.
    match bob.receive(relay, NOW).as_slice() {
        [Got::Text(text)] => assert_eq!(text, "alice: count the fridge"),
        other => panic!("Bob reads the relayed copy, got {other:?}"),
    }
}

#[test]
fn state_only_travels_inside_a_secured_session_from_the_creator() {
    let mut alice = Pc::new("alice");
    let mut bob = Pc::new("bob");
    let mut carol = Pc::new("carol");
    announce(&mut alice, &mut bob);
    announce(&mut alice, &mut carol);
    announce(&mut bob, &mut carol);

    let id = alice.create("Pharmacy");
    let payload = alice.add(&id, bob.member_entry());

    // Before the handshake there is nowhere to put the state: it never travels
    // in the clear.
    assert!(
        alice.router.send_group_state(&bob.peer_id(), true, &payload).is_err(),
        "state needs an authenticated session"
    );

    secure(&mut alice, &mut bob);
    secure(&mut alice, &mut carol);
    secure(&mut bob, &mut carol);
    let joined = deliver(&mut alice, &mut bob, true, payload);
    assert!(matches!(joined, StateOutcome::Joined { .. }));

    // Bob is a member and holds Alice's signed epoch-2 state, but forwarding it
    // to Carol does not make it his: the receiver trusts the session, not the
    // payload's story about who sent it.
    let signed_by_alice = bob.group(&id).state.encode().expect("state encodes");
    let packet = bob.router.send_group_state(&carol.peer_id(), false, &signed_by_alice).expect("secured");
    let ingest = carol.router.ingest_packet(packet);
    let (sender, body) = ingest
        .events
        .iter()
        .find_map(|event| match event {
            MeshEvent::GroupKeyUpdate(peer, body) => Some((peer.clone(), body.clone())),
            _ => None,
        })
        .expect("the payload arrives");
    let proven = session_fingerprint(&carol.router, &sender).expect("session identity");
    assert_eq!(proven, bob.fingerprint);
    match carol.book.apply_state(GroupState::decode(&body).expect("state"), proven, carol.fingerprint) {
        Err(GroupError::NotFromCreator) => {}
        other => panic!("only the creator may deliver state, got {other:?}"),
    }
    assert!(carol.book.get(&id).is_none(), "Carol never joined a group she was not invited to");

    // A payload that is not a state at all is simply not a state.
    let garbage = alice.router.send_group_state(&carol.peer_id(), true, b"not a group state").expect("secured");
    let ingest = carol.router.ingest_packet(garbage);
    let body = ingest
        .events
        .iter()
        .find_map(|event| match event {
            MeshEvent::GroupInvite(_, body) => Some(body.clone()),
            _ => None,
        })
        .expect("the bytes arrive");
    assert!(GroupState::decode(&body).is_none(), "undecodable state is dropped by the receiver");
    assert!(carol.book.get(&id).is_none());
}

#[test]
fn every_pc_can_own_its_own_group() {
    let mut alice = Pc::new("alice");
    let mut bob = Pc::new("bob");
    let mut carol = Pc::new("carol");
    announce(&mut alice, &mut bob);
    announce(&mut alice, &mut carol);
    secure(&mut alice, &mut bob);
    secure(&mut alice, &mut carol);

    // Alice owns one group and Bob owns another; membership is independent.
    let ward = alice.create("Ward");
    let payload = alice.add(&ward, bob.member_entry());
    deliver(&mut alice, &mut bob, true, payload);

    let stock = bob.create("Stock");
    assert!(bob.group(&stock).is_creator());
    let payload = bob.add(&stock, alice.member_entry());
    let joined = deliver(&mut bob, &mut alice, true, payload);
    assert_eq!(joined, StateOutcome::Joined { name: "Stock".into(), creator_nickname: "bob".into() });

    assert_eq!(alice.book.len(), 2, "Alice belongs to both groups");
    assert_eq!(bob.book.len(), 2);
    assert!(alice.group(&ward).is_creator() && !alice.group(&stock).is_creator());
    assert!(bob.group(&stock).is_creator() && !bob.group(&ward).is_creator());

    // A message in Bob's group never opens as Alice's group, and Carol, who is
    // in neither of Bob's, has no key for it.
    let sealed = bob.seal(&stock, "order more gauze", "msg-bob-2", NOW);
    let envelope = GroupEnvelope::decode(&sealed).expect("envelope");
    assert!(envelope.group_id == stock, "the envelope names its group");
    assert!(alice.book.open(&envelope, NOW).is_ok());
    match carol.book.open(&envelope, NOW) {
        Err(GroupError::UnknownGroup) => {}
        other => panic!("Carol is in no group of Bob's, got {other:?}"),
    }

    // Carol can start her own group too, and invite Alice into it.
    let deliveries = carol.create("Deliveries");
    let payload = carol.add(&deliveries, alice.member_entry());
    let joined = deliver(&mut carol, &mut alice, true, payload);
    assert!(matches!(joined, StateOutcome::Joined { .. }));
    assert_eq!(alice.book.len(), 3, "Alice now belongs to three groups");
}

#[test]
fn a_restarted_pc_reopens_its_groups_and_reads_new_messages() {
    let mut alice = Pc::new("alice");
    let mut bob = Pc::new("bob");
    announce(&mut alice, &mut bob);
    secure(&mut alice, &mut bob);

    let id = alice.create("Rota");
    let payload = alice.add(&id, bob.member_entry());
    deliver(&mut alice, &mut bob, true, payload);
    let payload = alice.add(&id, carol_entry());
    deliver(&mut alice, &mut bob, false, payload);

    // Bob quits and comes back with nothing but the sealed states on disk.
    let saved = bob.book.encoded_states();
    let (mut reopened, skipped) = GroupBook::from_encoded_states(saved.clone(), bob.fingerprint);
    assert_eq!((reopened.len(), skipped), (1, 0));
    let group = reopened.get(&id).expect("the group survived the restart");
    assert_eq!(group.epoch(), 3);
    assert_eq!(group.members().len(), 3);

    // The key survived too, so new traffic still opens.
    let sealed = alice.seal(&id, "swap on friday", "msg-alice-4", NOW);
    let envelope = GroupEnvelope::decode(&sealed).expect("envelope");
    match reopened.open(&envelope, NOW) {
        Ok(OpenOutcome::Message(message)) => assert_eq!(message.content, "swap on friday"),
        other => panic!("the reopened key still opens the epoch, got {other:?}"),
    }

    // Another identity's saved file is not ours to trust.
    let (stranger, skipped) = GroupBook::from_encoded_states(saved, [0xAB; 32]);
    assert_eq!((stranger.len(), skipped), (0, 1), "a roster that does not name us is dropped");
}

/// A roster entry for a PC that never joins; it only needs plausible keys.
fn carol_entry() -> GroupMember {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    GroupMember::new([9u8; 32], key.verifying_key().to_bytes(), "carol")
}
