use super::*;
use ed25519_dalek::{Signer, SigningKey};
use ghostchat_protocol::group::random_key;

const CREATOR_FP: [u8; 32] = [0x11; 32];
const BOB_FP: [u8; 32] = [0x22; 32];
const CAROL_FP: [u8; 32] = [0x33; 32];

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_of(seed: u8) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

fn signer(seed: u8) -> impl Fn(&[u8]) -> Option<[u8; 64]> {
    move |data| Some(signing_key(seed).sign(data).to_bytes())
}

fn member(seed: u8, fingerprint: [u8; 32], nickname: &str) -> GroupMember {
    GroupMember::new(fingerprint, public_of(seed), nickname)
}

fn bob() -> GroupMember {
    member(2, BOB_FP, "bob")
}

fn carol() -> GroupMember {
    member(3, CAROL_FP, "carol")
}

fn created() -> Group {
    Group::create("testers", CREATOR_FP, public_of(1), "amy", signer(1)).expect("creates")
}

/// Creates a group owned by the creator and invites the given members,
/// returning the creator's group plus the final state to hand out.
fn group_with(members: Vec<GroupMember>) -> (Group, GroupState) {
    let mut group = created();
    let mut state = group.state.clone();
    for member in members {
        state = group.add_member(member, signer(1)).expect("invites");
    }
    (group, state)
}

/// The book of a member who accepted `state` from the creator.
fn joined(state: GroupState, my_fingerprint: [u8; 32]) -> GroupBook {
    let mut book = GroupBook::default();
    let outcome = book.apply_state(state, CREATOR_FP, my_fingerprint).expect("accepts an invite");
    assert!(matches!(outcome, StateOutcome::Joined { .. }), "unexpected outcome: {outcome:?}");
    book
}

fn envelope_of(payload: &[u8]) -> GroupEnvelope {
    GroupEnvelope::decode(payload).expect("decodes an envelope")
}

#[test]
fn create_group_starts_at_epoch_one_with_only_the_creator() {
    let group = created();
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.name(), "testers");
    assert_eq!(group.members().len(), 1);
    assert_eq!(group.members()[0].fingerprint, CREATOR_FP);
    assert_eq!(group.members()[0].signing_key, public_of(1));
    assert!(group.state.verify());
    assert!(group.is_creator());
}

#[test]
fn invite_bumps_the_epoch_rotates_the_key_and_reaches_the_invitee() {
    let mut group = created();
    let first_key = group.state.key;
    let state = group.add_member(bob(), signer(1)).expect("invites bob");

    assert_eq!(group.epoch(), 2);
    assert_eq!(state.epoch, 2);
    assert_ne!(state.key, first_key, "every roster change rotates the key");
    assert!(state.verify());

    let book = joined(state, BOB_FP);
    let bob_group = book.get(group.id()).expect("bob holds the group");
    assert_eq!(bob_group.members().len(), 2);
    assert!(!bob_group.is_creator());
}

#[test]
fn rotation_makes_old_epoch_ciphertext_unreadable() {
    let mut group = created();
    let now = 1_700_000_000_000;
    let stale = group.seal("before bob", "m1", "amy", &public_of(1), now, signer(1)).expect("seals");
    let stale = envelope_of(&stale);

    let state = group.add_member(bob(), signer(1)).expect("invites");
    let mut book = joined(state, BOB_FP);

    assert!(matches!(book.open(&stale, now), Err(GroupError::EpochMismatch { found: 1, current: 2 })));
}

#[test]
fn only_the_creator_can_change_the_roster() {
    let (group, state) = group_with(vec![bob()]);
    let id = group.state.group_id;
    let mut book = joined(state, BOB_FP);
    let bob_group = book.get_mut(&id).expect("member view");

    assert!(matches!(bob_group.add_member(carol(), signer(2)), Err(GroupError::CreatorOnly)));
    assert!(matches!(bob_group.remove_member(&CREATOR_FP, signer(2)), Err(GroupError::CreatorOnly)));
}

#[test]
fn the_creator_cannot_be_removed_and_a_duplicate_invite_is_refused() {
    let mut group = created();
    assert!(matches!(group.remove_member(&CREATOR_FP, signer(1)), Err(GroupError::CannotRemoveCreator)));
    group.add_member(bob(), signer(1)).expect("invites once");
    assert!(matches!(group.add_member(bob(), signer(1)), Err(GroupError::AlreadyMember)));
}

#[test]
fn the_roster_cap_is_sixteen_members() {
    let mut group = created();
    for i in 0..(MAX_MEMBERS - 1) {
        let fingerprint = [0x40 + i as u8; 32];
        group.add_member(GroupMember::new(fingerprint, public_of(4), "x"), signer(1)).expect("below the cap");
    }
    assert_eq!(group.members().len(), MAX_MEMBERS);
    let overflow = GroupMember::new([0xFF; 32], public_of(5), "overflow");
    assert!(matches!(group.add_member(overflow, signer(1)), Err(GroupError::Full)));
}

#[test]
fn group_names_are_trimmed_and_capped_at_forty_characters() {
    assert!(matches!(Group::create("   ", CREATOR_FP, public_of(1), "amy", signer(1)), Err(GroupError::BadName)));
    let long = "n".repeat(MAX_NAME_CHARS + 1);
    assert!(matches!(Group::create(&long, CREATOR_FP, public_of(1), "amy", signer(1)), Err(GroupError::BadName)));
    let exact = "n".repeat(MAX_NAME_CHARS);
    assert!(Group::create(&exact, CREATOR_FP, public_of(1), "amy", signer(1)).is_ok());
}

#[test]
fn an_invite_must_arrive_from_the_creator_it_names() {
    let (_, state) = group_with(vec![bob()]);
    let mut book = GroupBook::default();
    assert!(matches!(book.apply_state(state.clone(), BOB_FP, BOB_FP), Err(GroupError::NotFromCreator)));
    assert!(book.is_empty());
}

#[test]
fn a_state_with_a_broken_creator_signature_is_refused() {
    let (_, mut state) = group_with(vec![bob()]);
    state.name = "renamed by a relay".into();
    let mut book = GroupBook::default();
    assert!(matches!(
        book.apply_state(state, CREATOR_FP, BOB_FP),
        Err(GroupError::Wire(WireError::BadCreatorSignature))
    ));
}

#[test]
fn a_stale_state_cannot_undo_a_later_roster_change() {
    let mut group = created();
    let epoch_two = group.add_member(bob(), signer(1)).expect("invites bob");
    let mut book = joined(epoch_two.clone(), BOB_FP);
    let epoch_three = group.add_member(carol(), signer(1)).expect("invites carol");
    book.apply_state(epoch_three, CREATOR_FP, BOB_FP).expect("accepts the newer state");

    assert!(matches!(
        book.apply_state(epoch_two, CREATOR_FP, BOB_FP),
        Err(GroupError::StaleEpoch { found: 2, current: 3 })
    ));
}

#[test]
fn replaying_the_same_state_is_idempotent() {
    let (_, state) = group_with(vec![bob()]);
    let mut book = joined(state.clone(), BOB_FP);
    assert_eq!(book.apply_state(state, CREATOR_FP, BOB_FP).expect("accepts a replay"), StateOutcome::Unchanged);
}

#[test]
fn a_creator_swap_is_refused_even_when_the_state_is_self_consistent() {
    let (group, state) = group_with(vec![bob()]);
    let mut book = joined(state, BOB_FP);

    // Mallory signs a state for the same group id naming herself creator and
    // keeping bob in the roster, so the missing-self removal branch does not
    // fire. It verifies on its own terms; only the pinned creator catches it.
    let forged = GroupState::make_signed(
        group.state.group_id,
        "testers",
        random_key(),
        9,
        vec![member(3, CAROL_FP, "mallory"), bob()],
        CAROL_FP,
        signer(3),
    )
    .expect("self-signs");
    assert!(forged.verify());

    assert!(matches!(book.apply_state(forged, CAROL_FP, BOB_FP), Err(GroupError::CreatorChanged)));
    assert!(book.get(&group.state.group_id).is_some(), "the real group survives");
}

#[test]
fn the_creators_signing_key_is_pinned_not_just_the_fingerprint() {
    let (group, state) = group_with(vec![bob()]);
    let mut book = joined(state, BOB_FP);

    // Same creator fingerprint, different authoring key: a member holding the
    // creator's Noise key but not its signing key could otherwise take over.
    let impostor_creator = GroupMember::new(CREATOR_FP, public_of(7), "amy");
    let forged = GroupState::make_signed(
        group.state.group_id,
        "testers",
        random_key(),
        9,
        vec![impostor_creator, bob()],
        CREATOR_FP,
        signer(7),
    )
    .expect("self-signs");
    assert!(forged.verify());

    assert!(matches!(book.apply_state(forged, CREATOR_FP, BOB_FP), Err(GroupError::CreatorChanged)));
}

#[test]
fn a_roster_without_us_is_a_removal() {
    let mut group = created();
    group.add_member(bob(), signer(1)).expect("invites bob");
    let with_bob = group.state.clone();
    let mut book = joined(with_bob, BOB_FP);

    let removal = group.remove_member(&BOB_FP, signer(1)).expect("removes bob");
    assert_eq!(
        book.apply_state(removal.state, CREATOR_FP, BOB_FP).expect("accepts the removal"),
        StateOutcome::Removed { name: "testers".into() }
    );
    assert!(book.is_empty());
}

#[test]
fn the_removal_notice_carries_a_zero_key_and_drops_the_group() {
    let mut group = created();
    group.add_member(bob(), signer(1)).expect("invites bob");
    let mut book = joined(group.state.clone(), BOB_FP);

    let removal = group.remove_member(&BOB_FP, signer(1)).expect("removes bob");
    assert_eq!(removal.notice.key, [0u8; 32], "a thrown-away key, never the rotated one");
    assert_ne!(removal.state.key, removal.notice.key);
    assert!(removal.notice.verify());
    assert!(!removal.notice.is_member(&BOB_FP));

    assert!(matches!(
        book.apply_state(removal.notice, CREATOR_FP, BOB_FP).expect("accepts the notice"),
        StateOutcome::Removed { .. }
    ));
    assert!(book.is_empty());
}

#[test]
fn the_notice_does_not_tell_remaining_members_anything_new() {
    let mut group = created();
    group.add_member(bob(), signer(1)).expect("invites bob");
    group.add_member(carol(), signer(1)).expect("invites carol");
    let mut book = joined(group.state.clone(), CAROL_FP);

    let removal = group.remove_member(&BOB_FP, signer(1)).expect("removes bob");
    assert_eq!(
        book.apply_state(removal.notice, CREATOR_FP, CAROL_FP).expect("carol still applies it"),
        StateOutcome::Unchanged,
        "a zero-key notice changes nothing for a remaining member"
    );
    // She keeps the roster and the epoch key she already had; the real rotated
    // state arrives over her own session, not through the notice.
    let kept = book.get(group.id()).expect("carol keeps the group");
    assert_eq!(kept.epoch(), 3, "the notice does not advance her epoch");
    assert_ne!(kept.state.key, [0u8; 32], "and never replaces a usable key");
    assert_eq!(kept.members().len(), 3, "and does not rewrite her roster");
}

#[test]
fn a_group_message_roundtrips_between_members() {
    let (group, state) = group_with(vec![bob()]);
    let mut book = joined(state, BOB_FP);
    let now = 1_700_000_000_000;

    let payload = group.seal("hello group", "msg-1", "amy", &public_of(1), now, signer(1)).expect("seals");
    let envelope = envelope_of(&payload);
    let open = book.open(&envelope, now).expect("opens");
    let OpenOutcome::Message(message) = open else { panic!("not a message: {open:?}") };
    assert_eq!(message.message_id, "msg-1");
    assert_eq!(message.content, "hello group");
    assert_eq!(message.sender.fingerprint, CREATOR_FP);
    assert_eq!(message.timestamp_ms, now);
    assert_eq!(message.epoch, 2);
}

#[test]
fn our_own_broadcast_is_dropped_as_an_echo() {
    let mut group = created();
    let payload = group.seal("hi", "msg-1", "amy", &public_of(1), 1, signer(1)).expect("seals");
    let envelope = envelope_of(&payload);
    assert!(matches!(group.open(&envelope, 1).expect("opens"), OpenOutcome::OwnEcho));
}

#[test]
fn the_same_message_id_is_accepted_once() {
    let (group, state) = group_with(vec![bob()]);
    let mut book = joined(state, BOB_FP);
    let payload = group.seal("hi", "msg-1", "amy", &public_of(1), 10, signer(1)).expect("seals");
    let envelope = envelope_of(&payload);

    assert!(matches!(book.open(&envelope, 10).expect("opens"), OpenOutcome::Message(_)));
    assert!(matches!(book.open(&envelope, 10).expect("opens"), OpenOutcome::Duplicate));
}

#[test]
fn a_message_from_outside_the_roster_is_refused() {
    let (group, state) = group_with(vec![bob()]);
    let mut book = joined(state, BOB_FP);
    // Mallory holds the epoch key but no roster entry. Her AEAD is valid and
    // her Ed25519 signature is valid; only the roster check stops her.
    let payload = ghostchat_protocol::group::seal_message(
        group.id(),
        group.epoch(),
        &group.state.key,
        "msg-1",
        &public_of(3),
        "mallory",
        10,
        "let me in",
        signer(3),
    )
    .expect("seals");
    assert!(matches!(book.open(&envelope_of(&payload), 10), Err(GroupError::SenderNotMember)));
}

#[test]
fn a_message_for_an_unknown_group_or_epoch_is_refused() {
    let mut group = created();
    let payload = group.seal("hi", "msg-1", "amy", &public_of(1), 1, signer(1)).expect("seals");
    let mut envelope = envelope_of(&payload);
    let mut book = GroupBook::default();
    assert!(matches!(book.open(&envelope, 1), Err(GroupError::UnknownGroup)));

    group.add_member(bob(), signer(1)).expect("invites");
    let mut bob_book = joined(group.state.clone(), BOB_FP);
    envelope.epoch = 1;
    assert!(matches!(bob_book.open(&envelope, 1), Err(GroupError::EpochMismatch { found: 1, current: 2 })));
}

#[test]
fn a_future_timestamp_is_clamped_to_now() {
    let (group, state) = group_with(vec![bob()]);
    let mut book = joined(state, BOB_FP);
    let payload = group.seal("from the future", "msg-1", "amy", &public_of(1), 9_000_000, signer(1)).expect("seals");
    let OpenOutcome::Message(message) = book.open(&envelope_of(&payload), 1_000).expect("opens") else {
        panic!("not a message");
    };
    assert_eq!(message.timestamp_ms, 1_000);
}

#[test]
fn a_member_can_seal_and_everyone_reads_it() {
    let (creator_group, state) = group_with(vec![bob()]);
    let mut creator_book = GroupBook::default();
    creator_book.insert(creator_group);
    let mut bob_book = joined(state, BOB_FP);
    let id = *creator_book.list()[0].id();

    let payload =
        bob_book.get_mut(&id).unwrap().seal("hi from bob", "m-b", "bob", &public_of(2), 5, signer(2)).expect("seals");
    let OpenOutcome::Message(message) = creator_book.open(&envelope_of(&payload), 5).expect("opens") else {
        panic!("not a message");
    };
    assert_eq!(message.sender.fingerprint, BOB_FP);
    assert_eq!(message.sender.nickname, "bob");
    assert_eq!(message.content, "hi from bob");
}

#[test]
fn sealing_requires_a_roster_signing_key() {
    let group = created();
    assert!(matches!(group.seal("hi", "m", "mallory", &public_of(3), 1, signer(3)), Err(GroupError::NotAMember)));
}

#[test]
fn an_overlong_message_is_refused_on_send() {
    let group = created();
    let content = "x".repeat(MAX_MESSAGE_CHARS + 1);
    assert!(matches!(group.seal(&content, "m", "amy", &public_of(1), 1, signer(1)), Err(GroupError::TooLong)));
}

#[test]
fn a_tampered_message_never_reaches_the_timeline() {
    let (group, state) = group_with(vec![bob()]);
    let mut book = joined(state, BOB_FP);
    let payload = group.seal("pay bob", "msg-1", "amy", &public_of(1), 1, signer(1)).expect("seals");
    let mut envelope = envelope_of(&payload);
    let last = envelope.ciphertext.len() - 1;
    envelope.ciphertext[last] ^= 0x01;
    assert!(matches!(book.open(&envelope, 1), Err(GroupError::Wire(WireError::DecryptionFailed))));

    // A failed open does not consume the id: the real payload still lands.
    assert!(matches!(book.open(&envelope_of(&payload), 1).expect("opens the original"), OpenOutcome::Message(_)));
}

#[test]
fn leaving_is_local_only() {
    let (group, state) = group_with(vec![bob()]);
    let id = group.state.group_id;
    let mut book = joined(state, BOB_FP);
    assert!(book.get(&id).is_some());
    assert!(book.remove(&id).is_some());
    assert!(book.is_empty());
    assert!(book.remove(&id).is_none());
}

#[test]
fn the_book_lists_groups_by_name() {
    let mut book = GroupBook::default();
    let mut zebra = Group::create("zebra", CREATOR_FP, public_of(1), "amy", signer(1)).expect("creates");
    let mut alpha = Group::create("Alpha", CREATOR_FP, public_of(1), "amy", signer(1)).expect("creates");
    zebra.add_member(bob(), signer(1)).unwrap();
    alpha.add_member(carol(), signer(1)).unwrap();
    book.insert(zebra);
    book.insert(alpha);
    let names: Vec<_> = book.list().iter().map(|g| g.name().to_string()).collect();
    assert_eq!(names, vec!["Alpha".to_string(), "zebra".to_string()]);
    assert_eq!(book.len(), 2);
}

#[test]
fn saved_states_reload_and_garbage_is_skipped() {
    let (group, state) = group_with(vec![bob()]);
    let id = group.state.group_id;
    let encoded = group.state.encode().expect("encodes");

    let (book, skipped) = GroupBook::from_encoded_states(vec![encoded, vec![0x01, 0x00]], BOB_FP);
    assert_eq!(skipped, 1);
    assert_eq!(book.len(), 1);
    assert_eq!(book.get(&id).expect("reloaded").epoch(), state.epoch);

    // Saved under the wrong identity: not our group, so it is not loaded.
    let (other, skipped) = GroupBook::from_encoded_states(vec![group.state.encode().unwrap()], CAROL_FP);
    assert!(other.is_empty());
    assert_eq!(skipped, 1);

    // And the on-disk bytes survive a roundtrip unchanged.
    let stored = group.state.encode().unwrap();
    let (reloaded, _) = GroupBook::from_encoded_states(vec![stored.clone()], CREATOR_FP);
    assert_eq!(reloaded.encoded_states(), vec![stored]);
}

#[test]
fn every_rotation_produces_a_fresh_key() {
    let mut group = created();
    let mut keys = vec![group.state.key];
    for i in 0..4 {
        group.add_member(GroupMember::new([0x50 + i; 32], public_of(4), "x"), signer(1)).expect("invites");
        keys.push(group.state.key);
    }
    let unique: HashSet<_> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len(), "a reused key would let a removed member read on");
}
