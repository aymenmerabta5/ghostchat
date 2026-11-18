use super::*;
use ed25519_dalek::Signer;

fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn public_of(seed: u8) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

fn member(seed: u8, fingerprint: u8, nickname: &str) -> GroupMember {
    GroupMember::new([fingerprint; 32], public_of(seed), nickname)
}

fn signed_state() -> GroupState {
    let creator = member(1, 0x11, "amy");
    let bob = member(2, 0x22, "bob");
    GroupState::make_signed(GroupId([7u8; 16]), "testers", [9u8; 32], 1, vec![creator, bob], [0x11; 32], |data| {
        Some(signing_key(1).sign(data).to_bytes())
    })
    .expect("state signs")
}

#[test]
fn roster_roundtrips() {
    let members = vec![member(1, 0x11, "amy"), member(2, 0x22, "bob with spaces")];
    let blob = encode_roster(&members).expect("encodes");
    let decoded = decode_roster(&blob).expect("decodes");
    assert_eq!(decoded, members);
    // Canonical: re-encoding decoded members must reproduce the exact bytes.
    assert_eq!(encode_roster(&decoded).unwrap(), blob);
}

#[test]
fn roster_truncates_nicknames_on_a_character_boundary() {
    // 30 three-byte characters = 90 bytes; the cap is 64.
    let long: String = "é".repeat(30);
    let members = vec![member(1, 0x11, &long)];
    let blob = encode_roster(&members).expect("encodes");
    let decoded = decode_roster(&blob).expect("decodes");
    let nickname = &decoded[0].nickname;
    assert!(nickname.len() <= MAX_NICKNAME_BYTES);
    assert_eq!(nickname.len() % 2, 0, "multi-byte scalars stay whole");
    assert!(long.starts_with(nickname.as_str()));
}

#[test]
fn roster_rejects_oversize_and_trailing_bytes() {
    let members: Vec<_> = (0..=MAX_MEMBERS).map(|i| member(1, i as u8, "x")).collect();
    assert!(encode_roster(&members).is_none(), "17 members is over the cap");

    let mut blob = encode_roster(&[member(1, 0x11, "amy")]).unwrap();
    blob.push(0);
    assert!(decode_roster(&blob).is_none(), "trailing bytes change the signed hash");
}

#[test]
fn roster_rejects_truncated_input() {
    let blob = encode_roster(&[member(1, 0x11, "amy")]).unwrap();
    for cut in 0..blob.len() {
        assert!(decode_roster(&blob[..cut]).is_none(), "prefix of {cut} bytes must not decode");
    }
}

#[test]
fn state_roundtrips_and_verifies() {
    let state = signed_state();
    assert!(state.verify());

    let encoded = state.encode().expect("encodes");
    let decoded = GroupState::decode(&encoded).expect("decodes");
    assert_eq!(decoded, state);
    assert!(decoded.verify());
}

#[test]
fn state_rejects_a_tampered_name() {
    let mut state = signed_state();
    state.name = "not testers".into();
    assert!(!state.verify(), "the name is covered by the creator signature");
}

#[test]
fn state_rejects_a_tampered_key() {
    let mut state = signed_state();
    state.key = [0xAB; 32];
    assert!(!state.verify(), "the epoch key is bound by hash");
}

#[test]
fn state_rejects_a_tampered_roster() {
    let mut state = signed_state();
    state.members.push(member(3, 0x33, "mallory"));
    assert!(!state.verify(), "the roster is bound by hash");
}

#[test]
fn state_rejects_a_tampered_signature() {
    let mut state = signed_state();
    state.signature[0] ^= 0xFF;
    assert!(!state.verify());
}

#[test]
fn state_rejects_a_creator_who_is_not_in_the_roster() {
    let mut state = signed_state();
    state.creator = [0x99; 32];
    assert!(!state.verify(), "the creator must be named in the signed roster");
}

#[test]
fn state_rejects_a_forged_creator_signature() {
    // Mallory self-signs a state that names her as creator. It verifies on its
    // own terms — which is exactly why a holder of an existing group must also
    // pin the creator (see `GroupBook::apply_state`).
    let mallory = member(3, 0x33, "mallory");
    let forged =
        GroupState::make_signed(GroupId([7u8; 16]), "testers", [9u8; 32], 2, vec![mallory], [0x33; 32], |data| {
            Some(signing_key(3).sign(data).to_bytes())
        })
        .expect("self-signed");
    assert!(forged.verify(), "self-consistent");
    let honest = signed_state();
    assert_ne!(forged.creator, honest.creator, "the pin is what defeats this");
}

#[test]
fn state_decode_ignores_unknown_tlvs() {
    let mut encoded = signed_state().encode().unwrap();
    put(&mut encoded, 0x7F, b"future").expect("fits");
    let decoded = GroupState::decode(&encoded).expect("unknown fields are forward compatible");
    assert!(decoded.verify());
}

#[test]
fn state_decode_rejects_missing_fields() {
    let encoded = signed_state().encode().unwrap();
    // Drop the last TLV (the signature).
    let fields = parse(&encoded).unwrap();
    let mut truncated = Vec::new();
    for (kind, value) in &fields[..fields.len() - 1] {
        put(&mut truncated, *kind, value).unwrap();
    }
    assert!(GroupState::decode(&truncated).is_none());
}

#[test]
fn state_decode_rejects_empty_roster() {
    let encoded = signed_state().encode().unwrap();
    let fields = parse(&encoded).unwrap();
    let mut rebuilt = Vec::new();
    for (kind, value) in fields {
        if kind == 0x05 {
            put(&mut rebuilt, kind, &[0u8]).unwrap(); // count = 0
        } else {
            put(&mut rebuilt, kind, value).unwrap();
        }
    }
    assert!(GroupState::decode(&rebuilt).is_none(), "a group with no members is meaningless");
}

#[test]
fn message_roundtrips_and_verifies() {
    let group = GroupId([7u8; 16]);
    let key = [9u8; 32];
    let payload =
        seal_message(&group, 1, &key, "msg-1", &public_of(2), "bob", 1_700_000_000_000, "hello group", |data| {
            Some(signing_key(2).sign(data).to_bytes())
        })
        .expect("seals");

    let envelope = GroupEnvelope::decode(&payload).expect("decodes");
    assert_eq!(envelope.group_id, group);
    assert_eq!(envelope.epoch, 1);

    let opened = open_message(&envelope, &key).expect("opens");
    assert_eq!(opened.message_id, "msg-1");
    assert_eq!(opened.sender_nickname, "bob");
    assert_eq!(opened.timestamp_ms, 1_700_000_000_000);
    assert_eq!(opened.content, "hello group");
    assert_eq!(opened.sender_signing_key, public_of(2));
}

fn sample_attachment(data: &[u8]) -> GroupAttachment {
    let digest = sha256(b"whole file")[..8].try_into().unwrap();
    GroupAttachment {
        kind: MediaKind::Image,
        attachment_id: [0x42; 8],
        index: 0,
        count: 1,
        total_bytes: data.len() as u32,
        digest,
        name: "photo.png".into(),
        mime: "image/png".into(),
        data: data.to_vec(),
        signature: [0u8; 64],
    }
}

fn seal_sample_attachment(attachment: &GroupAttachment, message_id: &str, timestamp_ms: u64) -> Vec<u8> {
    let group = GroupId([7u8; 16]);
    seal_attachment(
        &group,
        1,
        &[9u8; 32],
        message_id,
        &public_of(2),
        "bob",
        timestamp_ms,
        "[image] 4 KB",
        attachment,
        |data| Some(signing_key(2).sign(data).to_bytes()),
    )
    .expect("seals")
}

#[test]
fn attachment_chunk_roundtrips_and_verifies() {
    let chunk = sample_attachment(&[0x89, b'P', b'N', b'G', 1, 2, 3]);
    let payload = seal_sample_attachment(&chunk, "msg-1", 1_700_000_000_000);
    let envelope = GroupEnvelope::decode(&payload).expect("decodes");
    let opened = open_message(&envelope, &[9u8; 32]).expect("opens");
    assert_eq!(opened.content, "[image] 4 KB");
    let got = opened.attachment.expect("attachment survives");
    assert_eq!(got.kind, MediaKind::Image);
    assert_eq!(got.attachment_id, [0x42; 8]);
    assert_eq!(got.index, 0);
    assert_eq!(got.count, 1);
    assert_eq!(got.total_bytes, 7);
    assert_eq!(got.name, "photo.png");
    assert_eq!(got.mime, "image/png");
    assert_eq!(got.data, chunk.data);
}

#[test]
fn attachment_signature_is_checked_even_when_the_text_signature_is_valid() {
    let group = GroupId([7u8; 16]);
    let chunk = sample_attachment(b"data");
    let descriptor = chunk.descriptor().unwrap();
    // The visible text is signed by the real sender...
    let text = message_signing_content(&group, 1, "msg-1", 5, "[image] 4 B");
    let text_signature = signing_key(2).sign(&text).to_bytes();
    // ...but the chunk was signed by someone else. The attachment signature is
    // a second, independent check, not decoration.
    let forged = signing_key(3).sign(&GroupAttachment::signing_content(&group, 1, "msg-1", 5, &descriptor));
    let mut value = descriptor;
    value.extend_from_slice(&forged.to_bytes());
    let payload = seal_inner(
        &group,
        1,
        &[9u8; 32],
        "msg-1",
        &public_of(2),
        "bob",
        5,
        "[image] 4 B",
        &text_signature,
        Some((INNER_TAG_ATTACHMENT, &value)),
    )
    .unwrap();
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    assert_eq!(open_message(&envelope, &[9u8; 32]), Err(GroupError::BadSenderSignature));
}

#[test]
fn unknown_inner_fields_are_ignored_like_the_reference() {
    let group = GroupId([7u8; 16]);
    let text = message_signing_content(&group, 1, "msg-1", 5, "hello");
    let signature = signing_key(2).sign(&text).to_bytes();
    let payload = seal_inner(
        &group,
        1,
        &[9u8; 32],
        "msg-1",
        &public_of(2),
        "bob",
        5,
        "hello",
        &signature,
        Some((0x7F, b"from a later revision")),
    )
    .unwrap();
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    let opened = open_message(&envelope, &[9u8; 32]).expect("an unknown field must not break the line");
    assert_eq!(opened.content, "hello");
    assert_eq!(opened.attachment, None);
}

#[test]
fn text_messages_have_no_attachment() {
    let payload = seal_message(&GroupId([7u8; 16]), 1, &[9u8; 32], "msg-1", &public_of(2), "bob", 1, "hi", |data| {
        Some(signing_key(2).sign(data).to_bytes())
    })
    .unwrap();
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    let opened = open_message(&envelope, &[9u8; 32]).unwrap();
    assert_eq!(opened.attachment, None, "plain text is the reference path");
}

#[test]
fn attachment_rejects_a_signature_from_another_key() {
    let chunk = sample_attachment(b"data");
    let payload = seal_attachment(
        &GroupId([7u8; 16]),
        1,
        &[9u8; 32],
        "msg-1",
        &public_of(2),
        "bob",
        1,
        "[image] 4 B",
        &chunk,
        |data| Some(signing_key(3).sign(data).to_bytes()),
    )
    .expect("seals");
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    assert_eq!(open_message(&envelope, &[9u8; 32]), Err(GroupError::BadSenderSignature));
}

#[test]
fn attachment_cannot_move_to_another_message_id() {
    let group = GroupId([7u8; 16]);
    let chunk = sample_attachment(b"data");
    let descriptor = chunk.descriptor().unwrap();
    // The signature was made for msg-1; seal the same value under msg-2.
    let chunk_signature = signing_key(2).sign(&GroupAttachment::signing_content(&group, 1, "msg-1", 5, &descriptor));
    let mut value = descriptor;
    value.extend_from_slice(&chunk_signature.to_bytes());
    let text = message_signing_content(&group, 1, "msg-2", 5, "[image] 4 B");
    let text_signature = signing_key(2).sign(&text).to_bytes();
    let payload = seal_inner(
        &group,
        1,
        &[9u8; 32],
        "msg-2",
        &public_of(2),
        "bob",
        5,
        "[image] 4 B",
        &text_signature,
        Some((INNER_TAG_ATTACHMENT, &value)),
    )
    .unwrap();
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    assert_eq!(open_message(&envelope, &[9u8; 32]), Err(GroupError::BadSenderSignature));
}

#[test]
fn attachment_rejects_tampered_descriptor_fields() {
    let chunk = sample_attachment(b"data");
    let mut value = chunk.encode().unwrap();
    // Change the MIME length byte inside the descriptor; the signature no
    // longer covers the descriptor that is decoded.
    let mime_len_at = 1 + 1 + 8 + 2 + 2 + 4 + 8 + 2 + "photo.png".len();
    value[mime_len_at] ^= 0x01;
    assert!(GroupAttachment::decode(&value).is_none(), "lengths must add up exactly");
}

#[test]
fn attachment_rejects_impossible_sizes() {
    let mut chunk = sample_attachment(b"data");
    chunk.total_bytes = 0;
    assert!(chunk.encode().is_err(), "an empty file has no chunks");

    let mut chunk = sample_attachment(b"data");
    chunk.count = 0;
    assert!(chunk.encode().is_err());

    let mut chunk = sample_attachment(b"data");
    chunk.index = 1;
    assert!(chunk.encode().is_err(), "index must be below count");

    let mut chunk = sample_attachment(b"data");
    chunk.data = vec![0u8; MAX_ATTACHMENT_CHUNK_BYTES + 1];
    chunk.total_bytes = chunk.data.len() as u32;
    assert!(chunk.encode().is_err(), "one chunk must fit one TLV value");
}

#[test]
fn attachment_signing_content_binds_every_field() {
    let group = GroupId([7u8; 16]);
    let descriptor = sample_attachment(b"data").descriptor().unwrap();
    let base = GroupAttachment::signing_content(&group, 1, "id", 5, &descriptor);
    assert_ne!(base, GroupAttachment::signing_content(&GroupId([8u8; 16]), 1, "id", 5, &descriptor));
    assert_ne!(base, GroupAttachment::signing_content(&group, 2, "id", 5, &descriptor));
    assert_ne!(base, GroupAttachment::signing_content(&group, 1, "id2", 5, &descriptor));
    assert_ne!(base, GroupAttachment::signing_content(&group, 1, "id", 6, &descriptor));
    assert_ne!(base, GroupAttachment::signing_content(&group, 1, "id", 5, b"other"));
}

#[test]
fn message_rejects_the_wrong_key() {
    let group = GroupId([7u8; 16]);
    let payload = seal_message(&group, 1, &[9u8; 32], "msg-1", &public_of(2), "bob", 1, "hi", |data| {
        Some(signing_key(2).sign(data).to_bytes())
    })
    .unwrap();
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    assert_eq!(open_message(&envelope, &[8u8; 32]), Err(GroupError::DecryptionFailed));
}

#[test]
fn message_rejects_a_cross_epoch_replay() {
    let group = GroupId([7u8; 16]);
    let key = [9u8; 32];
    let payload = seal_message(&group, 1, &key, "msg-1", &public_of(2), "bob", 1, "hi", |data| {
        Some(signing_key(2).sign(data).to_bytes())
    })
    .unwrap();
    let mut envelope = GroupEnvelope::decode(&payload).unwrap();
    // The rotated key is the same, but the epoch is bound as AEAD data.
    envelope.epoch = 2;
    assert_eq!(open_message(&envelope, &key), Err(GroupError::DecryptionFailed));
}

#[test]
fn message_rejects_a_cross_group_replay() {
    let payload = seal_message(&GroupId([7u8; 16]), 1, &[9u8; 32], "msg-1", &public_of(2), "bob", 1, "hi", |data| {
        Some(signing_key(2).sign(data).to_bytes())
    })
    .unwrap();
    let mut envelope = GroupEnvelope::decode(&payload).unwrap();
    envelope.group_id = GroupId([8u8; 16]);
    assert_eq!(open_message(&envelope, &[9u8; 32]), Err(GroupError::DecryptionFailed));
}

#[test]
fn message_rejects_tampered_ciphertext() {
    let payload = seal_message(&GroupId([7u8; 16]), 1, &[9u8; 32], "msg-1", &public_of(2), "bob", 1, "hi", |data| {
        Some(signing_key(2).sign(data).to_bytes())
    })
    .unwrap();
    let mut envelope = GroupEnvelope::decode(&payload).unwrap();
    let last = envelope.ciphertext.len() - 1;
    envelope.ciphertext[last] ^= 0x01;
    assert_eq!(open_message(&envelope, &[9u8; 32]), Err(GroupError::DecryptionFailed));
}

#[test]
fn message_rejects_a_bad_sender_signature() {
    // Seal under a valid key but sign with someone else's key: decryption
    // succeeds, the inner signature does not.
    let payload = seal_message(&GroupId([7u8; 16]), 1, &[9u8; 32], "msg-1", &public_of(2), "bob", 1, "hi", |data| {
        Some(signing_key(3).sign(data).to_bytes())
    })
    .unwrap();
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    assert_eq!(open_message(&envelope, &[9u8; 32]), Err(GroupError::BadSenderSignature));
}

#[test]
fn message_rejects_an_empty_id() {
    let payload = seal_message(&GroupId([7u8; 16]), 1, &[9u8; 32], "", &public_of(2), "bob", 1, "hi", |data| {
        Some(signing_key(2).sign(data).to_bytes())
    })
    .unwrap();
    let envelope = GroupEnvelope::decode(&payload).unwrap();
    assert_eq!(open_message(&envelope, &[9u8; 32]), Err(GroupError::Malformed));
}

#[test]
fn message_signing_content_binds_every_field() {
    let group = GroupId([7u8; 16]);
    let base = message_signing_content(&group, 1, "id", 5, "hi");
    assert_ne!(base, message_signing_content(&group, 2, "id", 5, "hi"));
    assert_ne!(base, message_signing_content(&group, 1, "id2", 5, "hi"));
    assert_ne!(base, message_signing_content(&group, 1, "id", 6, "hi"));
    assert_ne!(base, message_signing_content(&group, 1, "id", 5, "hi!"));
    assert_ne!(base, message_signing_content(&GroupId([8u8; 16]), 1, "id", 5, "hi"));
}

#[test]
fn state_signing_content_binds_every_field() {
    let group = GroupId([7u8; 16]);
    let roster = encode_roster(&[member(1, 0x11, "amy")]).unwrap();
    let base = GroupState::signing_content(&group, 1, &[9u8; 32], &roster, "g");
    assert_ne!(base, GroupState::signing_content(&GroupId([8u8; 16]), 1, &[9u8; 32], &roster, "g"));
    assert_ne!(base, GroupState::signing_content(&group, 2, &[9u8; 32], &roster, "g"));
    assert_ne!(base, GroupState::signing_content(&group, 1, &[8u8; 32], &roster, "g"));
    assert_ne!(base, GroupState::signing_content(&group, 1, &[9u8; 32], &roster, "h"));
    assert_ne!(
        base,
        GroupState::signing_content(&group, 1, &[9u8; 32], &encode_roster(&[member(1, 0x11, "bob")]).unwrap(), "g")
    );
}

#[test]
fn malformed_tlv_is_rejected() {
    // Declares 5 bytes of value with only 2 present.
    assert!(parse(&[0x01, 0x00, 0x05, 0xAA, 0xBB]).is_none());
    // Declares a 3-byte header but the buffer is 2 bytes.
    assert!(parse(&[0x01, 0x00]).is_none());
    assert!(parse(&[]).unwrap().is_empty());
}

#[test]
fn group_id_hex_roundtrips() {
    let id = GroupId::random();
    assert_eq!(GroupId::from_hex(&id.hex()), Some(id));
    assert_eq!(id.hex().len(), 32);
    assert!(GroupId::from_hex("not hex").is_none());
    assert!(GroupId::from_hex("00").is_none(), "truncated ids are rejected");
}
