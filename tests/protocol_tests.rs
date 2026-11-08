use vedoy_shield_core::{
    chain::SessionChains,
    hybrid::{initiate, RecipientPrivate, SenderIdentity},
    identity::{IdentityDocument, IdentityProofing, ProofingRequest, UnconfiguredProofing},
    json::{capabilities, encode_bounded, parse_bounded},
    storage::EncryptedAtomicStore,
    transport::{decode_packet, encode_packet},
    vault::{SecureKeyVault, UnavailableVault},
    wordforge::{decrypt_message, encrypt_message, WordEnvelope},
};
const PASSWORD2: &str = "long-second-password-not-used-in-production";
const PIN: &str = "728194";
#[test]
fn authenticated_hybrid_agreement_and_message() {
    let (bob, bundle) = RecipientPrivate::generate();
    let alice_id = SenderIdentity::generate();
    let (invite, alice_root) = initiate(&bundle, &bob.identity_public(), &alice_id, "chat-a").unwrap();
    let bob_root = bob.accept(&invite, &bundle, &alice_id.identity_public()).unwrap();
    let mut alice = SessionChains::initiator(&alice_root).unwrap();
    let mut bob_chains = SessionChains::responder(&bob_root).unwrap();
    let a = alice.send.prepare().unwrap();
    let b = bob_chains.receive.prepare().unwrap();
    let plaintext = "Hei, Vedoy Shield! 🔐";
    let packet = encrypt_message(plaintext, "chat-a", a.sequence, &a.key).unwrap();
    assert_eq!(decrypt_message(&packet, "chat-a", b.sequence, &b.key).unwrap(), plaintext);
    alice.send.commit(a).unwrap();
    bob_chains.receive.commit(b).unwrap();
    assert_eq!(alice.send.sequence(), 1);
}
#[test]
fn refuses_untrusted_sender_and_recipient() {
    let (bob, bundle) = RecipientPrivate::generate();
    let sender = SenderIdentity::generate();
    assert!(initiate(&bundle, &[3u8; 32], &sender, "chat-a").is_err());
    let (invite, _) = initiate(&bundle, &bob.identity_public(), &sender, "chat-a").unwrap();
    assert!(bob.accept(&invite, &bundle, &[8u8; 32]).is_err());
    assert!(bob.accept(&invite, &bundle, &sender.identity_public()).is_ok());
}
#[test]
fn refuses_tampered_sender_signature_and_context() {
    let (bob, bundle) = RecipientPrivate::generate();
    let sender = SenderIdentity::generate();
    let (mut invite, _) = initiate(&bundle, &bob.identity_public(), &sender, "chat-a").unwrap();
    invite.chat_id = "chat-b".to_string();
    assert!(bob.accept(&invite, &bundle, &sender.identity_public()).is_err());
    invite.chat_id = "chat-a".to_string();
    invite.sender_signature[0] ^= 1;
    assert!(bob.accept(&invite, &bundle, &sender.identity_public()).is_err());
}
#[test]
fn rejects_tampered_wordforge_envelope() {
    let (bob, bundle) = RecipientPrivate::generate();
    let sender = SenderIdentity::generate();
    let (_, root) = initiate(&bundle, &bob.identity_public(), &sender, "chat-a").unwrap();
    let chain = SessionChains::initiator(&root).unwrap();
    let step = chain.send.prepare().unwrap();
    let mut env = encrypt_message("Hei der!", "chat-a", step.sequence, &step.key).unwrap();
    assert!(decrypt_message(&env, "chat-b", step.sequence, &step.key).is_err());
    env.ciphertext[0] ^= 1;
    assert!(decrypt_message(&env, "chat-a", step.sequence, &step.key).is_err());
}
#[test]
fn transport_codec_rejects_tampering_and_wrong_version() {
    let (bob, bundle) = RecipientPrivate::generate();
    let sender = SenderIdentity::generate();
    let (_, root) = initiate(&bundle, &bob.identity_public(), &sender, "chat-a").unwrap();
    let chain = SessionChains::initiator(&root).unwrap();
    let step = chain.send.prepare().unwrap();
    let envelope = encrypt_message("Wire test", "chat-a", 0, &step.key).unwrap();
    let packet = vedoy_shield_core::session::SentPacket { chat_id: "chat-a".into(), envelope };
    let encoded = encode_packet(&packet).unwrap();
    assert_eq!(decode_packet(&encoded).unwrap().chat_id, "chat-a");

    let mut malformed = packet;
    malformed.envelope.version = 99;
    assert!(encode_packet(&malformed).is_err());
}
#[test]
fn json_bounded_and_versioned() {
    let (bob, bundle) = RecipientPrivate::generate();
    let sender = SenderIdentity::generate();
    let (_, root) = initiate(&bundle, &bob.identity_public(), &sender, "chat-a").unwrap();
    let chain = SessionChains::initiator(&root).unwrap();
    let step = chain.send.prepare().unwrap();
    let env = encrypt_message("Hei!", "chat-a", 0, &step.key).unwrap();
    let bytes = encode_bounded(&env).unwrap();
    let parsed: WordEnvelope = parse_bounded(&bytes).unwrap();
    assert_eq!(parsed.version, 3);
    assert_eq!(decrypt_message(&parsed, "chat-a", 0, &step.key).unwrap(), "Hei!");
    assert_eq!(capabilities().core_version, "0.3.0");
    assert!(!capabilities().production_ready);
}
#[test]
fn absent_secure_key_vault_and_id_provider_fail_closed() {
    let vault = UnavailableVault;
    assert!(vault.store("id1", &[4; 32]).is_err());
    assert!(vault.load("id1").is_err());
    let provider = UnconfiguredProofing;
    assert!(provider.start(&ProofingRequest {
        account_pseudonym: "account123".to_string(),
        request_nonce: "nonce-dummy".to_string(),
        document_type: IdentityDocument::Passport,
    }).is_err());
}
#[cfg(unix)]
fn test_store() -> (EncryptedAtomicStore, std::path::PathBuf) {
    use rand_core::{OsRng, RngCore};
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let path = std::env::temp_dir().join(format!("vedoy-shield-test-{}", u64::from_be_bytes(random)));
    (EncryptedAtomicStore::new(&path, "ratchet.json").unwrap(), path)
}
#[test]
#[cfg(unix)]
fn encrypted_snapshot_roundtrip_wrong_pin_and_revision_conflict() {
    let (store, dir) = test_store();
    let plain = b"secret ratchet bytes: never stored unencrypted";
    assert_eq!(store.save(PASSWORD2, PIN, "chat-a", 0, plain).unwrap(), 1);
    let disk = std::fs::read(dir.join("ratchet.json")).unwrap();
    assert!(!disk.windows(plain.len()).any(|x| x == plain));
    let loaded = store.load(PASSWORD2, PIN, "chat-a").unwrap();
    assert_eq!(&*loaded.plaintext, plain);
    assert_eq!(loaded.revision, 1);
    assert!(store.load(PASSWORD2, "000000", "chat-a").is_err());
    assert!(store.load(PASSWORD2, PIN, "chat-b").is_err());
    assert!(store.save(PASSWORD2, PIN, "chat-a", 0, b"replay state").is_err());
    assert_eq!(store.save(PASSWORD2, PIN, "chat-a", 1, b"next state").unwrap(), 2);
    assert_eq!(&*store.load(PASSWORD2, PIN, "chat-a").unwrap().plaintext, b"next state");
    std::fs::remove_dir_all(dir).unwrap();
}
#[cfg(not(feature = "signal-spqr"))]
#[test]
fn no_insecure_ratchet_fallback() {
    use vedoy_shield_core::ratchet::PostQuantumRatchet;
    assert!(PostQuantumRatchet::from_encrypted_snapshot(vec![1,2,3]).is_err());
}
#[cfg(all(unix, feature = "signal-spqr"))]
#[test]
fn pq_ratchet_persists_before_exposure() {
    use vedoy_shield_core::session::{create_session, queue_message, receive_message, PrivateSession};
    use rand_core::{OsRng, RngCore};
    let (bob, bundle) = RecipientPrivate::generate();
    let alice_id = SenderIdentity::generate();
    let (invite, alice_root) = initiate(&bundle, &bob.identity_public(), &alice_id, "chat-a").unwrap();
    let bob_root = bob.accept(&invite, &bundle, &alice_id.identity_public()).unwrap();
    let mut n = [0u8; 8];
    OsRng.fill_bytes(&mut n);
    let dir = std::env::temp_dir().join(format!("vedoy-pq-test-{}", u64::from_be_bytes(n)));
    let send = EncryptedAtomicStore::new(&dir.join("sender"), "state.json").unwrap();
    let recv = EncryptedAtomicStore::new(&dir.join("receiver"), "state.json").unwrap();
    create_session(&send, PASSWORD2, PIN, "alice/chat-a", "chat-a", &alice_root, true).unwrap();
    create_session(&recv, PASSWORD2, PIN, "bob/chat-a", "chat-a", &bob_root, false).unwrap();
    let pkt = queue_message(&send, PASSWORD2, PIN, "alice/chat-a", "chat-a", "Hei! 🔐").unwrap();
    let (_, snapshot): (u64, PrivateSession) =
        send.load_json(PASSWORD2, PIN, "alice/chat-a").unwrap();
    assert_eq!(snapshot.outbox.len(), 1);
    assert_eq!(receive_message(&recv, PASSWORD2, PIN, "bob/chat-a", "chat-a", &pkt).unwrap(), "Hei! 🔐");
    assert!(receive_message(&recv, PASSWORD2, PIN, "bob/chat-a", "chat-a", &pkt).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
