use km_common::crypto::secret_box::SecretBox;
use km_common::crypto::{PrivateKey, generate_keypair};
use km_common::key_types::KeyRecord;
use km_common::protected_mem::Vault;
use km_common::proto::{AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm};
use std::fmt::Debug;
use std::time::Duration;

fn assert_redacted<T>(value: &T)
where
    T: Debug,
{
    let debug_str = format!("{value:?}");
    assert!(
        debug_str.contains("[REDACTED]"),
        "Debug output does not contain [REDACTED]: {}",
        debug_str
    );
    assert!(
        !debug_str.contains("sentinel"),
        "Debug output leaked 'sentinel': {}",
        debug_str
    );
}

#[test]
fn secret_box_is_redacted_for_debug_and_display() {
    let secret_box = SecretBox::new(b"secret-box-sentinel".to_vec());
    assert_redacted(&secret_box);
}

#[test]
fn private_key_types_are_redacted_for_debug_and_display() {
    let (_, private_key) = generate_keypair(KemAlgorithm::DhkemX25519HkdfSha256)
        .expect("X25519 key generation should succeed");
    assert_redacted(&private_key);

    let PrivateKey::X25519(x25519_private_key) = private_key;
    assert_redacted(&x25519_private_key);
}

#[test]
fn vault_is_redacted_for_debug_and_display() {
    let vault = Vault::new(SecretBox::new(b"vault-sentinel".to_vec()))
        .expect("memfd_secret should be available on the Linux test runner");
    assert_redacted(&vault);
}

#[test]
fn key_record_is_redacted_for_debug_and_display() {
    let algorithm = HpkeAlgorithm {
        kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
        kdf: KdfAlgorithm::HkdfSha256 as i32,
        aead: AeadAlgorithm::Aes256Gcm as i32,
    };
    let key_record = KeyRecord::create_binding_key(algorithm, Duration::from_secs(60))
        .expect("binding key creation should succeed");
    assert_redacted(&key_record);
}
