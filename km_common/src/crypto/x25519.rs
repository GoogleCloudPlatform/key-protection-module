#[cfg(any(test, feature = "test-utils"))]
use crate::crypto::PrivateKeyRef;
use crate::crypto::secret_box::SecretBox;
use crate::crypto::{PrivateKeyOps, PublicKeyOps, Status};
use crate::protected_mem::Vault;
use crate::proto::{AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm};
#[cfg(any(test, feature = "test-utils"))]
use bssl_crypto::x25519;
use bssl_crypto::{hkdf, hpke};
/// X25519-based public key implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey(pub(crate) [u8; 32]);

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKeyOps for X25519PublicKey {
    fn hpke_seal_internal(
        &self,
        plaintext: &SecretBox,
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<(Vec<u8>, Vec<u8>), Status> {
        let (
            Ok(KemAlgorithm::DhkemX25519HkdfSha256),
            Ok(KdfAlgorithm::HkdfSha256),
            Ok(AeadAlgorithm::Aes256Gcm),
        ) = (
            KemAlgorithm::try_from(algo.kem),
            KdfAlgorithm::try_from(algo.kdf),
            AeadAlgorithm::try_from(algo.aead),
        )
        else {
            return Err(Status::UnsupportedAlgorithm);
        };

        let params = hpke::Params::new(
            hpke::Kem::X25519HkdfSha256,
            hpke::Kdf::HkdfSha256,
            hpke::Aead::Aes256Gcm,
        );

        let (mut sender_ctx, encapsulated_key) =
            hpke::SenderContext::new(&params, self.as_ref(), b"")
                .ok_or(Status::EncryptionFailure)?;

        let ciphertext = sender_ctx.seal(plaintext.as_slice(), aad);
        Ok((encapsulated_key, ciphertext))
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn encap_internal(
        &self,
        ephemeral_sk: Option<&PrivateKeyRef>,
    ) -> Result<(SecretBox, Vec<u8>), Status> {
        let (pk_e_bytes, sk_e_bytes) = match ephemeral_sk {
            Some(PrivateKeyRef::X25519(sk)) => {
                let sk_e = x25519::PrivateKey(*sk.0);
                (sk_e.to_public().to_vec(), sk.0.to_vec())
            }
            None => hpke::Kem::X25519HkdfSha256.generate_keypair(),
        };

        let sk_e = x25519::PrivateKey(sk_e_bytes.try_into().map_err(|_| Status::CryptoError)?);
        let pk_r = self.0;

        // 1. Compute Diffie-Hellman shared secret
        // dh = dhExchange(skE, pkR)
        let shared_key = SecretBox::new(
            sk_e.compute_shared_key(&pk_r)
                .ok_or(Status::CryptoError)?
                .to_vec(),
        );

        // DHKEM(X25519, HKDF-SHA256)
        // suite_id = "KEM" || I2OSP(kem_id, 2)
        // For X25519 (0x0020)
        let suite_id = [b'K', b'E', b'M', 0, 0x20];

        // 2. Extract eae_prk
        // eae_prk = LabeledExtract("", "eae_prk", dh)
        let prk = labeled_extract(b"", b"eae_prk", shared_key.as_slice(), &suite_id);

        // 3. Expand shared_secret
        // shared_secret = LabeledExpand(eae_prk, "shared_secret", enc || pkR, L)
        let info = [&pk_e_bytes[..], &pk_r[..]].concat();
        let shared_secret = labeled_expand(&prk, b"shared_secret", &info, &suite_id, 32)?;

        Ok((shared_secret, pk_e_bytes.to_vec()))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// X25519-based borrowed private key wrapper.
pub struct X25519PrivateKeyRef<'a>(pub(crate) &'a [u8; 32]);

impl<'a> X25519PrivateKeyRef<'a> {
    fn to_public(&self) -> [u8; 32] {
        let mut pub_key = [0u8; 32];
        unsafe {
            bssl_sys::X25519_public_from_private(pub_key.as_mut_ptr(), self.0.as_ptr());
        }
        pub_key
    }
}

impl<'a> PrivateKeyOps for X25519PrivateKeyRef<'a> {
    /// Decapsulates the shared secret from an encapsulated key.
    /// Uses raw direct-to-heap FFI pointer arithmetic to ensure the private key
    /// and derived intermediate shared secret bypass standard stack allocations.
    /// Follows RFC 9180 Section 4.1. DHKEM(Group, Hash).
    fn decaps_internal(&self, enc: &[u8]) -> Result<SecretBox, Status> {
        if enc.len() != 32 {
            return Err(Status::DecapsulationFailure);
        }

        // Allocate directly on the heap to avoid stack pollution
        let mut shared_key = SecretBox::new(vec![0u8; 32]);

        // Direct raw pointer invocation
        // 1. Compute Diffie-Hellman shared secret
        // dh = dhExchange(skR, pkE)
        let ret = unsafe {
            bssl_sys::X25519(
                shared_key.as_mut_slice().as_mut_ptr(),
                self.0.as_ptr(),
                enc.as_ptr(),
            )
        };

        if ret != 1 {
            return Err(Status::DecapsulationFailure);
        }

        // DHKEM(X25519, HKDF-SHA256)
        // suite_id = "KEM" || I2OSP(kem_id, 2)
        // For X25519 (0x0020)
        let suite_id = [b'K', b'E', b'M', 0, 0x20];

        // 2. Extract eae_prk
        // eae_prk = LabeledExtract("", "eae_prk", dh)
        let prk = labeled_extract(b"", b"eae_prk", shared_key.as_slice(), &suite_id);

        let pub_key = self.to_public();

        // 3. Expand shared_secret
        // shared_secret = LabeledExpand(eae_prk, "shared_secret", enc || pkR, L)
        let info = [enc, &pub_key].concat();

        labeled_expand(&prk, b"shared_secret", &info, &suite_id, 32)
    }

    fn hpke_open_internal(
        &self,
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<SecretBox, Status> {
        let (
            Ok(KemAlgorithm::DhkemX25519HkdfSha256),
            Ok(KdfAlgorithm::HkdfSha256),
            Ok(AeadAlgorithm::Aes256Gcm),
        ) = (
            KemAlgorithm::try_from(algo.kem),
            KdfAlgorithm::try_from(algo.kdf),
            AeadAlgorithm::try_from(algo.aead),
        )
        else {
            return Err(Status::UnsupportedAlgorithm);
        };

        let params = hpke::Params::new(
            hpke::Kem::X25519HkdfSha256,
            hpke::Kdf::HkdfSha256,
            hpke::Aead::Aes256Gcm,
        );

        // RecipientContext::new FFI call is stack-less on the private key slice on the Rust side
        let mut recipient_ctx = hpke::RecipientContext::new(&params, self.0, enc, b"")
            .ok_or(Status::DecryptionFailure)?;

        recipient_ctx
            .open(ciphertext, aad)
            .map(SecretBox::new)
            .ok_or(Status::DecryptionFailure)
    }
}

/// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8], suite_id: &[u8]) -> hkdf::Prk {
    let labeled_ikm = SecretBox::new([b"HPKE-v1".as_slice(), suite_id, label, ikm].concat());
    hkdf::HkdfSha256::extract(labeled_ikm.as_slice(), hkdf::Salt::NonEmpty(salt))
}

/// LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, "HPKE-v1" || suite_id || label || info, L)
fn labeled_expand(
    prk: &hkdf::Prk,
    label: &[u8],
    info: &[u8],
    suite_id: &[u8],
    len: u16,
) -> Result<SecretBox, Status> {
    let labeled_info =
        SecretBox::new([&len.to_be_bytes()[..], b"HPKE-v1", suite_id, label, info].concat());

    let mut result = vec![0u8; len as usize];
    prk.expand_into(labeled_info.as_slice(), &mut result)
        .map_err(|_| Status::DecapsulationFailure)?;

    Ok(SecretBox::new(result))
}

/// Generates a new X25519 keypair directly inside Vault (memfd_secret).
pub(crate) fn generate_keypair() -> Result<(X25519PublicKey, Vault), Status> {
    let mut pub_key_bytes = [0u8; 32];
    let mut vault = Vault::new_empty(32).map_err(|_| Status::CryptoError)?;

    vault.write_secret(|vault_mut_slice| unsafe {
        bssl_sys::X25519_keypair(pub_key_bytes.as_mut_ptr(), vault_mut_slice.as_mut_ptr());
    });

    Ok((X25519PublicKey(pub_key_bytes), vault))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_decaps_x25519_clamped_vector() {
        // Vectors from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1
        let sk_r_hex = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
        let enc_hex = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";

        let expected_shared_secret_hex =
            "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";

        let sk_r_bytes: Vec<u8> = hex::decode(sk_r_hex).unwrap();
        let sk_r = X25519PrivateKeyRef(sk_r_bytes.as_slice().try_into().unwrap());
        let enc = hex::decode(enc_hex).unwrap();

        let result = sk_r.decaps_internal(&enc).expect("Decapsulation failed");

        assert_eq!(
            hex::encode(result.as_slice()),
            expected_shared_secret_hex,
            "Shared secret mismatch"
        );
    }

    #[test]
    fn test_labeled_extract_and_expand() {
        let suite_id = [b'K', b'E', b'M', 0, 0x20];
        let salt = b"test_salt";
        let label = b"test_label";
        let ikm = b"test_ikm";
        let info = b"test_info";

        // 1. Test labeled_extract against manual HKDF
        let prk = labeled_extract(salt, label, ikm, &suite_id);

        let expected_labeled_ikm = [b"HPKE-v1".as_slice(), &suite_id, label, ikm].concat();
        let expected_prk =
            hkdf::HkdfSha256::extract(&expected_labeled_ikm, hkdf::Salt::NonEmpty(salt));

        // We can't directly compare Prk objects, so we expand them and compare the results
        let mut prk_output = vec![0u8; 32];
        prk.expand_into(b"test", &mut prk_output).unwrap();
        let mut expected_prk_output = vec![0u8; 32];
        expected_prk
            .expand_into(b"test", &mut expected_prk_output)
            .unwrap();
        assert_eq!(prk_output, expected_prk_output);

        // 2. Test labeled_expand against manual HKDF
        let len = 32;
        let result = labeled_expand(&prk, label, info, &suite_id, len).expect("expand failed");

        let expected_labeled_info =
            [&len.to_be_bytes()[..], b"HPKE-v1", &suite_id, label, info].concat();
        let mut expected_result = vec![0u8; len as usize];
        expected_prk
            .expand_into(&expected_labeled_info, &mut expected_result)
            .unwrap();

        assert_eq!(result.as_slice(), expected_result.as_slice());

        // 3. Test labeled_expand with different length
        let len2 = 16;
        let result2 = labeled_expand(&prk, label, info, &suite_id, len2).expect("expand failed");
        assert_eq!(result2.as_slice().len(), len2 as usize);

        let expected_labeled_info2 =
            [&len2.to_be_bytes()[..], b"HPKE-v1", &suite_id, label, info].concat();
        let mut expected_result2 = vec![0u8; len2 as usize];
        expected_prk
            .expand_into(&expected_labeled_info2, &mut expected_result2)
            .unwrap();
        assert_eq!(result2.as_slice(), expected_result2.as_slice());

        // 4. Test labeled_expand with different info produces different result
        let result3 =
            labeled_expand(&prk, label, b"other_info", &suite_id, len).expect("expand failed");
        assert_ne!(result.as_slice(), result3.as_slice());

        // 5. Test labeled_expand with different label produces different result
        let result4 =
            labeled_expand(&prk, b"other_label", info, &suite_id, len).expect("expand failed");
        assert_ne!(result.as_slice(), result4.as_slice());
    }

    #[test]
    fn test_encaps_x25519_clamped_vector() {
        // Vectors from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1
        let sk_e_hex = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
        let pk_e_hex = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
        let pk_r_hex = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
        let expected_shared_secret_hex =
            "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";

        let sk_e_bytes: Vec<u8> = hex::decode(sk_e_hex).unwrap();
        let pk_r_bytes: [u8; 32] = hex::decode(pk_r_hex).unwrap().try_into().unwrap();

        let pk_r = X25519PublicKey(pk_r_bytes);
        let sk_ref = X25519PrivateKeyRef(sk_e_bytes.as_slice().try_into().unwrap());
        let sk_e = PrivateKeyRef::X25519(sk_ref);

        let (shared_secret, enc) = pk_r.encap_internal(Some(&sk_e)).expect("encap failed");

        assert_eq!(hex::encode(enc), pk_e_hex, "Encapsulated key mismatch");
        assert_eq!(
            hex::encode(shared_secret.as_slice()),
            expected_shared_secret_hex,
            "Shared secret mismatch"
        );
    }

    #[test]
    fn test_generate_keypair_roundtrip() {
        let (pub_key, vault) = generate_keypair().expect("Failed to generate keypair");

        // Verify public key matches private key
        vault.with_secret(|priv_key_bytes| {
            let mut derived_pub = [0u8; 32];
            unsafe {
                bssl_sys::X25519_public_from_private(
                    derived_pub.as_mut_ptr(),
                    priv_key_bytes.as_ptr(),
                );
            }
            assert_eq!(
                pub_key.0, derived_pub,
                "Public key does not match private key"
            );
        });

        // Verify decapsulation works
        let (shared_secret_sender, enc) = pub_key.encap_internal(None).expect("Failed to encap");

        let shared_secret_receiver = vault.with_secret(|priv_key_bytes| {
            let sk_ref = X25519PrivateKeyRef(priv_key_bytes.try_into().unwrap());
            sk_ref.decaps_internal(&enc).expect("Failed to decaps")
        });

        assert_eq!(
            shared_secret_sender.as_slice(),
            shared_secret_receiver.as_slice()
        );
    }
}
