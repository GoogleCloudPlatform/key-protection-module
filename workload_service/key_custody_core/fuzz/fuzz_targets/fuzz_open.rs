// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ws_key_custody_core::{key_manager_generate_binding_keypair, key_manager_open};
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Dynamic size splitting to fuzz semantic size boundaries
    if data.len() < 3 {
        return;
    }
    let enc_len = std::cmp::min(data[0] as usize, 128); // Cap at 128 bytes
    let aad_len = std::cmp::min(u16::from_be_bytes([data[1], data[2]]) as usize, 1024); // Cap at 1024 bytes
    let rest = &data[3..];

    if rest.len() < enc_len + aad_len {
        return;
    }
    let enc = &rest[0..enc_len];
    let aad = &rest[enc_len..enc_len + aad_len];
    let ciphertext = &rest[enc_len + aad_len..];

    // Initialize a valid key once
    static VALID_UUID: std::sync::OnceLock<Option<[u8; 16]>> = std::sync::OnceLock::new();

    let uuid_opt = VALID_UUID.get_or_init(|| {
        let algo = km_common::proto::HpkeAlgorithm {
            kem: km_common::proto::KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: km_common::proto::KdfAlgorithm::HkdfSha256 as i32,
            aead: km_common::proto::AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();

        let mut uuid = [0u8; 16];
        let mut pubkey = [0u8; 32];
        let pubkey_len = pubkey.len();

        unsafe {
            let status = key_manager_generate_binding_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
                3600,
                uuid.as_mut_ptr(),
                pubkey.as_mut_ptr(),
                pubkey_len,
            );
            if status == km_common::proto::Status::Success {
                Some(uuid)
            } else {
                None
            }
        }
    });

    let Some(uuid) = uuid_opt else {
        return; // Setup failed
    };

    // Call open. Output buffer should be large enough.
    // Plaintext is at most ciphertext len.
    let mut out_plaintext = vec![0u8; ciphertext.len()];
    let out_plaintext_len = out_plaintext.len();

    unsafe {
        key_manager_open(
            uuid.as_ptr(),
            enc.as_ptr(),
            enc.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            aad.as_ptr(),
            aad.len(),
            out_plaintext.as_mut_ptr(),
            out_plaintext_len,
        );
    }
});
